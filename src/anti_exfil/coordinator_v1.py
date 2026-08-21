"""Durable temporary coordinator for the frozen multi-slot protocol v1."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from embit import bip32

from .crypto import host_commit, verify_anti_exfil
from .errors import AntiExfilError, ErrorCode
from .protocol_v1_codec import Network, ProtocolMessage, SigningSlot, Stage, decode_message, validate_transition
from .protocol_v1_transport import ProtocolV1Package
from .psbt_v1 import build_host_commit_message, enumerate_signing_slots_for_fingerprint, reconstruct_signed_psbt_v1
from .storage import read_bytes, save_state, write_exact


STATE_VERSION = 2
ORIGINAL_PSBT = "original.psbt"
MESSAGE_1 = "message-1.aex"


def host_init_v1(
    *,
    psbt_path: Path,
    root: bip32.HDKey | None,
    signer_fingerprint: bytes | None = None,
    network: Network,
    session_dir: Path,
    output_package_path: Path,
    session_id: bytes | None = None,
    rhos: dict[tuple[int, bytes], bytes] | None = None,
) -> ProtocolV1Package:
    raw = read_bytes(psbt_path)
    session_id = os.urandom(32) if session_id is None else session_id
    # Enumerate once with deterministic placeholders to learn the exact slot set.
    from .psbt_v1 import enumerate_signing_slots

    if root is not None:
        semantic = enumerate_signing_slots(raw, root)
    elif signer_fingerprint is not None:
        semantic = enumerate_signing_slots_for_fingerprint(raw, signer_fingerprint)
    else:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "coordinator requires a signer fingerprint")
    if rhos is None:
        rhos = {slot.identifier: os.urandom(32) for slot in semantic}
    if root is not None:
        message = build_host_commit_message(raw, root, network, session_id, rhos)
    else:
        records = tuple(
            SigningSlot(slot.input_index, slot.signer_pubkey, slot.message_hash,
                        slot.sighash_type, host_commit(rhos[slot.identifier]))
            for slot in semantic
        )
        message = ProtocolMessage(network, Stage.HOST_COMMIT, session_id, hashlib.sha256(raw).digest(), records)
        message.encode()
    package = ProtocolV1Package(message, raw)
    encoded_package = package.encode()
    state = {
        "state_version": STATE_VERSION,
        "protocol": "AEXB-v1-multislot",
        "phase": "COMMITMENTS_CREATED",
        "network": int(network),
        "session_id": session_id.hex(),
        "psbt_sha256": hashlib.sha256(raw).hexdigest(),
        "message_1": message.encode().hex(),
        "message_2": None,
        "message_3": None,
        "message_4": None,
        "rhos": [
            {
                "input_index": slot.input_index,
                "signer_pubkey": slot.signer_pubkey.hex(),
                "rho": rhos[slot.identifier].hex(),
            }
            for slot in semantic
        ],
    }
    save_state(session_dir, state, create=True)
    write_exact(session_dir / ORIGINAL_PSBT, raw)
    write_exact(session_dir / MESSAGE_1, message.encode())
    write_exact(output_package_path, encoded_package)
    return package


def host_accept_openings_v1(
    *,
    session_dir: Path,
    input_package_path: Path,
    output_package_path: Path,
) -> ProtocolV1Package:
    state = _load_state(session_dir)
    incoming = ProtocolV1Package.decode(read_bytes(input_package_path))
    if incoming.message.stage != Stage.SIGNER_OPENINGS:
        raise AntiExfilError(ErrorCode.WRONG_STAGE, "coordinator requires signer-openings message 2")
    previous = decode_message(bytes.fromhex(state["message_1"]))
    validate_transition(previous, incoming.message)
    _require_state_context(state, incoming.message)
    encoded_message_2 = incoming.message.encode().hex()
    phase = state["phase"]
    if phase == "COMMITMENTS_CREATED":
        state["message_2"] = encoded_message_2
        state["phase"] = "OPENINGS_ACCEPTED"
    elif phase in ("OPENINGS_ACCEPTED", "COMPLETE"):
        if state.get("message_2") != encoded_message_2:
            raise AntiExfilError(ErrorCode.RETRY_CONFLICT, "retry changed accepted signer openings")
    else:
        raise AntiExfilError(ErrorCode.STATE_INVALID, f"cannot accept openings in phase {phase}")

    rho_map = _rho_map(state)
    reveal_slots = tuple(
        SigningSlot(
            slot.input_index,
            slot.signer_pubkey,
            slot.message_hash,
            slot.sighash_type,
            slot.commitment,
            opening=slot.opening,
            rho=rho_map[slot.identifier],
        )
        for slot in incoming.message.slots
    )
    reveal = ProtocolMessage(
        incoming.message.network,
        Stage.HOST_REVEAL,
        incoming.message.session_id,
        incoming.message.psbt_digest,
        reveal_slots,
    )
    validate_transition(incoming.message, reveal)
    encoded_reveal = reveal.encode().hex()
    if state.get("message_3") not in (None, encoded_reveal):
        raise AntiExfilError(ErrorCode.RETRY_CONFLICT, "retry would change host reveal message 3")
    state["message_3"] = encoded_reveal
    save_state(session_dir, state)
    original = _load_original(session_dir, state)
    package = ProtocolV1Package(reveal, original)
    write_exact(output_package_path, package.encode())
    return package


def host_complete_v1(
    *,
    session_dir: Path,
    input_package_path: Path,
    signed_psbt_path: Path,
    receipt_path: Path,
) -> dict[str, object]:
    state = _load_state(session_dir)
    incoming = ProtocolV1Package.decode(read_bytes(input_package_path))
    if incoming.message.stage != Stage.SIGNER_SIGNATURES:
        raise AntiExfilError(ErrorCode.WRONG_STAGE, "coordinator requires signer-signatures message 4")
    encoded_message_4 = incoming.message.encode().hex()
    if state["phase"] == "COMPLETE" and state.get("message_4") != encoded_message_4:
        raise AntiExfilError(ErrorCode.RETRY_CONFLICT, "completed session received different signatures")
    if state["phase"] not in ("OPENINGS_ACCEPTED", "COMPLETE"):
        raise AntiExfilError(ErrorCode.STATE_INVALID, f"cannot complete in phase {state['phase']}")
    reveal = decode_message(bytes.fromhex(state["message_3"]))
    validate_transition(reveal, incoming.message)
    _require_state_context(state, incoming.message)
    rho_map = _rho_map(state)
    for slot in incoming.message.slots:
        if slot.opening is None or slot.signature is None or not verify_anti_exfil(
            slot.signer_pubkey,
            slot.message_hash,
            rho_map[slot.identifier],
            slot.opening,
            slot.signature,
        ):
            raise AntiExfilError(ErrorCode.SIGNATURE_INVALID, "message 4 contains an invalid anti-exfil signature")
    original = _load_original(session_dir, state)
    commit = decode_message(bytes.fromhex(state["message_1"]))
    # Reconstruction re-enumerates every slot and imports only verified signatures.
    signed = reconstruct_signed_psbt_v1(original, None, commit, incoming.message, rho_map)
    write_exact(signed_psbt_path, signed)
    state["phase"] = "COMPLETE"
    state["message_4"] = encoded_message_4
    save_state(session_dir, state)
    receipt = {
        "status": "verified",
        "protocol": "AEXB-v1-multislot",
        "network": incoming.message.network.name,
        "session_id": incoming.message.session_id.hex(),
        "psbt_sha256": hashlib.sha256(original).hexdigest(),
        "signed_psbt_sha256": hashlib.sha256(signed).hexdigest(),
        "slot_count": len(incoming.message.slots),
        "slots": [
            {
                "input_index": slot.input_index,
                "signer_pubkey": slot.signer_pubkey.hex(),
                "message_hash": slot.message_hash.hex(),
                "signature_compact": slot.signature.hex(),
                "anti_exfil_verified": True,
            }
            for slot in incoming.message.slots
        ],
        "psbt_reconstructed_from_original": True,
        "broadcast": False,
    }
    write_exact(receipt_path, (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
    return receipt


def _load_state(session_dir: Path) -> dict[str, object]:
    try:
        state = json.loads((session_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AntiExfilError(ErrorCode.STATE_INVALID, f"cannot load v1 coordinator state: {exc}") from exc
    if not isinstance(state, dict) or state.get("state_version") != STATE_VERSION:
        raise AntiExfilError(ErrorCode.STATE_INVALID, "not a protocol-v1 multi-slot coordinator session")
    return state


def _load_original(session_dir: Path, state: dict[str, object]) -> bytes:
    original = read_bytes(session_dir / ORIGINAL_PSBT)
    if hashlib.sha256(original).hexdigest() != state.get("psbt_sha256"):
        raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "stored original PSBT changed")
    return original


def _rho_map(state: dict[str, object]) -> dict[tuple[int, bytes], bytes]:
    try:
        return {
            (int(item["input_index"]), bytes.fromhex(item["signer_pubkey"])): bytes.fromhex(item["rho"])
            for item in state["rhos"]
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise AntiExfilError(ErrorCode.STATE_INVALID, "invalid coordinator rho set") from exc


def _require_state_context(state: dict[str, object], message: ProtocolMessage) -> None:
    if message.session_id.hex() != state.get("session_id"):
        raise AntiExfilError(ErrorCode.SESSION_MISMATCH, "message session differs from coordinator state")
    if int(message.network) != state.get("network") or message.psbt_digest.hex() != state.get("psbt_sha256"):
        raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "message network or PSBT differs from coordinator state")
