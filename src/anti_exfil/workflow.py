"""Independent host and signer operations for the Rung B file transcript."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .crypto import anti_exfil_sign, host_commit, public_key, signer_opening, verify_anti_exfil
from .errors import AntiExfilError, ErrorCode
from .messages import RungBMessage, Stage, decode_message
from .storage import load_state, read_bytes, save_state, write_exact


def host_init(
    *,
    message_hash: bytes,
    signer_pubkey: bytes,
    session_dir: Path,
    output_path: Path,
    rho: bytes | None = None,
    session_id: bytes | None = None,
) -> RungBMessage:
    rho = os.urandom(32) if rho is None else rho
    session_id = os.urandom(32) if session_id is None else session_id
    commitment = host_commit(rho)
    message = RungBMessage(
        stage=Stage.HOST_COMMIT,
        session_id=session_id,
        message_hash=message_hash,
        signer_pubkey=signer_pubkey,
        commitment=commitment,
    )
    encoded = message.encode()
    state = {
        "state_version": 1,
        "phase": "COMMITMENTS_CREATED",
        "session_id": session_id.hex(),
        "message_hash": message_hash.hex(),
        "signer_pubkey": signer_pubkey.hex(),
        "rho": rho.hex(),
        "commitment": commitment.hex(),
        "opening": None,
        "signature": None,
    }
    save_state(session_dir, state, create=True)
    write_exact(output_path, encoded)
    return message


def signer_commit(*, input_path: Path, test_secret_key: bytes, output_path: Path) -> RungBMessage:
    request = decode_message(read_bytes(input_path))
    _require_stage(request, Stage.HOST_COMMIT)
    _require_signer_key(request, test_secret_key)
    opening = signer_opening(test_secret_key, request.message_hash, request.commitment)
    response = RungBMessage(
        stage=Stage.SIGNER_OPENINGS,
        session_id=request.session_id,
        message_hash=request.message_hash,
        signer_pubkey=request.signer_pubkey,
        commitment=request.commitment,
        opening=opening,
    )
    write_exact(output_path, response.encode())
    return response


def host_reveal(*, session_dir: Path, input_path: Path, output_path: Path) -> RungBMessage:
    state = load_state(session_dir)
    response = decode_message(read_bytes(input_path))
    _require_stage(response, Stage.SIGNER_OPENINGS)
    _require_state_context(state, response)
    opening_hex = response.opening.hex() if response.opening is not None else None
    phase = state.get("phase")
    if phase == "COMMITMENTS_CREATED":
        state["opening"] = opening_hex
        state["phase"] = "OPENINGS_ACCEPTED"
        save_state(session_dir, state)
    elif phase in ("OPENINGS_ACCEPTED", "COMPLETE"):
        if state.get("opening") != opening_hex:
            raise AntiExfilError(
                ErrorCode.RETRY_CONFLICT,
                "retry supplied a different signer opening for this host session",
            )
    else:
        raise AntiExfilError(ErrorCode.STATE_INVALID, f"host cannot reveal in phase {phase}")

    reveal = RungBMessage(
        stage=Stage.HOST_REVEAL,
        session_id=response.session_id,
        message_hash=response.message_hash,
        signer_pubkey=response.signer_pubkey,
        commitment=response.commitment,
        opening=response.opening,
        rho=bytes.fromhex(state["rho"]),
    )
    write_exact(output_path, reveal.encode())
    return reveal


def signer_sign(*, input_path: Path, test_secret_key: bytes, output_path: Path) -> RungBMessage:
    reveal = decode_message(read_bytes(input_path))
    _require_stage(reveal, Stage.HOST_REVEAL)
    _require_signer_key(reveal, test_secret_key)
    if reveal.rho is None or reveal.opening is None:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "reveal message is incomplete")
    if host_commit(reveal.rho) != reveal.commitment:
        raise AntiExfilError(
            ErrorCode.COMMITMENT_MISMATCH,
            "host randomness does not match the original commitment",
        )
    expected_opening = signer_opening(
        test_secret_key, reveal.message_hash, reveal.commitment
    )
    if expected_opening != reveal.opening:
        raise AntiExfilError(
            ErrorCode.OPENING_MISMATCH,
            "recomputed signer opening does not match the accepted opening",
        )
    signature, signing_opening = anti_exfil_sign(
        test_secret_key, reveal.message_hash, reveal.rho
    )
    if signing_opening != reveal.opening:
        raise AntiExfilError(
            ErrorCode.OPENING_MISMATCH,
            "signing primitive did not reproduce the accepted opening",
        )
    response = RungBMessage(
        stage=Stage.SIGNER_SIGNATURES,
        session_id=reveal.session_id,
        message_hash=reveal.message_hash,
        signer_pubkey=reveal.signer_pubkey,
        commitment=reveal.commitment,
        opening=reveal.opening,
        rho=reveal.rho,
        signature=signature,
    )
    write_exact(output_path, response.encode())
    return response


def host_verify(*, session_dir: Path, input_path: Path, receipt_path: Path) -> dict[str, Any]:
    state = load_state(session_dir)
    response = decode_message(read_bytes(input_path))
    _require_stage(response, Stage.SIGNER_SIGNATURES)
    _require_state_context(state, response)
    if state.get("phase") not in ("OPENINGS_ACCEPTED", "COMPLETE"):
        raise AntiExfilError(
            ErrorCode.STATE_INVALID,
            f"host cannot verify signatures in phase {state.get('phase')}",
        )
    if response.opening is None or response.rho is None or response.signature is None:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "signature response is incomplete")
    if response.opening.hex() != state.get("opening"):
        raise AntiExfilError(ErrorCode.OPENING_MISMATCH, "signature response changed the opening")
    if response.rho.hex() != state.get("rho"):
        raise AntiExfilError(ErrorCode.COMMITMENT_MISMATCH, "signature response changed host randomness")
    if not verify_anti_exfil(
        response.signer_pubkey,
        response.message_hash,
        response.rho,
        response.opening,
        response.signature,
    ):
        raise AntiExfilError(
            ErrorCode.SIGNATURE_INVALID,
            "ordinary ECDSA or anti-exfil opening verification failed",
        )
    signature_hex = response.signature.hex()
    if state.get("phase") == "COMPLETE" and state.get("signature") != signature_hex:
        raise AntiExfilError(
            ErrorCode.RETRY_CONFLICT,
            "completed session received a different signature",
        )
    state["phase"] = "COMPLETE"
    state["signature"] = signature_hex
    save_state(session_dir, state)
    receipt: dict[str, Any] = {
        "status": "verified",
        "session_id": response.session_id.hex(),
        "message_hash": response.message_hash.hex(),
        "signer_pubkey": response.signer_pubkey.hex(),
        "host_commitment": response.commitment.hex(),
        "signer_opening": response.opening.hex(),
        "signature_compact": signature_hex,
        "ordinary_ecdsa_verified": True,
        "anti_exfil_opening_verified": True,
    }
    write_exact(
        receipt_path,
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return receipt


def inspect_message(path: Path) -> dict[str, object]:
    return decode_message(read_bytes(path)).diagnostic()


def load_test_secret(path: Path) -> bytes:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        secret_hex = value["secret_key"]
        secret = bytes.fromhex(secret_hex)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise AntiExfilError(ErrorCode.STATE_INVALID, f"invalid test key fixture: {exc}") from exc
    # public_key performs full scalar validation.
    public_key(secret)
    return secret


def _require_stage(message: RungBMessage, expected: Stage) -> None:
    if message.stage != expected:
        raise AntiExfilError(
            ErrorCode.WRONG_STAGE,
            f"expected {expected.name}, received {message.stage.name}",
        )


def _require_signer_key(message: RungBMessage, test_secret_key: bytes) -> None:
    if public_key(test_secret_key) != message.signer_pubkey:
        raise AntiExfilError(
            ErrorCode.TEST_KEY_MISMATCH,
            "test fixture key does not match the requested signer public key",
        )


def _require_state_context(state: dict[str, Any], message: RungBMessage) -> None:
    comparisons = (
        ("session_id", message.session_id.hex(), ErrorCode.SESSION_MISMATCH),
        ("message_hash", message.message_hash.hex(), ErrorCode.TRANSACTION_MISMATCH),
        ("signer_pubkey", message.signer_pubkey.hex(), ErrorCode.SIGNATURE_SLOT_MISMATCH),
        ("commitment", message.commitment.hex(), ErrorCode.COMMITMENT_MISMATCH),
    )
    for field, actual, code in comparisons:
        if state.get(field) != actual:
            raise AntiExfilError(code, f"message {field} does not match host session")

