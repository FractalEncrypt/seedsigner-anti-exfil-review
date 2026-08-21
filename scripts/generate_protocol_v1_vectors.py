"""Regenerate canonical multi-slot AEXB/AEXT/UR protocol-v1 vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from anti_exfil.crypto import anti_exfil_sign, host_commit, public_key, signer_opening
from anti_exfil.protocol_v1_codec import (
    Network,
    ProtocolMessage,
    SIGHASH_ALL,
    SigningSlot,
    Stage,
)
from anti_exfil.protocol_v1_transport import ProtocolV1Package
from anti_exfil.transport import _cbor_bytes, encode_ur_frames


SESSION = bytes.fromhex("c3" * 32)
PSBT = b"psbt\xff" + b"protocol-v1-synthetic-wire-fixture"
SECRETS = (
    bytes.fromhex("11" * 32),
    bytes.fromhex("22" * 32),
    bytes.fromhex("33" * 32),
)
RHOS = (
    bytes.fromhex("a1" * 32),
    bytes.fromhex("a2" * 32),
    bytes.fromhex("a3" * 32),
)
MESSAGE_HASHES = (
    bytes.fromhex("81" * 32),
    bytes.fromhex("82" * 32),
    bytes.fromhex("83" * 32),
)


def build_message(stage: Stage) -> ProtocolMessage:
    slots = []
    for input_index, secret, rho, message_hash in (
        (0, SECRETS[0], RHOS[0], MESSAGE_HASHES[0]),
        (1, SECRETS[1], RHOS[1], MESSAGE_HASHES[1]),
        (1, SECRETS[2], RHOS[2], MESSAGE_HASHES[2]),
    ):
        commitment = host_commit(rho)
        opening = None
        reveal = None
        signature = None
        if stage >= Stage.SIGNER_OPENINGS:
            opening = signer_opening(secret, message_hash, commitment)
        if stage == Stage.HOST_REVEAL:
            reveal = rho
        if stage == Stage.SIGNER_SIGNATURES:
            signature, signing_opening = anti_exfil_sign(secret, message_hash, rho)
            if signing_opening != opening:
                raise RuntimeError("deterministic signing opening mismatch")
        slots.append(
            SigningSlot(
                input_index=input_index,
                signer_pubkey=public_key(secret),
                message_hash=message_hash,
                sighash_type=SIGHASH_ALL,
                commitment=commitment,
                opening=opening,
                rho=reveal,
                signature=signature,
            )
        )
    slots.sort(key=lambda slot: slot.identifier)
    return ProtocolMessage(
        network=Network.TESTNET4,
        stage=stage,
        session_id=SESSION,
        psbt_digest=hashlib.sha256(PSBT).digest(),
        slots=tuple(slots),
    )


def generate(seedsigner_src: Path) -> dict[str, object]:
    messages = []
    for stage in Stage:
        message = build_message(stage)
        message_bytes = message.encode()
        psbt = PSBT if stage in (Stage.HOST_COMMIT, Stage.HOST_REVEAL) else None
        package_bytes = ProtocolV1Package(message, psbt).encode()
        messages.append(
            {
                "name": f"message-{int(stage)}-{stage.name.lower().replace('_', '-')}",
                "stage": int(stage),
                "record_length": (len(message_bytes) - 78) // len(message.slots),
                "message_length": len(message_bytes),
                "message_sha256": hashlib.sha256(message_bytes).hexdigest(),
                "message_hex": message_bytes.hex(),
                "package_length": len(package_bytes),
                "package_sha256": hashlib.sha256(package_bytes).hexdigest(),
                "package_hex": package_bytes.hex(),
                "canonical_cbor_hex": _cbor_bytes(package_bytes).hex(),
                "medium_ur_parts": encode_ur_frames(
                    package_bytes,
                    seedsigner_src=seedsigner_src,
                    max_fragment_len=30,
                    fountain_windows=1,
                ),
            }
        )
    first = build_message(Stage.HOST_COMMIT)
    return {
        "format": "AEXB/AEXT protocol-v1 multi-slot golden vectors",
        "protocol_version": 1,
        "aexb_format_version": 1,
        "aext_version": 1,
        "ur_type": "x-btc-anti-exfil",
        "network": "testnet4",
        "network_code": int(Network.TESTNET4),
        "slot_count": len(first.slots),
        "slot_identifiers": [
            {
                "input_index": slot.input_index,
                "signer_pubkey": slot.signer_pubkey.hex(),
            }
            for slot in first.slots
        ],
        "psbt_fixture_kind": "synthetic AEXT/UR byte fixture; not a semantically valid or spendable PSBT",
        "psbt_hex": PSBT.hex(),
        "psbt_sha256": hashlib.sha256(PSBT).hexdigest(),
        "messages": messages,
    }


def main() -> None:
    default_seedsigner = (
        Path(__file__).resolve().parents[2] / "Windsurf" / "SeedSigner_AntiExfil" / "src"
    )
    default_output = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "protocol-v1-multislot-vectors.json"
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--seedsigner-src", type=Path, default=default_seedsigner)
    parser.add_argument("--output", type=Path, default=default_output)
    args = parser.parse_args()
    document = generate(args.seedsigner_src)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
