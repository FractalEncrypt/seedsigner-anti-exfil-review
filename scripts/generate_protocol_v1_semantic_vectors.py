"""Regenerate the canonical semantic PSBT-v0 and signed-transcript vector."""

from __future__ import annotations

from dataclasses import replace
import argparse
import hashlib
import json
from pathlib import Path

from anti_exfil.crypto import anti_exfil_sign
from anti_exfil.protocol_v1_codec import Network, ProtocolMessage, Stage
from anti_exfil.protocol_v1_transport import ProtocolV1Package
from anti_exfil.psbt_v1 import (
    build_host_commit_message,
    enumerate_signing_slots,
    reconstruct_signed_psbt_v1,
)
from anti_exfil.psbt_v1_fixtures import build_multiscript_fixture


def generate() -> dict[str, object]:
    fixture = build_multiscript_fixture()
    slots = enumerate_signing_slots(fixture.psbt, fixture.root)
    rhos = {slot.identifier: bytes([0x80 + index]) * 32 for index, slot in enumerate(slots)}
    commit = build_host_commit_message(
        fixture.psbt, fixture.root, Network.TESTNET4, b"z" * 32, rhos
    )
    signature_records = []
    opening_records = []
    reveal_records = []
    for slot, record in zip(slots, commit.slots, strict=True):
        secret = fixture.root.derive(slot.derivation).key.secret
        signature, opening = anti_exfil_sign(secret, slot.message_hash, rhos[slot.identifier])
        opening_records.append(replace(record, opening=opening))
        reveal_records.append(replace(record, opening=opening, rho=rhos[slot.identifier]))
        signature_records.append(replace(record, opening=opening, signature=signature))
    openings = ProtocolMessage(
        Network.TESTNET4, Stage.SIGNER_OPENINGS, commit.session_id,
        commit.psbt_digest, tuple(opening_records),
    )
    reveal = ProtocolMessage(
        Network.TESTNET4, Stage.HOST_REVEAL, commit.session_id,
        commit.psbt_digest, tuple(reveal_records),
    )
    signatures = ProtocolMessage(
        Network.TESTNET4,
        Stage.SIGNER_SIGNATURES,
        commit.session_id,
        commit.psbt_digest,
        tuple(signature_records),
    )
    signed = reconstruct_signed_psbt_v1(
        fixture.psbt, fixture.root, commit, signatures, rhos
    )
    messages = (commit, openings, reveal, signatures)
    packages = tuple(
        ProtocolV1Package(
            message,
            fixture.psbt if message.stage in (Stage.HOST_COMMIT, Stage.HOST_REVEAL) else None,
        ).encode()
        for message in messages
    )
    return {
        "description": "Deterministic canonical PSBT-v0 semantic and signed-transcript vector",
        "network": "testnet4",
        "psbt_hex": fixture.psbt.hex(),
        "psbt_sha256": hashlib.sha256(fixture.psbt).hexdigest(),
        "slot_count": len(slots),
        "slots": [
            {
                "input_index": slot.input_index,
                "script_kind": slot.script_kind,
                "signer_pubkey": slot.signer_pubkey.hex(),
                "message_hash": slot.message_hash.hex(),
            }
            for slot in slots
        ],
        "host_randomness": [
            {
                "input_index": slot.input_index,
                "signer_pubkey": slot.signer_pubkey.hex(),
                "rho": rhos[slot.identifier].hex(),
            }
            for slot in slots
        ],
        "message_1_hex": commit.encode().hex(),
        "message_2_hex": openings.encode().hex(),
        "message_3_hex": reveal.encode().hex(),
        "message_4_hex": signatures.encode().hex(),
        "aext_packages": [
            {
                "stage": int(message.stage),
                "package_hex": package.hex(),
                "package_sha256": hashlib.sha256(package).hexdigest(),
            }
            for message, package in zip(messages, packages, strict=True)
        ],
        "signed_psbt_sha256": hashlib.sha256(signed).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "fixtures"
        / "protocol-v1-semantic-psbt-vector.json",
    )
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(generate(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
