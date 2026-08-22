"""Regenerate shared host-side negative vectors for anti-exfil protocol v1."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from anti_exfil.crypto import host_commit, public_key, signer_opening
from anti_exfil.protocol_v1_codec import (
    COMMON_RECORD,
    HEADER as AEXB_HEADER,
    Network,
    ProtocolMessage,
    SIGHASH_ALL,
    SigningSlot,
    Stage,
)
from anti_exfil.protocol_v1_transport import (
    HEADER as AEXT_HEADER,
    MAGIC as AEXT_MAGIC,
    VERSION as AEXT_VERSION,
)


SESSION = bytes.fromhex("d4" * 32)
PSBT_DIGEST = hashlib.sha256(b"protocol-v1-host-negative-vectors").digest()
SECRET = bytes.fromhex("41" * 32)
MESSAGE_HASHES = (bytes.fromhex("91" * 32), bytes.fromhex("92" * 32))
RHOS = (bytes.fromhex("b1" * 32), bytes.fromhex("b2" * 32))


def reused_opening_message() -> bytes:
    signer_pubkey = public_key(SECRET)
    slots = []
    for input_index, message_hash, rho in zip(
        (0, 1), MESSAGE_HASHES, RHOS, strict=True
    ):
        commitment = host_commit(rho)
        slots.append(
            SigningSlot(
                input_index=input_index,
                signer_pubkey=signer_pubkey,
                message_hash=message_hash,
                sighash_type=SIGHASH_ALL,
                commitment=commitment,
                opening=signer_opening(SECRET, message_hash, commitment),
            )
        )
    valid = bytearray(
        ProtocolMessage(
            network=Network.TESTNET4,
            stage=Stage.SIGNER_OPENINGS,
            session_id=SESSION,
            psbt_digest=PSBT_DIGEST,
            slots=tuple(slots),
        ).encode()
    )
    record_length = COMMON_RECORD.size + 33
    first_opening = AEXB_HEADER.size + COMMON_RECORD.size
    second_opening = AEXB_HEADER.size + record_length + COMMON_RECORD.size
    valid[second_opening : second_opening + 33] = valid[first_opening : first_opening + 33]
    return bytes(valid)


def generate() -> dict[str, object]:
    encoded = reused_opening_message()
    package = AEXT_HEADER.pack(
        AEXT_MAGIC,
        AEXT_VERSION,
        int(Network.TESTNET4),
        int(Stage.SIGNER_OPENINGS),
        0,
        len(encoded),
        0,
        bytes(32),
    ) + encoded
    return {
        "format": "AEXB protocol-v1 host-side negative vectors",
        "protocol_version": 1,
        "cases": [
            {
                "name": "same-signer-opening-reused-across-inputs",
                "stage": int(Stage.SIGNER_OPENINGS),
                "expected_error": "OPENING_MISMATCH",
                "message_length": len(encoded),
                "message_sha256": hashlib.sha256(encoded).hexdigest(),
                "message_hex": encoded.hex(),
                "package_length": len(package),
                "package_sha256": hashlib.sha256(package).hexdigest(),
                "package_hex": package.hex(),
            }
        ],
    }


def main() -> None:
    default_output = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "protocol-v1-negative-vectors.json"
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=default_output)
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(generate(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
