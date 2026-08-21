"""Experimental fixed binary messages for the Rung B terminal workflow.

`AEXB` is intentionally not the final QR/PSBT wire format. It gives the host
and signer a strict canonical byte boundary while the normative envelope is
still under design.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import struct

from .crypto import CryptoModelError, GROUP_N, parse_point
from .errors import AntiExfilError, ErrorCode


MAGIC = b"AEXB"
FORMAT_VERSION = 1
HEADER = struct.Struct(">4sBBH")
COMMON_LENGTH = 32 + 32 + 33


class Stage(IntEnum):
    HOST_COMMIT = 1
    SIGNER_OPENINGS = 2
    HOST_REVEAL = 3
    SIGNER_SIGNATURES = 4


_STAGE_EXTRA_LENGTHS = {
    Stage.HOST_COMMIT: 32,
    Stage.SIGNER_OPENINGS: 32 + 33,
    Stage.HOST_REVEAL: 32 + 33 + 32,
    Stage.SIGNER_SIGNATURES: 32 + 33 + 32 + 64,
}


@dataclass(frozen=True, slots=True)
class RungBMessage:
    stage: Stage
    session_id: bytes
    message_hash: bytes
    signer_pubkey: bytes
    commitment: bytes
    opening: bytes | None = None
    rho: bytes | None = None
    signature: bytes | None = None

    def encode(self) -> bytes:
        _validate_message(self)
        payload = self.session_id + self.message_hash + self.signer_pubkey + self.commitment
        if self.opening is not None:
            payload += self.opening
        if self.rho is not None:
            payload += self.rho
        if self.signature is not None:
            payload += self.signature
        return HEADER.pack(MAGIC, FORMAT_VERSION, int(self.stage), len(payload)) + payload

    def diagnostic(self) -> dict[str, object]:
        result: dict[str, object] = {
            "format": "AEXB",
            "format_version": FORMAT_VERSION,
            "stage": self.stage.name,
            "stage_number": int(self.stage),
            "session_id": self.session_id.hex(),
            "message_hash": self.message_hash.hex(),
            "signer_pubkey": self.signer_pubkey.hex(),
            "host_commitment": self.commitment.hex(),
        }
        if self.opening is not None:
            result["signer_opening"] = self.opening.hex()
        if self.rho is not None:
            result["host_randomness"] = self.rho.hex()
        if self.signature is not None:
            result["signature_compact"] = self.signature.hex()
        return result


def decode_message(encoded: bytes) -> RungBMessage:
    if len(encoded) < HEADER.size:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "message is shorter than the AEXB header")
    magic, version, stage_number, payload_length = HEADER.unpack(encoded[: HEADER.size])
    if magic != MAGIC:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "message has the wrong AEXB magic")
    if version != FORMAT_VERSION:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE,
            f"unsupported AEXB format version {version}",
        )
    try:
        stage = Stage(stage_number)
    except ValueError as exc:
        raise AntiExfilError(
            ErrorCode.WRONG_STAGE, f"unknown AEXB stage {stage_number}"
        ) from exc
    payload = encoded[HEADER.size :]
    expected_length = COMMON_LENGTH + _STAGE_EXTRA_LENGTHS[stage]
    if payload_length != len(payload) or payload_length != expected_length:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE,
            f"stage {stage.name} payload length is not canonical",
        )

    offset = 0

    def take(length: int) -> bytes:
        nonlocal offset
        value = payload[offset : offset + length]
        offset += length
        return value

    session_id = take(32)
    message_hash = take(32)
    signer_pubkey = take(33)
    commitment = take(32)
    opening = take(33) if stage >= Stage.SIGNER_OPENINGS else None
    rho = take(32) if stage >= Stage.HOST_REVEAL else None
    signature = take(64) if stage >= Stage.SIGNER_SIGNATURES else None
    message = RungBMessage(
        stage=stage,
        session_id=session_id,
        message_hash=message_hash,
        signer_pubkey=signer_pubkey,
        commitment=commitment,
        opening=opening,
        rho=rho,
        signature=signature,
    )
    _validate_message(message)
    return message


def _validate_message(message: RungBMessage) -> None:
    for name, value, length in (
        ("session ID", message.session_id, 32),
        ("message hash", message.message_hash, 32),
        ("signer public key", message.signer_pubkey, 33),
        ("host commitment", message.commitment, 32),
    ):
        if not isinstance(value, bytes) or len(value) != length:
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, f"{name} must be exactly {length} bytes"
            )
    try:
        parse_point(message.signer_pubkey)
    except CryptoModelError as exc:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "invalid signer public key") from exc

    needs_opening = message.stage >= Stage.SIGNER_OPENINGS
    needs_rho = message.stage >= Stage.HOST_REVEAL
    needs_signature = message.stage >= Stage.SIGNER_SIGNATURES
    if (message.opening is not None) != needs_opening:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "opening presence conflicts with stage")
    if (message.rho is not None) != needs_rho:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "host reveal presence conflicts with stage")
    if (message.signature is not None) != needs_signature:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "signature presence conflicts with stage")
    if message.opening is not None:
        try:
            parse_point(message.opening)
        except CryptoModelError as exc:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "invalid signer opening") from exc
    if message.rho is not None and len(message.rho) != 32:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "host reveal must be 32 bytes")
    if message.signature is not None:
        if len(message.signature) != 64:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "compact signature must be 64 bytes")
        r = int.from_bytes(message.signature[:32], "big")
        s = int.from_bytes(message.signature[32:], "big")
        if not (1 <= r < GROUP_N and 1 <= s <= GROUP_N // 2):
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, "signature scalars are invalid or non-low-S"
            )

