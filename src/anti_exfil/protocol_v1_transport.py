"""Strict AEXT envelope for canonical multi-slot protocol-v1 messages."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from .errors import AntiExfilError, ErrorCode
from .protocol_v1_codec import (
    MAX_MESSAGE_BYTES,
    Network,
    ProtocolMessage,
    Stage,
    decode_message,
)


MAGIC = b"AEXT"
VERSION = 1
FLAG_PSBT = 1
MAX_PSBT_BYTES = 2_000_000
HEADER = struct.Struct(">4sBBBBII32s")


@dataclass(frozen=True, slots=True)
class ProtocolV1Package:
    message: ProtocolMessage
    psbt: bytes | None = None

    @property
    def network(self) -> Network:
        """Expose the bound wire network consistently with the legacy package API."""
        return self.message.network

    def encode(self) -> bytes:
        message_bytes = self.message.encode()
        requires_psbt = self.message.stage in (Stage.HOST_COMMIT, Stage.HOST_REVEAL)
        if requires_psbt != (self.psbt is not None):
            requirement = "requires" if requires_psbt else "forbids"
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE,
                f"transport stage {self.message.stage.name} {requirement} a PSBT",
            )
        psbt = self.psbt or b""
        if len(psbt) > MAX_PSBT_BYTES:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "transport PSBT is oversized")
        if psbt and not psbt.startswith(b"psbt\xff"):
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "transport PSBT has invalid magic")
        digest = hashlib.sha256(psbt).digest() if psbt else bytes(32)
        if psbt and digest != self.message.psbt_digest:
            raise AntiExfilError(
                ErrorCode.TRANSACTION_MISMATCH,
                "embedded protocol digest does not match the exact transport PSBT",
            )
        flags = FLAG_PSBT if psbt else 0
        return HEADER.pack(
            MAGIC,
            VERSION,
            int(self.message.network),
            int(self.message.stage),
            flags,
            len(message_bytes),
            len(psbt),
            digest,
        ) + message_bytes + psbt

    @classmethod
    def decode(cls, payload: bytes) -> "ProtocolV1Package":
        if len(payload) < HEADER.size:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "truncated AEXT transport header")
        (
            magic,
            version,
            network_number,
            stage_number,
            flags,
            message_len,
            psbt_len,
            digest,
        ) = HEADER.unpack_from(payload)
        if magic != MAGIC or version != VERSION or flags & ~FLAG_PSBT:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "invalid AEXT transport header")
        try:
            network = Network(network_number)
        except ValueError as exc:
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, f"unknown AEXT network {network_number}"
            ) from exc
        try:
            stage = Stage(stage_number)
        except ValueError as exc:
            raise AntiExfilError(ErrorCode.WRONG_STAGE, f"unknown AEXT stage {stage_number}") from exc
        if message_len > MAX_MESSAGE_BYTES or psbt_len > MAX_PSBT_BYTES:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "transport package is oversized")
        if len(payload) != HEADER.size + message_len + psbt_len:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "AEXT lengths do not match payload")
        has_psbt = bool(flags & FLAG_PSBT)
        if has_psbt != bool(psbt_len):
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "AEXT PSBT flag is inconsistent")
        message_bytes = payload[HEADER.size : HEADER.size + message_len]
        psbt_bytes = payload[HEADER.size + message_len :]
        expected_digest = hashlib.sha256(psbt_bytes).digest() if has_psbt else bytes(32)
        if digest != expected_digest:
            raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "AEXT PSBT digest mismatch")
        message = decode_message(message_bytes)
        if message.network != network:
            raise AntiExfilError(
                ErrorCode.TRANSACTION_MISMATCH,
                "AEXT network conflicts with the embedded protocol message",
            )
        if message.stage != stage:
            raise AntiExfilError(
                ErrorCode.WRONG_STAGE,
                "AEXT stage conflicts with the embedded protocol message",
            )
        package = cls(message=message, psbt=psbt_bytes if has_psbt else None)
        if package.encode() != payload:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "AEXT package is not canonical")
        return package
