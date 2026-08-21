"""Rung E strict transport package and SeedSigner-compatible UR2 framing."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib
from pathlib import Path
import struct
import sys

from .errors import AntiExfilError, ErrorCode
from .messages import Stage, decode_message


MAGIC = b"AEXT"
VERSION = 1
UR_TYPE = "x-btc-anti-exfil"
FLAG_PSBT = 1
HEADER = struct.Struct(">4sBBBBII32s")
MAX_MESSAGE_BYTES = 65_536
MAX_PSBT_BYTES = 2_000_000


class TransportNetwork(IntEnum):
    """User-visible Bitcoin network bound to every transport message."""

    MAINNET = 0
    TESTNET = 1
    REGTEST = 2
    SIGNET = 3


@dataclass(frozen=True, slots=True)
class TransportPackage:
    message: bytes
    network: TransportNetwork
    psbt: bytes | None = None

    def encode(self) -> bytes:
        parsed = decode_message(self.message)
        requires_psbt = parsed.stage in (Stage.HOST_COMMIT, Stage.HOST_REVEAL)
        if requires_psbt != (self.psbt is not None):
            requirement = "requires" if requires_psbt else "forbids"
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE,
                f"transport stage {parsed.stage.name} {requirement} a PSBT context",
            )
        psbt = self.psbt or b""
        if len(self.message) > MAX_MESSAGE_BYTES or len(psbt) > MAX_PSBT_BYTES:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "transport package is oversized")
        try:
            network = TransportNetwork(self.network)
        except (TypeError, ValueError) as exc:
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, "transport network is invalid"
            ) from exc
        if psbt and not psbt.startswith(b"psbt\xff"):
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, "transport PSBT has invalid magic"
            )
        flags = FLAG_PSBT if psbt else 0
        digest = hashlib.sha256(psbt).digest() if psbt else bytes(32)
        return HEADER.pack(
            MAGIC,
            VERSION,
            int(network),
            int(parsed.stage),
            flags,
            len(self.message),
            len(psbt),
            digest,
        ) + self.message + psbt

    @classmethod
    def decode(cls, payload: bytes) -> "TransportPackage":
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
            network = TransportNetwork(network_number)
        except ValueError as exc:
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, f"unknown AEXT network {network_number}"
            ) from exc
        try:
            outer_stage = Stage(stage_number)
        except ValueError as exc:
            raise AntiExfilError(
                ErrorCode.WRONG_STAGE, f"unknown AEXT stage {stage_number}"
            ) from exc
        if message_len > MAX_MESSAGE_BYTES or psbt_len > MAX_PSBT_BYTES:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "transport package is oversized")
        if len(payload) != HEADER.size + message_len + psbt_len:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "AEXT lengths do not match payload")
        message = payload[HEADER.size : HEADER.size + message_len]
        psbt_bytes = payload[HEADER.size + message_len :]
        has_psbt = bool(flags & FLAG_PSBT)
        if has_psbt != bool(psbt_len):
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "AEXT PSBT flag is inconsistent")
        expected_digest = hashlib.sha256(psbt_bytes).digest() if has_psbt else bytes(32)
        if digest != expected_digest:
            raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "AEXT PSBT digest mismatch")
        parsed = decode_message(message)
        if parsed.stage != outer_stage:
            raise AntiExfilError(
                ErrorCode.WRONG_STAGE,
                "AEXT stage conflicts with the embedded protocol message",
            )
        package = cls(
            message=message,
            network=network,
            psbt=psbt_bytes if has_psbt else None,
        )
        # Reapply all stage/context invariants during decode.
        package.encode()
        return package


def _load_ur2(seedsigner_src: Path):
    source = str(seedsigner_src.resolve())
    if source not in sys.path:
        sys.path.insert(0, source)
    try:
        from seedsigner.helpers.ur2.ur import UR
        from seedsigner.helpers.ur2.ur_decoder import URDecoder
        from seedsigner.helpers.ur2.ur_encoder import UREncoder
    except ImportError as exc:
        raise AntiExfilError(
            ErrorCode.STATE_INVALID, f"cannot import SeedSigner UR2 implementation: {exc}"
        ) from exc
    return UR, URDecoder, UREncoder


def _cbor_bytes(data: bytes) -> bytes:
    length = len(data)
    if length < 24:
        return bytes([0x40 | length]) + data
    if length <= 0xFF:
        return b"\x58" + bytes([length]) + data
    if length <= 0xFFFF:
        return b"\x59" + length.to_bytes(2, "big") + data
    if length <= 0xFFFFFFFF:
        return b"\x5a" + length.to_bytes(4, "big") + data
    raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "CBOR byte string is too large")


def _decode_cbor_bytes(encoded: bytes) -> bytes:
    if not encoded:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "empty CBOR payload")
    initial = encoded[0]
    if initial >> 5 != 2:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "UR payload is not a CBOR byte string")
    additional = initial & 0x1F
    if additional < 24:
        length, offset = additional, 1
    elif additional == 24:
        if len(encoded) < 2:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "truncated CBOR length")
        length, offset = encoded[1], 2
        if length < 24:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "non-canonical CBOR length")
    elif additional == 25:
        if len(encoded) < 3:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "truncated CBOR length")
        length, offset = int.from_bytes(encoded[1:3], "big"), 3
        if length <= 0xFF:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "non-canonical CBOR length")
    elif additional == 26:
        if len(encoded) < 5:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "truncated CBOR length")
        length, offset = int.from_bytes(encoded[1:5], "big"), 5
        if length <= 0xFFFF:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "non-canonical CBOR length")
    else:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "unsupported CBOR byte-string length")
    if len(encoded) != offset + length:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "CBOR length does not match payload")
    return encoded[offset:]


def encode_ur_frames(
    payload: bytes,
    *,
    seedsigner_src: Path,
    max_fragment_len: int = 80,
    fountain_windows: int = 2,
) -> list[str]:
    if max_fragment_len < 10:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "UR fragment size must be at least 10")
    if not 1 <= fountain_windows <= 4:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, "UR fountain windows must be between 1 and 4"
        )
    UR, _, UREncoder = _load_ur2(seedsigner_src)
    # SeedSigner's vendored fountain encoder pads its input in place.
    cbor = bytearray(_cbor_bytes(payload))
    encoder = UREncoder(UR(UR_TYPE, cbor), max_fragment_len=max_fragment_len)
    count = (
        1
        if encoder.is_single_part()
        else encoder.fountain_encoder.seq_len() * fountain_windows
    )
    return [encoder.next_part().upper() for _ in range(count)]


def decode_ur_frames(frames: list[str], *, seedsigner_src: Path) -> bytes:
    decoder = URPackageAccumulator(seedsigner_src=seedsigner_src)
    for frame in frames:
        decoder.receive(frame)
        if decoder.is_complete:
            break
    if not decoder.is_complete:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "UR frames are incomplete or invalid")
    return decoder.payload


class URPackageAccumulator:
    """Incrementally reconstruct one strict x-btc-anti-exfil UR payload."""

    def __init__(self, *, seedsigner_src: Path):
        _, URDecoder, _ = _load_ur2(seedsigner_src)
        self._decoder = URDecoder()
        self._payload: bytes | None = None

    def receive(self, frame: str) -> bool:
        normalized = frame.strip()
        if not normalized.lower().startswith(f"ur:{UR_TYPE}/"):
            return False
        accepted = bool(self._decoder.receive_part(normalized))
        if self._decoder.is_success():
            result = self._decoder.result_message()
            if result.type != UR_TYPE:
                raise AntiExfilError(
                    ErrorCode.INVALID_MESSAGE, f"unexpected UR type {result.type}"
                )
            self._payload = bytes(_decode_cbor_bytes(result.cbor))
        return accepted

    @property
    def is_complete(self) -> bool:
        return self._payload is not None

    @property
    def progress(self) -> float:
        if self.is_complete:
            return 1.0
        return float(self._decoder.estimated_percent_complete())

    @property
    def expected_parts(self) -> int | None:
        try:
            value = self._decoder.expected_part_count()
        except (AttributeError, TypeError):
            return None
        return int(value) if value else None

    @property
    def processed_parts(self) -> int:
        try:
            return int(self._decoder.processed_parts_count())
        except (AttributeError, TypeError):
            return 0

    @property
    def payload(self) -> bytes:
        if self._payload is None:
            raise AntiExfilError(ErrorCode.STATE_INVALID, "UR package is not complete")
        return self._payload


def inspect_ur_fountain_part(frame: str, *, seedsigner_src: Path) -> dict[str, int | str]:
    """Return non-payload fountain metadata for live-scan diagnostics."""
    _load_ur2(seedsigner_src)
    from seedsigner.helpers.ur2.bytewords import Bytewords, Bytewords_Style_minimal
    from seedsigner.helpers.ur2.fountain_encoder import Part as FountainEncoderPart
    from seedsigner.helpers.ur2.ur_decoder import URDecoder

    normalized = frame.strip()
    ur_type, components = URDecoder.parse(normalized)
    if len(components) != 2:
        return {"type": ur_type, "form": "single"}
    seq_num, seq_len = URDecoder.parse_sequence_component(components[0])
    cbor = Bytewords.decode(Bytewords_Style_minimal, components[1])
    part = FountainEncoderPart.from_cbor(cbor)
    if seq_num != part.seq_num or seq_len != part.seq_len:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE,
            "UR path sequence does not match its fountain fragment",
        )
    return {
        "type": ur_type,
        "form": "multipart",
        "seq_num": int(part.seq_num),
        "seq_len": int(part.seq_len),
        "message_len": int(part.message_len),
        "checksum": f"{int(part.checksum):08x}",
        "fragment_len": len(part.data),
    }
