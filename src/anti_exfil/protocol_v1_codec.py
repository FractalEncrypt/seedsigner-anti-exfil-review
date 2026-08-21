"""Canonical multi-slot wire codec for anti-exfil protocol v1.

This codec is deliberately separate from ``messages.RungBMessage`` while the
working single-slot physical prototype is migrated.  Both currently use the
experimental AEXB magic; callers must select the intended codec explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import struct

from .crypto import CryptoModelError, GROUP_N, host_commit, parse_point
from .errors import AntiExfilError, ErrorCode


MAGIC = b"AEXB"
FORMAT_VERSION = 1
FLAGS = 0
SIGHASH_ALL = 0x00000001
MAX_SLOTS = 128
MAX_SLOTS_PER_INPUT = 16
MAX_MESSAGE_BYTES = 65_536

# magic, version, network, stage, flags, payload length, session id,
# SHA256(exact frozen PSBT bytes), slot count
HEADER = struct.Struct(">4sBBBBI32s32sH")
COMMON_RECORD = struct.Struct(">II33s32s32s")


class Network(IntEnum):
    MAINNET = 0
    TESTNET3 = 1
    REGTEST = 2
    SIGNET = 3
    TESTNET4 = 4


class Stage(IntEnum):
    HOST_COMMIT = 1
    SIGNER_OPENINGS = 2
    HOST_REVEAL = 3
    SIGNER_SIGNATURES = 4


_EXTRA_LENGTHS = {
    Stage.HOST_COMMIT: 0,
    Stage.SIGNER_OPENINGS: 33,
    Stage.HOST_REVEAL: 33 + 32,
    Stage.SIGNER_SIGNATURES: 33 + 64,
}


@dataclass(frozen=True, slots=True)
class SigningSlot:
    input_index: int
    signer_pubkey: bytes
    message_hash: bytes
    sighash_type: int
    commitment: bytes
    opening: bytes | None = None
    rho: bytes | None = None
    signature: bytes | None = None

    @property
    def identifier(self) -> tuple[int, bytes]:
        return self.input_index, self.signer_pubkey


@dataclass(frozen=True, slots=True)
class ProtocolMessage:
    network: Network
    stage: Stage
    session_id: bytes
    psbt_digest: bytes
    slots: tuple[SigningSlot, ...]

    def encode(self) -> bytes:
        _validate_message(self)
        records = b"".join(_encode_slot(self.stage, slot) for slot in self.slots)
        encoded = HEADER.pack(
            MAGIC,
            FORMAT_VERSION,
            int(self.network),
            int(self.stage),
            FLAGS,
            len(records),
            self.session_id,
            self.psbt_digest,
            len(self.slots),
        ) + records
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "AEXB message is oversized")
        return encoded

    def diagnostic(self) -> dict[str, object]:
        return {
            "format": "AEXB",
            "format_version": FORMAT_VERSION,
            "network": self.network.name,
            "stage": self.stage.name,
            "stage_number": int(self.stage),
            "session_id": self.session_id.hex(),
            "psbt_digest": self.psbt_digest.hex(),
            "slot_count": len(self.slots),
            "slots": [_slot_diagnostic(slot) for slot in self.slots],
        }


def decode_message(encoded: bytes) -> ProtocolMessage:
    if not isinstance(encoded, bytes) or len(encoded) < HEADER.size:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "message is shorter than the AEXB header")
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "AEXB message is oversized")
    (
        magic,
        version,
        network_number,
        stage_number,
        flags,
        payload_length,
        session_id,
        psbt_digest,
        slot_count,
    ) = HEADER.unpack_from(encoded)
    if magic != MAGIC:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "message has the wrong AEXB magic")
    if version != FORMAT_VERSION:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, f"unsupported AEXB format version {version}"
        )
    if flags != FLAGS:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "unknown AEXB flags are set")
    try:
        network = Network(network_number)
    except ValueError as exc:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, f"unknown AEXB network {network_number}"
        ) from exc
    try:
        stage = Stage(stage_number)
    except ValueError as exc:
        raise AntiExfilError(ErrorCode.WRONG_STAGE, f"unknown AEXB stage {stage_number}") from exc
    if not 1 <= slot_count <= MAX_SLOTS:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "AEXB slot count is outside v1 limits")
    record_length = COMMON_RECORD.size + _EXTRA_LENGTHS[stage]
    expected_payload_length = slot_count * record_length
    if payload_length != expected_payload_length:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, "AEXB payload length is not canonical for its stage"
        )
    if len(encoded) != HEADER.size + payload_length:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "AEXB length does not match payload")

    slots: list[SigningSlot] = []
    offset = HEADER.size
    for _ in range(slot_count):
        slots.append(_decode_slot(stage, encoded[offset : offset + record_length]))
        offset += record_length
    message = ProtocolMessage(
        network=network,
        stage=stage,
        session_id=session_id,
        psbt_digest=psbt_digest,
        slots=tuple(slots),
    )
    _validate_message(message)
    return message


def validate_transition(previous: ProtocolMessage, current: ProtocolMessage) -> None:
    """Validate one exact adjacent transcript transition.

    Cryptographic signature verification remains the responsibility of the
    workflow.  This function enforces the complete slot set and all wire-bound
    context, including accepted openings.
    """

    expected_stage = int(previous.stage) + 1
    if expected_stage > int(Stage.SIGNER_SIGNATURES) or int(current.stage) != expected_stage:
        raise AntiExfilError(
            ErrorCode.WRONG_STAGE,
            f"expected stage {expected_stage}, received stage {int(current.stage)}",
        )
    if previous.network != current.network:
        raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "network changed between stages")
    if previous.session_id != current.session_id:
        raise AntiExfilError(ErrorCode.SESSION_MISMATCH, "session changed between stages")
    if previous.psbt_digest != current.psbt_digest:
        raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "PSBT digest changed between stages")
    if len(previous.slots) != len(current.slots):
        raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "slot count changed between stages")

    for before, after in zip(previous.slots, current.slots, strict=True):
        if before.identifier != after.identifier:
            raise AntiExfilError(
                ErrorCode.SIGNATURE_SLOT_MISMATCH, "slot identifier changed between stages"
            )
        if (
            before.message_hash != after.message_hash
            or before.sighash_type != after.sighash_type
        ):
            raise AntiExfilError(
                ErrorCode.TRANSACTION_MISMATCH, "slot signing context changed between stages"
            )
        if before.commitment != after.commitment:
            raise AntiExfilError(
                ErrorCode.COMMITMENT_MISMATCH, "slot commitment changed between stages"
            )
        if previous.stage >= Stage.SIGNER_OPENINGS and before.opening != after.opening:
            raise AntiExfilError(ErrorCode.OPENING_MISMATCH, "accepted opening changed between stages")

    if current.stage == Stage.HOST_REVEAL:
        for slot in current.slots:
            if slot.rho is None or host_commit(slot.rho) != slot.commitment:
                raise AntiExfilError(
                    ErrorCode.COMMITMENT_MISMATCH,
                    "host reveal does not match its slot commitment",
                )


def _encode_slot(stage: Stage, slot: SigningSlot) -> bytes:
    encoded = COMMON_RECORD.pack(
        slot.input_index,
        slot.sighash_type,
        slot.signer_pubkey,
        slot.message_hash,
        slot.commitment,
    )
    if stage >= Stage.SIGNER_OPENINGS:
        encoded += slot.opening or b""
    if stage == Stage.HOST_REVEAL:
        encoded += slot.rho or b""
    if stage == Stage.SIGNER_SIGNATURES:
        encoded += slot.signature or b""
    return encoded


def _decode_slot(stage: Stage, encoded: bytes) -> SigningSlot:
    input_index, sighash_type, signer_pubkey, message_hash, commitment = (
        COMMON_RECORD.unpack_from(encoded)
    )
    offset = COMMON_RECORD.size
    opening = None
    rho = None
    signature = None
    if stage >= Stage.SIGNER_OPENINGS:
        opening = encoded[offset : offset + 33]
        offset += 33
    if stage == Stage.HOST_REVEAL:
        rho = encoded[offset : offset + 32]
    if stage == Stage.SIGNER_SIGNATURES:
        signature = encoded[offset : offset + 64]
    return SigningSlot(
        input_index=input_index,
        signer_pubkey=signer_pubkey,
        message_hash=message_hash,
        sighash_type=sighash_type,
        commitment=commitment,
        opening=opening,
        rho=rho,
        signature=signature,
    )


def _validate_message(message: ProtocolMessage) -> None:
    try:
        network = Network(message.network)
        stage = Stage(message.stage)
    except (TypeError, ValueError) as exc:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "invalid network or stage") from exc
    if network != message.network or stage != message.stage:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "network and stage must be canonical enums")
    _require_bytes("session ID", message.session_id, 32)
    _require_bytes("PSBT digest", message.psbt_digest, 32)
    if not isinstance(message.slots, tuple) or not 1 <= len(message.slots) <= MAX_SLOTS:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "slot collection is outside v1 limits")

    previous_identifier: tuple[int, bytes] | None = None
    per_input: dict[int, int] = {}
    commitments: set[bytes] = set()
    reveals: set[bytes] = set()
    for slot in message.slots:
        _validate_slot(stage, slot)
        if previous_identifier is not None and slot.identifier <= previous_identifier:
            raise AntiExfilError(
                ErrorCode.SIGNATURE_SLOT_MISMATCH,
                "slots must be unique and ordered by input index then compressed public key",
            )
        previous_identifier = slot.identifier
        if slot.commitment in commitments:
            raise AntiExfilError(
                ErrorCode.COMMITMENT_MISMATCH,
                "host commitments must be unique across the slot set",
            )
        commitments.add(slot.commitment)
        if slot.rho is not None:
            if slot.rho in reveals:
                raise AntiExfilError(
                    ErrorCode.COMMITMENT_MISMATCH,
                    "host reveals must be unique across the slot set",
                )
            reveals.add(slot.rho)
        per_input[slot.input_index] = per_input.get(slot.input_index, 0) + 1
        if per_input[slot.input_index] > MAX_SLOTS_PER_INPUT:
            raise AntiExfilError(
                ErrorCode.SIGNATURE_SLOT_MISMATCH,
                f"input {slot.input_index} exceeds the v1 per-input slot limit",
            )


def _validate_slot(stage: Stage, slot: SigningSlot) -> None:
    if not isinstance(slot.input_index, int) or not 0 <= slot.input_index <= 0xFFFFFFFF:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "input index must be a uint32")
    if slot.sighash_type != SIGHASH_ALL:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, "protocol v1 supports only explicit SIGHASH_ALL"
        )
    _require_point("signer public key", slot.signer_pubkey)
    _require_bytes("message hash", slot.message_hash, 32)
    _require_bytes("host commitment", slot.commitment, 32)

    needs_opening = stage >= Stage.SIGNER_OPENINGS
    needs_rho = stage == Stage.HOST_REVEAL
    needs_signature = stage == Stage.SIGNER_SIGNATURES
    if (slot.opening is not None) != needs_opening:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "opening presence conflicts with stage")
    if (slot.rho is not None) != needs_rho:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "host reveal presence conflicts with stage")
    if (slot.signature is not None) != needs_signature:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "signature presence conflicts with stage")
    if slot.opening is not None:
        _require_point("signer opening", slot.opening)
    if slot.rho is not None:
        _require_bytes("host reveal", slot.rho, 32)
    if slot.signature is not None:
        _require_bytes("compact signature", slot.signature, 64)
        r = int.from_bytes(slot.signature[:32], "big")
        s = int.from_bytes(slot.signature[32:], "big")
        if not (1 <= r < GROUP_N and 1 <= s <= GROUP_N // 2):
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, "signature scalars are invalid or non-low-S"
            )


def _require_bytes(name: str, value: bytes, length: int) -> None:
    if not isinstance(value, bytes) or len(value) != length:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, f"{name} must be exactly {length} bytes")


def _require_point(name: str, value: bytes) -> None:
    _require_bytes(name, value, 33)
    try:
        parse_point(value)
    except CryptoModelError as exc:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, f"invalid {name}") from exc


def _slot_diagnostic(slot: SigningSlot) -> dict[str, object]:
    result: dict[str, object] = {
        "input_index": slot.input_index,
        "sighash_type": slot.sighash_type,
        "signer_pubkey": slot.signer_pubkey.hex(),
        "message_hash": slot.message_hash.hex(),
        "host_commitment": slot.commitment.hex(),
    }
    if slot.opening is not None:
        result["signer_opening"] = slot.opening.hex()
    if slot.rho is not None:
        result["host_randomness"] = slot.rho.hex()
    if slot.signature is not None:
        result["signature_compact"] = slot.signature.hex()
    return result
