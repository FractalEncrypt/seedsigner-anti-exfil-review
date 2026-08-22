"""Explicit malicious-signer and selective-abort models for the test corpus."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Callable

from .crypto import GROUP_N, point_mul, serialize_point
from .errors import AntiExfilError, ErrorCode


def sign_with_nonce(secret32: bytes, message32: bytes, nonce: int) -> bytes:
    secret, message = int.from_bytes(secret32, "big"), int.from_bytes(message32, "big") % GROUP_N
    if not 1 <= secret < GROUP_N or not 1 <= nonce < GROUP_N or len(message32) != 32:
        raise ValueError("invalid ECDSA signing material")
    point = point_mul(nonce)
    if point is None or point.x % GROUP_N == 0:
        raise ValueError("invalid ECDSA nonce")
    r = point.x % GROUP_N
    s = (pow(nonce, -1, GROUP_N) * (message + r * secret)) % GROUP_N
    if not s:
        raise ValueError("invalid ECDSA nonce")
    if s > GROUP_N // 2:
        s = GROUP_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def predetermined_nonce_signature(secret32: bytes, message32: bytes, nonce: int = 7) -> bytes:
    return sign_with_nonce(secret32, message32, nonce)


def dark_skippy_signature(secret32: bytes, message32: bytes, leaked_bits: int = 2) -> tuple[bytes, int]:
    """Model a nonce whose low bits leak the corresponding secret-key bits."""
    mask = (1 << leaked_bits) - 1
    leak = int.from_bytes(secret32, "big") & mask
    base = 1 + int.from_bytes(hashlib.sha256(message32).digest(), "big") % (GROUP_N - 1)
    nonce = (base & ~mask) + leak
    if nonce == 0:
        nonce += 1 << leaked_bits
    if nonce >= GROUP_N:
        nonce -= 1 << leaked_bits
    return sign_with_nonce(secret32, message32, nonce), nonce


def grind_nonce(secret32: bytes, message32: bytes, predicate: Callable[[bytes], bool],
                max_attempts: int = 100_000) -> tuple[bytes, int]:
    """Model nonce grinding against a visible final ECDSA R point."""
    for nonce in range(1, max_attempts + 1):
        point = point_mul(nonce)
        if point is not None and predicate(serialize_point(point)):
            return sign_with_nonce(secret32, message32, nonce), nonce
    raise ValueError("nonce-grinding predicate was not met")


@dataclass(slots=True)
class SelectiveAbortJournal:
    """Minimal persistent-state model required after signer openings are accepted."""
    session_id: bytes
    transcript_digest: bytes | None = None
    host_reveal_accepted: bool = False
    terminal_failure: bool = False

    def accept_openings(self, transcript: bytes) -> None:
        digest = hashlib.sha256(transcript).digest()
        if self.transcript_digest is not None and digest != self.transcript_digest:
            raise AntiExfilError(ErrorCode.RETRY_CONFLICT, "post-opening retry changed the transcript")
        self.transcript_digest = digest

    def accept_host_reveal(self, transcript: bytes) -> None:
        self.accept_openings(transcript)
        if self.terminal_failure:
            raise AntiExfilError(ErrorCode.RETRY_CONFLICT, "terminal post-reveal failure forbids restart")
        self.host_reveal_accepted = True

    def record_post_reveal_failure(self) -> None:
        if not self.host_reveal_accepted:
            raise AntiExfilError(ErrorCode.STATE_INVALID, "host reveal was not accepted")
        self.terminal_failure = True

    def require_exact_retry(self, session_id: bytes, transcript: bytes) -> None:
        if session_id != self.session_id:
            raise AntiExfilError(ErrorCode.RETRY_CONFLICT, "fresh session after selective abort is forbidden")
        self.accept_openings(transcript)


@dataclass(frozen=True, slots=True)
class AbortEvent:
    session_id: bytes
    reason: str


@dataclass(slots=True)
class WalletAbortJournal:
    """Implementation-independent wallet-wide abort-state reference model."""
    events: dict[bytes, AbortEvent]

    def __init__(self) -> None:
        self.events = {}

    def digest(self) -> bytes:
        encoded = bytearray(b"AEXJ-REFERENCE-V1")
        for event in self.events.values():
            reason = event.reason.encode("utf-8")
            encoded.extend(len(event.session_id).to_bytes(2, "big"))
            encoded.extend(event.session_id)
            encoded.extend(len(reason).to_bytes(2, "big"))
            encoded.extend(reason)
        return hashlib.sha256(encoded).digest()

    def create_session(self, session_id: bytes, *, acknowledge_abort_history: bool = False) -> AbortBoundSession:
        if not session_id:
            raise AntiExfilError(ErrorCode.STATE_INVALID, "session ID is required")
        if self.events and not acknowledge_abort_history:
            raise AntiExfilError(ErrorCode.RETRY_CONFLICT, "abort history requires explicit acknowledgement")
        return AbortBoundSession(self, session_id, self.digest())

    def record(self, session_id: bytes, reason: str) -> AbortEvent:
        if not session_id or not reason:
            raise AntiExfilError(ErrorCode.STATE_INVALID, "abort event context is required")
        existing = self.events.get(session_id)
        if existing is not None:
            return existing
        event = AbortEvent(bytes(session_id), reason)
        self.events[event.session_id] = event
        return event


@dataclass(slots=True)
class AbortBoundSession:
    journal: WalletAbortJournal
    session_id: bytes
    accepted_journal_digest: bytes
    transcript_digest: bytes | None = None
    host_reveal_accepted: bool = False

    def accept_host_reveal(self, transcript: bytes) -> None:
        digest = hashlib.sha256(transcript).digest()
        if self.transcript_digest is not None and digest != self.transcript_digest:
            raise AntiExfilError(ErrorCode.RETRY_CONFLICT, "opening retry changed the transcript")
        if self.host_reveal_accepted:
            return
        if self.journal.digest() != self.accepted_journal_digest:
            raise AntiExfilError(ErrorCode.RETRY_CONFLICT, "abort history changed after session creation")
        self.transcript_digest = digest
        self.host_reveal_accepted = True

    def record_post_reveal_failure(self, reason: str) -> AbortEvent:
        if not self.host_reveal_accepted:
            raise AntiExfilError(ErrorCode.STATE_INVALID, "host reveal was not accepted")
        return self.journal.record(self.session_id, reason)

    def reject_signer_data(self) -> AbortEvent:
        return self.journal.record(self.session_id, "SIGNATURE_REJECTED")
