"""Stable errors shared by terminal workflow components."""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    INVALID_MESSAGE = "AE_INVALID_MESSAGE"
    WRONG_STAGE = "AE_WRONG_STAGE"
    SESSION_MISMATCH = "AE_SESSION_MISMATCH"
    TRANSACTION_MISMATCH = "AE_TRANSACTION_MISMATCH"
    SIGNATURE_SLOT_MISMATCH = "AE_SIGNATURE_SLOT_MISMATCH"
    COMMITMENT_MISMATCH = "AE_COMMITMENT_MISMATCH"
    OPENING_MISMATCH = "AE_OPENING_MISMATCH"
    SIGNATURE_INVALID = "AE_SIGNATURE_INVALID"
    RETRY_CONFLICT = "AE_RETRY_CONFLICT"
    STATE_INVALID = "AE_STATE_INVALID"
    OUTPUT_EXISTS = "AE_OUTPUT_EXISTS"
    TEST_KEY_MISMATCH = "AE_TEST_KEY_MISMATCH"
    UNEXPECTED_RETURN_DATA = "AE_UNEXPECTED_RETURN_DATA"
    NATIVE_BACKEND = "AE_NATIVE_BACKEND"


class AntiExfilError(Exception):
    def __init__(self, code: ErrorCode, message: str):
        super().__init__(message)
        self.code = code
        self.message = message
