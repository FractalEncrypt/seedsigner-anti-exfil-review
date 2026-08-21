"""Narrow ctypes binding for the pinned secp256k1-zkp anti-exfil API."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path

from .errors import AntiExfilError, ErrorCode


CONTEXT_SIGN_VERIFY = 0x301
OPAQUE_SIZE = 64


def _require_length(value: bytes, length: int, name: str) -> None:
    if len(value) != length:
        raise AntiExfilError(ErrorCode.NATIVE_BACKEND, f"{name} must be {length} bytes")


class NativeAntiExfil:
    """Own one randomized native context and expose serialized values only."""

    def __init__(self, library_path: Path):
        self.library_path = library_path.resolve()
        if not self.library_path.is_file():
            raise AntiExfilError(
                ErrorCode.NATIVE_BACKEND, f"native library does not exist: {self.library_path}"
            )
        try:
            self.lib = ctypes.CDLL(str(self.library_path))
            self._bind()
            self.context = self.lib.secp256k1_context_create(CONTEXT_SIGN_VERIFY)
        except (OSError, AttributeError) as exc:
            raise AntiExfilError(
                ErrorCode.NATIVE_BACKEND, f"cannot load required anti-exfil symbols: {exc}"
            ) from exc
        if not self.context:
            raise AntiExfilError(ErrorCode.NATIVE_BACKEND, "native context creation failed")
        seed = os.urandom(32)
        if self.lib.secp256k1_context_randomize(self.context, seed) != 1:
            self.close()
            raise AntiExfilError(ErrorCode.NATIVE_BACKEND, "native context randomization failed")

    def _bind(self) -> None:
        lib = self.lib
        lib.secp256k1_context_create.argtypes = [ctypes.c_uint]
        lib.secp256k1_context_create.restype = ctypes.c_void_p
        lib.secp256k1_context_destroy.argtypes = [ctypes.c_void_p]
        lib.secp256k1_context_destroy.restype = None
        lib.secp256k1_context_randomize.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.secp256k1_context_randomize.restype = ctypes.c_int

        pointer_args = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        lib.secp256k1_ecdsa_anti_exfil_host_commit.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p
        ]
        lib.secp256k1_ecdsa_anti_exfil_host_commit.restype = ctypes.c_int
        lib.secp256k1_ecdsa_anti_exfil_signer_commit.argtypes = pointer_args + [ctypes.c_char_p]
        lib.secp256k1_ecdsa_anti_exfil_signer_commit.restype = ctypes.c_int
        lib.secp256k1_anti_exfil_sign.argtypes = pointer_args + [ctypes.c_char_p]
        lib.secp256k1_anti_exfil_sign.restype = ctypes.c_int

        lib.secp256k1_ecdsa_s2c_opening_serialize.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
        ]
        lib.secp256k1_ecdsa_s2c_opening_serialize.restype = ctypes.c_int
        lib.secp256k1_ecdsa_s2c_opening_parse.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p
        ]
        lib.secp256k1_ecdsa_s2c_opening_parse.restype = ctypes.c_int
        lib.secp256k1_ecdsa_signature_serialize_compact.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
        ]
        lib.secp256k1_ecdsa_signature_serialize_compact.restype = ctypes.c_int
        lib.secp256k1_ecdsa_signature_parse_compact.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p
        ]
        lib.secp256k1_ecdsa_signature_parse_compact.restype = ctypes.c_int
        lib.secp256k1_ec_pubkey_parse.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t
        ]
        lib.secp256k1_ec_pubkey_parse.restype = ctypes.c_int
        lib.secp256k1_anti_exfil_host_verify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
        ]
        lib.secp256k1_anti_exfil_host_verify.restype = ctypes.c_int

    def close(self) -> None:
        context = getattr(self, "context", None)
        if context:
            self.lib.secp256k1_context_destroy(context)
            self.context = None

    def __enter__(self) -> "NativeAntiExfil":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def host_commit(self, rho: bytes) -> bytes:
        _require_length(rho, 32, "host randomness")
        output = ctypes.create_string_buffer(32)
        if self.lib.secp256k1_ecdsa_anti_exfil_host_commit(self.context, output, rho) != 1:
            raise AntiExfilError(ErrorCode.NATIVE_BACKEND, "native host commitment failed")
        return output.raw

    def signer_commit(self, secret: bytes, message_hash: bytes, commitment: bytes) -> bytes:
        _require_length(secret, 32, "secret key")
        _require_length(message_hash, 32, "message hash")
        _require_length(commitment, 32, "host commitment")
        opening = ctypes.create_string_buffer(OPAQUE_SIZE)
        if self.lib.secp256k1_ecdsa_anti_exfil_signer_commit(
            self.context, opening, message_hash, secret, commitment
        ) != 1:
            raise AntiExfilError(ErrorCode.NATIVE_BACKEND, "native signer commitment failed")
        serialized = ctypes.create_string_buffer(33)
        if self.lib.secp256k1_ecdsa_s2c_opening_serialize(
            self.context, serialized, opening
        ) != 1:
            raise AntiExfilError(ErrorCode.NATIVE_BACKEND, "native opening serialization failed")
        return serialized.raw

    def sign(self, secret: bytes, message_hash: bytes, rho: bytes) -> bytes:
        _require_length(secret, 32, "secret key")
        _require_length(message_hash, 32, "message hash")
        _require_length(rho, 32, "host randomness")
        signature = ctypes.create_string_buffer(OPAQUE_SIZE)
        if self.lib.secp256k1_anti_exfil_sign(
            self.context, signature, message_hash, secret, rho
        ) != 1:
            raise AntiExfilError(ErrorCode.NATIVE_BACKEND, "native anti-exfil signing failed")
        compact = ctypes.create_string_buffer(64)
        if self.lib.secp256k1_ecdsa_signature_serialize_compact(
            self.context, compact, signature
        ) != 1:
            raise AntiExfilError(ErrorCode.NATIVE_BACKEND, "native signature serialization failed")
        return compact.raw

    def verify(
        self,
        pubkey33: bytes,
        message_hash: bytes,
        rho: bytes,
        opening33: bytes,
        signature64: bytes,
    ) -> bool:
        _require_length(pubkey33, 33, "public key")
        _require_length(message_hash, 32, "message hash")
        _require_length(rho, 32, "host randomness")
        _require_length(opening33, 33, "opening")
        _require_length(signature64, 64, "compact signature")
        pubkey = ctypes.create_string_buffer(OPAQUE_SIZE)
        opening = ctypes.create_string_buffer(OPAQUE_SIZE)
        signature = ctypes.create_string_buffer(OPAQUE_SIZE)
        if self.lib.secp256k1_ec_pubkey_parse(
            self.context, pubkey, pubkey33, len(pubkey33)
        ) != 1:
            return False
        if self.lib.secp256k1_ecdsa_s2c_opening_parse(
            self.context, opening, opening33
        ) != 1:
            return False
        if self.lib.secp256k1_ecdsa_signature_parse_compact(
            self.context, signature, signature64
        ) != 1:
            return False
        return bool(
            self.lib.secp256k1_anti_exfil_host_verify(
                self.context, signature, message_hash, pubkey, rho, opening
            )
        )
