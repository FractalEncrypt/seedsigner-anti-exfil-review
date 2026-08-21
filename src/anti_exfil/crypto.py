"""Transparent Python model of secp256k1-zkp ECDSA anti-exfil.

This module is for deterministic vectors, protocol tests, and explanation. It
uses ordinary Python integers and is not constant-time. It MUST NOT be used as
SeedSigner's production signing implementation.

The construction targets BlockstreamResearch/secp256k1-zkp commit
2af926dc309a673461f0e2da090105c8f05b4505.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Iterator


FIELD_P = 2**256 - 2**32 - 977
GROUP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DATA_TAG = b"s2c/ecdsa/data"
POINT_TAG = b"s2c/ecdsa/point"


class CryptoModelError(ValueError):
    """Raised when a cryptographic input is invalid in the reference model."""


@dataclass(frozen=True, slots=True)
class Point:
    x: int
    y: int

    def __post_init__(self) -> None:
        if not (0 <= self.x < FIELD_P and 0 <= self.y < FIELD_P):
            raise CryptoModelError("point coordinate outside secp256k1 field")
        if (self.y * self.y - (self.x * self.x * self.x + 7)) % FIELD_P != 0:
            raise CryptoModelError("point is not on secp256k1")


GENERATOR = Point(
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)


def _require_bytes32(name: str, value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise CryptoModelError(f"{name} must be exactly 32 bytes")


def tagged_hash(tag: bytes, data: bytes) -> bytes:
    """BIP340-style tagged SHA256, as used by the zkp S2C module."""

    tag_hash = hashlib.sha256(tag).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def host_commit(rho: bytes) -> bytes:
    """Commit to the host's unrevealed 32-byte nonce contribution."""

    _require_bytes32("rho", rho)
    return tagged_hash(DATA_TAG, rho)


def _inverse(value: int, modulus: int) -> int:
    if value % modulus == 0:
        raise CryptoModelError("cannot invert zero")
    return pow(value, -1, modulus)


def point_add(left: Point | None, right: Point | None) -> Point | None:
    """Add affine secp256k1 points; None represents the point at infinity."""

    if left is None:
        return right
    if right is None:
        return left
    if left.x == right.x:
        if (left.y + right.y) % FIELD_P == 0:
            return None
        if left.y == 0:
            return None
        slope = (3 * left.x * left.x) * _inverse(2 * left.y, FIELD_P)
    else:
        slope = (right.y - left.y) * _inverse(right.x - left.x, FIELD_P)
    slope %= FIELD_P
    x = (slope * slope - left.x - right.x) % FIELD_P
    y = (slope * (left.x - x) - left.y) % FIELD_P
    return Point(x, y)


def point_mul(scalar: int, point: Point = GENERATOR) -> Point | None:
    """Multiply a point by an integer using a transparent test-only algorithm."""

    scalar %= GROUP_N
    result: Point | None = None
    addend: Point | None = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def serialize_point(point: Point) -> bytes:
    prefix = 3 if point.y & 1 else 2
    return bytes([prefix]) + point.x.to_bytes(32, "big")


def parse_point(encoded: bytes) -> Point:
    if not isinstance(encoded, bytes) or len(encoded) != 33:
        raise CryptoModelError("opening must be a 33-byte compressed point")
    if encoded[0] not in (2, 3):
        raise CryptoModelError("opening has invalid compressed-point prefix")
    x = int.from_bytes(encoded[1:], "big")
    if x >= FIELD_P:
        raise CryptoModelError("opening x-coordinate outside field")
    y_squared = (pow(x, 3, FIELD_P) + 7) % FIELD_P
    y = pow(y_squared, (FIELD_P + 1) // 4, FIELD_P)
    if pow(y, 2, FIELD_P) != y_squared:
        raise CryptoModelError("opening is not a secp256k1 point")
    if (y & 1) != (encoded[0] & 1):
        y = FIELD_P - y
    return Point(x, y)


def public_key(seckey32: bytes) -> bytes:
    secret = _secret_scalar(seckey32)
    point = point_mul(secret)
    if point is None:  # excluded by scalar validation
        raise CryptoModelError("secret key produced infinity")
    return serialize_point(point)


def _secret_scalar(seckey32: bytes) -> int:
    _require_bytes32("secret key", seckey32)
    secret = int.from_bytes(seckey32, "big")
    if not 1 <= secret < GROUP_N:
        raise CryptoModelError("secret key must be in [1, n-1]")
    return secret


def _rfc6979_stream(keydata: bytes) -> Iterator[bytes]:
    """Yield libsecp256k1 RFC6979 HMAC-SHA256 output blocks."""

    key = b"\x00" * 32
    value = b"\x01" * 32
    key = hmac.new(key, value + b"\x00" + keydata, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + keydata, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        yield value


def nonce_candidates(seckey32: bytes, msg32: bytes, additional_data32: bytes) -> Iterator[int]:
    """Yield valid nonce candidates matching libsecp256k1's default function."""

    _secret_scalar(seckey32)
    _require_bytes32("message hash", msg32)
    _require_bytes32("additional data", additional_data32)
    reduced_message = (int.from_bytes(msg32, "big") % GROUP_N).to_bytes(32, "big")
    keydata = seckey32 + reduced_message + additional_data32
    for candidate32 in _rfc6979_stream(keydata):
        candidate = int.from_bytes(candidate32, "big")
        if 1 <= candidate < GROUP_N:
            yield candidate


def signer_opening(seckey32: bytes, msg32: bytes, commitment32: bytes) -> bytes:
    """Compute the deterministic base public nonce sent in protocol message 2."""

    _require_bytes32("host commitment", commitment32)
    nonce = next(nonce_candidates(seckey32, msg32, commitment32))
    point = point_mul(nonce)
    if point is None:
        raise CryptoModelError("nonce produced infinity")
    return serialize_point(point)


def _s2c_tweak(opening_point: Point, rho: bytes) -> int:
    _require_bytes32("rho", rho)
    tweak = int.from_bytes(
        tagged_hash(POINT_TAG, serialize_point(opening_point) + rho), "big"
    )
    # libsecp256k1 tweak-add rejects overflow instead of reducing it.
    if tweak >= GROUP_N:
        raise CryptoModelError("S2C tweak overflows the group order")
    return tweak


def anti_exfil_sign(seckey32: bytes, msg32: bytes, rho: bytes) -> tuple[bytes, bytes]:
    """Return (compact low-S signature, opening) for an accepted host reveal."""

    secret = _secret_scalar(seckey32)
    _require_bytes32("message hash", msg32)
    commitment = host_commit(rho)
    message = int.from_bytes(msg32, "big") % GROUP_N

    for base_nonce in nonce_candidates(seckey32, msg32, commitment):
        opening_point = point_mul(base_nonce)
        if opening_point is None:
            continue
        tweak = _s2c_tweak(opening_point, rho)
        nonce = (base_nonce + tweak) % GROUP_N
        if nonce == 0:
            continue
        final_point = point_add(opening_point, point_mul(tweak))
        if final_point is None:
            continue
        r = final_point.x % GROUP_N
        if r == 0:
            continue
        s = (_inverse(nonce, GROUP_N) * (message + r * secret)) % GROUP_N
        if s == 0:
            continue
        if s > GROUP_N // 2:
            s = GROUP_N - s
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return signature, serialize_point(opening_point)
    raise CryptoModelError("unable to derive a valid anti-exfil signature")


def ecdsa_verify(pubkey33: bytes, msg32: bytes, signature64: bytes) -> bool:
    """Verify a compact ECDSA signature in the transparent reference model."""

    _require_bytes32("message hash", msg32)
    if not isinstance(signature64, bytes) or len(signature64) != 64:
        return False
    try:
        public = parse_point(pubkey33)
    except CryptoModelError:
        return False
    r = int.from_bytes(signature64[:32], "big")
    s = int.from_bytes(signature64[32:], "big")
    if not (1 <= r < GROUP_N and 1 <= s < GROUP_N):
        return False
    message = int.from_bytes(msg32, "big") % GROUP_N
    inverse_s = _inverse(s, GROUP_N)
    check = point_add(
        point_mul((message * inverse_s) % GROUP_N),
        point_mul((r * inverse_s) % GROUP_N, public),
    )
    return check is not None and check.x % GROUP_N == r


def verify_anti_exfil(
    pubkey33: bytes,
    msg32: bytes,
    rho: bytes,
    opening33: bytes,
    signature64: bytes,
) -> bool:
    """Perform both the S2C opening check and ordinary ECDSA verification."""

    try:
        opening_point = parse_point(opening33)
        tweak = _s2c_tweak(opening_point, rho)
        committed_point = point_add(opening_point, point_mul(tweak))
    except CryptoModelError:
        return False
    if committed_point is None or len(signature64) != 64:
        return False
    r = int.from_bytes(signature64[:32], "big")
    if committed_point.x % GROUP_N != r:
        return False
    return ecdsa_verify(pubkey33, msg32, signature64)
