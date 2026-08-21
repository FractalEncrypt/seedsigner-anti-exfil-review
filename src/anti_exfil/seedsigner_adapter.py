"""Rung D adapter to SeedSigner's seed, PSBT, derivation, and native binding."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys

from embit.psbt import PSBT

from .errors import AntiExfilError, ErrorCode
from .crypto import host_commit
from .messages import RungBMessage, Stage, decode_message
from .native import NativeAntiExfil
from .psbt_tools import SignatureSlot, find_single_p2wpkh_slot, load_psbt
from .storage import read_bytes, write_exact
from .workflow import signer_commit, signer_sign


@dataclass(frozen=True, slots=True)
class SeedSignerContext:
    slot: SignatureSlot
    secret_key: bytes
    fingerprint: str
    derivation: str
    input_amount: int
    spend_amount: int
    fee_amount: int


def _load_seedsigner_types(seedsigner_src: Path):
    source = str(seedsigner_src.resolve())
    if source not in sys.path:
        sys.path.insert(0, source)
    try:
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.models.seed import Seed
        from seedsigner.models.settings import SettingsConstants
    except ImportError as exc:
        raise AntiExfilError(
            ErrorCode.STATE_INVALID,
            f"cannot import SeedSigner from {seedsigner_src}: {exc}",
        ) from exc
    return Seed, PSBTParser, SettingsConstants


def _load_seedsigner_native_backend(seedsigner_src: Path):
    _load_seedsigner_types(seedsigner_src)
    try:
        from seedsigner.helpers.anti_exfil import (
            AntiExfilNativeBackend,
            AntiExfilNativeError as SeedSignerNativeError,
        )
    except ImportError as exc:
        raise AntiExfilError(
            ErrorCode.NATIVE_BACKEND,
            f"SeedSigner anti-exfil binding is unavailable: {exc}",
        ) from exc
    return AntiExfilNativeBackend, SeedSignerNativeError


def derive_seedsigner_context(
    *, psbt: PSBT, mnemonic: str, seedsigner_src: Path
) -> SeedSignerContext:
    Seed, PSBTParser, SettingsConstants = _load_seedsigner_types(seedsigner_src)
    try:
        seed = Seed(mnemonic.strip().split())
        parser = PSBTParser(psbt, seed, SettingsConstants.REGTEST)
    except Exception as exc:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, f"SeedSigner rejected the PSBT or seed: {exc}"
        ) from exc
    if parser.root is None or parser.policy is None:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "SeedSigner did not parse the PSBT")

    candidates: list[tuple[bytes, str]] = []
    fingerprint = parser.root.my_fingerprint
    for input_scope in psbt.inputs:
        if input_scope.is_taproot:
            raise AntiExfilError(
                ErrorCode.SIGNATURE_SLOT_MISMATCH,
                "Rung D rejects Taproot because v1 is ECDSA-only",
            )
        for pubkey, origin in input_scope.bip32_derivations.items():
            if origin.fingerprint != fingerprint:
                continue
            derived = parser.root.derive(origin.derivation)
            if derived.key.get_public_key().sec() != pubkey.sec():
                raise AntiExfilError(
                    ErrorCode.SIGNATURE_SLOT_MISMATCH,
                    "SeedSigner derivation path does not reproduce the PSBT public key",
                )
            path = "m/" + "/".join(
                f"{index & 0x7fffffff}{'h' if index & 0x80000000 else ''}"
                for index in origin.derivation
            )
            candidates.append((derived.key.secret, path))
    if len(candidates) != 1:
        raise AntiExfilError(
            ErrorCode.SIGNATURE_SLOT_MISMATCH,
            f"Rung D requires exactly one SeedSigner-derived ECDSA key; found {len(candidates)}",
        )
    secret, derivation = candidates[0]
    from .crypto import public_key

    slot = find_single_p2wpkh_slot(psbt, public_key(secret))
    return SeedSignerContext(
        slot=slot,
        secret_key=secret,
        fingerprint=fingerprint.hex(),
        derivation=derivation,
        input_amount=parser.input_amount,
        spend_amount=parser.spend_amount,
        fee_amount=parser.fee_amount,
    )


def _validated_context(
    *, psbt_path: Path, input_path: Path, mnemonic: str, seedsigner_src: Path, stage: Stage
) -> SeedSignerContext:
    message = decode_message(read_bytes(input_path))
    if message.stage != stage:
        raise AntiExfilError(ErrorCode.WRONG_STAGE, f"SeedSigner adapter requires {stage.name}")
    psbt, _ = load_psbt(psbt_path)
    context = derive_seedsigner_context(
        psbt=psbt, mnemonic=mnemonic, seedsigner_src=seedsigner_src
    )
    if context.slot.signer_pubkey != message.signer_pubkey:
        raise AntiExfilError(
            ErrorCode.SIGNATURE_SLOT_MISMATCH,
            "SeedSigner-derived public key does not match the transcript",
        )
    if context.slot.message_hash != message.message_hash:
        raise AntiExfilError(
            ErrorCode.TRANSACTION_MISMATCH,
            "SeedSigner-derived sighash does not match the transcript",
        )
    return context


def signer_commit_seedsigner(
    *,
    psbt_path: Path,
    input_path: Path,
    mnemonic: str,
    seedsigner_src: Path,
    output_path: Path,
    native_library: Path | None = None,
):
    context = _validated_context(
        psbt_path=psbt_path,
        input_path=input_path,
        mnemonic=mnemonic,
        seedsigner_src=seedsigner_src,
        stage=Stage.HOST_COMMIT,
    )
    if native_library is None:
        message = signer_commit(
            input_path=input_path, test_secret_key=context.secret_key, output_path=output_path
        )
    else:
        request = decode_message(read_bytes(input_path))
        NativeBackend, SeedSignerNativeError = _load_seedsigner_native_backend(
            seedsigner_src
        )
        try:
            with NativeBackend(native_library) as native:
                opening = native.signer_commit(
                    context.secret_key, request.message_hash, request.commitment
                )
        except SeedSignerNativeError as exc:
            raise AntiExfilError(ErrorCode.NATIVE_BACKEND, str(exc)) from exc
        message = RungBMessage(
            stage=Stage.SIGNER_OPENINGS,
            session_id=request.session_id,
            message_hash=request.message_hash,
            signer_pubkey=request.signer_pubkey,
            commitment=request.commitment,
            opening=opening,
        )
        write_exact(output_path, message.encode())
    return message, context


def signer_sign_seedsigner(
    *,
    psbt_path: Path,
    input_path: Path,
    mnemonic: str,
    seedsigner_src: Path,
    output_path: Path,
    native_library: Path | None = None,
):
    context = _validated_context(
        psbt_path=psbt_path,
        input_path=input_path,
        mnemonic=mnemonic,
        seedsigner_src=seedsigner_src,
        stage=Stage.HOST_REVEAL,
    )
    if native_library is None:
        message = signer_sign(
            input_path=input_path, test_secret_key=context.secret_key, output_path=output_path
        )
    else:
        reveal = decode_message(read_bytes(input_path))
        if reveal.rho is None or reveal.opening is None:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "reveal message is incomplete")
        if host_commit(reveal.rho) != reveal.commitment:
            raise AntiExfilError(
                ErrorCode.COMMITMENT_MISMATCH,
                "host randomness does not match the original commitment",
            )
        NativeBackend, SeedSignerNativeError = _load_seedsigner_native_backend(
            seedsigner_src
        )
        try:
            with NativeBackend(native_library) as native:
                expected_opening = native.signer_commit(
                    context.secret_key, reveal.message_hash, reveal.commitment
                )
                if expected_opening != reveal.opening:
                    raise AntiExfilError(
                        ErrorCode.OPENING_MISMATCH,
                        "native signer opening does not match the accepted opening",
                    )
                signature = native.sign(
                    context.secret_key, reveal.message_hash, reveal.rho
                )
        except SeedSignerNativeError as exc:
            raise AntiExfilError(ErrorCode.NATIVE_BACKEND, str(exc)) from exc

        # The reference harness performs coordinator-style verification before
        # writing message 4. The production signer binding itself remains limited
        # to the two signer operations SeedSigner needs.
        with NativeAntiExfil(native_library) as verifier:
            if not verifier.verify(
                reveal.signer_pubkey,
                reveal.message_hash,
                reveal.rho,
                reveal.opening,
                signature,
            ):
                raise AntiExfilError(
                    ErrorCode.SIGNATURE_INVALID,
                    "native anti-exfil self-verification failed",
                )
        message = RungBMessage(
            stage=Stage.SIGNER_SIGNATURES,
            session_id=reveal.session_id,
            message_hash=reveal.message_hash,
            signer_pubkey=reveal.signer_pubkey,
            commitment=reveal.commitment,
            opening=reveal.opening,
            rho=reveal.rho,
            signature=signature,
        )
        write_exact(output_path, message.encode())
    return message, context
