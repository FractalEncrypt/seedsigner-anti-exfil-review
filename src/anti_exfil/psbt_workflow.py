"""Rung C adapters that bind the four-message workflow to a frozen PSBT."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .errors import AntiExfilError, ErrorCode
from .messages import Stage, decode_message
from .psbt_tools import (
    SignatureSlot,
    find_single_p2wpkh_slot,
    load_psbt,
    reconstruct_signed_psbt,
    validate_psbt_context,
)
from .storage import load_state, read_bytes, save_state, write_exact
from .workflow import host_init, host_reveal, host_verify, signer_commit, signer_sign


ORIGINAL_PSBT_FILENAME = "original.psbt"
INTERNAL_RECEIPT_FILENAME = "anti-exfil-receipt.json"


def host_init_psbt(
    *,
    psbt_path: Path,
    signer_pubkey: bytes,
    session_dir: Path,
    output_path: Path,
    rho: bytes | None = None,
    session_id: bytes | None = None,
):
    psbt, original = load_psbt(psbt_path)
    slot = find_single_p2wpkh_slot(psbt, signer_pubkey)
    message = host_init(
        message_hash=slot.message_hash,
        signer_pubkey=signer_pubkey,
        session_dir=session_dir,
        output_path=output_path,
        rho=rho,
        session_id=session_id,
    )
    state = load_state(session_dir)
    state.update(
        {
            "rung": "C",
            "psbt_sha256": hashlib.sha256(original).hexdigest(),
            "input_index": slot.input_index,
            "sighash_type": slot.sighash_type,
        }
    )
    save_state(session_dir, state)
    write_exact(session_dir / ORIGINAL_PSBT_FILENAME, original)
    return message, slot


def signer_commit_psbt(
    *,
    psbt_path: Path,
    input_path: Path,
    test_secret_key: bytes,
    output_path: Path,
):
    request = decode_message(read_bytes(input_path))
    if request.stage != Stage.HOST_COMMIT:
        raise AntiExfilError(ErrorCode.WRONG_STAGE, "PSBT opening flow requires message 1")
    psbt, _ = load_psbt(psbt_path)
    validate_psbt_context(psbt, request.signer_pubkey, request.message_hash)
    return signer_commit(
        input_path=input_path,
        test_secret_key=test_secret_key,
        output_path=output_path,
    )


def signer_sign_psbt(
    *,
    psbt_path: Path,
    input_path: Path,
    test_secret_key: bytes,
    output_path: Path,
):
    reveal = decode_message(read_bytes(input_path))
    if reveal.stage != Stage.HOST_REVEAL:
        raise AntiExfilError(ErrorCode.WRONG_STAGE, "PSBT signing flow requires message 3")
    psbt, _ = load_psbt(psbt_path)
    validate_psbt_context(psbt, reveal.signer_pubkey, reveal.message_hash)
    return signer_sign(
        input_path=input_path,
        test_secret_key=test_secret_key,
        output_path=output_path,
    )


def host_verify_psbt(
    *,
    session_dir: Path,
    input_path: Path,
    signed_psbt_path: Path,
    raw_transaction_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    state = load_state(session_dir)
    if state.get("rung") != "C":
        raise AntiExfilError(ErrorCode.STATE_INVALID, "host session is not a Rung C PSBT session")
    original = read_bytes(session_dir / ORIGINAL_PSBT_FILENAME)
    if hashlib.sha256(original).hexdigest() != state.get("psbt_sha256"):
        raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "stored original PSBT changed")
    response = decode_message(read_bytes(input_path))
    internal_receipt = host_verify(
        session_dir=session_dir,
        input_path=input_path,
        receipt_path=session_dir / INTERNAL_RECEIPT_FILENAME,
    )
    if response.signature is None:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "signature response is incomplete")
    slot = SignatureSlot(
        input_index=int(state["input_index"]),
        signer_pubkey=response.signer_pubkey,
        message_hash=response.message_hash,
        sighash_type=int(state["sighash_type"]),
    )
    signed_psbt, raw_transaction, txid = reconstruct_signed_psbt(
        original, slot, response.signature
    )
    write_exact(signed_psbt_path, signed_psbt)
    write_exact(raw_transaction_path, raw_transaction)
    receipt = {
        **internal_receipt,
        "psbt_reconstructed_from_original": True,
        "signed_psbt_sha256": hashlib.sha256(signed_psbt).hexdigest(),
        "raw_transaction_sha256": hashlib.sha256(raw_transaction).hexdigest(),
        "txid": txid,
        "broadcast": False,
    }
    write_exact(
        receipt_path,
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return receipt


__all__ = [
    "host_init_psbt",
    "host_reveal",
    "host_verify_psbt",
    "signer_commit_psbt",
    "signer_sign_psbt",
]

