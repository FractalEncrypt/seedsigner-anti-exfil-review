"""Rung C PSBT fixtures, signature-slot validation, and reconstruction."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from embit import bip32, bip39, ec, finalizer, script
from embit.networks import NETWORKS
from embit.psbt import DerivationPath, PSBT, PSBTError
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput

from .crypto import GROUP_N, public_key
from .errors import AntiExfilError, ErrorCode
from .storage import read_bytes


@dataclass(frozen=True, slots=True)
class SignatureSlot:
    input_index: int
    signer_pubkey: bytes
    message_hash: bytes
    sighash_type: int


def build_single_p2wpkh_fixture() -> tuple[bytes, bytes]:
    """Return (PSBT bytes, test secret) for a deterministic no-value fixture."""

    secret = bytes.fromhex("55" * 32)
    signer = ec.PublicKey.parse(public_key(secret))
    destination = ec.PublicKey.parse(public_key(bytes.fromhex("44" * 32)))
    unsigned_tx = Transaction(
        version=2,
        vin=[
            TransactionInput(
                txid=bytes.fromhex("11" * 32),
                vout=0,
                sequence=0xFFFFFFFD,
            )
        ],
        vout=[TransactionOutput(90_000, script.p2wpkh(destination))],
        locktime=0,
    )
    psbt = PSBT(unsigned_tx)
    psbt.inputs[0].witness_utxo = TransactionOutput(100_000, script.p2wpkh(signer))
    psbt.inputs[0].sighash_type = SIGHASH.ALL
    return psbt.serialize(), secret


SEEDSIGNER_TEST_MNEMONIC = (
    "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast"
)
SEEDSIGNER_TEST_DERIVATION = "m/84h/1h/0h/0/0"


def build_seedsigner_p2wpkh_fixture() -> tuple[bytes, str]:
    """Return a deterministic PSBT carrying SeedSigner-compatible BIP32 metadata."""

    seed_bytes = bip39.mnemonic_to_seed(SEEDSIGNER_TEST_MNEMONIC)
    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS["regtest"]["xprv"])
    derivation = bip32.parse_path(SEEDSIGNER_TEST_DERIVATION)
    signer = root.derive(derivation).key.get_public_key()
    destination = ec.PublicKey.parse(public_key(bytes.fromhex("44" * 32)))
    unsigned_tx = Transaction(
        version=2,
        vin=[TransactionInput(txid=bytes.fromhex("22" * 32), vout=0, sequence=0xFFFFFFFD)],
        vout=[TransactionOutput(90_000, script.p2wpkh(destination))],
        locktime=0,
    )
    psbt = PSBT(unsigned_tx)
    psbt.inputs[0].witness_utxo = TransactionOutput(100_000, script.p2wpkh(signer))
    psbt.inputs[0].sighash_type = SIGHASH.ALL
    psbt.inputs[0].bip32_derivations[signer] = DerivationPath(
        root.my_fingerprint, derivation
    )
    return psbt.serialize(), SEEDSIGNER_TEST_MNEMONIC


def load_psbt(path: Path) -> tuple[PSBT, bytes]:
    raw = read_bytes(path)
    try:
        parsed = PSBT.parse(raw)
    except (PSBTError, ValueError, IndexError) as exc:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, f"invalid PSBT: {exc}") from exc
    if parsed.serialize() != raw:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE,
            "PSBT is not in embit's canonical round-trip representation",
        )
    return parsed, raw


def find_single_p2wpkh_slot(psbt: PSBT, signer_pubkey33: bytes) -> SignatureSlot:
    """Find exactly one native P2WPKH SIGHASH_ALL slot for the signer."""

    try:
        signer = ec.PublicKey.parse(signer_pubkey33)
    except Exception as exc:
        raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "invalid signer public key") from exc
    expected_script = script.p2wpkh(signer)
    matches: list[SignatureSlot] = []
    for index, input_scope in enumerate(psbt.inputs):
        if input_scope.is_taproot:
            continue
        try:
            utxo = psbt.utxo(index)
        except Exception as exc:
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, f"input {index} is missing usable UTXO data"
            ) from exc
        if utxo.script_pubkey != expected_script:
            continue
        sighash_type = input_scope.sighash_type
        if sighash_type is None:
            sighash_type = SIGHASH.ALL
        if sighash_type != SIGHASH.ALL:
            raise AntiExfilError(
                ErrorCode.SIGNATURE_SLOT_MISMATCH,
                f"input {index} requests unsupported sighash type {sighash_type}",
            )
        matches.append(
            SignatureSlot(
                input_index=index,
                signer_pubkey=signer_pubkey33,
                message_hash=psbt.sighash(index, sighash=sighash_type),
                sighash_type=sighash_type,
            )
        )
    if len(matches) != 1:
        raise AntiExfilError(
            ErrorCode.SIGNATURE_SLOT_MISMATCH,
            f"Rung C requires exactly one matching P2WPKH slot; found {len(matches)}",
        )
    return matches[0]


def validate_psbt_context(
    psbt: PSBT,
    signer_pubkey33: bytes,
    expected_message_hash: bytes,
) -> SignatureSlot:
    slot = find_single_p2wpkh_slot(psbt, signer_pubkey33)
    if slot.message_hash != expected_message_hash:
        raise AntiExfilError(
            ErrorCode.TRANSACTION_MISMATCH,
            "PSBT sighash does not match the anti-exfil transcript",
        )
    return slot


def compact_to_der(signature64: bytes) -> bytes:
    if len(signature64) != 64:
        raise AntiExfilError(ErrorCode.SIGNATURE_INVALID, "compact signature must be 64 bytes")
    r = int.from_bytes(signature64[:32], "big")
    s = int.from_bytes(signature64[32:], "big")
    if not (1 <= r < GROUP_N and 1 <= s <= GROUP_N // 2):
        raise AntiExfilError(ErrorCode.SIGNATURE_INVALID, "invalid compact signature scalars")

    def encode_integer(value: int) -> bytes:
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
        return b"\x02" + bytes([len(encoded)]) + encoded

    encoded_r = encode_integer(r)
    encoded_s = encode_integer(s)
    body = encoded_r + encoded_s
    return b"\x30" + bytes([len(body)]) + body


def reconstruct_signed_psbt(
    original_psbt: bytes,
    slot: SignatureSlot,
    signature64: bytes,
) -> tuple[bytes, bytes, str]:
    """Import only the expected signature and return PSBT, raw tx, and txid."""

    try:
        psbt = PSBT.parse(original_psbt)
        signer = ec.PublicKey.parse(slot.signer_pubkey)
    except Exception as exc:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, f"cannot reconstruct PSBT: {exc}") from exc
    authoritative = validate_psbt_context(psbt, slot.signer_pubkey, slot.message_hash)
    if authoritative.input_index != slot.input_index or authoritative.sighash_type != slot.sighash_type:
        raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "PSBT signature slot changed")
    if signer in psbt.inputs[slot.input_index].partial_sigs:
        raise AntiExfilError(
            ErrorCode.UNEXPECTED_RETURN_DATA,
            "original PSBT already contains a signature for this signer",
        )
    psbt.inputs[slot.input_index].partial_sigs[signer] = (
        compact_to_der(signature64) + bytes([slot.sighash_type])
    )
    finalized = finalizer.finalize_psbt(psbt)
    if finalized is None:
        raise AntiExfilError(ErrorCode.SIGNATURE_INVALID, "signed PSBT could not be finalized")
    return psbt.serialize(), finalized.serialize(), finalized.txid().hex()
