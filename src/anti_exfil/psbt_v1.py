"""Strict semantic PSBT-v0 layer for protocol-v1 multi-slot transcripts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from embit import bip32, ec, script
from embit.psbt import PSBT, PSBTError
from embit.transaction import SIGHASH

from .crypto import host_commit, verify_anti_exfil
from .errors import AntiExfilError, ErrorCode
from .protocol_v1_codec import MAX_SLOTS, MAX_SLOTS_PER_INPUT, Network, ProtocolMessage, SigningSlot, Stage
from .psbt_tools import compact_to_der


@dataclass(frozen=True, slots=True)
class SemanticSigningSlot:
    input_index: int
    signer_pubkey: bytes
    message_hash: bytes
    sighash_type: int
    derivation: tuple[int, ...]
    script_kind: str

    @property
    def identifier(self) -> tuple[int, bytes]:
        return self.input_index, self.signer_pubkey


def parse_psbt_v0(raw: bytes) -> PSBT:
    if not isinstance(raw, bytes) or not raw.startswith(b"psbt\xff"):
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "invalid PSBT magic")
    try:
        parsed = PSBT.parse(raw)
    except Exception as exc:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, f"invalid PSBT: {exc}") from exc
    if parsed.serialize() != raw:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "PSBT is not canonically encoded")
    if parsed.version not in (None, 0):
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "protocol v1 accepts PSBT v0 only")
    if parsed.tx is None or not parsed.inputs or not parsed.outputs:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "PSBT requires an unsigned transaction")
    return parsed


def enumerate_signing_slots(raw: bytes, root: bip32.HDKey) -> tuple[SemanticSigningSlot, ...]:
    """Validate every input and enumerate every non-finalized key controlled by root."""
    psbt = parse_psbt_v0(raw)
    slots: list[SemanticSigningSlot] = []
    for index, scope in enumerate(psbt.inputs):
        if _has_taproot_metadata(scope):
            _fail(index, "Taproot data is unsupported and fails the whole ceremony")
        utxo = _resolve_utxo(psbt, index)
        kind, signing_keys = _classify_script(index, scope, utxo.script_pubkey)
        sighash = SIGHASH.ALL if scope.sighash_type is None else scope.sighash_type
        if sighash != SIGHASH.ALL:
            _fail(index, f"unsupported sighash type {sighash}")
        _validate_derivations(index, scope, signing_keys)
        message_hash = psbt.sighash(index, sighash=SIGHASH.ALL)
        for pub, derivation in scope.bip32_derivations.items():
            pubkey = pub.sec()
            if pubkey not in signing_keys or derivation.fingerprint != root.my_fingerprint:
                continue
            if root.derive(derivation.derivation).key.get_public_key().sec() != pubkey:
                _fail(index, "BIP32 path does not derive its declared public key")
            if pub in scope.partial_sigs:
                raise AntiExfilError(ErrorCode.UNEXPECTED_RETURN_DATA, f"input {index} already has a controlled signature")
            if scope.final_scriptsig is not None or scope.final_scriptwitness is not None:
                continue
            slots.append(SemanticSigningSlot(index, pubkey, message_hash, int(SIGHASH.ALL), tuple(derivation.derivation), kind))
    slots.sort(key=lambda item: item.identifier)
    if not slots:
        raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "PSBT has no controlled signing slots")
    if len(slots) > MAX_SLOTS:
        raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "PSBT exceeds the global slot limit")
    counts: dict[int, int] = {}
    for slot in slots:
        counts[slot.input_index] = counts.get(slot.input_index, 0) + 1
        if counts[slot.input_index] > MAX_SLOTS_PER_INPUT:
            _fail(slot.input_index, "input exceeds the per-input slot limit")
    if len({slot.identifier for slot in slots}) != len(slots):
        raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "duplicate signing slot")
    return tuple(slots)


def validate_protocol_slots(
    raw: bytes, records: tuple[SigningSlot, ...]
) -> tuple[SemanticSigningSlot, ...]:
    """Re-derive host-declared slots without requiring signer private material."""

    psbt = parse_psbt_v0(raw)
    requested = {record.identifier: record for record in records}
    if len(requested) != len(records):
        raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "duplicate protocol slot")
    derived: list[SemanticSigningSlot] = []
    for index, scope in enumerate(psbt.inputs):
        if _has_taproot_metadata(scope):
            _fail(index, "Taproot data is unsupported and fails the whole ceremony")
        utxo = _resolve_utxo(psbt, index)
        kind, signing_keys = _classify_script(index, scope, utxo.script_pubkey)
        sighash = SIGHASH.ALL if scope.sighash_type is None else scope.sighash_type
        if sighash != SIGHASH.ALL:
            _fail(index, f"unsupported sighash type {sighash}")
        _validate_derivations(index, scope, signing_keys)
        digest = psbt.sighash(index, sighash=SIGHASH.ALL)
        derivations = {pub.sec(): tuple(origin.derivation) for pub, origin in scope.bip32_derivations.items()}
        for pubkey in signing_keys:
            record = requested.get((index, pubkey))
            if record is None:
                continue
            if pubkey not in derivations:
                _fail(index, "requested signer key lacks BIP32 derivation metadata")
            public = ec.PublicKey.parse(pubkey)
            if public in scope.partial_sigs:
                raise AntiExfilError(
                    ErrorCode.UNEXPECTED_RETURN_DATA,
                    f"input {index} already has a signature for a requested key",
                )
            if scope.final_scriptsig is not None or scope.final_scriptwitness is not None:
                _fail(index, "requested signing slot is already finalized")
            if record.message_hash != digest or record.sighash_type != SIGHASH.ALL:
                raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "protocol slot sighash differs from PSBT")
            derived.append(SemanticSigningSlot(index, pubkey, digest, int(SIGHASH.ALL), derivations[pubkey], kind))
    derived.sort(key=lambda slot: slot.identifier)
    if tuple(slot.identifier for slot in derived) != tuple(record.identifier for record in records):
        raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "protocol slot set is not represented by the PSBT")
    return tuple(derived)


def enumerate_signing_slots_for_fingerprint(
    raw: bytes, fingerprint: bytes
) -> tuple[SemanticSigningSlot, ...]:
    """Enumerate host-known signer slots using public PSBT origin metadata only."""

    if not isinstance(fingerprint, bytes) or len(fingerprint) != 4:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "signer fingerprint must be four bytes")
    psbt = parse_psbt_v0(raw)
    slots: list[SemanticSigningSlot] = []
    for index, scope in enumerate(psbt.inputs):
        if _has_taproot_metadata(scope):
            _fail(index, "Taproot data is unsupported and fails the whole ceremony")
        utxo = _resolve_utxo(psbt, index)
        kind, signing_keys = _classify_script(index, scope, utxo.script_pubkey)
        sighash = SIGHASH.ALL if scope.sighash_type is None else scope.sighash_type
        if sighash != SIGHASH.ALL:
            _fail(index, f"unsupported sighash type {sighash}")
        _validate_derivations(index, scope, signing_keys)
        digest = psbt.sighash(index, sighash=SIGHASH.ALL)
        for pub, origin in scope.bip32_derivations.items():
            if pub.sec() not in signing_keys or origin.fingerprint != fingerprint:
                continue
            if pub in scope.partial_sigs:
                raise AntiExfilError(ErrorCode.UNEXPECTED_RETURN_DATA, f"input {index} already has a requested signature")
            if scope.final_scriptsig is not None or scope.final_scriptwitness is not None:
                continue
            slots.append(SemanticSigningSlot(index, pub.sec(), digest, int(SIGHASH.ALL), tuple(origin.derivation), kind))
    slots.sort(key=lambda slot: slot.identifier)
    if not slots:
        raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "PSBT has no slots for signer fingerprint")
    if len(slots) > MAX_SLOTS:
        raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "PSBT exceeds global slot limit")
    return tuple(slots)


def build_host_commit_message(raw: bytes, root: bip32.HDKey, network: Network, session_id: bytes,
                              rhos: dict[tuple[int, bytes], bytes]) -> ProtocolMessage:
    slots = enumerate_signing_slots(raw, root)
    if set(rhos) != {slot.identifier for slot in slots}:
        raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "host randomness must cover the exact slot set")
    if len(set(rhos.values())) != len(rhos):
        raise AntiExfilError(ErrorCode.COMMITMENT_MISMATCH, "host randomness must be unique per slot")
    records = tuple(SigningSlot(slot.input_index, slot.signer_pubkey, slot.message_hash,
                                slot.sighash_type, host_commit(rhos[slot.identifier])) for slot in slots)
    return ProtocolMessage(network, Stage.HOST_COMMIT, session_id, hashlib.sha256(raw).digest(), records)


def reconstruct_signed_psbt_v1(original: bytes, root: bip32.HDKey | None, commit: ProtocolMessage,
                               signatures: ProtocolMessage,
                               rhos: dict[tuple[int, bytes], bytes]) -> bytes:
    """Verify a complete response and import only expected partial signatures."""
    if root is None:
        authoritative = validate_protocol_slots(original, commit.slots)
        if commit.psbt_digest != hashlib.sha256(original).digest():
            raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "commit digest differs from the PSBT")
        if set(rhos) != {slot.identifier for slot in authoritative}:
            raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "host randomness differs from slot set")
        for slot in commit.slots:
            if host_commit(rhos[slot.identifier]) != slot.commitment:
                raise AntiExfilError(ErrorCode.COMMITMENT_MISMATCH, "stored host randomness differs from commitment")
    else:
        authoritative = enumerate_signing_slots(original, root)
        expected = build_host_commit_message(original, root, commit.network, commit.session_id, rhos)
        if commit != expected:
            raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "commit message is not authoritative for the PSBT")
    if signatures.stage != Stage.SIGNER_SIGNATURES:
        raise AntiExfilError(ErrorCode.WRONG_STAGE, "expected signer-signatures message")
    if (signatures.network, signatures.session_id, signatures.psbt_digest) != (commit.network, commit.session_id, commit.psbt_digest):
        raise AntiExfilError(ErrorCode.TRANSACTION_MISMATCH, "signature response context changed")
    if len(signatures.slots) != len(commit.slots):
        raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "signature response is incomplete")
    for before, after in zip(commit.slots, signatures.slots, strict=True):
        if (before.identifier, before.message_hash, before.sighash_type, before.commitment) != (after.identifier, after.message_hash, after.sighash_type, after.commitment):
            raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, "signature slot context changed")
        if after.opening is None or after.signature is None or not verify_anti_exfil(after.signer_pubkey, after.message_hash, rhos[before.identifier], after.opening, after.signature):
            raise AntiExfilError(ErrorCode.SIGNATURE_INVALID, "anti-exfil signature verification failed")
    psbt = parse_psbt_v0(original)
    for semantic, response in zip(authoritative, signatures.slots, strict=True):
        psbt.inputs[semantic.input_index].partial_sigs[ec.PublicKey.parse(semantic.signer_pubkey)] = compact_to_der(response.signature) + b"\x01"
    return psbt.serialize()


def _resolve_utxo(psbt: PSBT, index: int):
    scope, witness, legacy = psbt.inputs[index], psbt.inputs[index].witness_utxo, psbt.inputs[index].non_witness_utxo
    if legacy is not None:
        txin = psbt.tx.vin[index]
        if legacy.txid() != txin.txid or txin.vout >= len(legacy.vout):
            _fail(index, "non-witness UTXO does not match the prevout")
        referenced = legacy.vout[txin.vout]
        if witness is not None and witness != referenced:
            _fail(index, "witness and non-witness UTXO data disagree")
        witness = referenced
    if witness is None:
        _fail(index, "missing UTXO data")
    return witness


def _classify_script(index: int, scope, outer: script.Script) -> tuple[str, tuple[bytes, ...]]:
    outer_type = outer.script_type()
    if outer_type == "p2tr":
        _fail(index, "Taproot input is unsupported")
    if outer_type == "p2wpkh" and scope.redeem_script is None and scope.witness_script is None:
        return "p2wpkh", (_p2wpkh_key(index, outer, scope),)
    if outer_type == "p2sh" and scope.redeem_script is not None and script.p2sh(scope.redeem_script) == outer:
        if scope.redeem_script.script_type() == "p2wpkh" and scope.witness_script is None:
            return "p2sh-p2wpkh", (_p2wpkh_key(index, scope.redeem_script, scope),)
        if scope.redeem_script.script_type() == "p2wsh" and scope.witness_script is not None:
            if script.p2wsh(scope.witness_script) != scope.redeem_script:
                _fail(index, "witness script does not match nested P2WSH program")
            return "p2sh-p2wsh-multisig", _parse_multisig(index, scope.witness_script)
    if outer_type == "p2wsh" and scope.redeem_script is None and scope.witness_script is not None:
        if script.p2wsh(scope.witness_script) != outer:
            _fail(index, "witness script does not match P2WSH program")
        return "p2wsh-multisig", _parse_multisig(index, scope.witness_script)
    _fail(index, f"unsupported or inconsistent script type {outer_type}")


def _p2wpkh_key(index: int, program: script.Script, scope) -> bytes:
    matches = [pub.sec() for pub in scope.bip32_derivations if script.p2wpkh(pub) == program]
    if len(matches) != 1:
        _fail(index, "P2WPKH requires exactly one matching BIP32 public key")
    return matches[0]


def _parse_multisig(index: int, witness_script: script.Script) -> tuple[bytes, ...]:
    raw = witness_script.data
    if len(raw) < 3 or raw[-1] != 0xAE or not 0x51 <= raw[0] <= 0x60 or not 0x51 <= raw[-2] <= 0x60:
        _fail(index, "witness script is not canonical standard multisig")
    required, declared, keys, cursor = raw[0] - 0x50, raw[-2] - 0x50, [], 1
    while cursor < len(raw) - 2:
        if raw[cursor] != 33 or cursor + 34 > len(raw) - 2:
            _fail(index, "multisig keys must use canonical 33-byte pushes")
        encoded = raw[cursor + 1:cursor + 34]
        try:
            ec.PublicKey.parse(encoded)
        except Exception:
            _fail(index, "multisig contains an invalid compressed public key")
        keys.append(encoded)
        cursor += 34
    if cursor != len(raw) - 2 or declared != len(keys) or not 1 <= required <= declared <= 16:
        _fail(index, "multisig threshold or key count is invalid")
    if len(set(keys)) != len(keys):
        _fail(index, "multisig public keys must be unique")
    return tuple(keys)


def _validate_derivations(index: int, scope, signing_keys: tuple[bytes, ...]) -> None:
    seen: set[bytes] = set()
    for pub, derivation in scope.bip32_derivations.items():
        encoded = pub.sec()
        if encoded in seen or encoded not in signing_keys:
            _fail(index, "BIP32 public key is duplicate or absent from the script")
        seen.add(encoded)
        if len(derivation.fingerprint) != 4 or not all(0 <= item <= 0xFFFFFFFF for item in derivation.derivation):
            _fail(index, "invalid BIP32 derivation metadata")


def _has_taproot_metadata(scope) -> bool:
    return bool(scope.taproot_bip32_derivations or scope.taproot_internal_key or scope.taproot_merkle_root or scope.taproot_sigs or scope.taproot_scripts)


def _fail(index: int, message: str):
    raise AntiExfilError(ErrorCode.SIGNATURE_SLOT_MISMATCH, f"input {index}: {message}")
