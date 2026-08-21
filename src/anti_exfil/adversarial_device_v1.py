"""Deterministic, test-only adversarial AEXT/QR corpus for physical devices.

This module is intentionally separate from the coordinator.  Several cases
cannot be represented by the strict production codecs and must never be used
as coordinator output.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import struct

from embit import ec, script
from embit.psbt import DerivationPath, PSBT
from embit.transaction import SIGHASH, TransactionOutput

from .crypto import signer_opening
from .errors import AntiExfilError, ErrorCode
from .protocol_v1_codec import (
    COMMON_RECORD,
    HEADER as AEXB_HEADER,
    Network,
    ProtocolMessage,
    SigningSlot,
    Stage,
)
from .protocol_v1_transport import (
    FLAG_PSBT,
    HEADER as AEXT_HEADER,
    MAGIC as AEXT_MAGIC,
    VERSION as AEXT_VERSION,
    ProtocolV1Package,
)
from .psbt_v1 import build_host_commit_message, enumerate_signing_slots
from .psbt_v1_fixtures import build_multiscript_fixture
from .qr_bitmap import extract_qr_frame, render_qr_frame
from .storage import write_exact
from .transport import encode_ur_frames


WARNING = "PUBLIC TEST DATA ONLY - NEVER SEND FUNDS TO THIS FIXTURE"


@dataclass(frozen=True, slots=True)
class AdversarialCase:
    slug: str
    title: str
    category: str
    payload: bytes
    expected_code: str
    expected_point: str
    device_path: str
    psbt: bytes | None = None


def _session(slug: str) -> bytes:
    return hashlib.sha256(b"aex-v1-physical-adversarial/session/" + slug.encode()).digest()


def _rhos(slug: str, semantic_slots) -> dict[tuple[int, bytes], bytes]:
    return {
        slot.identifier: hashlib.sha256(
            b"aex-v1-physical-adversarial/rho/"
            + slug.encode()
            + struct.pack(">I", slot.input_index)
            + slot.signer_pubkey
        ).digest()
        for slot in semantic_slots
    }


def _raw_envelope(
    message: bytes,
    psbt: bytes | None,
    *,
    network: Network,
    stage: Stage,
) -> bytes:
    """Wrap raw bytes without invoking either strict production encoder."""

    psbt_bytes = psbt or b""
    flags = FLAG_PSBT if psbt is not None else 0
    digest = hashlib.sha256(psbt_bytes).digest() if psbt is not None else bytes(32)
    return AEXT_HEADER.pack(
        AEXT_MAGIC,
        AEXT_VERSION,
        int(network),
        int(stage),
        flags,
        len(message),
        len(psbt_bytes),
        digest,
    ) + message + psbt_bytes


def _commit_for_psbt(base: ProtocolMessage, psbt: bytes) -> ProtocolMessage:
    return replace(base, psbt_digest=hashlib.sha256(psbt).digest())


def _case(
    slug: str,
    title: str,
    category: str,
    package: ProtocolV1Package,
    expected_code: str,
    expected_point: str,
    device_path: str = "main-menu Scan",
) -> AdversarialCase:
    return AdversarialCase(
        slug,
        title,
        category,
        package.encode(),
        expected_code,
        expected_point,
        device_path,
        package.psbt,
    )


def build_adversarial_cases_v1() -> tuple[AdversarialCase, ...]:
    fixture = build_multiscript_fixture()
    semantic = enumerate_signing_slots(fixture.psbt, fixture.root)
    rhos = _rhos("base", semantic)
    base = build_host_commit_message(
        fixture.psbt,
        fixture.root,
        Network.TESTNET4,
        _session("base"),
        rhos,
    )

    cases: list[AdversarialCase] = []

    wrong_network = replace(base, network=Network.MAINNET, session_id=_session("wrong-mainnet"))
    cases.append(_case(
        "01-wrong-mainnet",
        "Mainnet request while device is in the test network family",
        "network",
        ProtocolV1Package(wrong_network, fixture.psbt),
        "AE_TRANSACTION_MISMATCH",
        "transport network check",
    ))

    openings = tuple(
        replace(
            record,
            opening=signer_opening(
                fixture.root.derive(slot.derivation).key.secret,
                slot.message_hash,
                record.commitment,
            ),
        )
        for slot, record in zip(semantic, base.slots, strict=True)
    )
    message_2 = ProtocolMessage(
        Network.TESTNET4,
        Stage.SIGNER_OPENINGS,
        _session("wrong-stage"),
        base.psbt_digest,
        openings,
    )
    cases.append(_case(
        "02-wrong-stage-message-2",
        "Signer-openings response scanned as a coordinator request",
        "stage",
        ProtocolV1Package(message_2),
        "AE_WRONG_STAGE",
        "request-stage check",
    ))

    mismatch_message = replace(base, session_id=_session("outer-inner-network"))
    mismatch_payload = _raw_envelope(
        mismatch_message.encode(),
        fixture.psbt,
        network=Network.MAINNET,
        stage=Stage.HOST_COMMIT,
    )
    cases.append(AdversarialCase(
        "03-outer-inner-network-mismatch",
        "AEXT and AEXB network fields disagree",
        "transport",
        mismatch_payload,
        "AE_TRANSACTION_MISMATCH",
        "strict transport decode",
        "main-menu Scan",
        fixture.psbt,
    ))

    truncated = fixture.psbt[:-1]
    truncated_message = _commit_for_psbt(
        replace(base, session_id=_session("truncated-psbt")), truncated
    )
    cases.append(AdversarialCase(
        "04-truncated-psbt",
        "AEXT contains a truncated PSBT with a matching digest",
        "psbt",
        _raw_envelope(
            truncated_message.encode(),
            truncated,
            network=Network.TESTNET4,
            stage=Stage.HOST_COMMIT,
        ),
        "AE_INVALID_MESSAGE",
        "canonical PSBT parse",
        "main-menu Scan",
        truncated,
    ))

    def mutated_psbt(change) -> bytes:
        value = PSBT.parse(fixture.psbt)
        change(value)
        return value.serialize()

    semantic_mutations = (
        (
            "05-missing-utxo",
            "Required witness UTXO removed from input 0",
            "utxo",
            lambda value: setattr(value.inputs[0], "witness_utxo", None),
        ),
        (
            "06-broken-witness-script",
            "Native P2WSH input carries a non-matching witness script",
            "script",
            lambda value: setattr(value.inputs[2], "witness_script", script.Script(b"\x51")),
        ),
        (
            "07-wrong-derivation-path",
            "Input 0 derivation path no longer derives its declared key",
            "derivation",
            lambda value: _set_wrong_path(value, fixture.root.my_fingerprint),
        ),
        (
            "08-unsupported-sighash-none",
            "Input 0 requests SIGHASH_NONE",
            "sighash",
            lambda value: setattr(value.inputs[0], "sighash_type", SIGHASH.NONE),
        ),
        (
            "09-mixed-taproot-input",
            "One input is changed to Taproot inside an otherwise ECDSA PSBT",
            "taproot",
            lambda value: setattr(
                value.inputs[3],
                "witness_utxo",
                TransactionOutput(
                    103_000,
                    script.p2tr(ec.PublicKey.parse(semantic[0].signer_pubkey)),
                ),
            ),
        ),
    )
    for slug, title, category, mutation in semantic_mutations:
        psbt = mutated_psbt(mutation)
        message = _commit_for_psbt(replace(base, session_id=_session(slug)), psbt)
        cases.append(_case(
            slug,
            title,
            category,
            ProtocolV1Package(message, psbt),
            "AE_SIGNATURE_SLOT_MISMATCH",
            "semantic PSBT/slot validation",
            "continue through seed selection if prompted",
        ))

    duplicate = bytearray(replace(base, session_id=_session("duplicate-slot")).encode())
    first = duplicate[AEXB_HEADER.size : AEXB_HEADER.size + COMMON_RECORD.size]
    duplicate[
        AEXB_HEADER.size + COMMON_RECORD.size : AEXB_HEADER.size + 2 * COMMON_RECORD.size
    ] = first
    cases.append(AdversarialCase(
        "10-duplicate-slot-record",
        "Message 1 repeats its first slot record",
        "slot-ordering",
        _raw_envelope(
            bytes(duplicate), fixture.psbt,
            network=Network.TESTNET4, stage=Stage.HOST_COMMIT,
        ),
        "AE_SIGNATURE_SLOT_MISMATCH",
        "strict AEXB slot decode",
        "main-menu Scan",
        fixture.psbt,
    ))

    reordered = bytearray(replace(base, session_id=_session("reordered-slot")).encode())
    start = AEXB_HEADER.size
    first = bytes(reordered[start : start + COMMON_RECORD.size])
    second = bytes(reordered[start + COMMON_RECORD.size : start + 2 * COMMON_RECORD.size])
    reordered[start : start + COMMON_RECORD.size] = second
    reordered[start + COMMON_RECORD.size : start + 2 * COMMON_RECORD.size] = first
    cases.append(AdversarialCase(
        "11-reordered-slot-records",
        "Message 1 places the second slot before the first",
        "slot-ordering",
        _raw_envelope(
            bytes(reordered), fixture.psbt,
            network=Network.TESTNET4, stage=Stage.HOST_COMMIT,
        ),
        "AE_SIGNATURE_SLOT_MISMATCH",
        "strict AEXB slot decode",
        "main-menu Scan",
        fixture.psbt,
    ))

    reveal_records = tuple(
        replace(record, opening=opening.opening, rho=rhos[record.identifier])
        for record, opening in zip(base.slots, openings, strict=True)
    )
    bad_rho_records = list(reveal_records)
    changed_rho = bytearray(bad_rho_records[0].rho)
    changed_rho[0] ^= 1
    bad_rho_records[0] = replace(bad_rho_records[0], rho=bytes(changed_rho))
    bad_rho = ProtocolMessage(
        Network.TESTNET4,
        Stage.HOST_REVEAL,
        _session("bad-host-reveal"),
        base.psbt_digest,
        tuple(bad_rho_records),
    )
    cases.append(_case(
        "12-altered-host-reveal",
        "Message 3 host randomness no longer matches its commitment",
        "message-3",
        ProtocolV1Package(bad_rho, fixture.psbt),
        "AE_COMMITMENT_MISMATCH",
        "message-3 commitment verification",
        "main-menu Scan; continue through seed selection if prompted",
    ))

    bad_opening_records = list(reveal_records)
    bad_opening_records[0] = replace(
        bad_opening_records[0], opening=reveal_records[1].opening
    )
    bad_opening = ProtocolMessage(
        Network.TESTNET4,
        Stage.HOST_REVEAL,
        _session("bad-signer-opening"),
        base.psbt_digest,
        tuple(bad_opening_records),
    )
    cases.append(_case(
        "13-altered-signer-opening",
        "Message 3 substitutes another slot's valid signer opening",
        "message-3",
        ProtocolV1Package(bad_opening, fixture.psbt),
        "AE_OPENING_MISMATCH",
        "stateless signer-opening recomputation",
        "main-menu Scan; continue through seed selection if prompted",
    ))

    return tuple(cases)


def _set_wrong_path(psbt: PSBT, fingerprint: bytes) -> None:
    pub = next(iter(psbt.inputs[0].bip32_derivations))
    psbt.inputs[0].bip32_derivations[pub] = DerivationPath(fingerprint, [0])


def generate_adversarial_device_corpus_v1(
    *,
    output_dir: Path,
    seedsigner_src: Path,
    fragment_size: int = 30,
    fountain_windows: int = 2,
) -> dict[str, object]:
    """Generate retained AEXT, UR text, and QR PNGs for every named case."""

    cases = build_adversarial_cases_v1()
    manifest_cases: list[dict[str, object]] = []
    for case in cases:
        case_dir = output_dir / case.slug
        package_path = case_dir / "package.aext"
        write_exact(package_path, case.payload)
        if case.psbt is not None:
            write_exact(case_dir / "embedded.psbt", case.psbt)
        frames = encode_ur_frames(
            case.payload,
            seedsigner_src=seedsigner_src,
            max_fragment_len=fragment_size,
            fountain_windows=fountain_windows,
        )
        for index, frame in enumerate(frames, start=1):
            text_path = case_dir / "frames" / f"frame-{index:04d}.txt"
            image_path = case_dir / "qr" / f"frame-{index:04d}.png"
            write_exact(text_path, (frame + "\n").encode("ascii"))
            if not image_path.exists():
                render_qr_frame(frame, image_path, seedsigner_src=seedsigner_src)
            if extract_qr_frame(image_path, seedsigner_src=seedsigner_src) != frame:
                raise AntiExfilError(
                    ErrorCode.OUTPUT_EXISTS,
                    f"retained QR differs from {case.slug} frame {index}",
                )
        manifest_cases.append({
            "number": len(manifest_cases) + 1,
            "slug": case.slug,
            "title": case.title,
            "category": case.category,
            "expected_error_code": case.expected_code,
            "expected_rejection_point": case.expected_point,
            "device_path": case.device_path,
            "package_sha256": hashlib.sha256(case.payload).hexdigest(),
            "package": str(package_path.resolve()),
            "qr_directory": str((case_dir / "qr").resolve()),
            "animation_frames": len(frames),
        })

    manifest = {
        "format": "anti-exfil-protocol-v1-physical-adversarial-corpus",
        "version": 1,
        "warning": WARNING,
        "network_under_test": "TESTNET4 (accepted as SeedSigner's test network family)",
        "fragment_size": fragment_size,
        "fountain_windows": fountain_windows,
        "case_count": len(manifest_cases),
        "cases": manifest_cases,
    }
    manifest_path = output_dir / "manifest.json"
    write_exact(
        manifest_path,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return {
        "status": "adversarial-corpus-ready",
        "warning": WARNING,
        "case_count": len(manifest_cases),
        "manifest": str(manifest_path.resolve()),
        "output_directory": str(output_dir.resolve()),
    }
