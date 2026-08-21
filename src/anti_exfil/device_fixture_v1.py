"""Pinned public five-slot fixture for physical protocol-v1 tests."""

from __future__ import annotations

from pathlib import Path
import sys

from .psbt_tools import SEEDSIGNER_TEST_MNEMONIC
from .psbt_v1_fixtures import build_multiscript_fixture
from .qr_bitmap import extract_qr_frame, render_qr_frame
from .storage import write_exact


def prepare_device_fixture_v1(*, output_dir: Path, seedsigner_src: Path) -> dict[str, object]:
    fixture = build_multiscript_fixture()
    psbt_path = output_dir / "original.psbt"
    mnemonic_path = output_dir / "PUBLIC-TEST-MNEMONIC.txt"
    fingerprint_path = output_dir / "signer-fingerprint.txt"
    seed_qr_path = output_dir / "seed-qr" / "frame-0001.png"
    write_exact(psbt_path, fixture.psbt)
    write_exact(mnemonic_path, (SEEDSIGNER_TEST_MNEMONIC + "\n").encode("utf-8"))
    write_exact(fingerprint_path, (fixture.root.my_fingerprint.hex() + "\n").encode("ascii"))

    source = str(seedsigner_src.resolve())
    if source not in sys.path:
        sys.path.insert(0, source)
    from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
    from seedsigner.models.encode_qr import SeedQrEncoder

    seed_frame = SeedQrEncoder(mnemonic=SEEDSIGNER_TEST_MNEMONIC.split()).next_part()
    render_qr_frame(seed_frame, seed_qr_path, seedsigner_src=seedsigner_src)
    extracted = extract_qr_frame(seed_qr_path, seedsigner_src=seedsigner_src)
    decoder = DecodeQR()
    if decoder.add_data(extracted) != DecodeQRStatus.COMPLETE:
        raise RuntimeError("public test SeedQR did not decode completely")
    if decoder.get_seed_phrase() != SEEDSIGNER_TEST_MNEMONIC.split():
        raise RuntimeError("public test SeedQR round trip changed the mnemonic")

    return {
        "status": "fixture-ready",
        "warning": "public deterministic test seed; never send funds to it",
        "psbt": str(psbt_path.resolve()),
        "mnemonic": str(mnemonic_path.resolve()),
        "signer_fingerprint": fixture.root.my_fingerprint.hex(),
        "signer_fingerprint_file": str(fingerprint_path.resolve()),
        "seed_qr_directory": str(seed_qr_path.parent.resolve()),
        "input_count": 4,
        "slot_count": 5,
    }
