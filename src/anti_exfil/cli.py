"""Terminal entry points for the research anti-exfil implementation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from .crypto import anti_exfil_sign, host_commit, public_key, signer_opening, verify_anti_exfil
from .errors import AntiExfilError, ErrorCode
from .psbt_tools import build_seedsigner_p2wpkh_fixture, build_single_p2wpkh_fixture
from .psbt_workflow import (
    host_init_psbt,
    host_verify_psbt,
    signer_commit_psbt,
    signer_sign_psbt,
)
from .qr_bitmap import extract_qr_frame, render_qr_frame
from .storage import write_exact
from .seedsigner_adapter import (
    derive_seedsigner_context,
    signer_commit_seedsigner,
    signer_sign_seedsigner,
)
from .workflow import (
    host_init,
    host_reveal,
    host_verify,
    inspect_message,
    load_test_secret,
    signer_commit,
    signer_sign,
)
from .messages import Stage, decode_message
from .transport import (
    TransportNetwork,
    TransportPackage,
    UR_TYPE,
    decode_ur_frames,
    encode_ur_frames,
)
from .camera_receiver import list_cameras, receive_package
from .coordinator import prepare_message_3
from .coordinator_v1 import host_accept_openings_v1, host_complete_v1, host_init_v1
from .protocol_v1_codec import Network as V1Network
from .protocol_v1_codec import Stage as V1Stage
from .qr_workflow_v1 import prepare_protocol_v1_qr
from .device_fixture_v1 import prepare_device_fixture_v1
from .adversarial_device_v1 import generate_adversarial_device_corpus_v1


DEMO_SECRET = bytes.fromhex("55" * 32)
DEMO_MESSAGE = bytes.fromhex("88" * 32)
DEMO_RHO = bytes.fromhex("a5" * 32)
DEMO_SESSION_ID = bytes.fromhex("c3" * 32)


def _rung_a_demo() -> int:
    commitment = host_commit(DEMO_RHO)
    opening = signer_opening(DEMO_SECRET, DEMO_MESSAGE, commitment)
    signature, signing_opening = anti_exfil_sign(DEMO_SECRET, DEMO_MESSAGE, DEMO_RHO)
    pubkey = public_key(DEMO_SECRET)
    verified = opening == signing_opening and verify_anti_exfil(
        pubkey, DEMO_MESSAGE, DEMO_RHO, opening, signature
    )
    print(
        json.dumps(
            {
                "construction": "secp256k1-zkp-ecdsa-anti-exfil",
                "reference_commit": "2af926dc309a673461f0e2da090105c8f05b4505",
                "message_hash": DEMO_MESSAGE.hex(),
                "host_randomness": DEMO_RHO.hex(),
                "host_commitment": commitment.hex(),
                "signer_pubkey": pubkey.hex(),
                "signer_opening": opening.hex(),
                "signature_compact": signature.hex(),
                "verified": verified,
                "warning": "test-only non-constant-time Python model",
            },
            indent=2,
        )
    )
    return 0 if verified else 1


def _bytes_from_hex(value: str, *, length: int, name: str) -> bytes:
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{name} must be hexadecimal") from exc
    if len(decoded) != length:
        raise argparse.ArgumentTypeError(f"{name} must decode to {length} bytes")
    return decoded


def _hex32(name: str):
    return lambda value: _bytes_from_hex(value, length=32, name=name)


def _hex4(name: str):
    return lambda value: _bytes_from_hex(value, length=4, name=name)


def _hex33(name: str):
    return lambda value: _bytes_from_hex(value, length=33, name=name)


def _rung_b_demo(run_dir: Path) -> int:
    exchange = run_dir / "exchange"
    host_private = run_dir / "host-private"
    output = run_dir / "output"
    message_1 = exchange / "message-1-host-commit.aex"
    message_2 = exchange / "message-2-signer-openings.aex"
    message_3 = exchange / "message-3-host-reveal.aex"
    message_4 = exchange / "message-4-signer-signatures.aex"
    receipt = output / "verified-receipt.json"
    signer_pubkey = public_key(DEMO_SECRET)

    host_init(
        message_hash=DEMO_MESSAGE,
        signer_pubkey=signer_pubkey,
        session_dir=host_private,
        output_path=message_1,
        rho=DEMO_RHO,
        session_id=DEMO_SESSION_ID,
    )
    signer_commit(input_path=message_1, test_secret_key=DEMO_SECRET, output_path=message_2)
    host_reveal(session_dir=host_private, input_path=message_2, output_path=message_3)
    signer_sign(input_path=message_3, test_secret_key=DEMO_SECRET, output_path=message_4)
    verified = host_verify(session_dir=host_private, input_path=message_4, receipt_path=receipt)
    print(
        json.dumps(
            {
                "status": "complete",
                "run_directory": str(run_dir.resolve()),
                "messages": [str(path.resolve()) for path in (message_1, message_2, message_3, message_4)],
                "receipt": str(receipt.resolve()),
                "session_id": verified["session_id"],
                "warning": "test-only fixed secret key and non-constant-time Python model",
            },
            indent=2,
        )
    )
    return 0


def _rung_c_demo(run_dir: Path) -> int:
    exchange = run_dir / "exchange"
    host_private = run_dir / "host-private"
    output = run_dir / "output"
    fixture_dir = run_dir / "fixtures"
    psbt_path = fixture_dir / "single-p2wpkh.psbt"
    key_path = fixture_dir / "test-key.json"
    message_paths = [exchange / f"message-{number}.aex" for number in range(1, 5)]
    original_psbt, secret = build_single_p2wpkh_fixture()
    write_exact(psbt_path, original_psbt)
    write_exact(
        key_path,
        (json.dumps({"secret_key": secret.hex()}, indent=2) + "\n").encode("utf-8"),
    )
    signer_pubkey = public_key(secret)
    _, slot = host_init_psbt(
        psbt_path=psbt_path,
        signer_pubkey=signer_pubkey,
        session_dir=host_private,
        output_path=message_paths[0],
        rho=DEMO_RHO,
        session_id=DEMO_SESSION_ID,
    )
    signer_commit_psbt(
        psbt_path=psbt_path,
        input_path=message_paths[0],
        test_secret_key=secret,
        output_path=message_paths[1],
    )
    host_reveal(
        session_dir=host_private,
        input_path=message_paths[1],
        output_path=message_paths[2],
    )
    signer_sign_psbt(
        psbt_path=psbt_path,
        input_path=message_paths[2],
        test_secret_key=secret,
        output_path=message_paths[3],
    )
    receipt = host_verify_psbt(
        session_dir=host_private,
        input_path=message_paths[3],
        signed_psbt_path=output / "signed.psbt",
        raw_transaction_path=output / "transaction.raw",
        receipt_path=output / "verified-receipt.json",
    )
    print(
        json.dumps(
            {
                "status": "complete",
                "run_directory": str(run_dir.resolve()),
                "frozen_psbt": str(psbt_path.resolve()),
                "input_index": slot.input_index,
                "sighash_type": slot.sighash_type,
                "message_hash": slot.message_hash.hex(),
                "messages": [str(path.resolve()) for path in message_paths],
                "signed_psbt": str((output / "signed.psbt").resolve()),
                "raw_transaction": str((output / "transaction.raw").resolve()),
                "txid": receipt["txid"],
                "broadcast": False,
                "warning": "deterministic no-value fixture; never use the test key for funds",
            },
            indent=2,
        )
    )
    return 0


def _rung_d_demo(
    run_dir: Path, seedsigner_src: Path, native_library: Path | None = None
) -> int:
    from embit.psbt import PSBT

    exchange = run_dir / "exchange"
    host_private = run_dir / "host-private"
    output = run_dir / "output"
    fixture_dir = run_dir / "fixtures"
    psbt_path = fixture_dir / "seedsigner-p2wpkh.psbt"
    mnemonic_path = fixture_dir / "test-mnemonic.txt"
    message_paths = [exchange / f"message-{number}.aex" for number in range(1, 5)]
    original_psbt, mnemonic = build_seedsigner_p2wpkh_fixture()
    write_exact(psbt_path, original_psbt)
    write_exact(mnemonic_path, (mnemonic + "\n").encode("utf-8"))
    context = derive_seedsigner_context(
        psbt=PSBT.parse(original_psbt), mnemonic=mnemonic, seedsigner_src=seedsigner_src
    )
    host_init_psbt(
        psbt_path=psbt_path,
        signer_pubkey=context.slot.signer_pubkey,
        session_dir=host_private,
        output_path=message_paths[0],
        rho=DEMO_RHO,
        session_id=DEMO_SESSION_ID,
    )
    signer_commit_seedsigner(
        psbt_path=psbt_path,
        input_path=message_paths[0],
        mnemonic=mnemonic,
        seedsigner_src=seedsigner_src,
        output_path=message_paths[1],
        native_library=native_library,
    )
    host_reveal(
        session_dir=host_private, input_path=message_paths[1], output_path=message_paths[2]
    )
    signer_sign_seedsigner(
        psbt_path=psbt_path,
        input_path=message_paths[2],
        mnemonic=mnemonic,
        seedsigner_src=seedsigner_src,
        output_path=message_paths[3],
        native_library=native_library,
    )
    receipt = host_verify_psbt(
        session_dir=host_private,
        input_path=message_paths[3],
        signed_psbt_path=output / "signed.psbt",
        raw_transaction_path=output / "transaction.raw",
        receipt_path=output / "verified-receipt.json",
    )
    print(
        json.dumps(
            {
                "status": "complete",
                "run_directory": str(run_dir.resolve()),
                "seedsigner_source": str(seedsigner_src.resolve()),
                "seed_fingerprint": context.fingerprint,
                "derivation": context.derivation,
                "message_hash": context.slot.message_hash.hex(),
                "input_amount": context.input_amount,
                "spend_amount": context.spend_amount,
                "fee_amount": context.fee_amount,
                "messages": [str(path.resolve()) for path in message_paths],
                "txid": receipt["txid"],
                "broadcast": False,
                "cryptographic_backend": (
                    "native-secp256k1-zkp" if native_library else "reference-python-fallback"
                ),
                "native_library": str(native_library.resolve()) if native_library else None,
                "native_checkpoint_complete": bool(native_library),
                "production_ready": False,
                "warning": (
                    "native SeedSigner binding checkpoint; SeedSigner OS runtime and physical-device validation remain"
                    if native_library
                    else "SeedSigner integration harness; native anti-exfil primitive still required"
                ),
            },
            indent=2,
        )
    )
    return 0


def _rung_e_demo(
    rung_d_dir: Path,
    output_dir: Path,
    seedsigner_src: Path,
    fragment_size: int,
    render_qr: bool,
) -> int:
    psbt = (rung_d_dir / "fixtures" / "seedsigner-p2wpkh.psbt").read_bytes()
    summaries = []
    for number in range(1, 5):
        message_path = rung_d_dir / "exchange" / f"message-{number}.aex"
        message = message_path.read_bytes()
        stage = decode_message(message).stage
        context = psbt if stage in (Stage.HOST_COMMIT, Stage.HOST_REVEAL) else None
        package = TransportPackage(
            message=message,
            network=TransportNetwork.TESTNET,
            psbt=context,
        )
        encoded = package.encode()
        package_path = output_dir / f"message-{number}.aext"
        write_exact(package_path, encoded)
        frames = encode_ur_frames(
            encoded, seedsigner_src=seedsigner_src, max_fragment_len=fragment_size
        )
        frames_dir = output_dir / f"message-{number}-frames"
        for index, frame in enumerate(frames, start=1):
            write_exact(frames_dir / f"frame-{index:04d}.txt", (frame + "\n").encode("ascii"))
        bitmap_round_trip = False
        if render_qr:
            images_dir = output_dir / f"message-{number}-qr"
            decoded_frames = []
            for index, frame in enumerate(frames, start=1):
                image_path = images_dir / f"frame-{index:04d}.png"
                render_qr_frame(
                    frame,
                    image_path,
                    seedsigner_src=seedsigner_src,
                )
                decoded_frames.append(
                    extract_qr_frame(image_path, seedsigner_src=seedsigner_src)
                )
            if decoded_frames != frames:
                raise AntiExfilError(
                    ErrorCode.INVALID_MESSAGE, "QR bitmap round trip changed a UR frame"
                )
            frames = decoded_frames
            bitmap_round_trip = True
        # Model an animated sender continuing after a missed/repeated first
        # cycle: reversed order, one duplicate, then another complete cycle.
        scan_stream = (
            [frames[-1], *reversed(frames), *frames]
            if len(frames) > 1
            else frames
        )
        decoded = decode_ur_frames(scan_stream, seedsigner_src=seedsigner_src)
        recovered = TransportPackage.decode(decoded)
        if recovered != package:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "QR round trip changed the package")
        summaries.append(
            {
                "message": number,
                "stage": stage.name,
                "package_bytes": len(encoded),
                "frame_count": len(frames),
                "psbt_included": context is not None,
                "byte_identical": decoded == encoded,
                "reordered_frames": True,
                "duplicate_frame_tolerated": True,
                "continued_animation": True,
                "bitmap_round_trip": bitmap_round_trip,
            }
        )
    print(
        json.dumps(
            {
                "status": "complete",
                "source_run": str(rung_d_dir.resolve()),
                "output_directory": str(output_dir.resolve()),
                "ur_type": UR_TYPE,
                "fragment_size": fragment_size,
                "messages": summaries,
                "qr_images_rendered": render_qr,
                "camera_used": False,
                "warning": (
                    "PNG frames passed SeedSigner's software decoder; physical camera scanning remains"
                    if render_qr
                    else "UR strings only; pass --render-qr for the headless bitmap gate"
                ),
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anti-exfil",
        description="Research-only terminal model for interactive ECDSA anti-exfil",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "demo-rung-a",
        help="run a fixed scalar/message-hash anti-exfil transcript",
    )
    rung_b = subparsers.add_parser(
        "demo-rung-b",
        help="write and verify a fixed four-message file transcript",
    )
    rung_b.add_argument("--run-dir", type=Path, required=True)

    rung_c = subparsers.add_parser(
        "demo-rung-c",
        help="complete a four-message transcript for a real P2WPKH PSBT fixture",
    )
    rung_c.add_argument("--run-dir", type=Path, required=True)

    rung_d = subparsers.add_parser(
        "demo-rung-d",
        help="run the transcript through SeedSigner's seed, PSBT, and derivation code",
    )
    rung_d.add_argument("--run-dir", type=Path, required=True)
    rung_d.add_argument("--seedsigner-src", type=Path, required=True)
    rung_d.add_argument(
        "--native-library",
        type=Path,
        help="pinned secp256k1-zkp shared library; omit only for the test Python fallback",
    )

    rung_e = subparsers.add_parser(
        "demo-rung-e",
        help="round-trip Rung D messages through SeedSigner's UR2 QR framing",
    )
    rung_e.add_argument("--rung-d-dir", type=Path, required=True)
    rung_e.add_argument("--out-dir", type=Path, required=True)
    rung_e.add_argument("--seedsigner-src", type=Path, required=True)
    rung_e.add_argument("--fragment-size", type=int, default=80)
    rung_e.add_argument(
        "--render-qr",
        action="store_true",
        help="render 240px PNGs and decode them through SeedSigner's QR extraction path",
    )

    fixture = subparsers.add_parser(
        "make-rung-c-fixture", help="write the deterministic P2WPKH PSBT and test key"
    )
    fixture.add_argument("--psbt-out", type=Path, required=True)
    fixture.add_argument("--test-key-out", type=Path, required=True)

    key_info = subparsers.add_parser(
        "test-key-info", help="show the public key for a research test-key fixture"
    )
    key_info.add_argument("--test-key", type=Path, required=True)

    init = subparsers.add_parser("host-init", help="create message 1 and private host state")
    init.add_argument("--message-hash", type=_hex32("message hash"), required=True)
    init.add_argument("--signer-pubkey", type=_hex33("signer public key"), required=True)
    init.add_argument("--session", type=Path, required=True)
    init.add_argument("--out", type=Path, required=True)
    init.add_argument(
        "--test-rho",
        type=_hex32("test rho"),
        help="fixed host randomness for vectors only; omit for OS CSPRNG",
    )
    init.add_argument(
        "--test-session-id",
        type=_hex32("test session ID"),
        help="fixed session ID for vectors only; omit for OS CSPRNG",
    )

    commit = subparsers.add_parser("signer-commit", help="consume message 1 and create message 2")
    commit.add_argument("--in", dest="input_path", type=Path, required=True)
    commit.add_argument("--test-key", type=Path, required=True)
    commit.add_argument("--out", type=Path, required=True)

    reveal = subparsers.add_parser("host-reveal", help="consume message 2 and create message 3")
    reveal.add_argument("--session", type=Path, required=True)
    reveal.add_argument("--in", dest="input_path", type=Path, required=True)
    reveal.add_argument("--out", type=Path, required=True)

    sign = subparsers.add_parser("signer-sign", help="consume message 3 and create message 4")
    sign.add_argument("--in", dest="input_path", type=Path, required=True)
    sign.add_argument("--test-key", type=Path, required=True)
    sign.add_argument("--out", type=Path, required=True)

    verify = subparsers.add_parser("host-verify", help="verify message 4 and complete the host session")
    verify.add_argument("--session", type=Path, required=True)
    verify.add_argument("--in", dest="input_path", type=Path, required=True)
    verify.add_argument("--receipt", type=Path, required=True)

    inspect = subparsers.add_parser("inspect", help="print a public AEXB message as diagnostic JSON")
    inspect.add_argument("--in", dest="input_path", type=Path, required=True)

    init_psbt = subparsers.add_parser(
        "host-init-psbt", help="create message 1 from a frozen single-input P2WPKH PSBT"
    )
    init_psbt.add_argument("--psbt", type=Path, required=True)
    init_psbt.add_argument("--signer-pubkey", type=_hex33("signer public key"), required=True)
    init_psbt.add_argument("--session", type=Path, required=True)
    init_psbt.add_argument("--out", type=Path, required=True)
    init_psbt.add_argument("--test-rho", type=_hex32("test rho"))
    init_psbt.add_argument("--test-session-id", type=_hex32("test session ID"))

    commit_psbt = subparsers.add_parser(
        "signer-commit-psbt", help="validate the frozen PSBT and create message 2"
    )
    commit_psbt.add_argument("--psbt", type=Path, required=True)
    commit_psbt.add_argument("--in", dest="input_path", type=Path, required=True)
    commit_psbt.add_argument("--test-key", type=Path, required=True)
    commit_psbt.add_argument("--out", type=Path, required=True)

    sign_psbt = subparsers.add_parser(
        "signer-sign-psbt", help="revalidate the frozen PSBT and create message 4"
    )
    sign_psbt.add_argument("--psbt", type=Path, required=True)
    sign_psbt.add_argument("--in", dest="input_path", type=Path, required=True)
    sign_psbt.add_argument("--test-key", type=Path, required=True)
    sign_psbt.add_argument("--out", type=Path, required=True)

    verify_psbt = subparsers.add_parser(
        "host-verify-psbt", help="verify message 4 and reconstruct/finalize the PSBT"
    )
    verify_psbt.add_argument("--session", type=Path, required=True)
    verify_psbt.add_argument("--in", dest="input_path", type=Path, required=True)
    verify_psbt.add_argument("--signed-psbt", type=Path, required=True)
    verify_psbt.add_argument("--raw-transaction", type=Path, required=True)
    verify_psbt.add_argument("--receipt", type=Path, required=True)

    v1_init = subparsers.add_parser(
        "v1-host-init", help="create frozen multi-slot message 1 and durable coordinator state"
    )
    v1_init.add_argument("--psbt", type=Path, required=True)
    v1_init.add_argument("--signer-fingerprint", type=_hex4("signer fingerprint"), required=True)
    v1_init.add_argument("--network", choices=[network.name for network in V1Network], required=True)
    v1_init.add_argument("--session", type=Path, required=True)
    v1_init.add_argument("--out-package", type=Path, required=True)
    v1_init.add_argument("--test-session-id", type=_hex32("test session ID"))

    v1_fixture = subparsers.add_parser(
        "v1-make-device-fixture", help="prepare the public four-input/five-slot device fixture"
    )
    v1_fixture.add_argument("--out-dir", type=Path, required=True)
    v1_fixture.add_argument("--seedsigner-src", type=Path, required=True)

    v1_adversarial = subparsers.add_parser(
        "v1-make-device-adversarial",
        help="generate the isolated physical adversarial AEXT/QR corpus",
    )
    v1_adversarial.add_argument("--out-dir", type=Path, required=True)
    v1_adversarial.add_argument("--seedsigner-src", type=Path, required=True)
    v1_adversarial.add_argument("--fragment-size", type=int, default=30)
    v1_adversarial.add_argument("--fountain-windows", type=int, default=2)

    v1_reveal = subparsers.add_parser(
        "v1-host-reveal", help="accept complete message 2 and create multi-slot message 3"
    )
    v1_reveal.add_argument("--session", type=Path, required=True)
    v1_reveal.add_argument("--in-package", type=Path, required=True)
    v1_reveal.add_argument("--out-package", type=Path, required=True)

    v1_complete = subparsers.add_parser(
        "v1-host-complete", help="verify message 4 and reconstruct the coordinator's original PSBT"
    )
    v1_complete.add_argument("--session", type=Path, required=True)
    v1_complete.add_argument("--in-package", type=Path, required=True)
    v1_complete.add_argument("--signed-psbt", type=Path, required=True)
    v1_complete.add_argument("--receipt", type=Path, required=True)

    camera_list = subparsers.add_parser(
        "camera-list", help="list cameras through Sparrow's OpenPnP capture stack"
    )
    camera_list.add_argument("--bridge", type=Path, required=True)

    camera_scan = subparsers.add_parser(
        "camera-scan", help="scan one complete x-btc-anti-exfil UR package"
    )
    camera_scan.add_argument("--bridge", type=Path, required=True)
    camera_scan.add_argument("--seedsigner-src", type=Path, required=True)
    camera_scan.add_argument("--out", type=Path, required=True)
    camera_scan.add_argument("--message-out", type=Path)
    camera_scan.add_argument("--psbt-out", type=Path)
    camera_scan.add_argument("--device", help="exact ID/name or unambiguous camera-name fragment")
    camera_scan.add_argument(
        "--expected-stage", choices=[stage.name for stage in Stage]
    )

    v1_camera_scan = subparsers.add_parser(
        "v1-camera-scan", help="scan one frozen multi-slot AEXT QR package"
    )
    v1_camera_scan.add_argument("--bridge", type=Path, required=True)
    v1_camera_scan.add_argument("--seedsigner-src", type=Path, required=True)
    v1_camera_scan.add_argument("--out-package", type=Path, required=True)
    v1_camera_scan.add_argument("--message-out", type=Path)
    v1_camera_scan.add_argument("--device")
    v1_camera_scan.add_argument("--expected-stage", choices=[stage.name for stage in V1Stage])
    v1_camera_scan.add_argument("--network", choices=[network.name for network in V1Network])
    v1_camera_scan.add_argument("--timeout", type=int, default=120)
    v1_camera_scan.add_argument("--no-preview", action="store_true")

    v1_qr = subparsers.add_parser(
        "v1-qr-display", help="validate and display any frozen multi-slot AEXT package"
    )
    v1_qr.add_argument("--in-package", type=Path, required=True)
    v1_qr.add_argument("--out-dir", type=Path, required=True)
    v1_qr.add_argument("--seedsigner-src", type=Path, required=True)
    v1_qr.add_argument("--expected-stage", choices=[stage.name for stage in V1Stage])
    v1_qr.add_argument("--network", choices=[network.name for network in V1Network])
    v1_qr.add_argument("--fragment-size", type=int, default=30)
    v1_qr.add_argument("--fountain-windows", type=int, default=2)
    v1_qr.add_argument("--fps", type=float, default=5.0)
    v1_qr.add_argument("--scale", type=int, default=3)
    v1_qr.add_argument("--no-display", action="store_true")
    camera_scan.add_argument(
        "--network", choices=[network.name for network in TransportNetwork]
    )
    camera_scan.add_argument("--timeout", type=int, default=120)
    camera_scan.add_argument(
        "--no-preview", action="store_true", help="disable the live camera preview window"
    )

    reveal_qr = subparsers.add_parser(
        "coordinator-reveal",
        help="consume message 2, create message 3, and display its animated QR",
    )
    reveal_qr.add_argument("--in-package", type=Path, required=True)
    reveal_qr.add_argument("--session", type=Path, required=True)
    reveal_qr.add_argument("--out-dir", type=Path, required=True)
    reveal_qr.add_argument("--seedsigner-src", type=Path, required=True)
    reveal_qr.add_argument(
        "--network", choices=[network.name for network in TransportNetwork], required=True
    )
    reveal_qr.add_argument("--fragment-size", type=int, default=30)
    reveal_qr.add_argument("--fountain-windows", type=int, default=2)
    reveal_qr.add_argument("--fps", type=float, default=5.0)
    reveal_qr.add_argument("--scale", type=int, default=3)
    reveal_qr.add_argument(
        "--no-display", action="store_true", help="prepare QR PNGs without opening the viewer"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "demo-rung-a":
            return _rung_a_demo()
        if args.command == "demo-rung-b":
            return _rung_b_demo(args.run_dir)
        if args.command == "demo-rung-c":
            return _rung_c_demo(args.run_dir)
        if args.command == "demo-rung-d":
            return _rung_d_demo(args.run_dir, args.seedsigner_src, args.native_library)
        if args.command == "demo-rung-e":
            return _rung_e_demo(
                args.rung_d_dir,
                args.out_dir,
                args.seedsigner_src,
                args.fragment_size,
                args.render_qr,
            )
        if args.command == "make-rung-c-fixture":
            raw, secret = build_single_p2wpkh_fixture()
            write_exact(args.psbt_out, raw)
            write_exact(
                args.test_key_out,
                (json.dumps({"secret_key": secret.hex()}, indent=2) + "\n").encode("utf-8"),
            )
            print(
                json.dumps(
                    {
                        "psbt": str(args.psbt_out.resolve()),
                        "test_key": str(args.test_key_out.resolve()),
                        "signer_pubkey": public_key(secret).hex(),
                        "warning": "deterministic no-value fixture only",
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "test-key-info":
            print(json.dumps({"signer_pubkey": public_key(load_test_secret(args.test_key)).hex()}, indent=2))
            return 0
        if args.command == "host-init":
            message = host_init(
                message_hash=args.message_hash,
                signer_pubkey=args.signer_pubkey,
                session_dir=args.session,
                output_path=args.out,
                rho=args.test_rho,
                session_id=args.test_session_id,
            )
            print(json.dumps(message.diagnostic(), indent=2))
            return 0
        if args.command == "signer-commit":
            message = signer_commit(
                input_path=args.input_path,
                test_secret_key=load_test_secret(args.test_key),
                output_path=args.out,
            )
            print(json.dumps(message.diagnostic(), indent=2))
            return 0
        if args.command == "host-reveal":
            message = host_reveal(
                session_dir=args.session,
                input_path=args.input_path,
                output_path=args.out,
            )
            print(json.dumps(message.diagnostic(), indent=2))
            return 0
        if args.command == "signer-sign":
            message = signer_sign(
                input_path=args.input_path,
                test_secret_key=load_test_secret(args.test_key),
                output_path=args.out,
            )
            print(json.dumps(message.diagnostic(), indent=2))
            return 0
        if args.command == "host-verify":
            receipt = host_verify(
                session_dir=args.session,
                input_path=args.input_path,
                receipt_path=args.receipt,
            )
            print(json.dumps(receipt, indent=2))
            return 0
        if args.command == "inspect":
            print(json.dumps(inspect_message(args.input_path), indent=2))
            return 0
        if args.command == "host-init-psbt":
            message, slot = host_init_psbt(
                psbt_path=args.psbt,
                signer_pubkey=args.signer_pubkey,
                session_dir=args.session,
                output_path=args.out,
                rho=args.test_rho,
                session_id=args.test_session_id,
            )
            diagnostic = message.diagnostic()
            diagnostic["input_index"] = slot.input_index
            diagnostic["sighash_type"] = slot.sighash_type
            print(json.dumps(diagnostic, indent=2))
            return 0
        if args.command == "signer-commit-psbt":
            message = signer_commit_psbt(
                psbt_path=args.psbt,
                input_path=args.input_path,
                test_secret_key=load_test_secret(args.test_key),
                output_path=args.out,
            )
            print(json.dumps(message.diagnostic(), indent=2))
            return 0
        if args.command == "signer-sign-psbt":
            message = signer_sign_psbt(
                psbt_path=args.psbt,
                input_path=args.input_path,
                test_secret_key=load_test_secret(args.test_key),
                output_path=args.out,
            )
            print(json.dumps(message.diagnostic(), indent=2))
            return 0
        if args.command == "host-verify-psbt":
            receipt = host_verify_psbt(
                session_dir=args.session,
                input_path=args.input_path,
                signed_psbt_path=args.signed_psbt,
                raw_transaction_path=args.raw_transaction,
                receipt_path=args.receipt,
            )
            print(json.dumps(receipt, indent=2))
            return 0
        if args.command == "v1-host-init":
            network = V1Network[args.network]
            package = host_init_v1(
                psbt_path=args.psbt,
                root=None,
                signer_fingerprint=args.signer_fingerprint,
                network=network,
                session_dir=args.session,
                output_package_path=args.out_package,
                session_id=args.test_session_id,
            )
            print(json.dumps(package.message.diagnostic(), indent=2))
            return 0
        if args.command == "v1-make-device-fixture":
            result = prepare_device_fixture_v1(
                output_dir=args.out_dir, seedsigner_src=args.seedsigner_src
            )
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "v1-make-device-adversarial":
            result = generate_adversarial_device_corpus_v1(
                output_dir=args.out_dir,
                seedsigner_src=args.seedsigner_src,
                fragment_size=args.fragment_size,
                fountain_windows=args.fountain_windows,
            )
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "v1-host-reveal":
            package = host_accept_openings_v1(
                session_dir=args.session,
                input_package_path=args.in_package,
                output_package_path=args.out_package,
            )
            print(json.dumps(package.message.diagnostic(), indent=2))
            return 0
        if args.command == "v1-host-complete":
            receipt = host_complete_v1(
                session_dir=args.session,
                input_package_path=args.in_package,
                signed_psbt_path=args.signed_psbt,
                receipt_path=args.receipt,
            )
            print(json.dumps(receipt, indent=2))
            return 0
        if args.command == "camera-list":
            cameras = list_cameras(bridge=args.bridge)
            print(
                json.dumps(
                    {
                        "cameras": [
                            {
                                "index": camera.index,
                                "name": camera.name,
                                "unique_id": camera.unique_id,
                            }
                            for camera in cameras
                        ]
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "camera-scan":
            if args.timeout <= 0:
                raise AntiExfilError(
                    ErrorCode.INVALID_MESSAGE, "camera timeout must be positive"
                )
            result = receive_package(
                bridge=args.bridge,
                seedsigner_src=args.seedsigner_src,
                output_path=args.out,
                message_output_path=args.message_out,
                psbt_output_path=args.psbt_out,
                device=args.device,
                expected_stage=Stage[args.expected_stage] if args.expected_stage else None,
                expected_network=(
                    TransportNetwork[args.network] if args.network else None
                ),
                timeout_seconds=args.timeout,
                preview=not args.no_preview,
            )
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "v1-camera-scan":
            if args.timeout <= 0:
                raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "camera timeout must be positive")
            result = receive_package(
                bridge=args.bridge,
                seedsigner_src=args.seedsigner_src,
                output_path=args.out_package,
                message_output_path=args.message_out,
                device=args.device,
                expected_stage=V1Stage[args.expected_stage] if args.expected_stage else None,
                expected_network=V1Network[args.network] if args.network else None,
                timeout_seconds=args.timeout,
                preview=not args.no_preview,
                protocol_v1=True,
            )
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "v1-qr-display":
            result = prepare_protocol_v1_qr(
                input_package_path=args.in_package,
                output_dir=args.out_dir,
                seedsigner_src=args.seedsigner_src,
                expected_stage=V1Stage[args.expected_stage] if args.expected_stage else None,
                expected_network=V1Network[args.network] if args.network else None,
                fragment_size=args.fragment_size,
                fountain_windows=args.fountain_windows,
                render_qr=True,
            )
            print(json.dumps(result, indent=2), flush=True)
            if not args.no_display:
                viewer = Path(__file__).resolve().parents[2] / "scripts" / "show-qr-animation.py"
                completed = subprocess.run(
                    [sys.executable, str(viewer), str(result["qr_directory"]),
                     "--fps", str(args.fps), "--scale", str(args.scale)],
                    check=False,
                )
                if completed.returncode != 0:
                    raise AntiExfilError(
                        ErrorCode.STATE_INVALID,
                        f"QR viewer exited with code {completed.returncode}",
                    )
            return 0
        if args.command == "coordinator-reveal":
            result = prepare_message_3(
                input_package_path=args.in_package,
                session_dir=args.session,
                output_dir=args.out_dir,
                seedsigner_src=args.seedsigner_src,
                expected_network=TransportNetwork[args.network],
                fragment_size=args.fragment_size,
                fountain_windows=args.fountain_windows,
                render_qr=True,
            )
            print(json.dumps(result, indent=2), flush=True)
            if not args.no_display:
                viewer = Path(__file__).resolve().parents[2] / "scripts" / "show-qr-animation.py"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(viewer),
                        str(result["qr_directory"]),
                        "--fps",
                        str(args.fps),
                        "--scale",
                        str(args.scale),
                    ],
                    check=False,
                )
                if completed.returncode != 0:
                    raise AntiExfilError(
                        ErrorCode.STATE_INVALID,
                        f"message-3 QR viewer exited with code {completed.returncode}",
                    )
            return 0
        raise AssertionError(f"unhandled command: {args.command}")
    except AntiExfilError as exc:
        print(
            json.dumps({"error": exc.code.value, "message": exc.message}),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
