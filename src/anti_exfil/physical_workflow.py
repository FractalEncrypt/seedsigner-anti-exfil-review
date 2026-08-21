"""Host orchestration for the test-only physical Pi Zero file exchange."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from embit.psbt import PSBT

from .errors import AntiExfilError, ErrorCode
from .psbt_tools import build_seedsigner_p2wpkh_fixture
from .psbt_workflow import host_init_psbt, host_reveal, host_verify_psbt
from .storage import read_bytes, write_exact


EXCHANGE_DIRECTORY = "aex-physical"
PSBT_FILENAME = "request.psbt"
MNEMONIC_FILENAME = "test-mnemonic.txt"
STAGE_MARKER = "signer-request-stage.txt"

MESSAGE_1 = "message-1-host-commit.aex"
MESSAGE_2 = "message-2-signer-openings.aex"
MESSAGE_3 = "message-3-host-reveal.aex"
MESSAGE_4 = "message-4-signer-signatures.aex"


def _paths(run_dir: Path) -> tuple[Path, Path, Path, Path]:
    fixtures = run_dir / "fixtures"
    transcript = run_dir / "exchange"
    host_private = run_dir / "host-private"
    output = run_dir / "output"
    return fixtures, transcript, host_private, output


def _exchange_dir(drive_root: Path) -> Path:
    if not drive_root.is_absolute():
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE,
            f"drive root must be absolute: {drive_root}",
        )
    try:
        if not drive_root.is_dir():
            # pathlib returns False for several Windows removable-media errors,
            # including an empty card-reader slot. Force an OS operation below
            # so the user receives the actual reason.
            with os.scandir(drive_root):
                pass
            raise OSError(f"not a directory: {drive_root}")
        with os.scandir(drive_root):
            pass
    except OSError as exc:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE,
            "drive root is not accessible; after flashing, remove and reinsert "
            f"the SD card and confirm its current Windows drive letter: {drive_root} ({exc})",
        ) from exc
    return drive_root / EXCHANGE_DIRECTORY


def _read_success_code(path: Path) -> None:
    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, f"missing signer result {path}: {exc}"
        ) from exc
    if value != "0":
        raise AntiExfilError(
            ErrorCode.SIGNATURE_INVALID,
            f"signer stage did not succeed; {path.name} contains {value!r}",
        )


def _replace_stage_marker(path: Path, expected: str, replacement: str) -> None:
    try:
        current = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, f"cannot read stage marker: {exc}"
        ) from exc
    if current != expected:
        raise AntiExfilError(
            ErrorCode.WRONG_STAGE,
            f"expected physical signer stage {expected}; marker contains {current!r}",
        )
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists():
        raise AntiExfilError(
            ErrorCode.OUTPUT_EXISTS, f"temporary stage marker already exists: {temporary}"
        )
    try:
        with temporary.open("x", encoding="ascii", newline="\n") as stream:
            stream.write(f"{replacement}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def prepare(drive_root: Path, run_dir: Path) -> dict[str, object]:
    exchange_on_card = _exchange_dir(drive_root)
    if run_dir.exists():
        raise AntiExfilError(
            ErrorCode.OUTPUT_EXISTS, f"refusing to reuse local run directory: {run_dir}"
        )
    if exchange_on_card.exists():
        raise AntiExfilError(
            ErrorCode.OUTPUT_EXISTS,
            f"refusing to reuse SD exchange directory: {exchange_on_card}",
        )

    fixtures, transcript, host_private, output = _paths(run_dir)
    for directory in (fixtures, transcript, host_private, output, exchange_on_card):
        directory.mkdir(parents=True, exist_ok=False)

    psbt_bytes, mnemonic = build_seedsigner_p2wpkh_fixture()
    local_psbt = fixtures / PSBT_FILENAME
    local_mnemonic = fixtures / MNEMONIC_FILENAME
    local_message_1 = transcript / MESSAGE_1
    write_exact(local_psbt, psbt_bytes)
    write_exact(local_mnemonic, (mnemonic + "\n").encode("utf-8"))

    parsed = PSBT.parse(psbt_bytes)
    derivations = parsed.inputs[0].bip32_derivations
    if len(derivations) != 1:
        raise AntiExfilError(
            ErrorCode.SIGNATURE_SLOT_MISMATCH,
            "physical test fixture must contain exactly one signer derivation",
        )
    signer_pubkey = next(iter(derivations)).sec()
    host_init_psbt(
        psbt_path=local_psbt,
        signer_pubkey=signer_pubkey,
        session_dir=host_private,
        output_path=local_message_1,
    )

    write_exact(exchange_on_card / PSBT_FILENAME, psbt_bytes)
    write_exact(exchange_on_card / MNEMONIC_FILENAME, (mnemonic + "\n").encode("utf-8"))
    write_exact(exchange_on_card / MESSAGE_1, read_bytes(local_message_1))
    write_exact(exchange_on_card / STAGE_MARKER, b"1\n")
    manifest = {
        "status": "prepared",
        "network": "testnet",
        "stage": 1,
        "drive_exchange": str(exchange_on_card.resolve()),
        "local_run": str(run_dir.resolve()),
        "signer_pubkey": signer_pubkey.hex(),
        "warning": "fixed public test fixture only; never send funds to this mnemonic",
    }
    write_exact(
        run_dir / "prepare-receipt.json",
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return manifest


def reveal(drive_root: Path, run_dir: Path) -> dict[str, object]:
    exchange_on_card = _exchange_dir(drive_root)
    _, transcript, host_private, _ = _paths(run_dir)
    _read_success_code(exchange_on_card / "stage-1-signer.exit-code")
    card_message_2 = exchange_on_card / MESSAGE_2
    local_message_2 = transcript / MESSAGE_2
    local_message_3 = transcript / MESSAGE_3
    write_exact(local_message_2, read_bytes(card_message_2))
    host_reveal(
        session_dir=host_private,
        input_path=local_message_2,
        output_path=local_message_3,
    )
    write_exact(exchange_on_card / MESSAGE_3, read_bytes(local_message_3))
    _replace_stage_marker(exchange_on_card / STAGE_MARKER, "1", "3")
    return {
        "status": "reveal-ready",
        "stage": 3,
        "message": str((exchange_on_card / MESSAGE_3).resolve()),
        "automatic_retry": False,
    }


def verify(drive_root: Path, run_dir: Path) -> dict[str, object]:
    exchange_on_card = _exchange_dir(drive_root)
    _, transcript, host_private, output = _paths(run_dir)
    _read_success_code(exchange_on_card / "stage-3-signer.exit-code")
    local_message_4 = transcript / MESSAGE_4
    write_exact(local_message_4, read_bytes(exchange_on_card / MESSAGE_4))
    receipt = host_verify_psbt(
        session_dir=host_private,
        input_path=local_message_4,
        signed_psbt_path=output / "signed.psbt",
        raw_transaction_path=output / "transaction.raw",
        receipt_path=output / "verified-receipt.json",
    )
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Coordinate the test-only physical Pi Zero file exchange"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "reveal", "verify"):
        command = subparsers.add_parser(name)
        command.add_argument("--drive-root", type=Path, required=True)
        command.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare(args.drive_root, args.run_dir)
        elif args.command == "reveal":
            result = reveal(args.drive_root, args.run_dir)
        else:
            result = verify(args.drive_root, args.run_dir)
    except AntiExfilError as exc:
        print(
            json.dumps(
                {"status": "error", "code": exc.code.value, "message": exc.message},
                indent=2,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
