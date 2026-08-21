"""Live QR receiver backed by Sparrow's OpenPnP Java camera stack."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
import time
from typing import Iterable

from .errors import AntiExfilError, ErrorCode
from .messages import Stage, decode_message
from .storage import write_exact
from .transport import (
    TransportNetwork,
    TransportPackage,
    URPackageAccumulator,
    inspect_ur_fountain_part,
)
from .transport import UR_TYPE
from .protocol_v1_transport import ProtocolV1Package


MAX_FOUNTAIN_CANDIDATES = 8


def fountain_candidate_key(
    metadata: dict[str, int | str], qr_text: str
) -> tuple[object, ...]:
    if metadata["form"] == "multipart":
        return (
            "multipart",
            int(metadata["seq_len"]),
            int(metadata["message_len"]),
            str(metadata["checksum"]),
            int(metadata["fragment_len"]),
        )
    return ("single", qr_text.strip().lower())


def safe_fountain_metadata(
    qr_text: str, *, seedsigner_src: Path
) -> dict[str, int | str] | None:
    """Treat every malformed camera symbol as rejected untrusted input."""
    try:
        return inspect_ur_fountain_part(qr_text, seedsigner_src=seedsigner_src)
    except Exception:
        # SeedSigner's vendored UR parser raises several non-public exception
        # types. None of them may terminate a live scan at this trust boundary.
        return None


@dataclass(frozen=True, slots=True)
class CameraInfo:
    index: int
    name: str
    unique_id: str


def format_duration(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _unb64(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, "camera bridge emitted invalid base64 text"
        ) from exc


def parse_bridge_line(line: str) -> tuple[str, tuple[object, ...]]:
    fields = line.rstrip("\r\n").split("\t")
    if not fields or not fields[0]:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "camera bridge emitted an empty line")
    if fields[0] == "CAMERA" and len(fields) == 4:
        try:
            index = int(fields[1])
        except ValueError as exc:
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, "camera bridge emitted an invalid camera index"
            ) from exc
        return "CAMERA", (CameraInfo(index, _unb64(fields[2]), _unb64(fields[3])),)
    if fields[0] == "OPENED" and len(fields) == 4:
        try:
            width, height = int(fields[2]), int(fields[3])
        except ValueError as exc:
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, "camera bridge emitted an invalid resolution"
            ) from exc
        return "OPENED", (_unb64(fields[1]), width, height)
    if fields[0] == "QR" and len(fields) == 2:
        return "QR", (_unb64(fields[1]),)
    if fields[0] == "STATUS" and len(fields) == 4:
        try:
            return "STATUS", tuple(int(value) for value in fields[1:])
        except ValueError as exc:
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, "camera bridge emitted invalid status counts"
            ) from exc
    raise AntiExfilError(
        ErrorCode.INVALID_MESSAGE, f"unknown camera bridge record {fields[0]!r}"
    )


def _bridge_argv(bridge: Path, arguments: Iterable[str]) -> list[str]:
    resolved = bridge.resolve()
    if not resolved.is_file():
        raise AntiExfilError(
            ErrorCode.STATE_INVALID, f"camera bridge launcher does not exist: {resolved}"
        )
    if resolved.suffix.lower() in (".bat", ".cmd"):
        return ["cmd.exe", "/d", "/c", str(resolved), *arguments]
    return [str(resolved), *arguments]


def list_cameras(*, bridge: Path) -> list[CameraInfo]:
    completed = subprocess.run(
        _bridge_argv(bridge, ["--list"]),
        check=False,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
    )
    cameras: list[CameraInfo] = []
    for line in completed.stdout.splitlines():
        kind, values = parse_bridge_line(line)
        if kind != "CAMERA":
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE, "unexpected record while listing cameras"
            )
        cameras.append(values[0])
    if completed.returncode not in (0, 3):
        raise AntiExfilError(
            ErrorCode.STATE_INVALID, f"camera bridge exited with code {completed.returncode}"
        )
    return cameras


def _stop_bridge_process(process: subprocess.Popen) -> None:
    """Stop the launcher and its camera-owning child process on every exit path."""
    if process.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def receive_package(
    *,
    bridge: Path,
    seedsigner_src: Path,
    output_path: Path,
    message_output_path: Path | None = None,
    psbt_output_path: Path | None = None,
    device: str | None = None,
    expected_stage: Stage | None = None,
    expected_network: TransportNetwork | None = None,
    timeout_seconds: int = 120,
    preview: bool = True,
    protocol_v1: bool = False,
) -> dict[str, object]:
    started = time.monotonic()

    def elapsed() -> str:
        return format_duration(time.monotonic() - started)

    arguments = ["--timeout", str(timeout_seconds)]
    if preview:
        arguments.append("--preview")
    if device:
        arguments.extend(("--device", device))
    process = subprocess.Popen(
        _bridge_argv(bridge, arguments),
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
    )
    if process.stdout is None:
        raise AntiExfilError(ErrorCode.STATE_INVALID, "camera bridge stdout is unavailable")
    accumulators: dict[tuple[object, ...], URPackageAccumulator] = {}
    ignored_candidates: set[tuple[object, ...]] = set()
    selected_accumulator: URPackageAccumulator | None = None
    selected_package: TransportPackage | ProtocolV1Package | None = None
    selected_message = None
    opened: tuple[str, int, int] | None = None
    accepted_frames = 0
    rejected_frames = 0
    seen_sequences: set[tuple[int, int, int, str]] = set()
    try:
        for line in process.stdout:
            kind, values = parse_bridge_line(line)
            if kind == "OPENED":
                opened = (str(values[0]), int(values[1]), int(values[2]))
                print(
                    f"[{elapsed()}] Camera opened: {opened[0]} ({opened[1]}x{opened[2]})",
                    file=sys.stderr,
                    flush=True,
                )
            elif kind == "QR":
                qr_text = str(values[0])
                if not qr_text.lower().startswith(f"ur:{UR_TYPE}/"):
                    qr_type = "non-UR"
                    if qr_text.lower().startswith("ur:"):
                        qr_type = qr_text[3:].split("/", 1)[0].upper()
                    print(
                        f"[{elapsed()}] Decoded {qr_type} QR; ignored "
                        f"(waiting for {UR_TYPE.upper()})",
                        file=sys.stderr,
                        flush=True,
                    )
                    continue
                metadata = safe_fountain_metadata(
                    qr_text, seedsigner_src=seedsigner_src
                )
                if metadata is None:
                    rejected_frames += 1
                    print(
                        f"[{elapsed()}] Rejected malformed anti-exfil QR symbol; "
                        "continuing scan",
                        file=sys.stderr,
                        flush=True,
                    )
                    continue
                sequence = None
                if metadata["form"] == "multipart":
                    sequence = (
                        int(metadata["seq_num"]),
                        int(metadata["seq_len"]),
                        int(metadata["message_len"]),
                        str(metadata["checksum"]),
                    )
                    first_seen = sequence not in seen_sequences
                    seen_sequences.add(sequence)
                else:
                    first_seen = not seen_sequences
                candidate_key = fountain_candidate_key(metadata, qr_text)
                if candidate_key in ignored_candidates:
                    rejected_frames += 1
                    continue
                accumulator = accumulators.get(candidate_key)
                if accumulator is None:
                    if len(accumulators) >= MAX_FOUNTAIN_CANDIDATES:
                        rejected_frames += 1
                        continue
                    accumulator = URPackageAccumulator(seedsigner_src=seedsigner_src)
                    accumulators[candidate_key] = accumulator
                try:
                    accepted = accumulator.receive(qr_text)
                except Exception:
                    rejected_frames += 1
                    print(
                        f"[{elapsed()}] Rejected malformed anti-exfil fountain part; "
                        "continuing scan",
                        file=sys.stderr,
                        flush=True,
                    )
                    continue
                if accepted:
                    accepted_frames += 1
                    detail = ""
                    if sequence:
                        detail = f" {sequence[0]}/{sequence[1]}"
                    print(
                        f"[{elapsed()}] Accepted anti-exfil QR symbol{detail}; "
                        f"{accepted_frames} accepted "
                        f"({accumulator.progress:.0%} reconstructed)",
                        file=sys.stderr,
                        flush=True,
                    )
                else:
                    rejected_frames += 1
                    if first_seen:
                        detail = "single-part"
                        if sequence:
                            detail = (
                                f"{sequence[0]}/{sequence[1]}, message {sequence[2]} bytes, "
                                f"checksum {sequence[3]}"
                            )
                        print(
                            f"[{elapsed()}] Rejected new anti-exfil symbol ({detail}); "
                            "it is duplicate, inconsistent, or malformed",
                            file=sys.stderr,
                            flush=True,
                        )
                if accumulator.is_complete:
                    if protocol_v1:
                        candidate_package = ProtocolV1Package.decode(accumulator.payload)
                        candidate_message = candidate_package.message
                    else:
                        candidate_package = TransportPackage.decode(accumulator.payload)
                        candidate_message = decode_message(candidate_package.message)
                    stage_matches = (
                        expected_stage is None or candidate_message.stage == expected_stage
                    )
                    network_matches = (
                        expected_network is None
                        or candidate_package.network == expected_network
                    )
                    if stage_matches and network_matches:
                        selected_accumulator = accumulator
                        selected_package = candidate_package
                        selected_message = candidate_message
                        break
                    ignored_candidates.add(candidate_key)
                    del accumulators[candidate_key]
                    print(
                        f"[{elapsed()}] Complete anti-exfil package ignored: "
                        f"stage {candidate_message.stage.name}, "
                        f"network {candidate_package.network.name}",
                        file=sys.stderr,
                        flush=True,
                    )
            elif kind == "STATUS":
                captured, decoded, emitted = (int(value) for value in values)
                leader = max(
                    accumulators.values(),
                    key=lambda candidate: candidate.progress,
                    default=None,
                )
                expected = leader.expected_parts if leader else None
                ratio = (
                    f"{leader.processed_parts}/{expected} source parts"
                    if expected
                    else "0/? anti-exfil parts"
                )
                print(
                    f"[{elapsed()}] Capture: {captured} camera frames sampled; "
                    f"{decoded} QR decodes; "
                    f"{emitted} changed symbols; {ratio}; "
                    f"{leader.progress:.0%} reconstructed; " if leader else "",
                    f"{accepted_frames} accepted; {rejected_frames} rejected; "
                    f"{len(seen_sequences)} unique sequences; "
                    f"{len(accumulators)} fountain candidates",
                    file=sys.stderr,
                    flush=True,
                )
        if selected_accumulator is None:
            code = process.wait(timeout=5)
            raise AntiExfilError(
                ErrorCode.INVALID_MESSAGE,
                f"camera scan ended after {elapsed()} before a complete anti-exfil QR "
                f"was received (bridge code {code})",
            )
    finally:
        _stop_bridge_process(process)

    encoded = selected_accumulator.payload
    package = selected_package
    message = selected_message
    if package is None or message is None:
        raise AntiExfilError(ErrorCode.STATE_INVALID, "selected camera package is missing")

    write_exact(output_path, encoded)
    if message_output_path is not None:
        encoded_message = (
            package.message.encode()
            if isinstance(package, ProtocolV1Package)
            else package.message
        )
        write_exact(message_output_path, encoded_message)
    if psbt_output_path is not None:
        if package.psbt is None:
            raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "received package contains no PSBT")
        write_exact(psbt_output_path, package.psbt)
    elapsed_seconds = time.monotonic() - started
    return {
        "status": "complete",
        "camera": opened[0] if opened else None,
        "resolution": f"{opened[1]}x{opened[2]}" if opened else None,
        "accepted_qr_symbols": accepted_frames,
        "rejected_qr_symbols": rejected_frames,
        "unique_sequences": len(seen_sequences),
        "expected_source_parts": selected_accumulator.expected_parts,
        "fountain_candidates": len(accumulators) + len(ignored_candidates),
        "elapsed": format_duration(elapsed_seconds),
        "elapsed_seconds": round(elapsed_seconds, 3),
        "stage": message.stage.name,
        "network": package.network.name,
        "package": str(output_path.resolve()),
        "message": str(message_output_path.resolve()) if message_output_path else None,
        "psbt": str(psbt_output_path.resolve()) if psbt_output_path else None,
    }
