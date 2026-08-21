"""QR preparation for any frozen protocol-v1 AEXT package."""

from __future__ import annotations

from pathlib import Path

from .errors import AntiExfilError, ErrorCode
from .protocol_v1_codec import Network, Stage
from .protocol_v1_transport import ProtocolV1Package
from .qr_bitmap import extract_qr_frame, render_qr_frame
from .storage import read_bytes, write_exact
from .transport import encode_ur_frames


def prepare_protocol_v1_qr(
    *,
    input_package_path: Path,
    output_dir: Path,
    seedsigner_src: Path,
    expected_stage: Stage | None = None,
    expected_network: Network | None = None,
    fragment_size: int = 30,
    fountain_windows: int = 2,
    render_qr: bool = True,
) -> dict[str, object]:
    """Validate one AEXT package and create retained UR text/PNG frames."""

    package = ProtocolV1Package.decode(read_bytes(input_package_path))
    message = package.message
    if expected_stage is not None and message.stage != expected_stage:
        raise AntiExfilError(
            ErrorCode.WRONG_STAGE,
            f"expected {expected_stage.name}, received {message.stage.name}",
        )
    if expected_network is not None and message.network != expected_network:
        raise AntiExfilError(
            ErrorCode.TRANSACTION_MISMATCH,
            f"expected {expected_network.name}, received {message.network.name}",
        )

    frames = encode_ur_frames(
        package.encode(),
        seedsigner_src=seedsigner_src,
        max_fragment_len=fragment_size,
        fountain_windows=fountain_windows,
    )
    frames_dir = output_dir / "frames"
    qr_dir = output_dir / "qr"
    for index, frame in enumerate(frames, start=1):
        write_exact(frames_dir / f"frame-{index:04d}.txt", (frame + "\n").encode("ascii"))
        if render_qr:
            image_path = qr_dir / f"frame-{index:04d}.png"
            render_qr_frame(frame, image_path, seedsigner_src=seedsigner_src)
            if extract_qr_frame(image_path, seedsigner_src=seedsigner_src) != frame:
                raise AntiExfilError(
                    ErrorCode.INVALID_MESSAGE,
                    f"QR bitmap round trip failed at frame {index}",
                )

    return {
        "status": "qr-ready",
        "stage": message.stage.name,
        "network": message.network.name,
        "session_id": message.session_id.hex(),
        "slot_count": len(message.slots),
        "package": str(input_package_path.resolve()),
        "psbt_included": package.psbt is not None,
        "fragment_size": fragment_size,
        "animation_frames": len(frames),
        "qr_directory": str(qr_dir.resolve()) if render_qr else None,
    }
