"""Headless QR bitmap adapter using SeedSigner's production QR dependencies."""

from __future__ import annotations

from pathlib import Path
import sys

from .errors import AntiExfilError, ErrorCode


def _load_qr_dependencies(seedsigner_src: Path):
    source = str(seedsigner_src.resolve())
    if source not in sys.path:
        sys.path.insert(0, source)
    try:
        from PIL import Image
        from seedsigner.helpers.qr import QR
        from seedsigner.models.decode_qr import DecodeQR
    except ImportError as exc:
        raise AntiExfilError(
            ErrorCode.STATE_INVALID,
            f"cannot import SeedSigner QR dependencies: {exc}",
        ) from exc
    return Image, QR, DecodeQR


def render_qr_frame(
    frame: str,
    output_path: Path,
    *,
    seedsigner_src: Path,
    size: int = 240,
) -> None:
    """Render one UR text frame with the same QR helper used by SeedSigner."""

    if size < 160 or size > 1024:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, "QR image size is out of range")
    _, QR, _ = _load_qr_dependencies(seedsigner_src)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    image = QR().qrimage(
        frame,
        width=size,
        height=size,
        border=3,
        background_color="white",
    )
    image.save(output_path, format="PNG")


def extract_qr_frame(image_path: Path, *, seedsigner_src: Path) -> str:
    """Decode one QR bitmap through SeedSigner's pyzbar extraction path."""

    Image, _, DecodeQR = _load_qr_dependencies(seedsigner_src)
    try:
        with Image.open(image_path) as image:
            data = DecodeQR.extract_qr_data(image.convert("RGB"), is_binary=True)
    except OSError as exc:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, f"cannot read QR image {image_path}: {exc}"
        ) from exc
    if data is None:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, f"QR image could not be decoded: {image_path}"
        )
    try:
        return data.decode("ascii") if isinstance(data, bytes) else str(data)
    except UnicodeDecodeError as exc:
        raise AntiExfilError(
            ErrorCode.INVALID_MESSAGE, "QR image did not contain ASCII UR text"
        ) from exc

