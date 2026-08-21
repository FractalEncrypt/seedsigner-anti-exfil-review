"""Temporary host coordinator steps for the physical QR ceremony."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .errors import AntiExfilError, ErrorCode
from .messages import Stage, decode_message
from .qr_bitmap import extract_qr_frame, render_qr_frame
from .storage import load_state, read_bytes, write_exact
from .transport import (
    TransportNetwork,
    TransportPackage,
    encode_ur_frames,
)
from .workflow import host_reveal


def prepare_message_3(
    *,
    input_package_path: Path,
    session_dir: Path,
    output_dir: Path,
    seedsigner_src: Path,
    expected_network: TransportNetwork,
    fragment_size: int = 30,
    fountain_windows: int = 2,
    render_qr: bool = True,
) -> dict[str, object]:
    """Consume strict message 2 and prepare the host-reveal QR package."""

    incoming_bytes = read_bytes(input_package_path)
    incoming = TransportPackage.decode(incoming_bytes)
    incoming_message = decode_message(incoming.message)
    if incoming_message.stage != Stage.SIGNER_OPENINGS:
        raise AntiExfilError(
            ErrorCode.WRONG_STAGE,
            f"message-3 preparation requires SIGNER_OPENINGS, received {incoming_message.stage.name}",
        )
    if incoming.network != expected_network:
        raise AntiExfilError(
            ErrorCode.TRANSACTION_MISMATCH,
            f"expected {expected_network.name}, received {incoming.network.name}",
        )
    if incoming.psbt is not None:
        raise AntiExfilError(
            ErrorCode.UNEXPECTED_RETURN_DATA,
            "signer opening response unexpectedly returned a PSBT",
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    message_2_path = output_dir / "message-2.aex"
    message_3_path = output_dir / "message-3.aex"
    package_3_path = output_dir / "message-3.aext"
    frames_dir = output_dir / "message-3-frames"
    qr_dir = output_dir / "message-3-qr"
    write_exact(message_2_path, incoming.message)

    message_3 = host_reveal(
        session_dir=session_dir,
        input_path=message_2_path,
        output_path=message_3_path,
    )

    state = load_state(session_dir)
    original_psbt_path = session_dir / "original.psbt"
    original_psbt = read_bytes(original_psbt_path)
    expected_psbt_digest = state.get("psbt_sha256")
    actual_psbt_digest = hashlib.sha256(original_psbt).hexdigest()
    if not isinstance(expected_psbt_digest, str) or actual_psbt_digest != expected_psbt_digest:
        raise AntiExfilError(
            ErrorCode.TRANSACTION_MISMATCH,
            "stored original PSBT does not match the durable host session",
        )

    outgoing = TransportPackage(
        message=message_3.encode(),
        network=incoming.network,
        psbt=original_psbt,
    )
    outgoing_bytes = outgoing.encode()
    write_exact(package_3_path, outgoing_bytes)
    frames = encode_ur_frames(
        outgoing_bytes,
        seedsigner_src=seedsigner_src,
        max_fragment_len=fragment_size,
        fountain_windows=fountain_windows,
    )
    for index, frame in enumerate(frames, start=1):
        write_exact(
            frames_dir / f"frame-{index:04d}.txt",
            (frame + "\n").encode("ascii"),
        )
        if render_qr:
            image_path = qr_dir / f"frame-{index:04d}.png"
            render_qr_frame(frame, image_path, seedsigner_src=seedsigner_src)
            if extract_qr_frame(image_path, seedsigner_src=seedsigner_src) != frame:
                raise AntiExfilError(
                    ErrorCode.INVALID_MESSAGE,
                    f"message-3 QR bitmap round trip failed at frame {index}",
                )

    return {
        "status": "message-3-ready",
        "stage": message_3.stage.name,
        "network": incoming.network.name,
        "session_id": message_3.session_id.hex(),
        "message_2": str(message_2_path.resolve()),
        "message_3": str(message_3_path.resolve()),
        "package": str(package_3_path.resolve()),
        "frozen_psbt": str(original_psbt_path.resolve()),
        "psbt_sha256": actual_psbt_digest,
        "fragment_size": fragment_size,
        "animation_frames": len(frames),
        "qr_directory": str(qr_dir.resolve()) if render_qr else None,
        "next_device_action": "Scan message 3 in SeedSigner to begin Anti-Exfil Signing (2 of 2)",
    }
