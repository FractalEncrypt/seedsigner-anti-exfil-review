"""Atomic file and host-state helpers for the terminal workflow."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .errors import AntiExfilError, ErrorCode


STATE_FILENAME = "state.json"


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AntiExfilError(ErrorCode.INVALID_MESSAGE, f"cannot read {path}: {exc}") from exc


def write_exact(path: Path, data: bytes) -> None:
    """Create a file atomically, or accept an identical existing file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            existing = path.read_bytes()
        except OSError as exc:
            raise AntiExfilError(ErrorCode.OUTPUT_EXISTS, f"cannot inspect {path}: {exc}") from exc
        if existing == data:
            return
        raise AntiExfilError(
            ErrorCode.OUTPUT_EXISTS,
            f"refusing to replace existing file with different content: {path}",
        )
    _atomic_replace(path, data)


def load_state(session_dir: Path) -> dict[str, Any]:
    state_path = session_dir / STATE_FILENAME
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AntiExfilError(
            ErrorCode.STATE_INVALID, f"cannot load host session state: {exc}"
        ) from exc
    if not isinstance(state, dict) or state.get("state_version") != 1:
        raise AntiExfilError(ErrorCode.STATE_INVALID, "unsupported host session state")
    return state


def save_state(session_dir: Path, state: dict[str, Any], *, create: bool = False) -> None:
    session_dir.mkdir(parents=True, exist_ok=True)
    state_path = session_dir / STATE_FILENAME
    if create and state_path.exists():
        raise AntiExfilError(
            ErrorCode.RETRY_CONFLICT, f"host session already exists: {session_dir}"
        )
    encoded = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_replace(state_path, encoded)


def _atomic_replace(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except Exception:
        try:
            temporary_path.unlink(missing_ok=True)
        finally:
            raise

