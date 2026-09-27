"""Build the deterministic, sanitized anti-exfil v2 review candidate."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)

EXACT_FILES = [
    "LICENSE",
    "README.md",
    "REVIEW-SCOPE.md",
    "SECURITY.md",
    "V2-CANDIDATE.md",
    "repositories.json",
    "pyproject.toml",
    "docs/m8-campaign-closure-summary.md",
    "docs/m9-hardening-closure.md",
    "docs/post-m9-kern-ci-formatting-accepted-update.md",
    "docs/m9-integration-candidate.md",
    "docs/m9-evidence-bindings.json",
    "docs/reviewer-build-and-test-runbook.md",
    "docs/interoperability-reproduction-checklist.md",
    "docs/p4-publication-boundary.md",
    "docs/review-bundle-manifest.md",
    "docs/maintainer-specification.md",
    "docs/protocol-v1.md",
    "docs/protocol-v1-wire-format.md",
    "docs/transport-aext.md",
    "docs/threat-model.md",
    "docs/maintainer-decisions-requested.md",
    "docs/security-review-findings.md",
    "docs/review-rounds-summary.md",
    "fixtures/protocol-v1-multislot-vectors.json",
    "fixtures/protocol-v1-mixed-provenance-vector.json",
    "fixtures/protocol-v1-mixed-provenance.psbt",
    "fixtures/protocol-v1-negative-vectors.json",
    "fixtures/protocol-v1-semantic-psbt-vector.json",
    "fixtures/transport-v1-vectors.json",
    "scripts/generate_protocol_v1_vectors.py",
    "scripts/generate_protocol_v1_semantic_vectors.py",
    "scripts/generate_protocol_v1_negative_vectors.py",
    "scripts/build_review_bundle_v2.py",
    "scripts/verify_review_bundle_v2.py",
    "scripts/scan_publication_candidate.py",
]

TREE_ROOTS = ["src/anti_exfil", "tests/reference"]


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, text=True, encoding="utf-8"
    ).strip()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_bytes(relative: str) -> bytes:
    """Read the exact blob bytes from HEAD, independent of checkout filters."""
    return subprocess.check_output(["git", "show", f"HEAD:{relative}"], cwd=ROOT)


def selected_files() -> list[str]:
    files: set[str] = set()
    for relative in EXACT_FILES:
        subprocess.check_call(
            ["git", "cat-file", "-e", f"HEAD:{relative}"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        files.add(relative)
    for relative in TREE_ROOTS:
        names = git("ls-tree", "-r", "--name-only", "HEAD", "--", relative)
        if not names:
            raise FileNotFoundError(relative)
        for name in names.splitlines():
            path = PurePosixPath(name)
            if "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}:
                files.add(path.as_posix())
    return sorted(files)


def write_entry(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    dirty = git("status", "--porcelain")
    if dirty:
        raise SystemExit("Refusing to freeze a dirty review-hub worktree")

    payloads = {
        relative: git_bytes(relative)
        for relative in selected_files()
    }
    sums = "".join(
        f"{sha256(data)}  {name}\n" for name, data in payloads.items()
    ).encode("utf-8")
    metadata = json.dumps(
        {
            "bundle": "SeedSigner anti-exfil review hub v2 candidate",
            "protocol_status": "experimental; testnet/public-test only; not a production audit",
            "source_commit": git("rev-parse", "HEAD^{commit}"),
            "source_tree": git("rev-parse", "HEAD^{tree}"),
            "source_commit_time": git("show", "-s", "--format=%cI", "HEAD"),
            "dirty_candidate": False,
            "payload_source": "exact Git blob bytes from source_commit",
            "payloads_match_source_blobs": True,
            "payload_file_count": len(payloads),
            "hash_manifest": "SHA256SUMS.txt",
            "publication_authorized": False,
        },
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"

    archive_payloads = {
        **payloads,
        "BUNDLE-METADATA.json": metadata,
        "SHA256SUMS.txt": sums,
    }
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in archive_payloads.items():
            write_entry(archive, name, data)

    with zipfile.ZipFile(output, "r") as archive:
        if archive.testzip() is not None or archive.namelist() != list(archive_payloads):
            raise RuntimeError("archive CRC, entry set, or ordering verification failed")
        for name, expected in archive_payloads.items():
            if archive.read(name) != expected:
                raise RuntimeError(f"archive payload mismatch: {name}")

    outer = sha256(output.read_bytes())
    sidecar = output.with_suffix(output.suffix + ".sha256")
    sidecar.write_text(f"{outer}  {output.name}\n", encoding="ascii")
    print(json.dumps({
        "path": str(output),
        "bytes": output.stat().st_size,
        "sha256": outer,
        "entries": len(archive_payloads),
        "source_commit": git("rev-parse", "HEAD^{commit}"),
        "source_tree": git("rev-parse", "HEAD^{tree}"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
