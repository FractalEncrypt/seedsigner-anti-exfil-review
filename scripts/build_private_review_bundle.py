"""Build a deterministic, minimal private anti-exfil review archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)

EXACT_FILES = [
    "LICENSE",
    "LICENSE.md",
    "README.md",
    "REVIEW-SCOPE.md",
    "SECURITY.md",
    "FROZEN-BUNDLE.md",
    "V12-CONTEXT.md",
    "repositories.json",
    "pyproject.toml",
    "docs/independent-security-review-brief.md",
    "docs/reviewer-build-and-test-runbook.md",
    "docs/maintainer-review-index.md",
    "docs/security-review-findings.md",
    "docs/maintainer-decisions-requested.md",
    "docs/maintainer-specification.md",
    "docs/protocol-v1.md",
    "docs/protocol-v1-wire-format.md",
    "docs/transport-aext.md",
    "docs/threat-model.md",
    "docs/shared-vector-index.md",
    "docs/physical-evidence-index.md",
    "docs/ux-proposal.md",
    "docs/review-bundle-manifest.md",
    "docs/review-rounds-summary.md",
    "docs/v12-audit-export.md",
    "docs/v12-findings-verification-plan.md",
    "docs/v12-gate1-implementation-review-brief.md",
    "docs/v12-gate2-abort-state-machine-design.md",
    "docs/v12-gate2-implementation-review-brief.md",
    "docs/v12-gate3-durable-bounds-design.md",
    "docs/v12-gate3-implementation-review-brief.md",
    "docs/v12-gate4-api-contracts-design.md",
    "docs/v12-gate4-implementation-review-brief.md",
    "docs/v12-gate5-trust-contracts-design.md",
    "docs/v12-gate5-implementation-review-brief.md",
    "docs/v12-remediation-checkpoint.json",
    "docs/drongo-review-series-checkpoint.json",
    "docs/sparrow-review-series-checkpoint.json",
    "docs/seedsigner-review-series-checkpoint.json",
    "docs/seedsigner-os-review-series-checkpoint.json",
    "docs/seedsigner-os-review-build-gate.md",
    "docs/repository-hygiene-publication-checkpoint.json",
    "docs/native-windows-checkpoint.json",
    "docs/protocol-v1-physical-checkpoint.json",
    "docs/protocol-v1-physical-rejection-checkpoint.json",
    "docs/protocol-v1-next-image-physical-checkpoint.json",
    "docs/seedsigner-os-integration-checkpoint.json",
    "docs/protocol-v1-funded-testnet4-checkpoint.json",
    "docs/sparrow-phase6-testnet4-checkpoint.json",
    "docs/sparrow-phase7-physical-negative-gates.md",
    "docs/sparrow-multislot-multisig-physical-checkpoint.json",
    "docs/sparrow-multislot-multisig-physical-checkpoint.md",
    "docs/sparrow-packaged-app-smoke-checkpoint.json",
    "docs/final-smoke-checkpoint.json",
    "docs/qr-brightness-correction-gate.md",
    "docs/p6-f1-implementation-review-brief.md",
    "docs/p6-f1-signature-provenance-physical-gate.md",
    "docs/assets/p6-f1-signer-b-standard-seedqr.png",
    "docs/r-f1-internal-sweep-smoke.md",
    "docs/r-f1-final-review-request.md",
    "docs/sparrow-xpub-import-smoke-test.md",
    "docs/seedsigner-direct-continuation-smoke-test.md",
    "fixtures/protocol-v1-multislot-vectors.json",
    "fixtures/protocol-v1-mixed-provenance-vector.json",
    "fixtures/protocol-v1-mixed-provenance.psbt",
    "fixtures/protocol-v1-negative-vectors.json",
    "fixtures/protocol-v1-semantic-psbt-vector.json",
    "fixtures/transport-v1-vectors.json",
    "scripts/generate_protocol_v1_vectors.py",
    "scripts/generate_protocol_v1_semantic_vectors.py",
    "scripts/generate_protocol_v1_negative_vectors.py",
    "scripts/build_private_review_bundle.py",
]

TREE_ROOTS = [
    "src/anti_exfil",
    "tests/reference",
    "docs/img/anti-exfil-checkpoints",
    "docs/assets/p6-f1-smoke",
    "docs/assets/r-f1-smoke",
]


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, text=True, encoding="utf-8"
    ).strip()


def selected_files() -> list[Path]:
    files: set[Path] = set()
    for relative in EXACT_FILES:
        path = ROOT / relative
        if path.is_file():
            files.add(path)
        elif relative not in {"LICENSE", "LICENSE.md"}:
            raise FileNotFoundError(relative)

    for relative in TREE_ROOTS:
        root = ROOT / relative
        if not root.is_dir():
            raise FileNotFoundError(relative)
        files.update(
            path
            for path in root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        )
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_entry(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def verify_archive(output: Path, payloads: dict[str, bytes]) -> None:
    with zipfile.ZipFile(output, "r") as archive:
        if archive.testzip() is not None:
            raise RuntimeError("ZIP CRC verification failed")
        if archive.namelist() != list(payloads):
            raise RuntimeError("Archive entry set or order mismatch")
        for name, expected in payloads.items():
            actual = archive.read(name)
            if sha256(actual) != sha256(expected):
                raise RuntimeError(f"Archive hash mismatch: {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "run" / "anti-exfil-private-review-bundle-v1.zip",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Build a non-final candidate even when the reference worktree is dirty.",
    )
    args = parser.parse_args()

    dirty = git("status", "--porcelain")
    if dirty and not args.allow_dirty:
        raise SystemExit(
            "Refusing to freeze a dirty reference worktree. Commit the reviewed "
            "documentation and rerun, or use --allow-dirty for a candidate only."
        )

    files = selected_files()
    payloads = {
        path.relative_to(ROOT).as_posix(): path.read_bytes() for path in files
    }
    sums = "".join(
        f"{sha256(data)}  {name}\n" for name, data in payloads.items()
    ).encode("utf-8")
    metadata = json.dumps(
        {
            "bundle": "AEXB-v1-multislot independent review",
            "protocol_status": "reviewed experimental prototype; not a production audit",
            "reference_commit": git("rev-parse", "HEAD"),
            "reference_commit_time": git("show", "-s", "--format=%cI", "HEAD"),
            "dirty_candidate": bool(dirty),
            "file_count": len(payloads),
            "hash_manifest": "SHA256SUMS.txt",
        },
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"

    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    archive_payloads = {
        **payloads,
        "BUNDLE-METADATA.json": metadata,
        "SHA256SUMS.txt": sums,
    }
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in archive_payloads.items():
            write_entry(archive, name, data)

    verify_archive(output, archive_payloads)
    outer_hash = sha256(output.read_bytes())
    sidecar = output.with_suffix(output.suffix + ".sha256")
    sidecar.write_text(f"{outer_hash}  {output.name}\n", encoding="ascii")

    print(json.dumps({
        "status": "candidate" if dirty else "frozen",
        "path": str(output),
        "bytes": output.stat().st_size,
        "sha256": outer_hash,
        "sha256_sidecar": str(sidecar),
        "files": len(archive_payloads),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
