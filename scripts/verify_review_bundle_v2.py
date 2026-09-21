#!/usr/bin/env python3
import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    parser.add_argument(
        "--repo",
        type=Path,
        help="optional exact Git repository used to verify every payload against its committed blob",
    )
    args = parser.parse_args()
    failures = []
    with zipfile.ZipFile(args.archive, "r") as archive:
        bad_crc = archive.testzip()
        if bad_crc:
            failures.append(f"CRC failure: {bad_crc}")
        names = archive.namelist()
        if len(names) != len(set(names)):
            failures.append("duplicate ZIP entry")
        if names[-2:] != ["BUNDLE-METADATA.json", "SHA256SUMS.txt"]:
            failures.append("metadata/manifest entry ordering mismatch")
        metadata = json.loads(archive.read("BUNDLE-METADATA.json"))
        expected = {}
        for line in archive.read("SHA256SUMS.txt").decode("utf-8").splitlines():
            digest, name = line.split("  ", 1)
            expected[name] = digest
        payload_names = names[:-2]
        if payload_names != sorted(payload_names):
            failures.append("payload entries are not sorted")
        if set(expected) != set(payload_names):
            failures.append("manifest/payload entry set mismatch")
        for name, digest in expected.items():
            actual = sha256(archive.read(name))
            if actual != digest:
                failures.append(f"hash mismatch: {name}")
        if metadata.get("dirty_candidate") is not False:
            failures.append("bundle metadata is not clean")
        if metadata.get("payload_file_count") != len(payload_names):
            failures.append("payload count mismatch")
        git_payloads_verified = None
        if args.repo is not None:
            repo = args.repo.resolve()
            commit = metadata.get("source_commit")
            tree = metadata.get("source_tree")
            try:
                actual_commit = subprocess.check_output(
                    ["git", "rev-parse", f"{commit}^{{commit}}"], cwd=repo, text=True
                ).strip()
                actual_tree = subprocess.check_output(
                    ["git", "rev-parse", f"{commit}^{{tree}}"], cwd=repo, text=True
                ).strip()
            except (OSError, subprocess.CalledProcessError) as exc:
                failures.append(f"Git identity lookup failed: {exc}")
                actual_commit = actual_tree = None
            if actual_commit != commit:
                failures.append("Git source commit mismatch")
            if actual_tree != tree:
                failures.append("Git source tree mismatch")
            verified = 0
            for name in payload_names:
                try:
                    blob = subprocess.check_output(
                        ["git", "show", f"{commit}:{name}"], cwd=repo
                    )
                except (OSError, subprocess.CalledProcessError) as exc:
                    failures.append(f"Git blob lookup failed: {name}: {exc}")
                    continue
                if archive.read(name) != blob:
                    failures.append(f"Git blob mismatch: {name}")
                else:
                    verified += 1
            git_payloads_verified = verified
    print(json.dumps({
        "archive_sha256": sha256(open(args.archive, "rb").read()),
        "entries": len(names),
        "payloads_verified": len(expected),
        "source_commit": metadata.get("source_commit"),
        "source_tree": metadata.get("source_tree"),
        "git_payloads_verified": git_payloads_verified,
        "failures": failures,
    }, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
