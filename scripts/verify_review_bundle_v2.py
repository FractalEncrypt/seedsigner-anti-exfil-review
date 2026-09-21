#!/usr/bin/env python3
import argparse
import hashlib
import json
import zipfile


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
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
    print(json.dumps({
        "archive_sha256": sha256(open(args.archive, "rb").read()),
        "entries": len(names),
        "payloads_verified": len(expected),
        "source_commit": metadata.get("source_commit"),
        "source_tree": metadata.get("source_tree"),
        "failures": failures,
    }, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
