#!/usr/bin/env python3
"""Fail closed on private-path, secret-key, generated-state, or size hazards."""
import argparse
import json
import re
import zipfile

TEXT_SUFFIXES = {".md", ".json", ".py", ".toml", ".txt", ".sh", ".yml", ".yaml"}
PATTERNS = {
    "windows_user_path": re.compile(rb"[A-Za-z]:[\\/]Users[\\/][^\\/\s`]+[\\/]", re.I),
    "posix_home_path": re.compile(rb"/(?:home|Users)/[^/\s`]+/", re.I),
    "private_key_pem": re.compile(rb"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY", re.I),
    "campaign_workspace": re.compile(rb"SeedSigner_AntiExfil[\\/]run[\\/]m[89]", re.I),
}
FORBIDDEN_NAMES = re.compile(
    r"(?:^|/)(?:wallets?|profiles?|build|dist|\.gradle|\.venv|__pycache__|sim_data)(?:/|$)|"
    r"\.(?:mv\.db|sqlite|keystore|pem|aexs|aexj|log)$",
    re.I,
)
MAX_ENTRY = 8 * 1024 * 1024


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    args = parser.parse_args()
    findings = []
    with zipfile.ZipFile(args.archive, "r") as archive:
        for info in archive.infolist():
            name = info.filename
            if info.file_size > MAX_ENTRY:
                findings.append({"type": "oversized_entry", "path": name, "bytes": info.file_size})
            if FORBIDDEN_NAMES.search(name):
                findings.append({"type": "forbidden_generated_or_state_path", "path": name})
            suffix = "." + name.rsplit(".", 1)[1].lower() if "." in name else ""
            if suffix in TEXT_SUFFIXES:
                data = archive.read(name)
                for label, pattern in PATTERNS.items():
                    if pattern.search(data):
                        findings.append({"type": label, "path": name})
    print(json.dumps({"archive": args.archive, "findings": findings, "finding_count": len(findings)}, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
