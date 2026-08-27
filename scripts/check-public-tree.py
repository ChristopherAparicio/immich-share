#!/usr/bin/env python3
"""Fail when tracked files contain operator-specific network or secret data."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PATHS = [
    re.compile(
        r"(^|/)(?:config\.ini|api-key|private\.key|credentials\.json|"
        r"\.netrc|\.npmrc|id_rsa|id_ed25519|managed-shares\.json)$"
    ),
    re.compile(r"(^|/).*\.key$"),
    re.compile(r"(^|/)\.env(?:\.(?!example$).+)?$"),
    re.compile(r"(^|/).+\.(?:pem|p8|p12|pfx|secret|mobileconfig|age|kdbx)$"),
]
FORBIDDEN_CONTENT = {
    "RFC1918 address": re.compile(
        r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
        r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
    ),
    "carrier-grade NAT address": re.compile(
        r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2}\b"
    ),
    "absolute user home": re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+/"),
    "NAS volume path": re.compile(r"/volume\d+/"),
    "non-placeholder private key": re.compile(
        r"^(?:PrivateKey|PresharedKey)\s*=\s*(?!<)[^\s#]+", re.MULTILINE
    ),
    "private-key block": re.compile(r"BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY"),
}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


def main() -> int:
    failures: list[str] = []
    for path in tracked_files():
        relative = path.relative_to(ROOT).as_posix()
        if any(pattern.search(relative) for pattern in FORBIDDEN_PATHS):
            failures.append(f"{relative}: forbidden tracked secret filename")
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for label, pattern in FORBIDDEN_CONTENT.items():
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                failures.append(f"{relative}:{line}: {label}")

    if failures:
        print("Public-tree privacy check failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("Public-tree privacy check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
