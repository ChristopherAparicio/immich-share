#!/usr/bin/env python3
"""Render fake shares into the Caddyfile for syntax validation on stdout.

`--shares N` renders N distinct share snippets so that `caddy validate` (and
`caddy adapt`) exercise the route set at the scale of a busy portal, not only
the single-share case.
"""

import argparse
import importlib.machinery
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader(
    "immich_share_cli", str(ROOT / "immich-share")
)
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


class TestEdge:
    upstream = "ipp:3000"
    download_upstream = "download-guard:8080"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--shares", type=int, default=1, help="number of fake shares")
    args = parser.parse_args()
    if args.shares < 1:
        parser.error("--shares must be at least 1")

    snippets = [module.GLOBALS_SNIPPET.format(upstream=TestEdge.upstream)]
    for index in range(args.shares):
        key = "redaction_test_key_1234" if index == 0 else f"ci_share_key_{index:04d}"
        snippets.append(
            module.render_share_snippet(
                TestEdge(), key, f"CI syntax test {index}", "2026-08-28T00:00:00Z"
            )
        )
    drop_snippet = (ROOT / "vps" / "drop-portal.caddy.template").read_text()
    caddyfile = (ROOT / "vps" / "Caddyfile").read_text()
    print(
        caddyfile.replace("\timport /etc/caddy/shares.d/*.caddy", "\n".join(snippets))
        .replace("\timport /etc/caddy/drops.d/*.caddy", drop_snippet)
    )


if __name__ == "__main__":
    main()
