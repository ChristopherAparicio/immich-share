#!/usr/bin/env python3
"""Render a fake share into Caddyfile for syntax validation on stdout."""

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


snippet = module.render_share_snippet(
    TestEdge(),
    "redaction_test_key_1234",
    "CI syntax test",
    "2026-08-28T00:00:00Z",
)
caddyfile = (ROOT / "vps" / "Caddyfile").read_text()
print(caddyfile.replace("\timport /etc/caddy/shares.d/*.caddy", snippet))
