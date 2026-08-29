#!/usr/bin/env python3
"""Static regression checks for the optional upload trust boundary."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise AssertionError(f"{label}: missing {needle!r}")


def log_format(text: str, name: str) -> str:
    marker = f"log_format {name}"
    start = text.index(marker)
    end = text.index(";", start)
    return text[start : end + 1]


nas_filter = read("nas/upload-filter.conf")
edge_filter = read("vps/upload-guard.conf.template")
caddy = read("vps/Caddyfile")
drop_snippet = read("vps/drop-portal.caddy.template")
nas_base = read("nas/docker-compose.yml")
nas_upload = read("nas/docker-compose.upload.yml")
nas_doctor = read("nas/upload-security-doctor.sh")
wireguard_entrypoint = read("nas/wireguard-entrypoint.sh")
vps_base = read("vps/docker-compose.yml")
vps_upload = read("vps/docker-compose.upload.yml")
setup = read("SETUP.md")
upload_wireguard = nas_upload.split("  upload-wireguard:", 1)[1].split("\n  upload-drop:", 1)[0]
upload_app = nas_upload.split("  upload-drop:", 1)[1].split("\n  upload-filter:", 1)[0]

contract = [
    "/drop/i/",
    "/drop/api/invites/",
    "/unlock",
    "/policy",
    "/uploads",
    "HEAD:/drop/api/uploads/",
    "PATCH:/drop/api/uploads/",
    "DELETE:/drop/api/uploads/",
]
for item in contract:
    require(nas_filter, item, "NAS allowlist")
    require(edge_filter, item, "VPS allowlist")

for asset in ("app.js", "drop.css", "favicon.png"):
    require(nas_filter, asset.replace(".", r"\."), "NAS asset allowlist")
    require(edge_filter, asset.replace(".", r"\."), "VPS asset allowlist")
    require(drop_snippet, f"/drop/assets/{asset}", "Caddy drop snippet")

for forbidden in ("/healthz", "/admin", "/api/admin", "/drop/static/"):
    if forbidden in nas_filter or forbidden in edge_filter:
        raise AssertionError(f"public filter unexpectedly exposes {forbidden}")

if "blob:" in drop_snippet:
    raise AssertionError("Caddy CSP grants unnecessary blob URL access")

for rendered in (
    log_format(nas_filter, "drop_route"),
    log_format(edge_filter, "upload_guard"),
):
    if re.search(r"\$(?:request_uri|request|uri)(?![A-Za-z0-9_])", rendered):
        raise AssertionError("upload log format contains a credential-bearing target")

for guarded in (nas_filter, edge_filter):
    require(guarded, "client_max_body_size 4k;", "small JSON body ceiling")
    require(guarded, "client_max_body_size ${UPLOAD_", "chunk body ceiling")
    require(guarded, "proxy_request_buffering off;", "streaming upload proxy")
require(drop_snippet, "max_size 4KB", "Caddy JSON body ceiling")
require(drop_snippet, "max_size 9MB", "Caddy chunk body ceiling")

require(caddy, "import /etc/caddy/drops.d/*.caddy", "closed Caddy import")
require(caddy, "request>uri replace REDACTED", "Caddy URI redaction")
if "upload-drop:" in nas_base or "upload-guard:" in vps_base:
    raise AssertionError("optional write services leaked into a base Compose file")

for needle in (
    "UPLOAD_DROP_IMAGE:?set UPLOAD_DROP_IMAGE",
    'user: "65532:65532"',
    "INCOMING_ROOT: /incoming",
    "STATE_DB: /data/state.db",
    "SESSION_SECRET_FILE: /run/secrets/session-secret",
    "DEFAULT_MAX_FILE_BYTES: ${UPLOAD_DROP_DEFAULT_MAX_FILE_BYTES:-536870912}",
    "DEFAULT_QUOTA_BYTES: ${UPLOAD_DROP_DEFAULT_QUOTA_BYTES:-1073741824}",
    "UPLOAD_CHUNK_TIMEOUT_SECONDS: ${UPLOAD_DROP_CHUNK_TIMEOUT_SECONDS:-180}",
    "SWEEP_INTERVAL_SECONDS: ${UPLOAD_DROP_SWEEP_INTERVAL_SECONDS:-300}",
    "SESSION_MAX_AGE_SECONDS: ${UPLOAD_DROP_SESSION_MAX_AGE_SECONDS:-43200}",
    "MAX_ACTIVE_UNLOCKS: ${UPLOAD_DROP_MAX_ACTIVE_UNLOCKS:-2}",
    'COOKIE_SECURE: "true"',
    "source: ${UPLOAD_DROP_SESSION_SECRET_FILE:?",
    "name: ${IMMICH_DROP_DOCKER_NETWORK:-immich_drop}",
):
    require(nas_upload, needle, "NAS upload Compose")

for network in ("immich_drop_net", "upload_egress_net"):
    require(upload_wireguard, f"- {network}", "upload WireGuard networks")
if "upload_egress_net" in upload_app:
    raise AssertionError("upload application has direct egress")
for needle in ('WG_OUTPUT_LOCKDOWN: "true"', "WG_INTERNAL_UPSTREAM_HOST: upload-drop",
               'WG_INTERNAL_UPSTREAM_PORT: "8080"', 'WG_LOCAL_PROXY_PORT: "18080"'):
    require(upload_wireguard, needle, "upload WireGuard lockdown")
for needle in ("iptables -P OUTPUT DROP", 'WG_INTERNAL_UPSTREAM_HOST:?',
               'WG_INTERNAL_UPSTREAM_PORT:?', 'WG_LOCAL_PROXY_PORT:?',
               'socat "TCP-LISTEN:', "iptables -D OUTPUT",
               "iptables -R OUTPUT 1 -o lo -d 127.0.0.1/32 -j ACCEPT"):
    require(wireguard_entrypoint, needle, "WireGuard output policy")
require(nas_upload, "DROP_UPSTREAM: 127.0.0.1:18080", "upload loopback relay")
require(nas_base, "IMMICH_UPSTREAM: 127.0.0.1:18080", "share loopback relay")
if "SETUID" in upload_wireguard or "SETGID" in upload_wireguard:
    raise AssertionError("upload WireGuard retains unnecessary identity capabilities")
require(setup, "docker network create --internal immich_drop", "upload network setup")

for forbidden in ("immich_share_net", "immich_server", "x-api-key", "api_key"):
    if forbidden in nas_upload.lower():
        raise AssertionError(f"NAS upload Compose crosses trust boundary: {forbidden}")

require(vps_upload, "upload-guard:", "VPS upload Compose")
if "ports:" in vps_upload or "UPLOAD_DROP_IMAGE" in vps_upload:
    raise AssertionError("VPS upload guard publishes a port or carries app credentials")

for needle in ("source_mode", 'source_owner', '[ "$source_mode" = 700 ]',
               '[ "$secret_mode" = 400 ]', "wg_config_source", "{{.Internal}}",
               "egress_members", "admin_helper", "upload administration helper",
               "-P OUTPUT DROP", "unexpected LAN or Internet egress",
               "certify_output_allowlist", "unexpected output allow rule",
               "-A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT",
               "expected_upstream_ip"):
    require(nas_doctor, needle, "NAS upload doctor")

print("Upload deployment boundary checks passed.")
