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
share_doctor = read("nas/security-doctor.sh")
preflight = read("nas/controller/doctor-preflight.sh")
egress_test = read("scripts/test-wireguard-egress-lockdown.sh")
wireguard_entrypoint = read("nas/wireguard-entrypoint.sh")
vps_base = read("vps/docker-compose.yml")
vps_upload = read("vps/docker-compose.upload.yml")
setup = read("SETUP.md")
vps_wireguard = read("vps/wireguard/wg0-vps.conf")
containment_script = read("vps/containment/immich-share-containment.sh")
containment_unit = read("vps/containment/immich-share-containment.service")
upload_wireguard = nas_upload.split("  upload-wireguard:", 1)[1].split("\n  upload-drop:", 1)[0]
upload_app = nas_upload.split("  upload-drop:", 1)[1].split("\n  upload-filter:", 1)[0]
share_wireguard = nas_base.split("  nginx-filter:", 1)[0]

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
    "UPLOAD_WORK_MULTIPLIER: ${UPLOAD_DROP_WORK_MULTIPLIER:-3}",
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
               "iptables -R OUTPUT 1 -o lo -d 127.0.0.1/32 -j ACCEPT",
               # Fail-closed default: only an explicit "false" disables lockdown.
               '${WG_OUTPUT_LOCKDOWN:-true}', "false) return 0 ;;",
               # Relay readiness and supervision.
               'until nc -z -w 1 127.0.0.1 "$local_proxy_port"',
               'wait "$proxy_pid" || relay_status=$?',
               "Internal upstream relay exited",
               # IPv6 is failed closed with ip6tables (no dependency on the
               # /proc sysctl, which is absent on IPv6-less kernels) and the
               # single opt-in controller SSH accept.
               "ip6tables -P OUTPUT DROP", "ip6tables -P FORWARD DROP",
               "Protocol not supported",
               'iptables -A OUTPUT -d "$controller_ssh_peer/32" -p tcp --dport 22 -j ACCEPT'):
    require(wireguard_entrypoint, needle, "WireGuard output policy")
if 'cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" != 1' in wireguard_entrypoint:
    raise AssertionError("WireGuard entrypoint must not fail on the IPv6 sysctl")
if wireguard_entrypoint.count("iptables -A OUTPUT -d \"$controller_ssh_peer/32\"") != 1:
    raise AssertionError("controller SSH opt-in must add exactly one rule")
if "WG_OUTPUT_LOCKDOWN:-false" in wireguard_entrypoint:
    raise AssertionError("WireGuard output lockdown must default to enabled")
# The OUTPUT allowlist is IPv4 iptables only. IPv6 is failed closed with an
# ip6tables policy inside the namespace; neither Compose file may set the IPv6
# sysctls (runc refuses to start the container when /proc/sys/net/ipv6 is
# absent) and neither doctor may depend on that /proc path.
for section, label in ((share_wireguard, "share WireGuard"), (upload_wireguard, "upload WireGuard")):
    if "disable_ipv6=1" in section:
        raise AssertionError(f"{label} sets an IPv6 sysctl that breaks IPv6-less kernels")
    require(section, "- net.ipv4.ip_forward=0", f"{label} forwarding")
for doctor, label in ((nas_doctor, "NAS upload doctor"), (share_doctor, "NAS share doctor")):
    require(doctor, "ip6tables -S OUTPUT", f"{label} IPv6 policy read")
    require(doctor, "= '-P OUTPUT DROP' ]", f"{label} IPv6 policy assertion")
    require(doctor, "Protocol not supported", f"{label} IPv6-less kernel tolerance")
    if "/proc/sys/net/ipv6" in doctor.replace("consult /proc/sys/net/ipv6", ""):
        raise AssertionError(f"{label} depends on the IPv6 sysctl path")
    require(doctor, "PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"{label} pinned PATH")
    require(doctor, "WG_CONTROLLER_SSH_PEER=", f"{label} controller SSH opt-in")
    require(doctor, "{{.HostConfig.Privileged}}", f"{label} privileged check")
    require(doctor, '\\[\\"no-new-privileges:true\\"\\]', f"{label} exact security options")
    if "*no-new-privileges*" in doctor:
        raise AssertionError(f"{label} accepts unconfined security options by substring match")
# The upload doctor never tolerates the controller SSH opt-in; the share doctor
# takes the expected peer only from the root-owned doctor file, never from the
# container it certifies.
require(nas_doctor, '[ -z "$controller_ssh_peer" ] || fail "upload tunnel must not carry WG_CONTROLLER_SSH_PEER"',
        "NAS upload doctor controller SSH rejection")
require(nas_doctor, "expected_rule_count=4", "NAS upload doctor fixed rule count")
if "expected_rule_count=5" in nas_doctor or "--dport 22" in nas_doctor:
    raise AssertionError("NAS upload doctor tolerates a controller SSH accept")
require(share_doctor, "doctor_env=/etc/immich-share/doctor.env", "NAS share doctor expectation file")
require(share_doctor, '"-A OUTPUT -d $expected_ssh_peer/32 -p tcp -m tcp --dport 22 -j ACCEPT"',
        "NAS share doctor controller SSH rule")
require(share_doctor, "read_expected_controller_ssh_peer\n", "NAS share doctor expectation source")
if "$(read_expected_controller_ssh_peer)" in share_doctor:
    raise AssertionError("NAS share doctor reads the expectation in a subshell, so fail cannot terminate it")
require(share_doctor, '[ "$controller_ssh_peer" = "$expected_ssh_peer" ]', "NAS share doctor container/file match")
require(share_doctor, "stat -c '%u' \"$doctor_env\"", "NAS share doctor expectation file owner check")
if "-A OUTPUT -d $controller_ssh_peer/32" in share_doctor:
    raise AssertionError("NAS share doctor compares the rule to the container's own variable")
require(share_doctor, 'denied_log=/var/log/immich-share/denied.log', "NAS share doctor tripwire source")
require(share_doctor, 'readlink -f "$denied_log"', "NAS share doctor tripwire source resolution")
require(preflight, '\\[\\"NET_ADMIN\\",\\"DAC_READ_SEARCH\\"\\]', "preflight CapAdd expectation")
require(preflight, "WG_CONTROLLER_SSH_PEER", "preflight controller SSH opt-in")
require(preflight, "DOCTOR_ENV=/etc/immich-share/doctor.env", "preflight doctor expectation file")
require(preflight, '[ "$doctor_env_peer" = "$VPS_WG_ADDRESS" ]', "preflight doctor expectation match")
if "*no-new-privileges*" in preflight:
    raise AssertionError("preflight accepts unconfined security options by substring match")
if "disable_ipv6=1" in egress_test:
    raise AssertionError("egress test passes an IPv6 sysctl the Compose files no longer set")
require(egress_test, "ip6tables -S OUTPUT", "egress test IPv6 policy assertion")
require(egress_test, "-P OUTPUT DROP", "egress test IPv4 policy assertion")
if "WG_CONTROLLER_SSH_PEER" in upload_wireguard:
    raise AssertionError("the upload tunnel must never carry controller SSH")
require(nas_upload, "DROP_UPSTREAM: 127.0.0.1:18080", "upload loopback relay")
require(nas_base, "IMMICH_UPSTREAM: 127.0.0.1:18080", "share loopback relay")
if "SETUID" in upload_wireguard or "SETGID" in upload_wireguard:
    raise AssertionError("upload WireGuard retains unnecessary identity capabilities")
require(setup, "docker network create --internal immich_drop", "upload network setup")

# The VPS bridge containment must not ride on wg-quick's lifecycle: wg0.conf
# keeps only the wg0 -> wg0 relay drop, while the DOCKER-USER rules come from
# the containment oneshot, whose rule text the CLI doctor asserts over SSH.
if re.search(r"^Post(?:Up|Down)\s*=.*DOCKER-USER", vps_wireguard, re.MULTILINE):
    raise AssertionError("wg0-vps.conf must not install DOCKER-USER rules (restart would drop containment)")
require(vps_wireguard, "PostUp = iptables -I FORWARD 1 -i wg0 -o wg0 -j DROP", "wg0 relay drop")
require(vps_wireguard, "PostDown = iptables -D FORWARD -i wg0 -o wg0 -j DROP", "wg0 relay drop teardown")
require(containment_script, "set -eu", "containment script strict mode")
require(containment_script, "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "containment script pinned PATH")
require(containment_script, "env_file=${CONTAINMENT_ENV_FILE:-/srv/photo-share/.env}", "containment config source")
require(containment_script, 'tag=immich-share', "containment rule tag")
require(containment_script, '-m comment --comment "$tag"', "containment rules are tagged")
for needle in ('insert_rule -i "$read_bridge" -o wg0 -d "$NAS_WG_ADDRESS/32" -p tcp --dport "$read_port" -j ACCEPT',
               'insert_rule -i "$upload_bridge" -o wg0 -d "$UPLOAD_NAS_WG_ADDRESS/32" -p tcp --dport "$upload_port" -j ACCEPT',
               'insert_rule -i "$read_bridge" -j DROP', 'insert_rule -i "$upload_bridge" -j DROP',
               "read_bridge=immich-tunnel", "upload_bridge=immich-uptun", "read_port=2283", "upload_port=2383",
               "stage_tag=immich-share-stage", "install_stage_guards", "remove_stage_rules"):
    require(containment_script, needle, "containment rule set")
if containment_script.count('insert_rule -i "$upload_bridge" -j DROP') != 1 or "iptables -F" in containment_script:
    raise AssertionError("containment must drop immich-uptun unconditionally and never flush DOCKER-USER")
apply_body = containment_script.split("apply() {", 1)[1].split("\n}", 1)[0]
if not (apply_body.index("install_stage_guards") < apply_body.index("remove_owned_rules")
        < apply_body.index("insert_rule") < apply_body.index("remove_stage_rules")):
    raise AssertionError("containment updates must stay behind temporary fail-closed guards")
for needle in ("Type=oneshot", "RemainAfterExit=yes", "After=network-online.target docker.service",
               "PartOf=docker.service", "ExecStart=/usr/local/sbin/immich-share-containment.sh apply",
               "WantedBy=multi-user.target"):
    require(containment_unit, needle, "containment unit")
if "ExecStop=" in containment_unit:
    raise AssertionError("containment unit must not remove rules on stop")
for needle in ("systemctl enable --now immich-share-containment",
               "/usr/local/sbin/immich-share-containment.sh",
               "/etc/systemd/system/immich-share-containment.service"):
    require(setup, needle, "containment installation steps")

for forbidden in ("immich_share_net", "immich_server", "x-api-key", "api_key"):
    if forbidden in nas_upload.lower():
        raise AssertionError(f"NAS upload Compose crosses trust boundary: {forbidden}")

require(vps_upload, "upload-guard:", "VPS upload Compose")
if "ports:" in vps_upload or "UPLOAD_DROP_IMAGE" in vps_upload:
    raise AssertionError("VPS upload guard publishes a port or carries app credentials")

for needle in ("source_mode", 'source_owner', '[ "$source_mode" = 700 ]',
               '[ "$secret_mode" = 400 ]', "wg_config_source", "{{.Internal}}",
               "egress_members", "admin_helper", "upload administration helper",
               "/var/log/nginx/denied.log drop_route", "drop_log_format",
               "listen 127.0.0.1:2383", 'docker exec -i "$filter_container"',
               "certify_ipv6_closed",
               "-P OUTPUT DROP", "unexpected LAN or Internet egress",
               "certify_output_allowlist", "unexpected output allow rule",
               "-A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT",
               "expected_upstream_ip"):
    require(nas_doctor, needle, "NAS upload doctor")

for readonly_mount in ("/config/wg0.conf", "/run/secrets/session-secret"):
    template = (
        '{{range .Mounts}}{{if eq .Destination "' + readonly_mount
        + '"}}{{if not .RW}}{{.Source}}{{end}}{{end}}{{end}}'
    )
    require(nas_doctor, template, "NAS upload doctor read-only mount inspection")

# Everything after the relay probe runs inside the filter, which is stopped
# whenever no share is open. Both doctors must say so instead of reporting an
# unreachable relay.
if share_doctor.index("filter is stopped") > share_doctor.index("loopback relay is unreachable"):
    raise AssertionError("share doctor probes the relay before checking the filter is running")
if nas_doctor.index("upload filter is stopped") > nas_doctor.index("127.0.0.1 18080"):
    raise AssertionError("upload doctor probes the relay before checking the filter is running")

print("Upload deployment boundary checks passed.")
