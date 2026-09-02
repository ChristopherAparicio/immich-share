#!/bin/sh
# Read-only NAS-controller prerequisites. This script creates no keys, changes
# no containers, and does not require an Immich API key.
set -eu

WG_CONTAINER=${WG_CONTAINER:-wg-tunnel}
FILTER_CONTAINER=${FILTER_CONTAINER:-wg-nginx-filter}
LOGROTATE_CONTAINER=${LOGROTATE_CONTAINER:-immich-share-logrotate}
IMMICH_CONTAINER=${IMMICH_CONTAINER:-immich_server}
IMMICH_SHARE_NETWORK=${IMMICH_SHARE_NETWORK:-immich_share}
VPS_WG_ADDRESS=${VPS_WG_ADDRESS:-}
IMMICH_URL=${IMMICH_URL:-http://127.0.0.1:2283}
# Fixed path read by the root-owned security doctor; it must name the same peer.
DOCTOR_ENV=/etc/immich-share/doctor.env

ok() { printf '  ✓ %s\n' "$1"; }
fail() { printf '  ✗ %s\n' "$1" >&2; exit 1; }

[ -n "$VPS_WG_ADDRESS" ] || fail "VPS_WG_ADDRESS must be set in the private operator environment"

command -v python3 >/dev/null 2>&1 || fail "Python 3 is not installed"
command -v ssh >/dev/null 2>&1 || fail "OpenSSH client is not installed"
command -v docker >/dev/null 2>&1 || fail "Docker CLI is not installed"
docker info >/dev/null 2>&1 || fail "the current user cannot access Docker"
ok "Python, SSH, and Docker are available"

running=$(docker inspect --format '{{.State.Running}}' "$WG_CONTAINER" 2>/dev/null || true)
[ "$running" = true ] || fail "$WG_CONTAINER is not running"
ok "$WG_CONTAINER is running"

forwarding=$(docker exec "$WG_CONTAINER" sysctl -n net.ipv4.ip_forward 2>/dev/null || true)
[ "$forwarding" = 0 ] || fail "$WG_CONTAINER has net.ipv4.ip_forward=$forwarding; expected 0"
ok "tunnel forwarding is disabled"

# Security options are compared as the exact JSON list so seccomp=unconfined or
# no-new-privileges:false cannot pass a substring match; privileged is refused.
wg_hardening=$(docker inspect --format \
  '{{.HostConfig.Privileged}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
  "$WG_CONTAINER" 2>/dev/null || true)
case "$wg_hardening" in
  false\|true\|\[\"ALL\"\]\|\[\"NET_ADMIN\",\"DAC_READ_SEARCH\"\]\|\[\"no-new-privileges:true\"\])
    ok "$WG_CONTAINER is unprivileged, read-only, with NET_ADMIN and DAC_READ_SEARCH only"
    ;;
  *) fail "$WG_CONTAINER hardening is incomplete" ;;
esac

members=$(docker network inspect --format \
  '{{range .Containers}}{{println .Name}}{{end}}' \
  "$IMMICH_SHARE_NETWORK" 2>/dev/null | sed '/^$/d' | sort || true)
expected_members=$(printf '%s\n%s\n' "$IMMICH_CONTAINER" "$WG_CONTAINER" | sort)
[ "$members" = "$expected_members" ] \
  || fail "$IMMICH_SHARE_NETWORK members are not exactly $IMMICH_CONTAINER and $WG_CONTAINER"
ok "$IMMICH_SHARE_NETWORK contains only Immich and the tunnel"

# The tunnel namespace is OUTPUT-DROP with a four-rule allowlist. Controller SSH
# through `docker exec wg-tunnel nc` opens a new TCP connection to the VPS
# WireGuard address, which is dropped unless the container was started with the
# explicit WG_CONTROLLER_SSH_PEER opt-in naming exactly that address.
controller_ssh_peer=$(docker inspect --format \
  '{{range .Config.Env}}{{println .}}{{end}}' "$WG_CONTAINER" 2>/dev/null \
  | sed -n 's/^WG_CONTROLLER_SSH_PEER=//p' | head -1)
[ -n "$controller_ssh_peer" ] \
  || fail "$WG_CONTAINER has no WG_CONTROLLER_SSH_PEER opt-in; its OUTPUT allowlist drops controller SSH"
[ "$controller_ssh_peer" = "$VPS_WG_ADDRESS" ] \
  || fail "$WG_CONTAINER WG_CONTROLLER_SSH_PEER does not match VPS_WG_ADDRESS"
ok "$WG_CONTAINER carries the controller SSH opt-in for the VPS WireGuard address"

# The security doctor takes its expected SSH peer from the root-owned doctor
# file (mode 0600), never from the container. It must exist and name the same
# address, or `doctor` will refuse the fifth OUTPUT accept. The file is only
# readable by root; fall back to a non-interactive sudo read when needed.
if [ -r "$DOCTOR_ENV" ]; then
  doctor_env_content=$(cat "$DOCTOR_ENV")
elif ! doctor_env_content=$(sudo -n cat "$DOCTOR_ENV" 2>/dev/null); then
  fail "$DOCTOR_ENV is missing or unreadable; create it root-owned mode 0600 (see README) or rerun with sudo"
fi
doctor_env_peer=$(printf '%s\n' "$doctor_env_content" \
  | sed -n 's/^WG_CONTROLLER_SSH_PEER=//p' | head -1)
[ "$doctor_env_peer" = "$VPS_WG_ADDRESS" ] \
  || fail "$DOCTOR_ENV WG_CONTROLLER_SSH_PEER does not match VPS_WG_ADDRESS"
ok "root-owned doctor expectation names the VPS WireGuard address"

docker exec "$WG_CONTAINER" nc -z -w 3 "$VPS_WG_ADDRESS" 22 >/dev/null 2>&1 \
  || fail "VPS SSH port is unreachable through $WG_CONTAINER"
ok "VPS SSH transport is reachable through WireGuard"

wg_id=$(docker inspect --format '{{.Id}}' "$WG_CONTAINER" 2>/dev/null || true)
network_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$FILTER_CONTAINER" 2>/dev/null || true)
[ "$network_mode" = "container:$wg_id" ] \
  || fail "$FILTER_CONTAINER does not share $WG_CONTAINER: $network_mode"
ok "$FILTER_CONTAINER shares the WireGuard network namespace"

hardening=$(docker inspect --format \
  '{{.HostConfig.Privileged}}|{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
  "$FILTER_CONTAINER" 2>/dev/null || true)
case "$hardening" in
  false\|101:101\|true\|\[\"ALL\"\]\|null\|\[\"no-new-privileges:true\"\]|false\|101:101\|true\|\[\"ALL\"\]\|\[\]\|\[\"no-new-privileges:true\"\])
    ok "$FILTER_CONTAINER is non-root, read-only, and capability-free"
    ;;
  *) fail "$FILTER_CONTAINER hardening is incomplete" ;;
esac

rotation=$(docker inspect --format \
  '{{.HostConfig.Privileged}}|{{.State.Running}}|{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.NetworkMode}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
  "$LOGROTATE_CONTAINER" 2>/dev/null || true)
case "$rotation" in
  false\|true\|101:101\|true\|none\|\[\"ALL\"\]\|null\|\[\"no-new-privileges:true\"\]|false\|true\|101:101\|true\|none\|\[\"ALL\"\]\|\[\]\|\[\"no-new-privileges:true\"\])
    ok "bounded NAS log rotation is isolated and running"
    ;;
  *) fail "$LOGROTATE_CONTAINER hardening is incomplete" ;;
esac

python3 - "$IMMICH_URL" <<'PY'
import sys
import urllib.error
import urllib.request

url = sys.argv[1].rstrip('/') + '/api/server/ping'
try:
    with urllib.request.urlopen(url, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError(f'HTTP {response.status}')
except Exception as exc:
    print(f'  ✗ local Immich is unreachable: {exc}', file=sys.stderr)
    raise SystemExit(1)
print('  ✓ local Immich ping succeeded')
PY

printf '\nNAS-controller preflight passed. No system state was changed.\n'
