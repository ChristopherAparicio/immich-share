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

wg_hardening=$(docker inspect --format \
  '{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
  "$WG_CONTAINER" 2>/dev/null || true)
case "$wg_hardening" in
  true\|\[\"ALL\"\]\|\[\"NET_ADMIN\"\]\|*no-new-privileges*)
    ok "$WG_CONTAINER is read-only with NET_ADMIN only"
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

docker exec "$WG_CONTAINER" nc -z -w 3 "$VPS_WG_ADDRESS" 22 >/dev/null 2>&1 \
  || fail "VPS SSH port is unreachable through $WG_CONTAINER"
ok "VPS SSH transport is reachable through WireGuard"

wg_id=$(docker inspect --format '{{.Id}}' "$WG_CONTAINER" 2>/dev/null || true)
network_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$FILTER_CONTAINER" 2>/dev/null || true)
[ "$network_mode" = "container:$wg_id" ] \
  || fail "$FILTER_CONTAINER does not share $WG_CONTAINER: $network_mode"
ok "$FILTER_CONTAINER shares the WireGuard network namespace"

hardening=$(docker inspect --format \
  '{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
  "$FILTER_CONTAINER" 2>/dev/null || true)
case "$hardening" in
  101:101\|true\|\[\"ALL\"\]\|null\|*no-new-privileges*|101:101\|true\|\[\"ALL\"\]\|\[\]\|*no-new-privileges*)
    ok "$FILTER_CONTAINER is non-root, read-only, and capability-free"
    ;;
  *) fail "$FILTER_CONTAINER hardening is incomplete" ;;
esac

rotation=$(docker inspect --format \
  '{{.State.Running}}|{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.NetworkMode}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
  "$LOGROTATE_CONTAINER" 2>/dev/null || true)
case "$rotation" in
  true\|101:101\|true\|none\|\[\"ALL\"\]\|null\|*no-new-privileges*|true\|101:101\|true\|none\|\[\"ALL\"\]\|\[\]\|*no-new-privileges*)
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
