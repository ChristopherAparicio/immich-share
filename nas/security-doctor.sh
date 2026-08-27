#!/bin/sh
# Root-owned, read-only boundary check used by the forced SSH gate. It emits no
# addresses, paths, container IDs, request targets, or credentials.
set -eu

# These names are deliberately fixed. The unprivileged SSH gate must not be
# able to redirect this root-run check through inherited environment values.
wg_container=wg-tunnel
filter_container=wg-nginx-filter
logrotate_container=immich-share-logrotate
immich_container=immich_server

fail() {
    printf 'NAS security check failed: %s\n' "$1" >&2
    exit 1
}

[ "$(docker inspect --format '{{.State.Running}}' "$wg_container" 2>/dev/null || true)" = true ] \
    || fail "WireGuard is not running"
[ "$(docker exec "$wg_container" sysctl -n net.ipv4.ip_forward 2>/dev/null || true)" = 0 ] \
    || fail "IP forwarding is enabled"

wg_hardening=$(docker inspect --format \
    '{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
    "$wg_container" 2>/dev/null || true)
case "$wg_hardening" in
    true\|\[\"ALL\"\]\|\[\"NET_ADMIN\",\"DAC_READ_SEARCH\"\]\|*no-new-privileges*) ;;
    *) fail "WireGuard hardening is incomplete" ;;
esac

networks=$(docker inspect --format \
    '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' \
    "$wg_container" 2>/dev/null | sed '/^$/d' || true)
[ -n "$networks" ] || fail "WireGuard has no dedicated Docker network"
[ "$(printf '%s\n' "$networks" | wc -l | tr -d ' ')" = 1 ] \
    || fail "WireGuard must join exactly one dedicated Docker network"
share_network=$networks
members=$(docker network inspect --format \
    '{{range .Containers}}{{println .Name}}{{end}}' "$share_network" 2>/dev/null \
    | sed '/^$/d' | sort || true)
expected=$(printf '%s\n%s\n' "$immich_container" "$wg_container" | sort)
[ "$members" = "$expected" ] || fail "dedicated network membership is unexpected"

wg_id=$(docker inspect --format '{{.Id}}' "$wg_container" 2>/dev/null || true)
[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$filter_container" 2>/dev/null || true)" = "container:$wg_id" ] \
    || fail "filter is outside the tunnel namespace"

filter_hardening=$(docker inspect --format \
    '{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
    "$filter_container" 2>/dev/null || true)
case "$filter_hardening" in
    101:101\|true\|\[\"ALL\"\]\|null\|*no-new-privileges*|101:101\|true\|\[\"ALL\"\]\|\[\]\|*no-new-privileges*) ;;
    *) fail "filter hardening is incomplete" ;;
esac

rotation=$(docker inspect --format \
    '{{.State.Running}}|{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.NetworkMode}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
    "$logrotate_container" 2>/dev/null || true)
case "$rotation" in
    true\|101:101\|true\|none\|\[\"ALL\"\]\|null\|*no-new-privileges*|true\|101:101\|true\|none\|\[\"ALL\"\]\|\[\]\|*no-new-privileges*) ;;
    *) fail "isolated log rotation is not running" ;;
esac

# A complete doctor is intentionally run while a controlled test share keeps
# the filter online. This lets us test the effective generated config and logs,
# not merely a source template that Docker may not be using.
[ "$(docker inspect --format '{{.State.Running}}' "$filter_container" 2>/dev/null || true)" = true ] \
    || fail "filter is stopped; run doctor during a controlled test share"
effective=$(docker exec "$filter_container" nginx -T 2>/dev/null) \
    || fail "effective nginx configuration cannot be read"
# nginx -T includes source comments. Inspect directives only so a defensive
# comment such as "Never log $request" cannot make the doctor fail closed.
effective_directives=$(printf '%s\n' "$effective" | sed '/^[[:space:]]*#/d')
printf '%s\n' "$effective_directives" | grep -F 'error_log /dev/null' >/dev/null \
    || fail "nginx error logging is not disabled"
if printf '%s\n' "$effective_directives" | grep -F '$request_uri' >/dev/null \
    || printf '%s\n' "$effective_directives" | grep -F '$request ' >/dev/null; then
    fail "nginx route logs include the raw request target"
fi
printf '%s\n' "$effective_directives" | grep -F '"$request_method $uri"' >/dev/null \
    || fail "nginx sanitized route log format is missing"

listen_address=$(printf '%s\n' "$effective_directives" \
    | sed -n 's/^[[:space:]]*listen[[:space:]]\+\([^:;]*\):2283.*/\1/p' | head -1)
[ -n "$listen_address" ] || fail "filter listener cannot be identified"
sentinel="DOCTORQUERY$$"
response=$(printf 'GET /api/auth/login?key=%s HTTP/1.0\r\nHost: doctor.invalid\r\n\r\n' "$sentinel" \
    | docker exec -i "$wg_container" nc -w 5 "$listen_address" 2283 2>/dev/null \
    | sed -n '1p' || true)
case "$response" in
    *" 404 "*) ;;
    *) fail "forbidden Immich route was not refused" ;;
esac

logs_dir=$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/var/log/nginx"}}{{.Source}}{{end}}{{end}}' \
    "$filter_container" 2>/dev/null || true)
[ -n "$logs_dir" ] || fail "sanitized log mount is missing"
if grep -R -F -q "$sentinel" "$logs_dir" 2>/dev/null \
    || docker logs "$filter_container" 2>&1 | grep -F "$sentinel" >/dev/null; then
    fail "query sentinel leaked into runtime logs"
fi

printf 'NAS boundary, filter, refusal, and live log checks passed\n'
