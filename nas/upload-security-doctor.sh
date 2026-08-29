#!/bin/sh
# Root-owned, read-only certification of the public upload trust boundary.
# It emits pass/fail summaries only: no paths, addresses, tokens, container IDs,
# filenames, or log contents.
set -eu

wg_container=wg-upload-tunnel
filter_container=wg-upload-filter
app_container=immich-upload-drop
logrotate_container=immich-upload-logrotate
admin_helper=/usr/local/sbin/immich-share-upload-admin

fail() {
    printf 'NAS upload security check failed: %s\n' "$1" >&2
    exit 1
}

certify_output_allowlist() {
    expected_upstream_ip=$1
    expected_upstream_port=$2
    endpoint=$(docker exec "$wg_container" awk '
        /^[[:space:]]*Endpoint[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); gsub(/[[:space:]]/, ""); print; exit
        }' /config/wg0.conf 2>/dev/null || true)
    endpoint_ip=${endpoint%:*}
    endpoint_port=${endpoint##*:}
    printf '%s\n' "$endpoint_ip" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
        || fail "upload WireGuard endpoint allowlist cannot be certified"
    case "$endpoint_port" in
        ''|*[!0-9]*) fail "upload WireGuard endpoint allowlist cannot be certified" ;;
    esac

    append_rules=$(printf '%s\n' "$output_policy" | grep '^-A OUTPUT ' || true)
    [ "$(printf '%s\n' "$append_rules" | sed '/^$/d' | wc -l | tr -d ' ')" = 4 ] \
        || fail "upload namespace has an unexpected output allow rule"
    printf '%s\n' "$append_rules" | grep -Fx -- \
        '-A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT' >/dev/null \
        || fail "upload namespace loopback rule is missing"
    printf '%s\n' "$append_rules" | grep -Fx -- \
        '-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' >/dev/null \
        || printf '%s\n' "$append_rules" | grep -Fx -- \
            '-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' >/dev/null \
        || fail "upload namespace stateful reply rule is missing"
    printf '%s\n' "$append_rules" | grep -Fx -- \
        "-A OUTPUT -d $endpoint_ip/32 -p udp -m udp --dport $endpoint_port -j ACCEPT" >/dev/null \
        || fail "upload namespace endpoint rule is incorrect"
    printf '%s\n' "$append_rules" | grep -Fx -- \
        "-A OUTPUT -d $expected_upstream_ip/32 -p tcp -m tcp --dport $expected_upstream_port -j ACCEPT" >/dev/null \
        || fail "upload namespace upstream rule is incorrect"
}

[ -f "$admin_helper" ] && [ ! -L "$admin_helper" ] \
    || fail "upload administration helper is missing or unsafe"
[ "$(stat -c '%u' "$admin_helper" 2>/dev/null || true)" = 0 ] \
    && [ "$(stat -c '%a' "$admin_helper" 2>/dev/null || true)" = 755 ] \
    || fail "upload administration helper owner or permissions are unsafe"

[ "$(docker inspect --format '{{.State.Running}}' "$wg_container" 2>/dev/null || true)" = true ] \
    || fail "upload WireGuard is not running"
[ "$(docker exec "$wg_container" sysctl -n net.ipv4.ip_forward 2>/dev/null || true)" = 0 ] \
    || fail "upload tunnel forwarding is enabled"
output_policy=$(docker exec "$wg_container" iptables -S OUTPUT 2>/dev/null || true)
printf '%s\n' "$output_policy" | grep -Fx -- '-P OUTPUT DROP' >/dev/null \
    || fail "upload namespace output policy is not fail-closed"
lan_probe=$(printf '192.%s.%s.%s' 168 1 1)
if docker exec "$wg_container" nc -z -w 2 1.1.1.1 443 >/dev/null 2>&1 \
    || docker exec "$wg_container" nc -z -w 2 "$lan_probe" 443 >/dev/null 2>&1; then
    fail "upload namespace has unexpected LAN or Internet egress"
fi

wg_hardening=$(docker inspect --format \
    '{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
    "$wg_container" 2>/dev/null || true)
case "$wg_hardening" in
    true\|\[\"ALL\"\]\|\[\"NET_ADMIN\",\"DAC_READ_SEARCH\"\]\|*no-new-privileges*) ;;
    *) fail "upload WireGuard hardening is incomplete" ;;
esac

wg_config_source=$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/config/wg0.conf"}}{{if not .RW}}{{.Source}}{{end}}{{end}}' \
    "$wg_container" 2>/dev/null || true)
[ -n "$wg_config_source" ] && [ -f "$wg_config_source" ] && [ ! -L "$wg_config_source" ] \
    || fail "upload WireGuard configuration mount is missing or unsafe"
[ "$(stat -c '%a' "$wg_config_source" 2>/dev/null || true)" = 600 ] \
    || fail "upload WireGuard configuration permissions are unsafe"

networks=$(docker inspect --format \
    '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' \
    "$wg_container" 2>/dev/null | sed '/^$/d' || true)
[ "$(printf '%s\n' "$networks" | wc -l | tr -d ' ')" = 2 ] \
    || fail "upload WireGuard must join exactly the data and egress networks"
drop_network=
egress_network=
for network in $networks; do
    internal=$(docker network inspect --format '{{.Internal}}' "$network" 2>/dev/null || true)
    case "$internal" in
        true)
            [ -z "$drop_network" ] || fail "multiple internal upload networks found"
            drop_network=$network
            ;;
        false)
            [ -z "$egress_network" ] || fail "multiple upload egress networks found"
            egress_network=$network
            ;;
        *) fail "upload network type cannot be certified" ;;
    esac
done
[ -n "$drop_network" ] && [ -n "$egress_network" ] \
    || fail "upload data/egress network split is missing"
members=$(docker network inspect --format \
    '{{range .Containers}}{{println .Name}}{{end}}' "$drop_network" 2>/dev/null \
    | sed '/^$/d' | sort || true)
expected=$(printf '%s\n%s\n' "$app_container" "$wg_container" | sort)
[ "$members" = "$expected" ] \
    || fail "upload network membership is unexpected"
app_ip=$(docker inspect --format \
    "{{with index .NetworkSettings.Networks \"$drop_network\"}}{{.IPAddress}}{{end}}" \
    "$app_container" 2>/dev/null || true)
printf '%s\n' "$app_ip" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
    || fail "allowlisted upload application address cannot be certified"
certify_output_allowlist "$app_ip" 8080
printf '%s\n' "$members" | grep -Eq '^(immich_server|immich_postgres|database|redis)$' \
    && fail "Immich data services joined the upload network"
egress_members=$(docker network inspect --format \
    '{{range .Containers}}{{println .Name}}{{end}}' "$egress_network" 2>/dev/null \
    | sed '/^$/d' | sort || true)
[ "$egress_members" = "$wg_container" ] \
    || fail "upload egress network contains an unexpected service"

wg_id=$(docker inspect --format '{{.Id}}' "$wg_container" 2>/dev/null || true)
[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$filter_container" 2>/dev/null || true)" = "container:$wg_id" ] \
    || fail "upload filter is outside the upload tunnel namespace"

filter_hardening=$(docker inspect --format \
    '{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
    "$filter_container" 2>/dev/null || true)
case "$filter_hardening" in
    101:101\|true\|\[\"ALL\"\]\|null\|*no-new-privileges*|101:101\|true\|\[\"ALL\"\]\|\[\]\|*no-new-privileges*) ;;
    *) fail "upload filter hardening is incomplete" ;;
esac
filter_ports=$(docker inspect --format '{{json .HostConfig.PortBindings}}' \
    "$filter_container" 2>/dev/null || true)
case "$filter_ports" in ""|null|'{}') ;; *) fail "upload filter publishes a host port" ;; esac

app_hardening=$(docker inspect --format \
    '{{.State.Running}}|{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
    "$app_container" 2>/dev/null || true)
case "$app_hardening" in
    true\|65532:65532\|true\|\[\"ALL\"\]\|null\|*no-new-privileges*|true\|65532:65532\|true\|\[\"ALL\"\]\|\[\]\|*no-new-privileges*) ;;
    *) fail "upload application hardening is incomplete" ;;
esac
app_ports=$(docker inspect --format '{{json .HostConfig.PortBindings}}' \
    "$app_container" 2>/dev/null || true)
case "$app_ports" in ""|null|'{}') ;; *) fail "upload application publishes a host port" ;; esac
app_image=$(docker inspect --format '{{.Config.Image}}' "$app_container" 2>/dev/null || true)
printf '%s\n' "$app_image" | grep -Eq '@sha256:[0-9a-fA-F]{64}$' \
    || fail "upload application image is not pinned by digest"
app_environment=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' \
    "$app_container" 2>/dev/null || true)
if printf '%s\n' "$app_environment" | grep -Ei '^(IMMICH|.*API[_-]?KEY|SESSION_SECRET)=' >/dev/null; then
    fail "upload application contains a forbidden credential value"
fi
printf '%s\n' "$app_environment" | grep -F 'SESSION_SECRET_FILE=/run/secrets/session-secret' >/dev/null \
    || fail "upload application does not use the private session-secret file"

app_networks=$(docker inspect --format \
    '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' \
    "$app_container" 2>/dev/null | sed '/^$/d' || true)
[ "$app_networks" = "$drop_network" ] \
    || fail "upload application joined an unexpected network"

writable_mounts=$(docker inspect --format \
    '{{range .Mounts}}{{if .RW}}{{println .Destination}}{{end}}{{end}}' \
    "$app_container" 2>/dev/null | sed '/^$/d' | sort || true)
expected_mounts=$(printf '/data\n/incoming\n' | sort)
[ "$writable_mounts" = "$expected_mounts" ] \
    || fail "upload application writable mounts are unexpected"
for destination in /data /incoming; do
    source_path=$(docker inspect --format \
        "{{range .Mounts}}{{if eq .Destination \"$destination\"}}{{.Source}}{{end}}{{end}}" \
        "$app_container" 2>/dev/null || true)
    [ -n "$source_path" ] && [ -d "$source_path" ] && [ ! -L "$source_path" ] \
        || fail "upload storage mount is missing or unsafe"
    source_mode=$(stat -c '%a' "$source_path" 2>/dev/null || true)
    source_owner=$(stat -c '%u' "$source_path" 2>/dev/null || true)
    [ "$source_mode" = 700 ] && [ "$source_owner" = 65532 ] \
        || fail "upload storage mount owner or permissions are unsafe"
done
secret_source=$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/run/secrets/session-secret"}}{{if not .RW}}{{.Source}}{{end}}{{end}}' \
    "$app_container" 2>/dev/null || true)
[ -n "$secret_source" ] && [ -f "$secret_source" ] && [ ! -L "$secret_source" ] \
    || fail "upload session secret mount is missing or unsafe"
secret_mode=$(stat -c '%a' "$secret_source" 2>/dev/null || true)
secret_owner=$(stat -c '%u' "$secret_source" 2>/dev/null || true)
[ "$secret_mode" = 400 ] && [ "$secret_owner" = 65532 ] \
    || fail "upload session secret owner or permissions are unsafe"

rotation=$(docker inspect --format \
    '{{.State.Running}}|{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.NetworkMode}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
    "$logrotate_container" 2>/dev/null || true)
case "$rotation" in
    true\|101:101\|true\|none\|\[\"ALL\"\]\|null\|*no-new-privileges*|true\|101:101\|true\|none\|\[\"ALL\"\]\|\[\]\|*no-new-privileges*) ;;
    *) fail "upload log rotation is not isolated" ;;
esac

# Run the full live check only while a controlled invitation has intentionally
# opened the filter. A stopped filter is a valid closed state, but cannot prove
# its effective generated config or runtime log redaction.
[ "$(docker inspect --format '{{.State.Running}}' "$filter_container" 2>/dev/null || true)" = true ] \
    || fail "upload filter is stopped; test during a controlled invitation"
effective=$(docker exec "$filter_container" nginx -T 2>/dev/null) \
    || fail "effective upload filter configuration cannot be read"
directives=$(printf '%s\n' "$effective" | sed '/^[[:space:]]*#/d')
printf '%s\n' "$directives" | grep -F 'error_log /dev/null' >/dev/null \
    || fail "upload filter error logging is not disabled"
printf '%s\n' "$directives" | grep -F 'log_format drop_route' >/dev/null \
    || fail "normalized upload log format is missing"
printf '%s\n' "$directives" | grep -F 'access_log /var/log/nginx/allowed.log drop_route' >/dev/null \
    || fail "normalized upload access log is not active"
# shellcheck disable=SC2016 # Match literal nginx variable names.
if printf '%s\n' "$directives" | grep -E 'log_format.*\$(request_uri|request)([^A-Za-z_]|$)' >/dev/null; then
    fail "upload route logs contain the raw request target"
fi

listen_address=$(printf '%s\n' "$directives" \
    | sed -n 's/^[[:space:]]*listen[[:space:]]\+\([^:;]*\):2383.*/\1/p' | head -1)
[ -n "$listen_address" ] || fail "upload filter listener cannot be identified"
sentinel="UPLOADDOCTOR$$"
response=$(printf 'GET /api/admin?token=%s HTTP/1.0\r\nHost: doctor.invalid\r\n\r\n' "$sentinel" \
    | docker exec -i "$wg_container" nc -w 5 "$listen_address" 2383 2>/dev/null \
    | sed -n '1p' || true)
case "$response" in
    *" 404 "*) ;;
    *) fail "forbidden upload route was not refused" ;;
esac

# Exercise an allowed token-bearing route with an unknown canary so runtime app
# logging is tested too. Its response may legitimately be 401 or 404.
app_token="UPLOADDOCTOR0123456789ABCDEF0123456789$$"
printf 'GET /drop/i/%s?probe=%s HTTP/1.0\r\nHost: doctor.invalid\r\n\r\n' \
    "$app_token" "$app_token" \
    | docker exec -i "$wg_container" nc -w 5 "$listen_address" 2383 >/dev/null 2>&1 \
    || true
sleep 1

logs_dir=$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/var/log/nginx"}}{{.Source}}{{end}}{{end}}' \
    "$filter_container" 2>/dev/null || true)
[ -n "$logs_dir" ] || fail "upload sanitized log mount is missing"
if grep -R -F -q "$sentinel" "$logs_dir" 2>/dev/null \
    || docker logs "$filter_container" 2>&1 | grep -F "$sentinel" >/dev/null \
    || docker logs "$app_container" 2>&1 | grep -F "$sentinel" >/dev/null \
    || grep -R -F -q "$app_token" "$logs_dir" 2>/dev/null \
    || docker logs "$filter_container" 2>&1 | grep -F "$app_token" >/dev/null \
    || docker logs "$app_container" 2>&1 | grep -F "$app_token" >/dev/null; then
    fail "upload query sentinel leaked into runtime logs"
fi

health=$(printf 'GET /healthz HTTP/1.0\r\nHost: upload-drop\r\n\r\n' \
    | docker exec -i "$filter_container" nc -w 5 127.0.0.1 18080 2>/dev/null \
    | sed -n '1p' || true)
case "$health" in
    *" 200 "*) ;;
    *) fail "private upload application health check failed" ;;
esac

printf 'NAS upload tunnel, isolation, filter, storage, refusal, and live log checks passed\n'
