#!/bin/sh
# Root-owned, read-only boundary check used by the forced SSH gate. It emits no
# addresses, paths, container IDs, request targets, or credentials.
set -eu

# This runs as root through sudo. Never resolve docker/iptables helpers through
# a caller-influenced search path.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# These names are deliberately fixed. The unprivileged SSH gate must not be
# able to redirect this root-run check through inherited environment values.
wg_container=wg-tunnel
filter_container=wg-nginx-filter
logrotate_container=immich-share-logrotate
immich_container=immich_server
# Root-owned expectation for the optional NAS-controller opt-in. The doctor
# must not take the expected SSH peer from the container it certifies; the
# operator writes it here (mode 0600, root, one WG_CONTROLLER_SSH_PEER= line).
doctor_env=/etc/immich-share/doctor.env
denied_log=/var/log/immich-share/denied.log

fail() {
    printf 'NAS security check failed: %s\n' "$1" >&2
    exit 1
}

is_ipv4() {
    printf '%s\n' "$1" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
}

# Sets expected_ssh_peer from the root-owned doctor file only. Absent or empty
# file: no opt-in is expected and exactly four rules are allowed. Runs in the
# main shell (not a command substitution) so that fail terminates the doctor.
read_expected_controller_ssh_peer() {
    expected_ssh_peer=
    [ -e "$doctor_env" ] || return 0
    [ -f "$doctor_env" ] && [ ! -L "$doctor_env" ] \
        || fail "doctor expectation file is not a regular file"
    [ "$(stat -c '%u' "$doctor_env" 2>/dev/null || true)" = 0 ] \
        && [ "$(stat -c '%a' "$doctor_env" 2>/dev/null || true)" = 600 ] \
        || fail "doctor expectation file owner or permissions are unsafe"
    # Only blank lines, comments and the single expected assignment may appear.
    if sed -e '/^[[:space:]]*$/d' -e '/^[[:space:]]*#/d' "$doctor_env" \
        | grep -Ev '^WG_CONTROLLER_SSH_PEER=' >/dev/null; then
        fail "doctor expectation file contains an unexpected entry"
    fi
    [ "$(grep -c '^WG_CONTROLLER_SSH_PEER=' "$doctor_env")" -le 1 ] \
        || fail "doctor expectation file names more than one controller SSH peer"
    expected_ssh_peer=$(sed -n 's/^WG_CONTROLLER_SSH_PEER=//p' "$doctor_env" | head -1)
    [ -z "$expected_ssh_peer" ] || is_ipv4 "$expected_ssh_peer" \
        || fail "doctor expectation controller SSH peer is not a literal IPv4 address"
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
    is_ipv4 "$endpoint_ip" \
        || fail "WireGuard endpoint allowlist cannot be certified"
    case "$endpoint_port" in
        ''|*[!0-9]*) fail "WireGuard endpoint allowlist cannot be certified" ;;
    esac

    # The NAS-controller profile may opt in to exactly one extra accept: TCP/22
    # to the VPS WireGuard address. The expected address comes from the
    # root-owned doctor file, never from the certified container: with no
    # expectation the container must not carry WG_CONTROLLER_SSH_PEER at all
    # and exactly four rules are allowed; with one, the container value must
    # match it exactly and exactly five rules are allowed.
    read_expected_controller_ssh_peer
    controller_ssh_peer=$(docker inspect --format \
        '{{range .Config.Env}}{{println .}}{{end}}' "$wg_container" 2>/dev/null \
        | sed -n 's/^WG_CONTROLLER_SSH_PEER=//p' | head -1)
    if [ -z "$expected_ssh_peer" ]; then
        [ -z "$controller_ssh_peer" ] \
            || fail "tunnel carries a controller SSH opt-in that the root-owned doctor expectation does not name"
        expected_rule_count=4
    else
        [ "$controller_ssh_peer" = "$expected_ssh_peer" ] \
            || fail "tunnel controller SSH opt-in does not match the root-owned doctor expectation"
        expected_rule_count=5
    fi

    append_rules=$(printf '%s\n' "$output_policy" | grep '^-A OUTPUT ' || true)
    [ "$(printf '%s\n' "$append_rules" | sed '/^$/d' | wc -l | tr -d ' ')" = "$expected_rule_count" ] \
        || fail "tunnel namespace has an unexpected output allow rule"
    printf '%s\n' "$append_rules" | grep -Fx -- \
        '-A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT' >/dev/null \
        || fail "tunnel namespace loopback rule is missing"
    printf '%s\n' "$append_rules" | grep -Fx -- \
        '-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' >/dev/null \
        || printf '%s\n' "$append_rules" | grep -Fx -- \
            '-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' >/dev/null \
        || fail "tunnel namespace stateful reply rule is missing"
    printf '%s\n' "$append_rules" | grep -Fx -- \
        "-A OUTPUT -d $endpoint_ip/32 -p udp -m udp --dport $endpoint_port -j ACCEPT" >/dev/null \
        || fail "tunnel namespace endpoint rule is incorrect"
    printf '%s\n' "$append_rules" | grep -Fx -- \
        "-A OUTPUT -d $expected_upstream_ip/32 -p tcp -m tcp --dport $expected_upstream_port -j ACCEPT" >/dev/null \
        || fail "tunnel namespace upstream rule is incorrect"
    if [ -n "$expected_ssh_peer" ]; then
        printf '%s\n' "$append_rules" | grep -Fx -- \
            "-A OUTPUT -d $expected_ssh_peer/32 -p tcp -m tcp --dport 22 -j ACCEPT" >/dev/null \
            || fail "tunnel namespace controller SSH rule is incorrect"
    fi
}

# The OUTPUT allowlist is IPv4 iptables only, so IPv6 must be fail-closed too:
# ip6tables OUTPUT policy DROP with no accept other than (at most) loopback.
# A kernel without IPv6 has no ip6tables table; that is equally closed. Never
# consult /proc/sys/net/ipv6: it is absent on such kernels.
certify_ipv6_closed() {
    if ipv6_policy=$(docker exec "$wg_container" ip6tables -S OUTPUT 2>&1); then
        ipv6_rules=$(printf '%s\n' "$ipv6_policy" \
            | grep -Fvx -- '-A OUTPUT -o lo -j ACCEPT' | sed '/^$/d')
        [ "$ipv6_rules" = '-P OUTPUT DROP' ] \
            || fail "tunnel namespace IPv6 output policy is not fail-closed"
    else
        case "$ipv6_policy" in
            *"can't initialize ip6tables table"*|*"Address family not supported"*|*"Protocol not supported"*) ;;
            *) fail "tunnel namespace IPv6 output policy cannot be certified" ;;
        esac
    fi
}

wg_state=$(docker inspect --format '{{.State.Running}}|{{.Id}}' "$wg_container" 2>/dev/null || true)
wg_id=${wg_state#*|}
[ "${wg_state%%|*}" = true ] && [ -n "$wg_id" ] \
    || fail "WireGuard is not running"
[ "$(docker exec "$wg_container" sysctl -n net.ipv4.ip_forward 2>/dev/null || true)" = 0 ] \
    || fail "IP forwarding is enabled"
certify_ipv6_closed
output_policy=$(docker exec "$wg_container" iptables -S OUTPUT 2>/dev/null || true)
printf '%s\n' "$output_policy" | grep -Fx -- '-P OUTPUT DROP' >/dev/null \
    || fail "tunnel namespace output policy is not fail-closed"
lan_probe=$(printf '192.%s.%s.%s' 168 1 1)
if docker exec "$wg_container" nc -z -w 2 1.1.1.1 443 >/dev/null 2>&1 \
    || docker exec "$wg_container" nc -z -w 2 "$lan_probe" 443 >/dev/null 2>&1; then
    fail "tunnel namespace has unexpected LAN or Internet egress"
fi
docker exec "$filter_container" nc -z -w 3 127.0.0.1 18080 >/dev/null 2>&1 \
    || fail "allowlisted Immich loopback relay is unreachable from the filter"

# Security options are compared as the exact JSON list so an extra
# seccomp=unconfined or apparmor=unconfined entry, or no-new-privileges:false,
# cannot pass a substring match. Privileged mode is rejected outright.
wg_hardening=$(docker inspect --format \
    '{{.HostConfig.Privileged}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
    "$wg_container" 2>/dev/null || true)
case "$wg_hardening" in
    false\|true\|\[\"ALL\"\]\|\[\"NET_ADMIN\",\"DAC_READ_SEARCH\"\]\|\[\"no-new-privileges:true\"\]) ;;
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
immich_ip=$(docker inspect --format \
    "{{with index .NetworkSettings.Networks \"$share_network\"}}{{.IPAddress}}{{end}}" \
    "$immich_container" 2>/dev/null || true)
is_ipv4 "$immich_ip" \
    || fail "allowlisted Immich address cannot be certified"
certify_output_allowlist "$immich_ip" 2283

[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$filter_container" 2>/dev/null || true)" = "container:$wg_id" ] \
    || fail "filter is outside the tunnel namespace"

filter_hardening=$(docker inspect --format \
    '{{.HostConfig.Privileged}}|{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
    "$filter_container" 2>/dev/null || true)
case "$filter_hardening" in
    false\|101:101\|true\|\[\"ALL\"\]\|null\|\[\"no-new-privileges:true\"\]|false\|101:101\|true\|\[\"ALL\"\]\|\[\]\|\[\"no-new-privileges:true\"\]) ;;
    *) fail "filter hardening is incomplete" ;;
esac

rotation=$(docker inspect --format \
    '{{.HostConfig.Privileged}}|{{.State.Running}}|{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.NetworkMode}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}' \
    "$logrotate_container" 2>/dev/null || true)
case "$rotation" in
    false\|true\|101:101\|true\|none\|\[\"ALL\"\]\|null\|\[\"no-new-privileges:true\"\]|false\|true\|101:101\|true\|none\|\[\"ALL\"\]\|\[\]\|\[\"no-new-privileges:true\"\]) ;;
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
# shellcheck disable=SC2016 # Match literal nginx variable names.
if printf '%s\n' "$effective_directives" | grep -F '$request_uri' >/dev/null \
    || printf '%s\n' "$effective_directives" | grep -F '$request ' >/dev/null; then
    fail "nginx route logs include the raw request target"
fi
# shellcheck disable=SC2016 # Match literal nginx variable names.
printf '%s\n' "$effective_directives" | grep -F '"$request_method $uri"' >/dev/null \
    || fail "nginx sanitized route log format is missing"

listen_address=$(printf '%s\n' "$effective_directives" \
    | sed -n 's/^[[:space:]]*listen[[:space:]]\+\([^:;]*\):2283.*/\1/p' | head -1)
[ -n "$listen_address" ] || fail "filter listener cannot be identified"
# The steady-state OUTPUT allowlist permits loopback only towards 127.0.0.1, so
# the live refusal probe must use the private loopback listener rather than the
# WireGuard address, and it must originate inside the shared namespace.
printf '%s\n' "$effective_directives" | grep -F 'listen 127.0.0.1:2283' >/dev/null \
    || fail "private filter probe listener is missing"
sentinel="DOCTORQUERY$$"
response=$({ printf 'GET /api/auth/login?key=%s HTTP/1.0\r\nHost: doctor.invalid\r\n\r\n' "$sentinel"; sleep 1; } \
    | docker exec -i "$filter_container" nc -w 5 127.0.0.1 2283 2>/dev/null \
    | sed -n '1p' || true)
case "$response" in
    *" 404 "*) ;;
    *) fail "forbidden Immich route was not refused" ;;
esac

logs_dir=$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/var/log/nginx"}}{{.Source}}{{end}}{{end}}' \
    "$filter_container" 2>/dev/null || true)
[ -n "$logs_dir" ] || fail "sanitized log mount is missing"
# The forced `tripwire follow` command tails a fixed path. It must exist and be
# the denied.log inside this filter's log bind mount, or the tripwire silently
# follows nothing while refusals land elsewhere.
[ -f "$denied_log" ] || fail "tripwire source is missing"
[ "$(readlink -f "$denied_log" 2>/dev/null || true)" = "$(readlink -f "$logs_dir" 2>/dev/null || true)/denied.log" ] \
    || fail "tripwire source does not resolve into the filter log mount"
if grep -R -F -q "$sentinel" "$logs_dir" 2>/dev/null \
    || docker logs "$filter_container" 2>&1 | grep -F "$sentinel" >/dev/null; then
    fail "query sentinel leaked into runtime logs"
fi

printf 'NAS boundary, filter, refusal, and live log checks passed\n'
