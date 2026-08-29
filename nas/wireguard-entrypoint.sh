#!/bin/sh
set -eu

config=/config/wg0.conf
proxy_pid=
[ -r "$config" ] || {
    printf 'WireGuard configuration is missing: %s\n' "$config" >&2
    exit 1
}

lock_output() {
    [ "${WG_OUTPUT_LOCKDOWN:-false}" = true ] || return 0
    upstream_host=${WG_INTERNAL_UPSTREAM_HOST:?WG_INTERNAL_UPSTREAM_HOST is required}
    upstream_port=${WG_INTERNAL_UPSTREAM_PORT:?WG_INTERNAL_UPSTREAM_PORT is required}
    local_proxy_port=${WG_LOCAL_PROXY_PORT:?WG_LOCAL_PROXY_PORT is required}

    endpoint=$(awk '
        /^[[:space:]]*Endpoint[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); gsub(/[[:space:]]/, ""); print; exit
        }' "$config")
    endpoint_ip=${endpoint%:*}
    endpoint_port=${endpoint##*:}
    printf '%s\n' "$endpoint_ip" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
        || { printf 'WireGuard Endpoint must use a literal public IPv4 address\n' >&2; exit 1; }
    case "$endpoint_port" in ''|*[!0-9]*) printf 'WireGuard Endpoint port is invalid\n' >&2; exit 1 ;; esac
    case "$upstream_port" in ''|*[!0-9]*) printf 'Internal upstream port is invalid\n' >&2; exit 1 ;; esac
    case "$local_proxy_port" in ''|*[!0-9]*) printf 'Local proxy port is invalid\n' >&2; exit 1 ;; esac
    [ "$endpoint_port" -ge 1 ] && [ "$endpoint_port" -le 65535 ] \
        || { printf 'WireGuard Endpoint port is out of range\n' >&2; exit 1; }
    [ "$upstream_port" -ge 1 ] && [ "$upstream_port" -le 65535 ] \
        || { printf 'Internal upstream port is out of range\n' >&2; exit 1; }
    [ "$local_proxy_port" -ge 1024 ] && [ "$local_proxy_port" -le 65535 ] \
        || { printf 'Local proxy port must be unprivileged and in range\n' >&2; exit 1; }

    dns_server=$(awk '$1 == "nameserver" { print $2; exit }' /etc/resolv.conf)
    printf '%s\n' "$dns_server" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
        || { printf 'A literal IPv4 Docker DNS server is required\n' >&2; exit 1; }

    # Install the deny policy before resolving the one internal service. The
    # shared nginx namespace then has no interval with general LAN/Internet
    # egress. Replies to inbound WireGuard requests remain stateful.
    iptables -P OUTPUT DROP
    # Docker may DNAT its 127.0.0.11 resolver to a random loopback port before
    # the filter sees it. Loopback is therefore broad only during bootstrap;
    # the tunnel is still down and the nginx sidecar has no public ingress.
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -d "$dns_server/32" -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d "$dns_server/32" -p tcp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d "$endpoint_ip/32" -p udp --dport "$endpoint_port" -j ACCEPT

    attempt=0
    upstream_ip=
    while [ "$attempt" -lt 30 ]; do
        upstream_ip=$(getent hosts "$upstream_host" 2>/dev/null \
            | awk '$1 ~ /^[0-9]+\./ { print $1; exit }')
        [ -n "$upstream_ip" ] && break
        attempt=$((attempt + 1))
        sleep 1
    done
    [ -n "$upstream_ip" ] \
        || { printf 'Internal upstream cannot be resolved\n' >&2; exit 1; }
    iptables -A OUTPUT -d "$upstream_ip/32" -p tcp --dport "$upstream_port" -j ACCEPT

    # nginx shares this network namespace but not the WireGuard container's
    # /etc/hosts. Give it a loopback-only relay instead of retaining Docker DNS
    # or injecting a dynamic address into either container's filesystem.
    socat "TCP-LISTEN:${local_proxy_port},bind=127.0.0.1,reuseaddr,fork" \
        "TCP:${upstream_ip}:${upstream_port}" &
    proxy_pid=$!
    kill -0 "$proxy_pid" 2>/dev/null \
        || { printf 'Internal upstream relay could not start\n' >&2; exit 1; }

    # Resolution is bootstrap-only. Unknown and public names cannot become a
    # steady-state exfiltration channel for either process in the namespace.
    iptables -D OUTPUT -d "$dns_server/32" -p udp --dport 53 -j ACCEPT
    iptables -D OUTPUT -d "$dns_server/32" -p tcp --dport 53 -j ACCEPT
    iptables -R OUTPUT 1 -o lo -d 127.0.0.1/32 -j ACCEPT
}

down() {
    if [ -n "$proxy_pid" ]; then
        kill "$proxy_pid" >/dev/null 2>&1 || true
        wait "$proxy_pid" >/dev/null 2>&1 || true
    fi
    wg-quick down "$config" >/dev/null 2>&1 || true
}

trap down EXIT INT TERM
lock_output
wg-quick up "$config"

while :; do
    sleep 3600 &
    wait "$!"
done
