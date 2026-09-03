#!/bin/sh
set -eu

config=/config/wg0.conf
proxy_pid=
torn_down=false
[ -r "$config" ] || {
    printf 'WireGuard configuration is missing: %s\n' "$config" >&2
    exit 1
}

is_ipv4() {
    printf '%s\n' "$1" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
}

lock_ipv6() {
    # The OUTPUT allowlist below is IPv4 iptables only, so any IPv6 path would
    # bypass it. Enforce the same fail-closed policy for IPv6 with ip6tables.
    # Nothing in this namespace uses IPv6 (nginx and the relay bind IPv4
    # loopback and the WireGuard address), so no accept rule is needed at all.
    # A kernel without IPv6 (compiled out or ipv6.disable=1) has no such table;
    # that is the same fail-closed outcome, so it is logged and accepted. Any
    # other failure is a configuration error.
    if ipv6_error=$(ip6tables -P OUTPUT DROP 2>&1); then
        ip6tables -P FORWARD DROP
    else
        case "$ipv6_error" in
            *"can't initialize ip6tables table"*|*"Address family not supported"*|*"Protocol not supported"*)
                printf 'IPv6 is unavailable in this kernel; no ip6tables policy is needed\n' >&2
                ;;
            *)
                printf 'IPv6 output policy could not be installed: %s\n' "$ipv6_error" >&2
                exit 1
                ;;
        esac
    fi
    # Defence in depth only: Docker mounts /proc/sys read-only, so this write
    # usually fails silently and the sysctl may be absent entirely. The
    # ip6tables policy above is the enforcement; never fail on this file.
    if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
        printf 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || true
    fi
}

lock_output() {
    # Fail closed: the OUTPUT lockdown is on unless an operator explicitly
    # writes WG_OUTPUT_LOCKDOWN=false. Any other value is a configuration error.
    case "${WG_OUTPUT_LOCKDOWN:-true}" in
        true) ;;
        false) return 0 ;;
        *) printf 'WG_OUTPUT_LOCKDOWN must be "true" or "false"\n' >&2; exit 1 ;;
    esac
    upstream_host=${WG_INTERNAL_UPSTREAM_HOST:?WG_INTERNAL_UPSTREAM_HOST is required}
    upstream_port=${WG_INTERNAL_UPSTREAM_PORT:?WG_INTERNAL_UPSTREAM_PORT is required}
    local_proxy_port=${WG_LOCAL_PROXY_PORT:?WG_LOCAL_PROXY_PORT is required}
    controller_ssh_peer=${WG_CONTROLLER_SSH_PEER:-}

    endpoint=$(awk '
        /^[[:space:]]*Endpoint[[:space:]]*=/ {
            sub(/^[^=]*=[[:space:]]*/, ""); gsub(/[[:space:]]/, ""); print; exit
        }' "$config")
    endpoint_ip=${endpoint%:*}
    endpoint_port=${endpoint##*:}
    is_ipv4 "$endpoint_ip" \
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
    # Optional NAS-controller opt-in: exactly one extra accept, TCP/22 to one
    # literal IPv4 /32 (the VPS WireGuard address). Anything else is refused.
    if [ -n "$controller_ssh_peer" ]; then
        is_ipv4 "$controller_ssh_peer" \
            || { printf 'WG_CONTROLLER_SSH_PEER must be a literal IPv4 address\n' >&2; exit 1; }
    fi

    dns_server=$(awk '$1 == "nameserver" { print $2; exit }' /etc/resolv.conf)
    is_ipv4 "$dns_server" \
        || { printf 'A literal IPv4 Docker DNS server is required\n' >&2; exit 1; }

    # Install the deny policy before resolving the one internal service. The
    # shared nginx namespace then has no interval with general LAN/Internet
    # egress. Replies to inbound WireGuard requests remain stateful.
    lock_ipv6
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
    if [ -n "$controller_ssh_peer" ]; then
        iptables -A OUTPUT -d "$controller_ssh_peer/32" -p tcp --dport 22 -j ACCEPT
    fi

    # nginx shares this network namespace but not the WireGuard container's
    # /etc/hosts. Give it a loopback-only relay instead of retaining Docker DNS
    # or injecting a dynamic address into either container's filesystem.
    socat "TCP-LISTEN:${local_proxy_port},bind=127.0.0.1,reuseaddr,fork" \
        "TCP:${upstream_ip}:${upstream_port}" &
    proxy_pid=$!
    # Do not remove DNS or bring the tunnel up until the relay actually accepts
    # connections; a relay that never listens must fail the container.
    attempt=0
    until nc -z -w 1 127.0.0.1 "$local_proxy_port" >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 10 ] || ! kill -0 "$proxy_pid" 2>/dev/null; then
            printf 'Internal upstream relay could not start\n' >&2
            exit 1
        fi
        sleep 1
    done

    # Resolution is bootstrap-only. Unknown and public names cannot become a
    # steady-state exfiltration channel for either process in the namespace.
    iptables -D OUTPUT -d "$dns_server/32" -p udp --dport 53 -j ACCEPT
    iptables -D OUTPUT -d "$dns_server/32" -p tcp --dport 53 -j ACCEPT
    iptables -R OUTPUT 1 -o lo -d 127.0.0.1/32 -j ACCEPT
}

down() {
    [ "$torn_down" = false ] || return 0
    torn_down=true
    if [ -n "$proxy_pid" ]; then
        kill "$proxy_pid" >/dev/null 2>&1 || true
        wait "$proxy_pid" >/dev/null 2>&1 || true
    fi
    wg-quick down "$config" >/dev/null 2>&1 || true
}

# A trapped signal must terminate the entrypoint explicitly; otherwise the
# handler returns into the supervision loop and Docker has to SIGKILL PID 1.
trap 'down; exit 130' INT
trap 'down; exit 143' TERM
trap down EXIT
lock_output
wg-quick up "$config"

if [ -n "$proxy_pid" ]; then
    # Supervise the relay. It is nginx's only path to the upstream, so if socat
    # dies the namespace is broken: exit non-zero and let `restart:
    # unless-stopped` rebuild the whole allowlist rather than serve 502s.
    relay_status=0
    wait "$proxy_pid" || relay_status=$?
    proxy_pid=
    printf 'Internal upstream relay exited (status %s); failing closed\n' "$relay_status" >&2
    exit 1
fi

while :; do
    sleep 3600 &
    wait "$!"
done
