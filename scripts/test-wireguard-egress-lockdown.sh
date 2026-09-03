#!/bin/sh
# Runtime proof that a shared WireGuard/nginx namespace can reach only its
# public UDP endpoint and one internal upstream, not the LAN or Internet.
set -eu

image=${WIREGUARD_TEST_IMAGE:-immich-share-wireguard:1.1.20260829-r0}
suffix=$$
data_network=wg-egress-data-$suffix
egress_network=wg-egress-public-$suffix
upstream_container=wg-egress-upstream-$suffix
wg_container=wg-egress-client-$suffix
optin_container=wg-egress-controller-$suffix
sidecar_container=wg-egress-sidecar-$suffix
temporary_directory=$(mktemp -d)
config=$temporary_directory/wg0.conf

cleanup() {
    docker rm -f "$sidecar_container" "$optin_container" "$wg_container" "$upstream_container" >/dev/null 2>&1 || true
    docker network rm "$data_network" "$egress_network" >/dev/null 2>&1 || true
    rm -f "$config"
    rmdir "$temporary_directory" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

private_key=$(docker run --rm --entrypoint wg "$image" genkey)
peer_private_key=$(docker run --rm --entrypoint wg "$image" genkey)
peer_public_key=$(printf '%s\n' "$peer_private_key" \
    | docker run --rm --interactive --entrypoint wg "$image" pubkey)
umask 077
printf '%s\n' \
    '[Interface]' \
    'Address = 192.0.2.2/32' \
    "PrivateKey = $private_key" \
    '' \
    '[Peer]' \
    "PublicKey = $peer_public_key" \
    'Endpoint = 198.51.100.10:51820' \
    'AllowedIPs = 192.0.2.1/32' \
    > "$config"
unset private_key peer_private_key peer_public_key

docker network create --internal "$data_network" >/dev/null
docker network create "$egress_network" >/dev/null
docker run -d --name "$upstream_container" --network "$data_network" \
    --network-alias test-upstream --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --tmpfs /tmp:size=1m \
    --entrypoint nc "$image" -lk -p 8080 >/dev/null

# Mirrors nas/docker-compose.yml: no IPv6 sysctls (absent on IPv6-less kernels,
# where they would keep the container from starting); the entrypoint itself
# must fail IPv6 closed with ip6tables. WG_OUTPUT_LOCKDOWN is deliberately NOT
# passed: the entrypoint must default to the lockdown.
start_tunnel() {
    name=$1
    shift
    docker create --name "$name" --network "$egress_network" \
        --read-only --cap-drop ALL --cap-add NET_ADMIN --cap-add DAC_READ_SEARCH \
        --security-opt no-new-privileges:true --sysctl net.ipv4.ip_forward=0 \
        --tmpfs /run:size=2m --tmpfs /tmp:size=2m \
        -e WG_INTERNAL_UPSTREAM_HOST=test-upstream \
        -e WG_INTERNAL_UPSTREAM_PORT=8080 \
        -e WG_LOCAL_PROXY_PORT=18080 \
        "$@" \
        -v "$config:/config/wg0.conf:ro" "$image" >/dev/null
    docker network connect "$data_network" "$name"
    docker start "$name" >/dev/null

    ready=false
    attempt=0
    while [ "$attempt" -lt 120 ]; do
        if docker exec "$name" iptables -S OUTPUT 2>/dev/null \
            | grep -Fx -- '-P OUTPUT DROP' >/dev/null \
            && docker exec "$name" nc -z -w 1 127.0.0.1 18080 >/dev/null 2>&1 \
            && ! docker exec "$name" getent hosts example.com >/dev/null 2>&1; then
            ready=true
            break
        fi
        [ "$(docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null || true)" = true ] \
            || break
        attempt=$((attempt + 1))
        sleep 0.25
    done
    [ "$ready" = true ] || {
        docker logs "$name" >&2
        docker inspect --format 'state={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' \
            "$name" >&2 || true
        exit 1
    }
}

start_tunnel "$wg_container"
# IPv6 must be fail-closed by policy: exactly `-P OUTPUT DROP` (at most a
# loopback accept) or an ip6tables error proving the kernel has no IPv6. The
# /proc sysctl is deliberately not consulted; Docker mounts /proc/sys read-only
# and the path does not exist on IPv6-less kernels.
if ipv6_policy=$(docker exec "$wg_container" ip6tables -S OUTPUT 2>&1); then
    ipv6_rules=$(printf '%s\n' "$ipv6_policy" \
        | grep -Fvx -- '-A OUTPUT -o lo -j ACCEPT' | sed '/^$/d')
    [ "$ipv6_rules" = '-P OUTPUT DROP' ] || {
        printf 'IPv6 output policy is not fail-closed in the WireGuard namespace:\n%s\n' "$ipv6_policy" >&2
        exit 1
    }
    [ "$(docker exec "$wg_container" ip6tables -S FORWARD | sed '/^$/d')" = '-P FORWARD DROP' ] || {
        printf 'IPv6 forward policy is not fail-closed in the WireGuard namespace\n' >&2
        exit 1
    }
else
    case "$ipv6_policy" in
        *"can't initialize ip6tables table"*|*"Address family not supported"*|*"Protocol not supported"*) ;;
        *)
            printf 'IPv6 output policy cannot be read in the WireGuard namespace: %s\n' "$ipv6_policy" >&2
            exit 1
            ;;
    esac
fi

upstream_ip=$(docker inspect --format \
    "{{with index .NetworkSettings.Networks \"$data_network\"}}{{.IPAddress}}{{end}}" \
    "$upstream_container")
policy=$(docker exec "$wg_container" iptables -S OUTPUT)
append_rules=$(printf '%s\n' "$policy" | grep '^-A OUTPUT ' || true)
[ "$(printf '%s\n' "$append_rules" | sed '/^$/d' | wc -l | tr -d ' ')" = 4 ]
printf '%s\n' "$append_rules" | grep -Fx -- \
    '-A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT' >/dev/null
printf '%s\n' "$append_rules" | grep -Fx -- \
    '-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' >/dev/null \
    || printf '%s\n' "$append_rules" | grep -Fx -- \
        '-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' >/dev/null
printf '%s\n' "$append_rules" | grep -Fx -- \
    '-A OUTPUT -d 198.51.100.10/32 -p udp -m udp --dport 51820 -j ACCEPT' >/dev/null
printf '%s\n' "$append_rules" | grep -Fx -- \
    "-A OUTPUT -d $upstream_ip/32 -p tcp -m tcp --dport 8080 -j ACCEPT" >/dev/null
docker exec "$wg_container" nc -z -w 3 127.0.0.1 18080

# nginx uses network_mode: service:wireguard, but gets its own filesystem and
# resolver configuration. Prove the actual sidecar topology reaches the relay
# via loopback without depending on a shared /etc/hosts entry or live DNS.
docker run -d --name "$sidecar_container" --network "container:$wg_container" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --entrypoint sleep "$image" 300 >/dev/null
docker exec "$sidecar_container" nc -z -w 3 127.0.0.1 18080
if docker exec "$sidecar_container" getent hosts example.com >/dev/null 2>&1; then
    printf 'Shared sidecar namespace unexpectedly resolved a public DNS name\n' >&2
    exit 1
fi
if docker exec "$wg_container" getent hosts example.com >/dev/null 2>&1; then
    printf 'WireGuard namespace unexpectedly resolved a public DNS name\n' >&2
    exit 1
fi
lan_probe=$(printf '192.%s.%s.%s' 168 1 1)
if docker exec "$wg_container" nc -z -w 2 1.1.1.1 443 >/dev/null 2>&1 \
    || docker exec "$wg_container" nc -z -w 2 "$lan_probe" 443 >/dev/null 2>&1; then
    printf 'WireGuard namespace unexpectedly reached LAN or Internet\n' >&2
    exit 1
fi


# An invalid WG_OUTPUT_LOCKDOWN value must fail closed rather than silently
# disabling the policy.
if docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN \
    --cap-add DAC_READ_SEARCH -e WG_OUTPUT_LOCKDOWN=off \
    -e WG_INTERNAL_UPSTREAM_HOST=test-upstream -e WG_INTERNAL_UPSTREAM_PORT=8080 \
    -e WG_LOCAL_PROXY_PORT=18080 -v "$config:/config/wg0.conf:ro" "$image" >/dev/null 2>&1; then
    printf 'WG_OUTPUT_LOCKDOWN=off unexpectedly succeeded\n' >&2
    exit 1
fi

# NAS-controller opt-in: exactly one extra accept, TCP/22 to the literal peer.
start_tunnel "$optin_container" -e WG_CONTROLLER_SSH_PEER=192.0.2.1
optin_rules=$(docker exec "$optin_container" iptables -S OUTPUT | grep '^-A OUTPUT ' || true)
[ "$(printf '%s\n' "$optin_rules" | sed '/^$/d' | wc -l | tr -d ' ')" = 5 ] || {
    printf 'controller opt-in did not yield exactly five accepts\n' >&2
    exit 1
}
printf '%s\n' "$optin_rules" | grep -Fx -- \
    '-A OUTPUT -d 192.0.2.1/32 -p tcp -m tcp --dport 22 -j ACCEPT' >/dev/null
printf '%s\n' "$optin_rules" | grep -F -- '--dport 53' >/dev/null && {
    printf 'controller opt-in retained Docker DNS\n' >&2
    exit 1
}
docker rm -f "$optin_container" >/dev/null
if docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN \
    --cap-add DAC_READ_SEARCH -e WG_CONTROLLER_SSH_PEER=vps.example \
    -e WG_INTERNAL_UPSTREAM_HOST=test-upstream -e WG_INTERNAL_UPSTREAM_PORT=8080 \
    -e WG_LOCAL_PROXY_PORT=18080 -v "$config:/config/wg0.conf:ro" "$image" >/dev/null 2>&1; then
    printf 'non-IPv4 WG_CONTROLLER_SSH_PEER unexpectedly succeeded\n' >&2
    exit 1
fi

# Relay supervision: if socat dies, PID 1 must exit non-zero so Docker's
# restart policy rebuilds the namespace instead of leaving nginx with 502s.
docker exec "$wg_container" pkill -x socat
attempt=0
while [ "$attempt" -lt 40 ] \
    && [ "$(docker inspect --format '{{.State.Running}}' "$wg_container")" = true ]; do
    attempt=$((attempt + 1))
    sleep 0.25
done
[ "$(docker inspect --format '{{.State.Running}}' "$wg_container")" = false ] || {
    printf 'WireGuard entrypoint survived the relay exiting\n' >&2
    exit 1
}
[ "$(docker inspect --format '{{.State.ExitCode}}' "$wg_container")" != 0 ] || {
    printf 'WireGuard entrypoint exited zero after the relay died\n' >&2
    exit 1
}

printf 'WireGuard namespace output allowlist passed\n'
