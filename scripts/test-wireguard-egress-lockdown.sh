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
sidecar_container=wg-egress-sidecar-$suffix
temporary_directory=$(mktemp -d)
config=$temporary_directory/wg0.conf

cleanup() {
    docker rm -f "$sidecar_container" "$wg_container" "$upstream_container" >/dev/null 2>&1 || true
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

docker create --name "$wg_container" --network "$egress_network" \
    --read-only --cap-drop ALL --cap-add NET_ADMIN --cap-add DAC_READ_SEARCH \
    --security-opt no-new-privileges:true --sysctl net.ipv4.ip_forward=0 \
    --tmpfs /run:size=2m --tmpfs /tmp:size=2m \
    -e WG_OUTPUT_LOCKDOWN=true \
    -e WG_INTERNAL_UPSTREAM_HOST=test-upstream \
    -e WG_INTERNAL_UPSTREAM_PORT=8080 \
    -e WG_LOCAL_PROXY_PORT=18080 \
    -v "$config:/config/wg0.conf:ro" "$image" >/dev/null
docker network connect "$data_network" "$wg_container"
docker start "$wg_container" >/dev/null

ready=false
attempt=0
while [ "$attempt" -lt 120 ]; do
    if docker exec "$wg_container" iptables -S OUTPUT 2>/dev/null \
        | grep -Fx -- '-P OUTPUT DROP' >/dev/null \
        && docker exec "$wg_container" nc -z -w 1 127.0.0.1 18080 >/dev/null 2>&1; then
        ready=true
        break
    fi
    [ "$(docker inspect --format '{{.State.Running}}' "$wg_container" 2>/dev/null || true)" = true ] \
        || break
    attempt=$((attempt + 1))
    sleep 0.25
done
[ "$ready" = true ] || {
    docker logs "$wg_container" >&2
    docker inspect --format 'state={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' \
        "$wg_container" >&2 || true
    exit 1
}

upstream_ip=$(docker inspect --format \
    "{{with index .NetworkSettings.Networks \"$data_network\"}}{{.IPAddress}}{{end}}" \
    "$upstream_container")
policy=$(docker exec "$wg_container" iptables -S OUTPUT)
append_rules=$(printf '%s\n' "$policy" | grep '^-A OUTPUT ' || true)
[ "$(printf '%s\n' "$append_rules" | sed '/^$/d' | wc -l | tr -d ' ')" = 4 ]
printf '%s\n' "$append_rules" | grep -Fx -- '-A OUTPUT -o lo -j ACCEPT' >/dev/null
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

printf 'WireGuard namespace output allowlist passed\n'
