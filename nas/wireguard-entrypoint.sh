#!/bin/sh
set -eu

config=/config/wg0.conf
[ -r "$config" ] || {
    printf 'WireGuard configuration is missing: %s\n' "$config" >&2
    exit 1
}

down() {
    wg-quick down "$config" >/dev/null 2>&1 || true
}

trap down EXIT INT TERM
wg-quick up "$config"

while :; do
    sleep 3600 &
    wait "$!"
done
