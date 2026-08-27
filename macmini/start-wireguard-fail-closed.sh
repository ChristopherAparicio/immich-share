#!/bin/sh
# Load and verify the inbound pf policy before bringing up WireGuard. Install as
# root-owned /usr/local/sbin/immich-share-wireguard-start.
set -eu

pf_config=${PF_CONFIG:-/etc/pf.conf}
pf_anchor=${PF_ANCHOR:-wg-inbound}
wg_config=${WG_CONFIG:-/opt/homebrew/etc/wireguard/wg0.conf}
pfctl_bin=${PFCTL_BIN:-/sbin/pfctl}
wg_quick_bin=${WG_QUICK_BIN:-/opt/homebrew/bin/wg-quick}

fail() {
    printf 'immich-share WireGuard startup refused: %s\n' "$1" >&2
    exit 1
}

[ "$(id -u)" = 0 ] || fail "must run as root"
[ -f "$pf_config" ] && [ ! -L "$pf_config" ] || fail "pf.conf is missing or a symlink"
[ -f "/etc/pf.anchors/$pf_anchor" ] && [ ! -L "/etc/pf.anchors/$pf_anchor" ] \
    || fail "pf anchor is missing or a symlink"
[ -f "$wg_config" ] && [ ! -L "$wg_config" ] || fail "WireGuard config is missing or a symlink"
[ "$(stat -f '%Su:%Lp' "$wg_config")" = "root:600" ] \
    || fail "WireGuard config must be root-owned mode 0600"

"$pfctl_bin" -n -f "$pf_config" >/dev/null \
    || fail "pf configuration validation failed"
"$pfctl_bin" -f "$pf_config" >/dev/null \
    || fail "pf configuration load failed"
"$pfctl_bin" -e >/dev/null 2>&1 || true

status=$("$pfctl_bin" -s info 2>/dev/null || true)
printf '%s\n' "$status" | grep -Eq 'Status:[[:space:]]+Enabled' \
    || fail "pf is not enabled"
rules=$("$pfctl_bin" -a "$pf_anchor" -sr 2>/dev/null || true)
printf '%s\n' "$rules" | grep -Eq '(^|[[:space:]])block([[:space:]].*)[[:space:]]in([[:space:]]|$)' \
    || fail "anchor has no inbound block rule"
printf '%s\n' "$rules" | grep -Eq '(^|[[:space:]])pass[[:space:]]+out.*keep state' \
    || fail "anchor has no stateful outbound rule"

# pf is now active and verified. If wg-quick fails, the filter deliberately
# remains enabled and the tunnel remains unavailable.
"$wg_quick_bin" up "$wg_config"
