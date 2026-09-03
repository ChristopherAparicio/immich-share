#!/bin/sh
# Load and verify the inbound pf policy before bringing up WireGuard. Install as
# root-owned /usr/local/sbin/immich-share-wireguard-start.
#
# Everything this script executes runs as root, so nothing it runs may live in
# a directory a non-root account can write. Homebrew's prefix is owned by the
# operator account: a root daemon that executed wg-quick (and, through it,
# bash, wg and wireguard-go) from there would let any compromise of that
# account, for example through the photo-share-monitor process, become root at
# the next boot. The starter therefore runs only root-owned copies of those
# tools from TOOL_DIR, reads the tunnel config from a root-owned directory
# outside the Homebrew prefix (see pf-wireguard.md), and refuses to start
# otherwise.
set -eu

pf_config=${PF_CONFIG:-/etc/pf.conf}
pf_anchor=${PF_ANCHOR:-wg-inbound}
tool_dir=${TOOL_DIR:-/usr/local/libexec/immich-share-wireguard}
wg_config=${WG_CONFIG:-/etc/wireguard/wg0.conf}
pfctl_bin=${PFCTL_BIN:-/sbin/pfctl}
wg_quick_bin=$tool_dir/wg-quick

# wg-quick resolves bash (through its shebang), wg and wireguard-go by name.
# Only the root-owned tool directory and the system directories are searched;
# the launchd plist sets the same PATH.
PATH=$tool_dir:/usr/bin:/bin:/usr/sbin:/sbin
export PATH

fail() {
    printf 'immich-share WireGuard startup refused: %s\n' "$1" >&2
    exit 1
}

# A file or directory reached without a symlink, owned by root, and writable
# by neither group nor others.
require_root_owned() {
    path=$1
    what=$2
    [ ! -L "$path" ] || fail "$what is a symlink: $path"
    [ -e "$path" ] || fail "$what is missing: $path"
    owner=$(stat -f '%Su' "$path")
    [ "$owner" = root ] || fail "$what must be owned by root, not $owner: $path"
    mode=$(stat -f '%Lp' "$path")
    [ $(( 0$mode & 022 )) -eq 0 ] \
        || fail "$what must not be group- or world-writable (mode $mode): $path"
}

[ "$(id -u)" = 0 ] || fail "must run as root"
[ -f "$pf_config" ] && [ ! -L "$pf_config" ] || fail "pf.conf is missing or a symlink"
[ -f "/etc/pf.anchors/$pf_anchor" ] && [ ! -L "/etc/pf.anchors/$pf_anchor" ] \
    || fail "pf anchor is missing or a symlink"

require_root_owned "$tool_dir" "tool directory"
[ -d "$tool_dir" ] || fail "tool directory is not a directory: $tool_dir"
for tool in wg-quick bash wg wireguard-go; do
    require_root_owned "$tool_dir/$tool" "$tool"
    [ -f "$tool_dir/$tool" ] && [ -x "$tool_dir/$tool" ] \
        || fail "$tool is not an executable file: $tool_dir/$tool"
    resolved=$(command -v "$tool" || true)
    [ "$resolved" = "$tool_dir/$tool" ] \
        || fail "$tool resolves to '$resolved' instead of $tool_dir/$tool"
done

require_root_owned "$(dirname "$wg_config")" "WireGuard config directory"
require_root_owned "$wg_config" "WireGuard config"
[ -f "$wg_config" ] || fail "WireGuard config is not a regular file: $wg_config"
[ "$(stat -f '%Lp' "$wg_config")" = 600 ] \
    || fail "WireGuard config must be mode 0600: $wg_config"

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
