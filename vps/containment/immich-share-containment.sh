#!/bin/sh
# immich-share VPS bridge containment.
#
# Installed as /usr/local/sbin/immich-share-containment.sh and run by the
# immich-share-containment.service oneshot (see SETUP.md, section 5,
# "Forwarding containment on the VPS").
#
# The Compose NAT bridges are pinned to fixed interface names: `immich-tunnel`
# (tunnel_net, IPP) in vps/docker-compose.yml and `immich-uptun`
# (upload_tunnel_net, upload-guard) in vps/docker-compose.upload.yml. Without
# extra rules either bridge could reach the whole Internet, the admin peer's
# WireGuard address and the other bridge through the host. This script keeps
# DOCKER-USER, which Docker evaluates before its own FORWARD rules and never
# flushes, in this state:
#
#   -A DOCKER-USER -d <WG_NAS_ADDRESS>/32 -i immich-tunnel -o wg0 -p tcp -m tcp --dport 2283 -m comment --comment immich-share -j ACCEPT
#   -A DOCKER-USER -d <UPLOAD_NAS_WG_ADDRESS>/32 -i immich-uptun -o wg0 -p tcp -m tcp --dport 2383 -m comment --comment immich-share -j ACCEPT
#   -A DOCKER-USER -o wg0 -m comment --comment immich-share -j DROP
#   -A DOCKER-USER -i immich-tunnel -m comment --comment immich-share -j DROP
#   -A DOCKER-USER -i immich-uptun -m comment --comment immich-share -j DROP
#
# The three DROP rules are unconditional; the `immich-uptun` ACCEPT is added
# only when the upload edge is enabled (see CONTAINMENT_UPLOAD below). The
# `-o wg0` DROP closes every other bridge toward the tunnel: Caddy, the only
# Internet-facing parser, sits on `public_net` and must not be able to reach
# the NAS filters on arbitrary ports or the admin peer if it is compromised.
# It keeps its ACME egress because that leaves through the default route, not
# wg0. Rules naming an interface are accepted before the bridge exists, so the
# order of Docker, Compose and this unit does not matter. Replies flow
# wg0 -> bridge through Docker's conntrack ESTABLISHED rule. The wg0 -> wg0
# relay DROP stays in wg0.conf because it belongs to the tunnel, not to Docker.
#
# The script owns exactly the rules it tags with `-m comment --comment
# immich-share` plus any legacy rule that names one of the two pinned bridges
# (earlier releases installed them from wg0.conf PostUp). Every run removes
# those and re-inserts the current set at the top of the chain behind temporary
# DROP guards, so it is idempotent, fails closed during partial updates,
# survives address changes and coexists with other DOCKER-USER users. It never
# flushes the chain and never removes the rules on stop:
# `ufw reload`/`ufw disable` flush Docker's chains, after which Docker and this
# unit must both be restarted.
#
# Configuration (environment overrides the file):
#   CONTAINMENT_ENV_FILE   default /srv/photo-share/.env
#   NAS_WG_ADDRESS         read filter peer address (required)
#   UPLOAD_NAS_WG_ADDRESS  upload filter peer address
#   CONTAINMENT_UPLOAD     auto (default: on when UPLOAD_NAS_WG_ADDRESS is a
#                          real address), on, or off
#
# Usage: immich-share-containment.sh [apply|remove|status]
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

tag=immich-share
stage_tag=immich-share-stage
chain=DOCKER-USER
read_bridge=immich-tunnel
upload_bridge=immich-uptun
read_port=2283
upload_port=2383
env_file=${CONTAINMENT_ENV_FILE:-/srv/photo-share/.env}
action=${1:-apply}

die() {
    printf 'immich-share-containment: %s\n' "$*" >&2
    exit 1
}

ipt() {
    iptables -w 10 "$@"
}

# Last assignment wins, as in Compose. Surrounding quotes are stripped;
# placeholders from vps/.env.example count as unset.
env_value() {
    value=$(sed -n "s/^[[:space:]]*$1=//p" "$env_file" 2>/dev/null | tail -n 1)
    case $value in
        \"*\") value=${value#\"}; value=${value%\"} ;;
        \'*\') value=${value#\'}; value=${value%\'} ;;
    esac
    case $value in
        REPLACE_WITH_*|\<*\>) value= ;;
    esac
    printf '%s' "$value"
}

is_ipv4() (
    case $1 in
        ''|*[!0-9.]*|.*|*.|*..*) return 1 ;;
    esac
    IFS=.
    # shellcheck disable=SC2086
    set -- $1
    [ $# -eq 4 ] || return 1
    for octet do
        [ "$octet" -le 255 ] || return 1
    done
)

# Index (1-based) of the first DOCKER-USER rule this script owns, or nothing.
owned_rule_index() {
    ipt -S "$chain" | awk -v tag="$tag" -v stage="$stage_tag" -v rb="$read_bridge" -v ub="$upload_bridge" '
        /^-A / {
            n++
            if (index($0, " -m comment --comment " stage " ") > 0 ||
                index($0, " -m comment --comment \"" stage "\" ") > 0) {
                next
            }
            if (index($0, " -m comment --comment " tag " ") > 0 ||
                index($0, " -m comment --comment \"" tag "\" ") > 0 ||
                index($0, " -i " rb " ") > 0 ||
                index($0, " -i " ub " ") > 0) {
                print n
                exit
            }
        }'
}

remove_owned_rules() {
    ipt -S "$chain" >/dev/null 2>&1 || return 0
    removed=0
    while :; do
        index=$(owned_rule_index)
        [ -n "$index" ] || break
        ipt -D "$chain" "$index"
        removed=$((removed + 1))
        [ "$removed" -le 256 ] || die "too many owned rules in $chain; refusing to loop"
    done
}

stage_rule_index() {
    ipt -S "$chain" | awk -v stage="$stage_tag" '
        /^-A / {
            n++
            if (index($0, " -m comment --comment " stage " ") > 0 ||
                index($0, " -m comment --comment \"" stage "\" ") > 0) {
                print n
                exit
            }
        }'
}

remove_stage_rules() {
    while :; do
        index=$(stage_rule_index)
        [ -n "$index" ] || break
        ipt -D "$chain" "$index"
    done
}

install_stage_guards() {
    # These temporary DROP rules remain below the new rules until the complete
    # allowlist has been installed. If any later command fails, they remain in
    # place and both bridges fail closed instead of being left uncontained.
    ipt -I "$chain" 1 -i "$read_bridge" -m comment --comment "$stage_tag" -j DROP
    ipt -I "$chain" 1 -i "$upload_bridge" -m comment --comment "$stage_tag" -j DROP
}

position=1
insert_rule() {
    ipt -I "$chain" "$position" "$@" -m comment --comment "$tag"
    position=$((position + 1))
}

load_config() {
    [ -n "${NAS_WG_ADDRESS:-}" ] || NAS_WG_ADDRESS=$(env_value NAS_WG_ADDRESS)
    [ -n "${UPLOAD_NAS_WG_ADDRESS:-}" ] || UPLOAD_NAS_WG_ADDRESS=$(env_value UPLOAD_NAS_WG_ADDRESS)
    [ -n "${CONTAINMENT_UPLOAD:-}" ] || CONTAINMENT_UPLOAD=$(env_value CONTAINMENT_UPLOAD)
    CONTAINMENT_UPLOAD=${CONTAINMENT_UPLOAD:-auto}

    is_ipv4 "$NAS_WG_ADDRESS" \
        || die "NAS_WG_ADDRESS is not an IPv4 address (set it in $env_file or the environment)"

    case $CONTAINMENT_UPLOAD in
        auto)
            if is_ipv4 "$UPLOAD_NAS_WG_ADDRESS"; then
                upload_enabled=1
            else
                upload_enabled=0
            fi
            ;;
        on|1|yes|true)
            is_ipv4 "$UPLOAD_NAS_WG_ADDRESS" \
                || die "CONTAINMENT_UPLOAD=on but UPLOAD_NAS_WG_ADDRESS is not an IPv4 address"
            upload_enabled=1
            ;;
        off|0|no|false)
            upload_enabled=0
            ;;
        *)
            die "CONTAINMENT_UPLOAD must be auto, on or off (got '$CONTAINMENT_UPLOAD')"
            ;;
    esac
}

apply() {
    load_config
    ipt -N "$chain" 2>/dev/null || true
    # Docker inserts this jump itself; restore it when a firewall reload has
    # flushed FORWARD so the chain stays effective until Docker is restarted.
    ipt -C FORWARD -j "$chain" 2>/dev/null || ipt -I FORWARD 1 -j "$chain"
    install_stage_guards
    remove_owned_rules
    position=1
    insert_rule -i "$read_bridge" -o wg0 -d "$NAS_WG_ADDRESS/32" -p tcp --dport "$read_port" -j ACCEPT
    if [ "$upload_enabled" -eq 1 ]; then
        insert_rule -i "$upload_bridge" -o wg0 -d "$UPLOAD_NAS_WG_ADDRESS/32" -p tcp --dport "$upload_port" -j ACCEPT
    fi
    insert_rule -o wg0 -j DROP
    insert_rule -i "$read_bridge" -j DROP
    insert_rule -i "$upload_bridge" -j DROP
    remove_stage_rules
    if [ "$upload_enabled" -eq 1 ]; then
        printf 'immich-share-containment: %s and %s limited to the NAS filter ports\n' "$read_bridge" "$upload_bridge"
    else
        printf 'immich-share-containment: %s limited to the read filter; %s egress dropped (uploads off)\n' "$read_bridge" "$upload_bridge"
    fi
}

case $action in
    apply)
        apply
        ;;
    remove)
        remove_owned_rules
        remove_stage_rules
        printf 'immich-share-containment: owned %s rules removed; bridges are UNCONTAINED\n' "$chain" >&2
        ;;
    status)
        ipt -S "$chain"
        ;;
    *)
        die "usage: $0 [apply|remove|status]"
        ;;
esac
