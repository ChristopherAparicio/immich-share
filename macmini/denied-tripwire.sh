#!/bin/bash
# Photo-share tripwire: follow the NAS nginx filter's denied.log through the
# forced-command gate and raise a critical ntfy alert. Any entry is an IPP
# request outside the explicit allowlist and a strong signal that the VPS may
# be compromised.
#
# The controller key has no NAS shell: `tripwire follow` is an exact forced
# command that runs a fixed `tail -F -n0` on the NAS. Alerts are coalesced to
# at most one notification per COALESCE_SECONDS, summarising N lines, so a
# scanner cannot turn the alert channel into a flood. SSH diagnostics go to
# stderr (launchd's StandardErrorPath), never to /dev/null.
# Started by local.photo-tripwire with KeepAlive; ntfy runs on the Mac mini.
set -euo pipefail

NTFY="${NTFY_URL:-http://localhost:9095/infra-critical}"
NAS_SSH_TARGET="${NAS_SSH_TARGET:-nas-photo-gate}"
COALESCE_SECONDS="${TRIPWIRE_COALESCE_SECONDS:-60}"
# Interval of the tick sentinel merged into the stream; bounds how late a
# coalesced summary can be. (bash 3.2 on macOS cannot distinguish a `read -t`
# timeout from EOF, so ticks are injected instead of relying on read timeouts.)
TICK_SECONDS=5
TICK=$'\001tick'

log() {
    printf '%s tripwire: %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*" >&2
}

notify() {
    local count=$1 first=$2 body
    if (( count == 1 )); then
        body="1 blocked route requested. ${first}"
    else
        body="${count} blocked routes requested within ${COALESCE_SECONDS}s. First: ${first}"
    fi
    if ! curl -fsS --max-time 5 \
        -H "Title: Photo-share: blocked route requested (VPS compromised?)" \
        -H "Priority: urgent" -H "Tags: rotating_light,camera" \
        --data-raw "$body" "$NTFY" >/dev/null; then
        log "ntfy delivery failed for ${count} line(s)"
    fi
}

# Follow denied.log through the exact forced command and interleave a tick
# sentinel so the consumer can flush a coalesced summary without input. nginx
# escapes control characters in access logs, so a real line never starts with
# the sentinel. SSH stderr is deliberately left attached: a refused forced
# command, a host-key change or an authentication failure must be visible in
# the tripwire log. A non-zero ssh exit (refused gate, missing denied.log on
# the NAS, transport failure) is logged with its status and propagated so the
# script exits 1 and launchd restarts it after ThrottleInterval.
stream() {
    local ssh_pid ssh_status=0
    ssh -o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
        "$NAS_SSH_TARGET" "tripwire follow" &
    ssh_pid=$!
    while kill -0 "$ssh_pid" 2>/dev/null; do
        sleep "$TICK_SECONDS"
        printf '%s\n' "$TICK"
    done
    wait "$ssh_pid" || ssh_status=$?
    if (( ssh_status != 0 )); then
        log "ssh to ${NAS_SSH_TARGET} exited with status ${ssh_status}; its stderr is above"
    fi
    return "$ssh_status"
}

consume() {
    local line pending=0 first='' last_sent=0 now
    while IFS= read -r line; do
        if [[ $line == "$TICK" ]]; then
            :
        elif [[ $line == "127.0.0.1 "* ]]; then
            # The NAS security doctor probes a forbidden route through the
            # filter's private loopback listener, so its refusal is logged with
            # source 127.0.0.1. Skipping these is safe: WireGuard cryptokey
            # routing and the kernel both reject 127/8 sources arriving on a
            # non-loopback interface, so only the doctor (or a process already
            # inside the tunnel namespace) can produce such a line; a VPS-side
            # attacker cannot spoof one to hide a real probe.
            :
        else
            if (( pending == 0 )); then
                first=$line
            fi
            pending=$((pending + 1))
        fi
        if (( pending > 0 )); then
            now=$(date +%s)
            if (( now - last_sent >= COALESCE_SECONDS )); then
                notify "$pending" "$first"
                last_sent=$now
                pending=0
                first=''
            fi
        fi
    done
    if (( pending > 0 )); then
        notify "$pending" "$first"
    fi
}

log "following denied.log through ${NAS_SSH_TARGET}"
if stream | consume; then
    log "denied.log stream ended"
else
    log "denied.log stream failed (see ssh diagnostics above)"
fi
# The stream must never end while the NAS is up; exit non-zero so launchd's
# KeepAlive restarts the follower instead of leaving the tripwire silently dead.
exit 1
