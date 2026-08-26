#!/bin/bash
# Photo-share tripwire: follow the NAS nginx filter's denied.log and send one
# critical ntfy alert per line. Any entry is an IPP request outside the explicit
# allowlist and a strong signal that the VPS may be compromised.
# Started by local.photo-tripwire with KeepAlive; ntfy runs on the Mac mini.
NTFY="http://localhost:9095/infra-critical"
: "${NAS_LOG:?set NAS_LOG to the private NAS denied-log path}"
NAS_SSH_TARGET="${NAS_SSH_TARGET:-nas}"
ssh -o BatchMode=yes -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes \
  "$NAS_SSH_TARGET" "tail -F -n0 $NAS_LOG" 2>/dev/null | \
while IFS= read -r line; do
  curl -s -H "Title: ⚠️ Photo-share: blocked route requested (VPS compromised?)" \
       -H "Priority: urgent" -H "Tags: rotating_light,camera" \
       -d "$line" "$NTFY" >/dev/null
done
