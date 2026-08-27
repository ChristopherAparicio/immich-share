#!/bin/sh
# Forced command for the separate controller's dedicated NAS SSH key.
# Install root-owned as /usr/local/sbin/immich-share-forward-command. The gate
# account must use the narrow sudoers policy; never add it to the Docker group.
set -eu

container=wg-nginx-filter

case "${SSH_ORIGINAL_COMMAND:-}" in
    "forward on")
        exec sudo -n /usr/bin/docker start "$container"
        ;;
    "forward off")
        exec sudo -n /usr/bin/docker stop --time 10 "$container"
        ;;
    "forward status")
        exec sudo -n /usr/bin/docker inspect --format '{{.State.Running}}' "$container"
        ;;
    "doctor")
        exec sudo -n /usr/local/sbin/immich-share-security-doctor
        ;;
    *)
        printf 'Denied command\n' >&2
        exit 64
        ;;
esac
