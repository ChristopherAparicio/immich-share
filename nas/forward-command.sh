#!/bin/sh
# Forced command for the separate controller's dedicated NAS SSH key.
# Install root-owned as /usr/local/sbin/immich-share-forward-command. The gate
# account must use the narrow sudoers policy; never add it to the Docker group.
set -eu

container=wg-nginx-filter

case "${SSH_ORIGINAL_COMMAND:-}" in
    "forward on")
        exec /usr/bin/sudo -n /usr/bin/docker start "$container"
        ;;
    "forward off")
        exec /usr/bin/sudo -n /usr/bin/docker stop --time 10 "$container"
        ;;
    "forward status")
        exec /usr/bin/sudo -n /usr/bin/docker inspect --format '{{.State.Running}}' "$container"
        ;;
    "doctor")
        exec /usr/bin/sudo -n /usr/local/sbin/immich-share-security-doctor
        ;;
    "upload on")
        exec /usr/bin/sudo -n /usr/bin/docker start wg-upload-filter
        ;;
    "upload off")
        exec /usr/bin/sudo -n /usr/bin/docker stop --time 10 wg-upload-filter
        ;;
    "upload status")
        exec /usr/bin/sudo -n /usr/bin/docker inspect --format '{{.State.Running}}' wg-upload-filter
        ;;
    "upload doctor")
        exec /usr/bin/sudo -n /usr/local/sbin/immich-share-upload-security-doctor
        ;;
    "upload admin open")
        exec /usr/bin/sudo -n /usr/local/sbin/immich-share-upload-admin open
        ;;
    "upload admin list")
        exec /usr/bin/sudo -n /usr/local/sbin/immich-share-upload-admin list
        ;;
    "upload admin close")
        exec /usr/bin/sudo -n /usr/local/sbin/immich-share-upload-admin close
        ;;
    "upload admin sweep")
        exec /usr/bin/sudo -n /usr/local/sbin/immich-share-upload-admin sweep
        ;;
    *)
        printf 'Denied command\n' >&2
        exit 64
        ;;
esac
