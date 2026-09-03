#!/bin/sh
# Forced command for the separate controller's dedicated NAS SSH key.
# Install root-owned as /usr/local/sbin/immich-share-forward-command. The gate
# account must use the narrow sudoers policy; never add it to the Docker group.
set -eu

# Fixed search path: this is the only program the gate key may run.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

container=wg-nginx-filter
# Fixed tripwire source. Point /var/log/immich-share at the deployed nas/logs
# directory (symlink or bind mount); the path itself is never caller-supplied.
denied_log=/var/log/immich-share/denied.log

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
    "tripwire follow")
        # Streams only new sanitized refusal lines (method + normalized path);
        # no history, no other file, no shell. Root is needed because logs/ is
        # mode 0750 and owned by the nginx UID. `tail -F` would wait forever
        # for a missing file, leaving the tripwire silently dead; refuse
        # instead so the controller logs it and launchd retries.
        /usr/bin/sudo -n /usr/bin/test -f "$denied_log" || {
            printf 'tripwire source missing or unreadable: %s\n' "$denied_log" >&2
            exit 65
        }
        exec /usr/bin/sudo -n /usr/bin/tail -F -n0 "$denied_log"
        ;;
    *)
        printf 'Denied command\n' >&2
        exit 64
        ;;
esac
