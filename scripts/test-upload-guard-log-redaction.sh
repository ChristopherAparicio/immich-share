#!/bin/sh
set -eu

root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
image=${UPLOAD_GUARD_TEST_IMAGE:-immich-share-nginx:1.31.4-hardened}
name="upload-guard-redaction-$$"
invite_token=UploadTokenSentinel1234567890abcdef
query_sentinel=UploadQuerySentinel987

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker run -d --name "$name" \
    -e 'NGINX_ENVSUBST_FILTER=^UPLOAD_' \
    -e UPLOAD_NAS_WG_ADDRESS=127.0.0.1 \
    -e UPLOAD_MAX_BODY=9m \
    -e UPLOAD_REQUEST_RATE=30r/s \
    -e UPLOAD_PER_IP=2 \
    -e UPLOAD_GLOBAL=6 \
    -v "$root_dir/vps/upload-guard-nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$root_dir/vps/upload-guard.conf.template:/etc/nginx/templates/default.conf.template:ro" \
    "$image" >/dev/null

# Wait until nginx has handled the canary. A detached container can exist a
# moment before its worker is listening; checking only once made CI randomly
# miss the expected normalized action and fail without a leak.
ready=false
attempt=0
while [ "$attempt" -lt 50 ]; do
    docker exec "$name" wget -q -O /dev/null \
        --header='X-Upload-Guard: caddy-internal-v1' \
        --header='X-Client-IP: 192.0.2.123' \
        "http://127.0.0.1:8081/drop/i/$invite_token?token=$query_sentinel" \
        2>/dev/null || true
    logs=$(docker logs "$name" 2>&1)
    if printf '%s\n' "$logs" | grep -F 'action=invite_ui' >/dev/null; then
        ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
[ "$ready" = true ] || {
    printf '%s\n' "$logs" >&2
    printf 'upload guard did not process the redaction canary\n' >&2
    exit 1
}

case "$logs" in
    *"$invite_token"*|*"$query_sentinel"*|*"?token="*|*"/drop/"*)
        printf '%s\n' "$logs" >&2
        printf 'upload-guard leaked a credential-bearing request target\n' >&2
        exit 1
        ;;
esac

printf 'upload-guard upstream-error log redaction passed\n'
