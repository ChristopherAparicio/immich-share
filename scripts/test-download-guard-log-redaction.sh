#!/bin/sh
set -eu

image=${DOWNLOAD_GUARD_TEST_IMAGE:-immich-share-nginx:1.31.4-hardened}
name="download-guard-redaction-$$"
share_key=ShareKeySentinel123
query_sentinel=QuerySentinel987
job_id=ABCDEFGHIJKLMNOPQRSTUVWX
asset_id=01234567-89ab-cdef-0123-456789abcdef

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker run -d --name "$name" \
    --add-host ipp:127.0.0.1 \
    -e 'NGINX_ENVSUBST_FILTER=^(DOWNLOAD_|ZIP_|IPP_UPSTREAM$)' \
    -e IPP_UPSTREAM=ipp:9 \
    -e DOWNLOAD_RATE=2m \
    -e DOWNLOAD_RATE_AFTER=1m \
    -e DOWNLOAD_PER_IP=2 \
    -e DOWNLOAD_GLOBAL=6 \
    -e DOWNLOAD_LIMIT_DRY_RUN=off \
    -e ZIP_RATE=2m \
    -e ZIP_RATE_AFTER=1m \
    -e ZIP_GLOBAL=1 \
    -v "$PWD/vps/download-guard-nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$PWD/vps/download-guard.conf.template:/etc/nginx/templates/default.conf.template:ro" \
    "$image" >/dev/null

# Force two upstream connection errors. The response code is irrelevant; the
# regression is that neither nginx error output nor its safe access metrics
# contain the path, share key, or query string.
docker exec "$name" wget -q -O /dev/null \
    --header='X-Download-Guard: caddy-internal-v1' \
    "http://127.0.0.1:8080/share/photo/$share_key/$asset_id/original?key=$query_sentinel" \
    2>/dev/null || true
docker exec "$name" wget -q -O /dev/null \
    --header='X-Download-Guard: caddy-internal-v1' \
    "http://127.0.0.1:8080/share/$share_key/download/jobs/$job_id/file?key=$query_sentinel" \
    2>/dev/null || true

logs=$(docker logs "$name" 2>&1)
case "$logs" in
    *"$share_key"*|*"$query_sentinel"*|*"?key="*|*"/share/"*)
        printf '%s\n' "$logs" >&2
        printf 'download-guard leaked a credential-bearing request target\n' >&2
        exit 1
        ;;
esac

printf 'download-guard upstream-error log redaction passed\n'
