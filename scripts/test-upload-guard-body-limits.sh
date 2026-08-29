#!/bin/sh
set -eu

image=${UPLOAD_GUARD_TEST_IMAGE:-immich-share-nginx:1.31.4-hardened}
name="upload-guard-body-test-$$"

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker run -d --name "$name" -p 127.0.0.1::8081 \
    -e 'NGINX_ENVSUBST_FILTER=^UPLOAD_' \
    -e UPLOAD_NAS_WG_ADDRESS=127.0.0.1 \
    -e UPLOAD_MAX_BODY=9m \
    -e UPLOAD_REQUEST_RATE=30r/s \
    -e UPLOAD_PER_IP=2 \
    -e UPLOAD_GLOBAL=6 \
    -v "$PWD/vps/upload-guard-nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$PWD/vps/upload-guard.conf.template:/etc/nginx/templates/default.conf.template:ro" \
    "$image" >/dev/null

port=$(docker port "$name" 8081/tcp | sed -n 's/.*://p' | tail -1)
test -n "$port"

# Oversized JSON is rejected at 4 KiB. A small PATCH reaches the deliberately
# absent upstream (502), proving it inherited the separate 9-MiB chunk ceiling.
# A ten-million-byte PATCH exceeds that ceiling and is rejected locally.
json_status=$(head -c 5000 /dev/zero | tr '\0' x | curl -s -o /dev/null -w '%{http_code}' \
    -H 'X-Upload-Guard: caddy-internal-v1' -H 'Content-Type: application/json' \
    --data-binary @- \
    'http://127.0.0.1:'"$port"'/drop/api/invites/UploadTokenSentinel1234567890abcdef/unlock')
chunk_status=$(head -c 5000 /dev/zero | curl -s -o /dev/null -w '%{http_code}' \
    -X PATCH -H 'X-Upload-Guard: caddy-internal-v1' --data-binary @- \
    'http://127.0.0.1:'"$port"'/drop/api/uploads/01234567-89ab-cdef-0123-456789abcdef')
oversized_status=$(head -c 10000000 /dev/zero | curl -s -o /dev/null -w '%{http_code}' \
    -X PATCH -H 'X-Upload-Guard: caddy-internal-v1' --data-binary @- \
    'http://127.0.0.1:'"$port"'/drop/api/uploads/01234567-89ab-cdef-0123-456789abcdef')

[ "$json_status" = 413 ] || { echo "expected JSON 413, got $json_status" >&2; exit 1; }
[ "$chunk_status" = 502 ] || { echo "expected chunk upstream 502, got $chunk_status" >&2; exit 1; }
[ "$oversized_status" = 413 ] || { echo "expected chunk 413, got $oversized_status" >&2; exit 1; }

printf 'upload-guard JSON and chunk body ceilings passed\n'
