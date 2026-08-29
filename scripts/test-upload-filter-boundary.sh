#!/bin/sh
set -eu

image=${UPLOAD_FILTER_TEST_IMAGE:-immich-share-nginx:1.31.4-hardened}
name="upload-filter-boundary-$$"
logs_dir=$(mktemp -d)
chmod 0777 "$logs_dir"
invite_token=UploadFilterToken1234567890abcdef
query_sentinel=UploadFilterQuery987

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -f "$logs_dir/allowed.log" "$logs_dir/denied.log"
    rmdir "$logs_dir" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker run -d --name "$name" -p 127.0.0.1::2383 \
    --add-host upload-drop:127.0.0.1 \
    -e 'NGINX_ENVSUBST_FILTER=^(UPLOAD_|DROP_UPSTREAM$)' \
    -e UPLOAD_NAS_WG_ADDRESS=0.0.0.0 \
    -e DROP_UPSTREAM=upload-drop:8080 \
    -e UPLOAD_FILTER_MAX_BODY=9m \
    -e UPLOAD_FILTER_REQUEST_RATE=30r/s \
    -e UPLOAD_FILTER_PER_IP=2 \
    -e UPLOAD_FILTER_GLOBAL=6 \
    -v "$PWD/nas/upload-filter.conf:/etc/nginx/templates/default.conf.template:ro" \
    -v "$logs_dir:/var/log/nginx" \
    "$image" >/dev/null

port=$(docker port "$name" 2383/tcp | sed -n 's/.*://p' | tail -1)
test -n "$port"

forbidden_status=$(curl -s -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$port/api/admin?token=$query_sentinel")
json_status=$(head -c 5000 /dev/zero | tr '\0' x | curl -s -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/json' --data-binary @- \
    "http://127.0.0.1:$port/drop/api/invites/$invite_token/unlock")
chunk_status=$(head -c 5000 /dev/zero | curl -s -o /dev/null -w '%{http_code}' \
    -X PATCH --data-binary @- \
    "http://127.0.0.1:$port/drop/api/uploads/01234567-89ab-cdef-0123-456789abcdef")
oversized_status=$(head -c 10000000 /dev/zero | curl -s -o /dev/null -w '%{http_code}' \
    -X PATCH --data-binary @- \
    "http://127.0.0.1:$port/drop/api/uploads/01234567-89ab-cdef-0123-456789abcdef" \
    || true)

[ "$forbidden_status" = 404 ] || { echo "expected refusal 404, got $forbidden_status" >&2; exit 1; }
[ "$json_status" = 413 ] || { echo "expected JSON 413, got $json_status" >&2; exit 1; }
[ "$chunk_status" = 502 ] || { echo "expected chunk upstream 502, got $chunk_status" >&2; exit 1; }
[ "$oversized_status" = 413 ] || { echo "expected chunk 413, got $oversized_status" >&2; exit 1; }

sleep 1
if grep -R -E "$invite_token|$query_sentinel|/drop/|/api/admin" "$logs_dir" >/dev/null 2>&1 \
    || docker logs "$name" 2>&1 | grep -E "$invite_token|$query_sentinel|/drop/|/api/admin" >/dev/null; then
    echo "NAS upload filter leaked a credential-bearing request target" >&2
    exit 1
fi
grep -F 'action=denied' "$logs_dir/denied.log" >/dev/null

printf 'NAS upload filter refusal, redaction, and body ceilings passed\n'
