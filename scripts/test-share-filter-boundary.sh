#!/bin/sh
# Runtime check of the NAS read filter (nas/nginx-filter.conf): the trust
# boundary must forward the normalized path only, keep share-key semantics by
# dropping every credential except the shared-link token cookie, refuse
# non-allowlisted and non-canonical targets, and never log a share key.
set -eu

image=${SHARE_FILTER_TEST_IMAGE:-immich-share-nginx:1.31.4-hardened}
upstream_image=${SHARE_FILTER_UPSTREAM_IMAGE:-python:3.12-alpine}
name="share-filter-boundary-$$"
upstream_name="$name-upstream"
logs_dir=$(mktemp -d)
chmod 0777 "$logs_dir"
share_key=ShareFilterKey1234567890abcdef
link_token=ShareFilterLinkToken0123456789
session_cookie=ShareFilterUserSession987
bearer=ShareFilterBearer654
api_key=ShareFilterApiKey321
asset=01234567-89ab-cdef-0123-456789abcdef
requests_log=$logs_dir/upstream-requests.log

cleanup() {
    docker rm -f "$upstream_name" "$name" >/dev/null 2>&1 || true
    rm -f "$logs_dir"/*.log "$logs_dir"/upstream.py
    rmdir "$logs_dir" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

# Records the exact request line and headers Immich would have received.
cat > "$logs_dir/upstream.py" <<'PY'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _record(self):
        with open("/out/upstream-requests.log", "a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "line": self.requestline,
                "headers": {k.lower(): v for k, v in self.headers.items()},
            }) + "\n")
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _record
    do_POST = _record


HTTPServer(("127.0.0.1", 18080), Echo).serve_forever()
PY

docker run -d --name "$name" -p 127.0.0.1::2283 \
    -e 'NGINX_ENVSUBST_FILTER=^(NAS_WG_ADDRESS|IMMICH_UPSTREAM)$' \
    -e NAS_WG_ADDRESS=0.0.0.0 \
    -e IMMICH_UPSTREAM=127.0.0.1:18080 \
    -v "$PWD/nas/nginx-filter.conf:/etc/nginx/templates/default.conf.template:ro" \
    -v "$logs_dir:/var/log/nginx" \
    "$image" >/dev/null
docker run -d --name "$upstream_name" --network "container:$name" \
    -v "$logs_dir:/out" "$upstream_image" \
    python3 /out/upstream.py >/dev/null

port=$(docker port "$name" 2283/tcp | sed -n 's/.*://p' | tail -1)
test -n "$port"

ready=false
attempt=0
while [ "$attempt" -lt 100 ]; do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/api/server/ping" || true)" = 200 ]; then
        ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
[ "$ready" = true ] || {
    docker logs "$name" >&2 || true
    docker logs "$upstream_name" >&2 || true
    echo "NAS read filter or echo upstream did not become ready" >&2
    exit 1
}

status() {
    curl -s -o /dev/null -w '%{http_code}' --path-as-is "$@" || true
}
expect() {
    [ "$1" = "$2" ] || { echo "$3: expected $2, got $1" >&2; exit 1; }
}
last_request() {
    tail -n 1 "$requests_log"
}

# 1. Credentials: only the shared-link token cookie crosses the boundary.
: > "$requests_log"
expect "$(status \
    -H "Cookie: immich_access_token=$session_cookie; immich_shared_link_token=$link_token; ipp-csrf=x" \
    -H "Authorization: Bearer $bearer" \
    -H "x-api-key: $api_key" \
    -H "x-immich-user-token: $session_cookie" \
    "http://127.0.0.1:$port/api/shared-links/me?key=$share_key")" 200 "allowlisted route"
seen=$(last_request)
printf '%s\n' "$seen" | grep -Fq "\"cookie\": \"immich_shared_link_token=$link_token\"" \
    || { echo "shared-link token cookie was not forwarded alone: $seen" >&2; exit 1; }
for secret in "$session_cookie" "$bearer" "$api_key"; do
    if printf '%s\n' "$seen" | grep -Fq "$secret"; then
        echo "credential crossed the trust boundary: $secret in $seen" >&2
        exit 1
    fi
done
printf '%s\n' "$seen" | grep -Fq "\"line\": \"GET /api/shared-links/me?key=$share_key HTTP/1.1\"" \
    || { echo "unexpected forwarded request line: $seen" >&2; exit 1; }

# 2. Non-canonical targets that normalize inside the allowlist are forwarded
#    normalized, never verbatim.
for target in '//api//server//version' '/api/users/../server/version' '/api/%73erver/version'; do
    : > "$requests_log"
    expect "$(status "http://127.0.0.1:$port$target")" 200 "normalized target $target"
    printf '%s\n' "$(last_request)" | grep -Fq '"line": "GET /api/server/version HTTP/1.1"' \
        || { echo "raw target forwarded for $target: $(last_request)" >&2; exit 1; }
done

# 3. Refusals: outside the allowlist, wrong method, trailing newline, case.
for target in '/api/users' '/api/albums' '/api/auth/login' '/api/server/version%0A' \
    '/API/server/version' '/api/assets' "/api/assets/$asset/download" '/api/server/version;x'; do
    expect "$(status "http://127.0.0.1:$port$target")" 404 "forbidden target $target"
done
expect "$(status -X DELETE "http://127.0.0.1:$port/api/shared-links/me")" 404 "forbidden method"
expect "$(status -X POST "http://127.0.0.1:$port/api/shared-links/login?key=$share_key")" 200 "login route"
expect "$(status "http://127.0.0.1:$port/api/assets/$asset/thumbnail?key=$share_key")" 200 "asset thumbnail"

# 4. Logs keep method + normalized path only; the share key and secrets never appear.
sleep 1
if grep -R -E "$share_key|$link_token|$session_cookie|$bearer|$api_key" \
        "$logs_dir/allowed.log" "$logs_dir/denied.log" 2>/dev/null \
    || docker logs "$name" 2>&1 | grep -E "$share_key|$link_token|$session_cookie|$bearer|$api_key" >/dev/null; then
    echo "NAS read filter leaked a credential into its logs" >&2
    exit 1
fi
grep -F '"GET /api/users"' "$logs_dir/denied.log" >/dev/null
grep -F '"GET /api/shared-links/me"' "$logs_dir/allowed.log" >/dev/null

printf 'NAS read filter credential stripping, normalization, refusals and redaction passed\n'
