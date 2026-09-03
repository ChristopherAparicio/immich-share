#!/bin/sh
set -eu

root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
image=${DOWNLOAD_GUARD_TEST_IMAGE:-immich-share-nginx:1.31.4-hardened}
name="download-guard-redaction-$$"
network="$name-net"
share_key=ShareKeySentinel123
query_sentinel=QuerySentinel987
job_id=ABCDEFGHIJKLMNOPQRSTUVWX
asset_id=01234567-89ab-cdef-0123-456789abcdef

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

# The guard resolves `ipp` through Docker's embedded resolver at request time,
# which only exists on a user-defined network. The alias points the name at this
# container, whose closed port 9 yields an immediate upstream connection error.
# The network is internal, so the test has no Internet route.
docker network create --internal "$network" >/dev/null
docker run -d --name "$name" --network "$network" --network-alias ipp \
    -e 'NGINX_ENVSUBST_FILTER=^(DOWNLOAD_|ZIP_|IPP_UPSTREAM$)' \
    -e IPP_UPSTREAM=ipp:9 \
    -e DOWNLOAD_RATE=2m \
    -e DOWNLOAD_RATE_AFTER=1m \
    -e DOWNLOAD_PER_IP=2 \
    -e DOWNLOAD_GLOBAL=6 \
    -e DOWNLOAD_LIMIT_DRY_RUN=off \
    -e ZIP_RATE=2m \
    -e ZIP_RATE_AFTER=1m \
    -e ZIP_GLOBAL=3 \
    -e ZIP_PER_IP=1 \
    -v "$root_dir/vps/download-guard-nginx.conf:/etc/nginx/nginx.conf:ro" \
    -v "$root_dir/vps/download-guard.conf.template:/etc/nginx/templates/default.conf.template:ro" \
    -v "$root_dir/vps/zip-busy.html:/usr/share/nginx/html/zip-busy.html:ro" \
    -v "$root_dir/vps/zip-too-large.html:/usr/share/nginx/html/zip-too-large.html:ro" \
    -v "$root_dir/vps/zip-unavailable.html:/usr/share/nginx/html/zip-unavailable.html:ro" \
    "$image" >/dev/null

# Returns 0 when nginx answered the request with any HTTP status and 1 when
# the connection never reached a listening worker. BusyBox wget exits 1 in
# both cases, so the distinction is made on its diagnostic.
probe() {
    if output=$(docker exec "$name" wget -q -O /dev/null \
        --header='X-Download-Guard: caddy-internal-v1' \
        "$1" 2>&1); then
        return 0
    fi
    case $output in
        *'server returned error'*) return 0 ;;
    esac
    return 1
}

count_502() {
    docker logs "$name" 2>&1 | grep -c 'status=502' || true
}

# Force two upstream connection errors and require each to be recorded as a
# 502 before checking for leaks. A detached container can exist before its
# worker is listening, so the readiness loop re-sends the individual-download
# canary only while the connection is refused. Each canary that reaches nginx
# is sent exactly once and must add exactly one 502 line; a probe that never
# reached nginx would otherwise make the leak check pass vacuously.
wait_for_502_count() {
    attempt=0
    while [ "$(count_502)" -lt "$1" ]; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 50 ]; then
            docker logs "$name" >&2 || true
            printf 'download-guard did not answer the %s canary\n' "$2" >&2
            exit 1
        fi
        sleep 0.1
    done
}

attempt=0
until probe "http://127.0.0.1:8080/share/photo/$share_key/$asset_id/original?key=$query_sentinel"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 50 ]; then
        docker logs "$name" >&2 || true
        printf 'download-guard never accepted a connection\n' >&2
        exit 1
    fi
    sleep 0.1
done
wait_for_502_count 1 individual-download
base=$(count_502)

probe "http://127.0.0.1:8080/share/$share_key/download/jobs/$job_id/file?key=$query_sentinel" \
    || { printf 'ZIP canary did not reach download-guard\n' >&2; exit 1; }
wait_for_502_count $((base + 1)) ZIP

logs=$(docker logs "$name" 2>&1)
case "$logs" in
    *"$share_key"*|*"$query_sentinel"*|*"?key="*|*"/share/"*)
        printf '%s\n' "$logs" >&2
        printf 'download-guard leaked a credential-bearing request target\n' >&2
        exit 1
        ;;
esac

printf 'download-guard upstream-error log redaction passed\n'
