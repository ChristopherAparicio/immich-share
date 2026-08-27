#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
container_name="immich-share-caddy-log-test-$$"
image_name=${CADDY_TEST_IMAGE:-photo-share-caddy}
share_key=redaction-test-share-key
query_secret=redaction-test-query-secret

cleanup() {
	docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --detach --rm \
	--name "$container_name" \
	--user 1000:1000 \
	--read-only \
	--tmpfs /data:uid=1000,gid=1000,mode=0700 \
	--tmpfs /config:uid=1000,gid=1000,mode=0700 \
	--tmpfs /tmp:uid=1000,gid=1000,mode=1777 \
	--publish 127.0.0.1::443 \
	--env PUBLIC_DOMAIN=localhost \
	--volume "$root_dir/vps/Caddyfile:/etc/caddy/Caddyfile:ro" \
	--volume "$root_dir/vps/shares.d:/etc/caddy/shares.d:ro" \
	"$image_name" >/dev/null

host_port=$(docker port "$container_name" 443/tcp | sed -n 's/.*://p' | tail -1)
test -n "$host_port"

attempt=0
while :; do
	attempt=$((attempt + 1))
	if curl --silent --show-error --insecure --output /dev/null \
		--max-time 2 \
		"https://localhost:$host_port/share/$share_key?token=$query_secret&key=$share_key"; then
		break
	fi
	if [ "$attempt" -ge 20 ]; then
		echo "Caddy did not become ready" >&2
		exit 1
	fi
	sleep 1
done

sleep 1
if docker exec "$container_name" grep -Fq "$share_key" /data/access.log; then
	echo "Caddy access log contains the share-key canary" >&2
	exit 1
fi
if docker exec "$container_name" grep -Fq "$query_secret" /data/access.log; then
	echo "Caddy access log contains the query canary" >&2
	exit 1
fi
docker exec "$container_name" grep -Fq '"uri":"REDACTED"' /data/access.log

echo "Caddy access-log redaction test passed"
