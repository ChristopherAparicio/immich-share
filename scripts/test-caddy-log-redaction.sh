#!/bin/sh
set -eu

root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
container_name="immich-share-caddy-log-test-$$"
image_name=${CADDY_TEST_IMAGE:-photo-share-caddy}
share_key=redaction_test_key_1234
drop_token=redaction-test-upload-token-1234567890
query_secret=redaction-test-query-secret
temporary_directory=$(mktemp -d)
rendered_config=$temporary_directory/Caddyfile

cleanup() {
	docker rm -f "$container_name" >/dev/null 2>&1 || true
	rm -f "$rendered_config"
	rmdir "$temporary_directory" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

python3 "$root_dir/scripts/render-caddy-test-config.py" > "$rendered_config"

docker run --detach --rm \
	--name "$container_name" \
	--user 1000:1000 \
	--read-only \
	--tmpfs /data:uid=1000,gid=1000,mode=0700 \
	--tmpfs /config:uid=1000,gid=1000,mode=0700 \
	--tmpfs /tmp:uid=1000,gid=1000,mode=1777 \
	--publish 127.0.0.1::443 \
	--env PUBLIC_DOMAIN=localhost \
	--add-host ipp:127.0.0.1 \
	--add-host download-guard:127.0.0.1 \
	--add-host upload-guard:127.0.0.1 \
	--volume "$rendered_config:/etc/caddy/Caddyfile:ro" \
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

curl --silent --show-error --insecure --output /dev/null \
	--max-time 2 \
	"https://localhost:$host_port/drop/i/$drop_token?token=$query_secret"

sleep 1
runtime_logs=$(docker logs "$container_name" 2>&1)
if docker exec "$container_name" grep -Fq "$share_key" /data/access.log \
	|| printf '%s\n' "$runtime_logs" | grep -Fq "$share_key"; then
	echo "Caddy access log contains the share-key canary" >&2
	exit 1
fi
if docker exec "$container_name" grep -Fq "$query_secret" /data/access.log \
	|| printf '%s\n' "$runtime_logs" | grep -Fq "$query_secret"; then
	echo "Caddy access log contains the query canary" >&2
	exit 1
fi
if docker exec "$container_name" grep -Fq "$drop_token" /data/access.log \
	|| printf '%s\n' "$runtime_logs" | grep -Fq "$drop_token"; then
	echo "Caddy access log contains the upload-token canary" >&2
	exit 1
fi
docker exec "$container_name" grep -Fq '"uri":"REDACTED"' /data/access.log
printf '%s\n' "$runtime_logs" | grep -Fq '"uri":"REDACTED"'

echo "Caddy access and runtime log redaction test passed"
