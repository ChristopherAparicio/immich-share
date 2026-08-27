# Complete immich-share setup

This runbook is ordered so either a human operator or a coding agent can deploy
the project without exposing Immich or opening inbound ports at home.

## 0. Installation questionnaire

Before changing any system, collect the following values. An agent following
this runbook should ask only for missing values, explain each proposed network
change, and never ask the operator to paste a private key or API key into chat.

| Area | Required information |
|---|---|
| Public edge | VPS provider, operating system, public address, SSH user, domain |
| Provider firewall | Whether TCP 80/443 and the chosen WireGuard UDP port can be opened |
| Home | NAS host, Immich URL, and ability to add a dedicated Docker network to `immich_server` |
| Administration | Controller placement (`separate` or `nas`), SSH aliases, and a private WireGuard subnet/address plan kept outside Git |
| Immich | Scoped API-key file path; shared-link and album-read permissions |
| Sharing policy | Default TTL, downloads enabled or disabled, gallery/download quality |
| ZIP policy | Maximum ZIP size, free-disk reserve, cache TTL, bandwidth and concurrency |
| Monitor | Loopback or encrypted-tailnet bind, allowed hostnames, and local password-file path |

Recommended defaults for a small VPS are already included in the repository:
2 GiB maximum ZIP contents, a 5 GiB disk reserve, a 30-minute cache, one active
ZIP lifecycle plus three waiting visitors, and 2 MiB/s per ZIP. The installer
must adjust them when the VPS disk or home upload is smaller.

The repository currently provides an operations CLI, not an interactive
installer. Deployment therefore follows this runbook and copies
`config.example.ini`, `vps/.env.example`, and `nas/.env.example`. The CLI then
manages shares with `open`, `list`, `adopt`, `sync`, `close`, and `sweep`.

## 1. Order the VPS and configure DNS

- Use a small Debian VPS. Debian 13 is the tested baseline.
- Confirm the provider terms and included disk size before ordering.
- Create `A photos.example.com → <VPS_PUBLIC_IP>` and an `AAAA` record only when
  IPv6 is configured end to end.
- Test the provider's emergency web console before hardening SSH. It is the
  recovery path if the tunnel is misconfigured.
- In the provider firewall, allow TCP 80/443 and UDP `<WG_LISTEN_PORT>`. TCP 80
  is used for ACME HTTP-01 and redirects; the private operator configuration
  supplies the WireGuard port.

## 2. First access and VPS hardening

Create a dedicated SSH key on the administration machine:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/vps-photos -C "vps-photos"
```

Initial `~/.ssh/config` entry:

```sshconfig
Host vps-photos
    HostName <VPS_PUBLIC_IP>
    User debian
    IdentityFile ~/.ssh/vps-photos
    ForwardAgent no
    IdentitiesOnly yes
```

On the VPS:

```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install wireguard ufw unattended-upgrades docker.io docker-compose-v2
sudo dpkg-reconfigure -plow unattended-upgrades

# Avoid writing fragments of transient photos to swap.
sudo swapoff -a

# Key-only SSH.
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl reload ssh

sudo ufw default deny incoming
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow <WG_LISTEN_PORT>/udp
sudo ufw allow 22/tcp    # Temporary; removed after WireGuard is verified.
sudo ufw enable
```

Remove any swap entry from `/etc/fstab` using the operator's preferred editor.

## 3. WireGuard topology

The VPS is the hub. In the recommended separate-controller profile, the NAS and
administration machine each have their own peer; there is no inbound port
forwarding at home.

```text
Admin <WG_CONTROLLER_ADDRESS> ── WireGuard ──┐
                                                ├── VPS <WG_VPS_ADDRESS>
NAS   <WG_NAS_ADDRESS>        ── WireGuard ──┘
```

Choose the private subnet and all three addresses locally. Do not commit those
values; replace the `<WG_...>` placeholders only in deployed copies.

1. Generate one key pair per machine with
   `wg genkey | tee private.key | wg pubkey > public.key`.
2. Copy `vps/wireguard/wg0-vps.conf` to `/etc/wireguard/wg0.conf` on the VPS,
   replace placeholders, then run `sudo systemctl enable --now wg-quick@wg0`.
3. Create a dedicated external Docker network named `immich_share`. Persistently
   attach only `immich_server` (with the `immich_server` alias) and the NAS
   tunnel stack to it. PostgreSQL, Redis, and unrelated NAS services must remain
   absent. For a standard Immich Compose service, merge this override and then
   recreate `immich-server`:

   ```yaml
   services:
     immich-server:
       networks:
         default:
         immich_share:
           aliases: [immich_server]
   networks:
     immich_share:
       external: true
       name: immich_share
   ```

   Create the network once with `docker network create immich_share`. Deploy
   `nas/docker-compose.yml`, all three `nas/Dockerfile.*` files,
   `nas/wireguard-entrypoint.sh`, `nas/nginx-filter.conf`, `nas/logrotate.conf`,
   `nas/logrotate-entrypoint.sh`, and `nas/wg0-nas.conf` next to Immich. Copy
   `nas/.env.example` to `nas/.env`; set the private `NAS_WG_ADDRESS`, and change
   `IMMICH_SHARE_DOCKER_NETWORK` only if the dedicated network has another
   name. `nginx-filter.conf` is an envsubst template, so the real address stays
   only in the ignored `.env`. Create `logs/` owned by UID/GID 101 with mode
   0750 and grant the
   tripwire account read access without making it world-readable. Inside the
   tunnel container, verify `sysctl net.ipv4.ip_forward` returns `0`.
   When replacing an existing bind-mounted `nginx-filter.conf` atomically,
   recreate only the filter with
   `docker compose up -d --no-deps --force-recreate nginx-filter`; an nginx
   reload can otherwise keep reading the previous bind-mounted inode. Repeat
   the query-sentinel log test after every filter update.
4. Import `macmini/wg0-macmini.conf` on the admin machine and apply
   `macmini/pf-wireguard.md`.
5. From the NAS and admin machine, verify `ping <WG_VPS_ADDRESS>`. Inspect handshakes
   on the VPS with `sudo wg show`.

For the optional NAS-controller profile, keep the data tunnel in its container
and transport controller SSH with
`ProxyCommand docker exec -i wg-tunnel nc %h %p`. This avoids exposing SSH
publicly or mounting the Docker socket into another container. Follow
`nas/controller/README.md`; run its read-only preflight before installing any
controller secret on the NAS.

For the recommended separate controller, do not grant its SSH key an ordinary
NAS shell or arbitrary Docker commands. Install `nas/forward-command.sh` as
root-owned `/usr/local/sbin/immich-share-forward-command`, create a dedicated
`immich-share-gate` account, and do **not** add it to the root-equivalent Docker
group. Validate and install `nas/sudoers-forward-gate.example` so the account
may only start, stop, or inspect `wg-nginx-filter`; prefix the key in
`authorized_keys` exactly as shown by `nas/ssh-forward-gate.example`. Merge
`nas/ssh-config-controller.example` on the controller. Test `forward status`,
then verify that `uname`, an interactive shell, port forwarding, agent
forwarding, and PTY allocation are all refused.

Install the helper with owner `root:root` and mode 0755. Validate the sudoers
file with `visudo -cf` before installing it as root-owned mode 0440 under
`/etc/sudoers.d/`; a syntax error there can break administrative sudo access.

## 4. Move SSH into WireGuard

The command order is critical. Removing the generic port-22 rule before adding
the interface-specific rule locks the operator out. Set and test the provider
console password first.

```bash
sudo ufw allow in on wg0 to any port 22 proto tcp
echo "ListenAddress <WG_VPS_ADDRESS>" | sudo tee -a /etc/ssh/sshd_config
# If the image uses ssh.socket, switch to the service first:
# sudo systemctl disable --now ssh.socket
# sudo systemctl enable --now ssh.service
sudo systemctl restart ssh
sudo ufw delete allow 22/tcp
sudo ss -tlnp | grep :22
```

Update the admin machine's SSH entry to `HostName <WG_VPS_ADDRESS>`. A workstation
without its own WireGuard peer can use the admin machine as a jump host:

```sshconfig
Host vps-photos
    HostName <WG_VPS_ADDRESS>
    ProxyJump youruser@<ADMIN_HOST>
    User debian
    IdentityFile ~/.ssh/vps-photos
    ForwardAgent no
```

## 5. Deploy Caddy, IPP, and the download guard

Choose the global quality profile in `vps/ipp-config.json`:

- `maxZoomQuality: "preview"` keeps gallery browsing light.
- `maxDownloadQuality: "original"` returns original files, including any
  embedded EXIF/GPS metadata.
- `maxDownloadQuality: "fullsize"` is an intermediate browser-friendly tier
  and is not guaranteed to reproduce original bytes for every asset.
- `maxDownloadQuality: "preview"` is preferable when stripping embedded
  metadata matters more than full resolution.

Recent Immich releases require shared-link metadata permission when original
downloads are enabled because the original may contain EXIF/GPS. The CLI sets
`showMetadata: true` with `--download` and `false` with `--no-download`. IPP
still hides metadata fields in the gallery; it cannot remove metadata embedded
inside an original download.

On the VPS:

```bash
# When upgrading an existing deployment that used named Caddy volumes, stop
# here and copy the current /data and /config contents out of the running caddy
# container before replacing it. This preserves ACME account and certificate
# state and avoids unnecessary reissuance.
sudo mkdir -p /srv/photo-share/shares.d /srv/photo-share/zip-staging \
  /srv/photo-share/caddy-data /srv/photo-share/caddy-config
sudo chown -R "$USER" /srv/photo-share
sudo chown 1000:1000 /srv/photo-share/zip-staging \
  /srv/photo-share/caddy-data /srv/photo-share/caddy-config
sudo chmod 0700 /srv/photo-share/zip-staging \
  /srv/photo-share/caddy-data /srv/photo-share/caddy-config
```

For an upgrade, use `docker cp caddy:/data/. /srv/photo-share/caddy-data/` and
the equivalent command for `/config`, then repeat the ownership and mode
commands above before recreating Caddy. Back up the two directories first.

Copy these repository files to `/srv/photo-share/`:

```text
vps/docker-compose.yml
vps/Dockerfile.caddy
vps/Dockerfile.nginx
vps/Caddyfile
vps/ipp-config.json
vps/download-guard.conf.template
vps/download-guard-nginx.conf
vps/zip-*.html
```

Copy `vps/.env.example` to `/srv/photo-share/.env`, set `PUBLIC_DOMAIN` and the
private `NAS_WG_ADDRESS`, then adjust resource ceilings if needed. The ignored
deployment `.env` is the only Compose source that should contain the real
WireGuard address. Resource ceilings are limits, not reservations.

```bash
cd /srv/photo-share
docker compose up -d --build
docker compose exec -T caddy caddy validate --config /etc/caddy/Caddyfile
docker compose exec -T download-guard nginx -t
```

After a routing change, run `./immich-share sync` on the admin machine. It
regenerates snippets only for links recorded in the local managed-share state;
it never publishes an unrelated Immich link.

Images and upstream versions are pinned. IPP source and releases live in the
separate AGPL fork linked from `THIRD_PARTY_NOTICES.md`. Updating IPP is an
explicit operation: validate the fork release, change the immutable GHCR
digest, and retest ZIP responses for 200, 206, 413, 429, and 507.

### Download limits and resumable ZIPs

Caddy sends only individual originals, the legacy `/share/<key>/download`
endpoint, and prepared `/share/<key>/download/jobs/<id>/file` responses to the
nginx download guard. Gallery HTML, thumbnails, preview zoom, metadata, and the
bounded queue-control endpoints go directly to IPP and are not throttled.

The HTTPS listener uses HTTP/1.1 and HTTP/2. Long ZIP downloads were observed to
be unreliable in Safari iOS over HTTP/3, while TCP-based HTTP/2 completed and
supports standard range retries.

Small-VPS defaults in `vps/.env.example`:

- `DOWNLOAD_RATE=2m`: 2 MiB/s per individual response after the first MiB.
- `DOWNLOAD_PER_IP=2`: two active individual downloads per client address.
- `DOWNLOAD_GLOBAL=6`: six active individual downloads globally.
- `DOWNLOAD_LIMIT_DRY_RUN=off`: excess requests receive HTTP 429.
- `ZIP_GLOBAL=1`: hard nginx backstop allowing one active ZIP transfer.
- `ZIP_RATE=2m`: 2 MiB/s per ZIP after the first MiB.

ZIP defaults in `vps/ipp-config.json`:

- `maxDownloadZipBytes`: maximum aggregate source size, 2 GiB by default.
- `minDownloadZipFreeBytes`: disk reserve, 5 GiB by default.
- `downloadZipCacheTtlSeconds`: private cache lifetime, 1,800 seconds.
- `downloadFromImmichConcurrencyLimit`: three simultaneous source fetches.
- `downloadZipQueueMaxWaiting`: three waiting visitors in the process-local FIFO.
- `downloadZipQueueHeartbeatSeconds`: remove a waiting job after five minutes
  without status polling.
- `downloadZipReadyLeaseSeconds`: reserve a prepared ZIP for two minutes while
  the visitor starts the download.
- `downloadZipMaxReadyLeaseSeconds`: absolute five-minute ceiling for the
  ready/retry lifecycle; HEAD and Range probes cannot extend it.

IPP stages originals on disk, creates an immutable STORE archive, and only then
sends headers with exact `Content-Length` and `Accept-Ranges: bytes`. A canceled
mobile download can resume while the private cache remains valid. Startup and
TTL cleanup remove stale files. The disk preflight accounts for staged originals,
the final archive, and the configured reserve.

One active ZIP lifecycle protects a small VPS. Additional visitors enter a
bounded in-memory FIFO and see position-independent English status text; the
queue does not survive an IPP restart and stores no database records. A request
beyond the configured waiting capacity receives HTTP 429 and `Retry-After: 30`;
oversized content receives 413 and insufficient staging space receives 507.
Public responses reveal no other visitor, share, throughput, or time estimate.

Theoretical individual-download throughput is
`DOWNLOAD_RATE × DOWNLOAD_GLOBAL`. Leave 20–25% headroom below measured NAS
upload capacity.

### Controlled benchmark

Create a temporary, non-sensitive album containing a sufficiently large file.
Open a short-lived share and copy an individual `.../original` URL. Temporarily
set the VPS guard to measurement mode:

```dotenv
DOWNLOAD_RATE=0
DOWNLOAD_LIMIT_DRY_RUN=on
```

```bash
cd /srv/photo-share
docker compose up -d --force-recreate download-guard
watch docker stats caddy download-guard ipp
```

From a machine outside the home LAN, run the benchmark without arguments so the
credential-bearing URL and password do not enter shell history:

```bash
./scripts/benchmark-downloads.py
```

The script tests 1, 2, 4, 6, 8, and 12 streams for 30 seconds by default. It
discards response bodies and reports aggregate throughput, HTTP 429 responses,
errors, and p95 time to first byte. Monitor NAS upload, disk, and CPU. Select a
ceiling one step below saturation, the first errors, or sustained 80% load.

Restore `DOWNLOAD_LIMIT_DRY_RUN=off`, choose final limits, recreate the guard,
and rerun a short test.

Set Immich's external domain to `https://photos.example.com` under
Administration → Settings → Server → External Domain.

## 6. Configure the CLI

```bash
cd ~/dev/projects/immich-share
mkdir -p ~/.config/immich-share
cp config.example.ini ~/.config/immich-share/config.ini
chmod 600 ~/.config/immich-share/config.ini
# Needed only when running photo-share-monitor.py; never paste this value into chat.
umask 077
openssl rand -base64 32 > ~/.config/immich-share/monitor-password
```

Create a dedicated Immich API key with shared-link and album-read permissions,
store it at the configured `api_key_file`, and set mode 600. Edit `config.ini`
to provide the local Immich URL, public domain, VPS SSH alias, and NAS forward
commands.

Use HTTPS between a separate controller and Immich. Plain HTTP is accepted only
on loopback; when an encrypted WireGuard, Tailscale, or SSH tunnel carries the
whole connection, set `allow_http_over_private_tunnel = true` explicitly. This
option is an acknowledgement, not encryption by itself.

```bash
./immich-share list
./immich-share open "Test album" --ttl 24h --for "Alex"
./immich-share doctor
```

### Migration from an earlier release

The ownership registry starts empty. Run `list`: old/manual links appear as
`external` and are neither published nor deleted by `sync`, `close`, or
`sweep`. For each old link that this tool should own, independently confirm a
strong password and a finite expiry, then run `./immich-share adopt
<unambiguous-key-prefix>`. Do not adopt passwordless links. Keep only one sweep
owner while migrating.

Install the expiry sweep timer on macOS:

```bash
# First replace <CONTROLLER_INSTALL_DIR> in the plist with the private local
# installation path.
cp local.immich-share-sweep.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/local.immich-share-sweep.plist
```

To run the controller directly on the NAS instead, use
`nas/controller/config.example.ini`, `ssh-config.example`, and the cron example.
Keep only one operational sweep owner during migration. The Mac mini and NAS
may both run read-only `doctor` checks, but must not both run share mutations.

## 7. Mandatory security validation

From an external connection such as cellular data:

- [ ] `https://photos.example.com/` returns 404.
- [ ] `/auth/login`, `/admin`, and `/api/admin/*` are inaccessible.
- [ ] A password-protected 24-hour test share works.
- [ ] A wrong password reveals no thumbnail or metadata.
- [ ] An expired link is inaccessible.
- [ ] Individual original download works.
- [ ] Bulk ZIP works, a concurrent visitor is queued, and a request beyond the
      queue capacity receives 429.
- [ ] A canceled ZIP resumes with HTTP 206 while its cache is valid.
- [ ] ZIP staging contains no source directories after success, error, or cancel.
- [ ] The gallery reveals no GPS/EXIF fields.
- [ ] `immich-share doctor` reports that every read-only check passed.

From the VPS:

- [ ] `ping <ANY_LAN_HOST>` and `curl <NAS_LAN_IP>:9999` fail.
- [ ] `curl http://<WG_NAS_ADDRESS>:2283/api/auth/login` returns 404 and appears in
      `denied.log`.
- [ ] A request containing `?key=TEST-SENTINEL` leaves no `key=`, sentinel, or
      query string in `allowed.log`, `denied.log`, Docker logs, or an nginx
      error log. Sanitized logs contain method + normalized path only.
- [ ] A fast burst of denied requests eventually returns 429 and the
      `immich-share-logrotate` container is running.
- [ ] The dedicated `immich_share` Docker network contains only `wg-tunnel`
      and `immich_server`; it contains no database or Redis container.
- [ ] `ping <WG_CONTROLLER_ADDRESS>` and `nc -vz <WG_CONTROLLER_ADDRESS> 22`
      fail because of the admin-host
      packet-filter rule.
- [ ] After closing every share, `curl http://<WG_NAS_ADDRESS>:2283/` is refused because
      the NAS forward is stopped.

## 8. Operations

- Review IPP routes in `logs/allowed.log` during a complete test. Any route
  introduced by an IPP update must first hit `denied.log`, be audited, and only
  then be added explicitly to the allowlist.
- Confirm Docker log limits and the isolated NAS `immich-share-logrotate`
  service remain active; never switch the route log format back to `$request`
  or `$request_uri`.
- Alert on proxy failure, tunnel failure, disk reserve, and tripwire events.
- Keep the monitor on loopback where possible. It always requires a mode-0600
  password file and rate-limits failed authentication. A non-loopback bind also
  requires `allow_http_over_private_tunnel = true`, and is valid only inside an
  encrypted private tunnel. The monitor sends no wildcard CORS response.
- Back up configuration without private keys, API keys, share keys, or passwords.
