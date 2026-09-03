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
| Optional upload | Whether `/drop` is enabled; dedicated NAS dataset/state paths and filesystem quota; media, file/count/byte, chunk, reserve and concurrency limits |
| Monitor | Loopback or encrypted-tailnet bind, allowed hostnames, and local password-file path |

Recommended defaults for a small VPS are already included in the repository:
2 GiB maximum ZIP contents, a 5 GiB disk reserve, a 30-minute cache, one active
ZIP lifecycle plus three waiting visitors, and 2 MiB/s per ZIP. The installer
must adjust them when the VPS disk or home upload is smaller.

The repository currently provides an operations CLI, not an interactive
installer. Deployment therefore follows this runbook and copies
`config.example.ini`, `vps/.env.example`, and `nas/.env.example`. The CLI then
manages shares with `open`, `list`, `adopt`, `sync`, `close`, and `sweep`.

The upload-drop deployment is optional and remains disabled until its separate
Compose overlays are selected, an immutable application image is supplied, a
controlled invitation exists, the NAS upload filter passes its doctor, and the
generic Caddy snippet is installed. It uses the same public domain under
`/drop`; there is no additional DNS record or public firewall port.

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

Docker manages its own `FORWARD`/`DOCKER-USER` iptables chains, and the
`immich-share-containment` unit (section 5, "Forwarding containment") adds the
bridge egress rules to `DOCKER-USER`. `ufw disable` and `ufw reload` flush
those chains. After either command, or any other `ufw` change, run
`sudo systemctl restart docker immich-share-containment` (the unit is
`PartOf=docker.service`, so restarting Docker alone re-applies it too) and
repeat the containment checks before reopening a share. The tunnel's own
`wg0 -> wg0` drop lives in `wg0.conf` and is restored by `wg-quick@wg0`.

## 3. WireGuard topology

The VPS is the hub. In the recommended separate-controller profile, the NAS and
administration machine each have their own peer; there is no inbound port
forwarding at home.

```text
Admin <WG_CONTROLLER_ADDRESS> ── WireGuard ──┐
                                                ├── VPS <WG_VPS_ADDRESS>
NAS   <WG_NAS_ADDRESS>        ── WireGuard ──┘
```

Optional upload support adds a separate NAS peer to the same VPS hub. It must
not reuse the read-side key, address, container namespace, or Docker network:

```text
NAS read   <WG_NAS_ADDRESS>        ──┐
NAS upload <UPLOAD_NAS_WG_ADDRESS> ──┼── VPS <WG_VPS_ADDRESS>
Admin      <WG_CONTROLLER_ADDRESS> ──┘
```

Choose the private subnet, the three base addresses, and the optional upload
address locally. Do not commit those values; replace placeholders only in
deployed copies.

1. Generate one key pair per machine with
   `wg genkey | tee private.key | wg pubkey > public.key`.
2. Copy `vps/wireguard/wg0-vps.conf` to `/etc/wireguard/wg0.conf` on the VPS,
   replace placeholders, then run `sudo systemctl enable --now wg-quick@wg0`.
3. Create a dedicated external Docker network named `immich_share`. Persistently
   attach only `immich_server` (with the `immich_server` alias) and the NAS
   tunnel stack to it. PostgreSQL, Redis, and unrelated NAS services must remain
   absent. Merge the tracked `nas/immich-network.override.yml` with the existing
   Immich Compose project whenever it is deployed or updated:

   ```bash
   docker network create immich_share
   docker compose -f docker-compose.yml \
     -f immich-network.override.yml up -d --no-deps immich-server
   ```

   Deploy
   `nas/docker-compose.yml`, all three `nas/Dockerfile.*` files,
   `nas/immich-network.override.yml`,
   `nas/wireguard-entrypoint.sh`, `nas/nginx-filter.conf`, `nas/logrotate.conf`,
   `nas/logrotate-entrypoint.sh`, `nas/security-doctor.sh`, and
   `nas/wg0-nas.conf` next to Immich. Copy
   `nas/.env.example` to `nas/.env`; set the private `NAS_WG_ADDRESS`, and change
   `IMMICH_SHARE_DOCKER_NETWORK` only if the dedicated network has another
   name. `nginx-filter.conf` is an envsubst template, so the real address stays
   only in the ignored `.env`. The WireGuard container keeps only
   `NET_ADMIN` and `DAC_READ_SEARCH`; the latter is required to read the
   operator-owned `wg0-nas.conf` kept at mode 0600 through its single
   read-only bind mount. It resolves `immich_server` only during bootstrap,
   closes Docker DNS and exposes that exact upstream to nginx through the
   loopback-only `127.0.0.1:18080` relay. If an Immich upgrade recreates the
   server with a new internal address, restart `wg-tunnel` and its filter and
   rerun `doctor` before reopening a share; a stale relay fails closed. Create
   `logs/` owned by UID/GID 101 with mode
   0750 and grant the
   tripwire account read access without making it world-readable. Inside the
   tunnel container, verify `sysctl net.ipv4.ip_forward` returns `0`.
   When replacing an existing bind-mounted `nginx-filter.conf` atomically,
   recreate only the filter with
   `docker compose up -d --no-deps --force-recreate nginx-filter`; an nginx
   reload can otherwise keep reading the previous bind-mounted inode. Repeat
   the query-sentinel log test after every filter update.
   For optional uploads, generate a fourth key pair and use
   `nas/wg0-upload-nas.conf` for the second NAS container. Add its public key and
   unique `/32` address by merging
   `vps/wireguard/upload-peer.conf.example` into the deployed VPS `wg0.conf`.
   Do not reuse the read-side key or address. No new UDP listener is needed.
4. Import `macmini/wg0-macmini.conf` on the admin machine and apply
   `macmini/pf-wireguard.md`.
5. From the NAS and admin machine, verify `ping <WG_VPS_ADDRESS>`. Inspect handshakes
   on the VPS with `sudo wg show`.

For the optional NAS-controller profile, keep the data tunnel in its container
and transport controller SSH with
`ProxyCommand docker exec -i wg-tunnel nc %h %p`. This avoids exposing SSH
publicly or mounting the Docker socket into another container. Because the
tunnel namespace is `OUTPUT DROP` with a four-rule allowlist, that `nc`
connection is refused unless you opt in explicitly: set
`WG_CONTROLLER_SSH_PEER=<WG_VPS_ADDRESS>` in the ignored `nas/.env` and recreate
`wg-tunnel`. The entrypoint then adds exactly one extra accept (TCP/22 to that
`/32`). The share doctor does not take the expected peer from the container it
certifies: record it in the root-owned `/etc/immich-share/doctor.env` (mode
0600, single line `WG_CONTROLLER_SSH_PEER=<WG_VPS_ADDRESS>`; see
`nas/controller/README.md` for the exact commands). The doctor then requires
the container to carry that same value and certifies five rules instead of
four. With the file absent or empty it requires exactly four rules and fails if
the container carries the variable. Leave the variable empty and the file
absent in the separate-controller profile, and never set it on
`wg-upload-tunnel`: the upload doctor always fails on it. Follow
`nas/controller/README.md`; run its read-only preflight before installing any
controller secret on the NAS.

For the recommended separate controller, do not grant its SSH key an ordinary
NAS shell or arbitrary Docker commands. Install `nas/forward-command.sh` as
root-owned `/usr/local/sbin/immich-share-forward-command`, create a dedicated
`immich-share-gate` account, and do **not** add it to the root-equivalent Docker
group. Validate and install `nas/sudoers-forward-gate.example` so the account
may invoke only the exact read filter, upload filter, doctor and invitation
helper actions listed there; prefix the key in
`authorized_keys` exactly as shown by `nas/ssh-forward-gate.example`, replacing
`<CONTROLLER_LAN_ADDRESS>` in `from=` with the controller's fixed LAN or tailnet
address as the NAS sshd sees it. Never use the controller's WireGuard address:
the NAS WireGuard interface lives inside `wg-tunnel`, its peer accepts only the
VPS `/32`, and the VPS drops wg0-to-wg0 traffic, so the host sshd can never
observe it. Merge
`nas/ssh-config-controller.example` on the controller. Test `forward status`,
then verify that `uname`, an interactive shell, port forwarding, agent
forwarding, and PTY allocation are all refused.

The tripwire needs no NAS shell either. The gate's exact `tripwire follow`
command runs a fixed `tail -F -n0 /var/log/immich-share/denied.log` as root, so
create that directory as a symlink to (or bind mount of) the deployed `nas/logs`
directory, for example `sudo ln -s <PRIVATE_NAS_DIR>/logs /var/log/immich-share`.
The gate refuses `tripwire follow` (exit 65) when that path does not exist so a
misconfigured tripwire fails loudly instead of tailing nothing, and the share
doctor verifies that the path resolves into the filter's log mount.
`macmini/denied-tripwire.sh` then follows it through the `nas-photo-gate` alias
and coalesces alerts to at most one ntfy notification per minute; run it under
`macmini/local.photo-tripwire.plist` with `NAS_SSH_TARGET=nas-photo-gate`. It
ignores refusals logged from `127.0.0.1`: those are the doctor's own probes
through the filter's private loopback listener, which nothing outside the
tunnel namespace can spoof.

Install the helper with owner `root:root` and mode 0755. Validate the sudoers
file with `visudo -cf` before installing it as root-owned mode 0440 under
`/etc/sudoers.d/`; a syntax error there can break administrative sudo access.
Install `nas/security-doctor.sh` as root-owned mode 0755 at
`/usr/local/sbin/immich-share-security-doctor`. The forced `doctor` command is
read-only and returns only a pass/fail summary; it does not expose paths,
addresses, container IDs, or log contents.

When uploads are installed, also install `nas/upload-security-doctor.sh` as
root-owned mode 0755 at
`/usr/local/sbin/immich-share-upload-security-doctor`. The same restricted key
may then run only the exact upload lifecycle and invitation commands listed in
the forced-command gate; the account still receives neither a shell nor
Docker-group membership. Install the JSON bridge root-owned as well:

```bash
/usr/bin/python3 --version  # Resolve this trusted absolute path first.
sudo install -o root -g root -m 0755 nas/upload-admin-helper.py \
  /usr/local/sbin/immich-share-upload-admin
sudo install -o root -g root -m 0755 nas/upload-security-doctor.sh \
  /usr/local/sbin/immich-share-upload-security-doctor
sudo visudo -cf nas/sudoers-forward-gate.example
```

The bridge fixes the container name and executes only `python -m app.cli
--json` through Docker argv. It also pins the local Unix Docker socket and
replaces the inherited environment, so sudo policy cannot redirect the client
with `DOCKER_HOST`, a context or a configuration directory. It never invokes a
shell, accepts a container name or executable, or exposes `init`/`purge`. Set
`expected_wireguard_peers = 3` in
the controller's private configuration once the upload peer is expected to
remain connected.

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
sudo mkdir -p /srv/photo-share/shares.d /srv/photo-share/drops.d \
  /srv/photo-share/zip-staging \
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
vps/docker-compose.upload.yml        # optional
vps/Dockerfile.caddy
vps/Dockerfile.nginx
vps/Caddyfile
vps/ipp-config.json
vps/download-guard.conf.template
vps/download-guard-nginx.conf
vps/upload-guard.conf.template       # optional
vps/upload-guard-nginx.conf          # optional
vps/drop-portal.caddy.template       # optional; never install directly
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

When upgrading a deployment created before the network split (Caddy on the
private `upload_net`, the `tunnel_net` bridge pinned to the interface name
`immich-tunnel`, and `upload-guard` moved off `app_net`), Compose cannot
change an existing network in place. Stop the optional upload edge first if it
is installed, then recreate the base stack, then the upload edge:

```bash
cd /srv/photo-share
docker compose -f docker-compose.upload.yml down   # only if uploads are installed
docker compose down
docker compose up -d --build
```

After a routing change, run `./immich-share sync` on the admin machine. It
regenerates snippets only for links recorded in the local managed-share state;
it never publishes an unrelated Immich link.

### Forwarding containment on the VPS

`tunnel_net` is an ordinary NAT bridge: without extra rules, IPP could reach
the whole Internet and the admin peer's WireGuard address through the host,
and a host that had `net.ipv4.ip_forward=1` before Docker started keeps
`FORWARD` at ACCEPT, so the VPS could relay packets between the NAS and admin
peers. Two independent pieces close this:

- The deployed `wg0.conf` copied from `vps/wireguard/wg0-vps.conf` drops
  wg0-to-wg0 forwarding from PostUp. That rule belongs to the tunnel and is
  the only firewall rule in `wg0.conf`.
- The `immich-share-containment` systemd oneshot from `vps/containment/` owns
  the `DOCKER-USER` rules that let the pinned bridges forward only to the
  filter they exist for: `immich-tunnel` (IPP) to `<WG_NAS_ADDRESS>:2283` and
  `immich-uptun` (`upload-guard`) to `<UPLOAD_NAS_WG_ADDRESS>:2383`.
  Everything else forwarded from those bridges is dropped, including
  cross-container traffic on the same bridge, and no other bridge may forward
  to `wg0` at all: a compromised Caddy keeps its ACME egress through the
  default route but cannot reach the NAS filters or the admin peer through the
  tunnel. The rules are deliberately not installed from
  `wg0.conf`: `systemctl restart wg-quick@wg0` would remove them in PostDown
  and leave both containers with open egress until the tunnel came back.

The script reads `NAS_WG_ADDRESS` and `UPLOAD_NAS_WG_ADDRESS` from
`/srv/photo-share/.env` (override the path with a drop-in setting
`Environment=CONTAINMENT_ENV_FILE=...`). The `immich-uptun` ACCEPT is added
only when `UPLOAD_NAS_WG_ADDRESS` holds a real address (or `CONTAINMENT_UPLOAD=on`
is set in the same file); both DROP rules are always installed, so an upload
bridge that appears before uploads are configured has no egress at all. Every
run removes exactly the rules tagged `immich-share`, plus any legacy rule that
names one of the two bridges, and re-inserts the current set at the top of
`DOCKER-USER`; other users of the chain are left alone and the chain is never
flushed. Temporary DROP guards remain in front of both bridges during every
replacement and are removed only after the complete new allowlist is present,
so a failed update leaves the bridges closed. Interface names are pinned in the
two Compose files and rules that name an interface are accepted before the
bridge exists, so the order of Docker, `docker compose up` and this unit does
not matter.

Install it on the VPS:

```bash
sudo install -m 0755 vps/containment/immich-share-containment.sh /usr/local/sbin/immich-share-containment.sh
sudo install -m 0644 vps/containment/immich-share-containment.service /etc/systemd/system/immich-share-containment.service
sudo systemctl daemon-reload
sudo systemctl enable --now immich-share-containment
sudo systemctl status immich-share-containment --no-pager
```

Re-run `sudo systemctl restart immich-share-containment` after editing the
addresses in `.env`, and `sudo systemctl restart docker immich-share-containment`
after any `ufw` command, because `ufw reload`/`ufw disable` flush Docker's
chains (section 2). `sudo immich-share-containment.sh remove` deletes only the
owned rules and is the decommissioning step; stopping the unit leaves them in
place on purpose.

If `wg0.conf` was deployed from an earlier release that carried the
`DOCKER-USER` PostUp/PostDown lines, replace it with the current
`vps/wireguard/wg0-vps.conf` (placeholders and peers filled in), install the
unit as above, then `sudo systemctl restart wg-quick@wg0`. The first run of
the unit removes the legacy rules by interface name. Verify from the VPS, with
a throwaway container on the IPP bridge (`photo-share_tunnel_net` when the
project directory is `/srv/photo-share`):

```bash
sudo iptables -S FORWARD | grep -- '-i wg0 -o wg0 -j DROP'
sudo iptables -S DOCKER-USER
# Expected, in this order (the upload ACCEPT only when uploads are configured):
#   -A DOCKER-USER -d <WG_NAS_ADDRESS>/32 -i immich-tunnel -o wg0 -p tcp -m tcp --dport 2283 -m comment --comment immich-share -j ACCEPT
#   -A DOCKER-USER -d <UPLOAD_NAS_WG_ADDRESS>/32 -i immich-uptun -o wg0 -p tcp -m tcp --dport 2383 -m comment --comment immich-share -j ACCEPT
#   -A DOCKER-USER -o wg0 -m comment --comment immich-share -j DROP
#   -A DOCKER-USER -i immich-tunnel -m comment --comment immich-share -j DROP
#   -A DOCKER-USER -i immich-uptun -m comment --comment immich-share -j DROP
sudo systemctl restart wg-quick@wg0 && sudo iptables -S DOCKER-USER | grep -c -- '--comment immich-share'   # unchanged
docker run --rm --network photo-share_tunnel_net alpine:3.22 sh -c '
  nc -zw3 <WG_NAS_ADDRESS> 2283 && echo "read filter reachable";
  nc -zw3 <WG_CONTROLLER_ADDRESS> 22 || echo "admin peer blocked";
  nc -zw3 <UPLOAD_NAS_WG_ADDRESS> 2383 || echo "upload filter blocked from IPP bridge";
  nc -zw3 <ANY_PUBLIC_ADDRESS> 443 || echo "Internet egress blocked"'
```

The read-filter probe succeeds only while a share keeps the NAS forward
running; the three refusals must hold at all times. `immich-share doctor`
repeats the `DOCKER-USER` check over SSH on every run.

Images and upstream versions are pinned. IPP source and releases live in the
separate AGPL fork linked from `THIRD_PARTY_NOTICES.md`. Updating IPP is an
explicit operation: validate the fork release, change the immutable GHCR
digest, and retest ZIP responses for 200, 206, 413, 429, and 507.

### Optional upload-drop deployment

Do not add upload services to the base gallery Compose invocation. This keeps a
read-only installation unchanged and prevents an ordinary IPP upgrade from
starting or reconfiguring the write path.

On the NAS, copy `docker-compose.upload.yml`, `wg0-upload-nas.conf`,
`upload-filter.conf`, `upload-security-doctor.sh`, and the existing pinned
Dockerfiles/entrypoints. Create a dedicated external network and two private
host directories or datasets:

```bash
docker network create --internal immich_drop
chmod 0600 wg0-upload-nas.conf
sudo install -d -o 65532 -g 65532 -m 0700 \
  <UPLOAD_DROP_STORAGE_PATH> <UPLOAD_DROP_STATE_PATH>
sudo install -o 65532 -g 65532 -m 0400 /dev/null \
  <UPLOAD_DROP_SESSION_SECRET_FILE>
# Write a printable high-entropy secret; the application reads it as UTF-8.
# It never appears in argv, terminal output, Git, or chat.
openssl rand -base64 48 \
  | sudo tee <UPLOAD_DROP_SESSION_SECRET_FILE> >/dev/null
sudo install -d -o 101 -g 101 -m 0750 upload-logs
```

Apply a hard filesystem quota to `<UPLOAD_DROP_STORAGE_PATH>` where the NAS
supports datasets, shared-folder quotas, ZFS or Btrfs quotas. Keep it outside
every Immich bind mount and external library. Do not back up partial uploads as
trusted photos.

`immich_drop` must remain an internal network. The optional Compose file creates
a second bridge joined only by `wg-upload-tunnel`. The WireGuard entrypoint
installs OUTPUT-DROP before resolving anything, temporarily permits Docker DNS
to resolve `upload-drop`, starts a loopback-only relay on `127.0.0.1:18080` to
that exact address and port, then closes DNS. Only the literal public WireGuard
endpoint over its configured UDP port, established replies and the resolved
`upload-drop:8080` address remain reachable. `upload-drop` has no direct
Internet route. The nginx filter shares the locked WireGuard network namespace
and connects only to the loopback relay, so its separate `/etc/hosts` and
resolver configuration cannot reopen DNS or general LAN/Internet egress.
If Docker recreates `upload-drop` with a new internal address, restart
`wg-upload-tunnel` and its filter, then rerun the upload doctor before reopening
the Caddy snippet. A stale relay fails closed; it never falls back to DNS.

In the ignored `nas/.env`, set both directory paths, the session-secret file
path, public HTTPS origin without `/drop`, private upload WireGuard address,
policy ceilings, and `UPLOAD_DROP_IMAGE`. The image value is deliberately
required and must include an immutable `@sha256:` digest. The reviewed
release is `ghcr.io/christopheraparicio/immich-drop:v0.2.1` at digest
`sha256:4711e71c0775aa8d157046fc486a3dc759a1ae38642f16ce59671099e86e3ed1`;
verify the release provenance before copying a newer digest.

Validate without opening a public route:

```bash
docker compose -f docker-compose.upload.yml config --quiet
docker compose -f docker-compose.upload.yml build \
  upload-wireguard upload-filter upload-logrotate
# The marker and state database are created only after the operator has checked
# that both bind mounts point at the intended empty/private NAS datasets.
docker compose -f docker-compose.upload.yml run --rm --no-deps \
  upload-drop python dropctl.py init --yes
docker compose -f docker-compose.upload.yml up -d
docker stop --time 10 wg-upload-filter
```

The application remains isolated on internal `immich_drop`; PostgreSQL, Redis,
`immich_server`, and the read-side `wg-tunnel` must be absent. Verify
`net.ipv4.ip_forward=0` in `wg-upload-tunnel`.

On the VPS, set `UPLOAD_NAS_WG_ADDRESS` and the upload guard ceilings in the
ignored `.env`, then validate the optional edge without installing a Caddy
handler:

```bash
docker compose -f docker-compose.upload.yml config --quiet
docker compose -f docker-compose.upload.yml up -d --build upload-guard
docker compose -f docker-compose.upload.yml exec -T upload-guard nginx -t
docker network inspect photo-share_upload_net \
  --format '{{range .Containers}}{{.Name}} {{end}}'   # caddy upload-guard only
docker network inspect photo-share_app_net photo-share_tunnel_net \
  --format '{{range .Containers}}{{.Name}} {{end}}'   # no upload-guard
```

`upload-guard` authorizes on a constant marker that Caddy overwrites, so it
must be reachable only by Caddy. It joins the private `upload_net` shared with
Caddy and its own NAT bridge `upload_tunnel_net` (`immich-uptun`) toward the
upload filter; it must never appear on `app_net` or IPP's `tunnel_net`. The
containment rules above restrict `immich-uptun` to
`<UPLOAD_NAS_WG_ADDRESS>:2383`.

`drop-portal.caddy.template` is a template, not an always-on configuration.
For a controlled invitation, use this fail-closed order:

1. Create the password-protected, finite invitation through the application's
   private administration interface. Never expose an admin route through nginx.
2. Start `wg-upload-filter` through the forced `upload on` command.
3. Run forced `upload doctor`; it certifies the second network, container
   hardening, writable mounts, private `/healthz`, exact refusal, and live log
   redaction without printing addresses or paths.
4. Copy the template atomically to `drops.d/00-drop.caddy`, validate Caddy, then
   reload. Caddy now exposes only `/drop/i/<token>`, the exact local assets
   `app.js`, `drop.css`, and `favicon.png`, the
   password/policy/create endpoints, and session-owned HEAD/PATCH/DELETE upload
   endpoints. `/healthz` and every admin route remain private.

On the VPS, the atomic activation itself can be performed without exposing a
partially written snippet. Caddy keeps serving its previous in-memory config if
validation fails:

```bash
cd /srv/photo-share
install -m 0600 drop-portal.caddy.template drops.d/.00-drop.caddy.pending
mv drops.d/.00-drop.caddy.pending drops.d/00-drop.caddy
docker compose exec -T caddy caddy validate --config /etc/caddy/Caddyfile
docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile
```

Close in the reverse safety order: revoke the invitation in the application,
move the Caddy snippet out of the imported `*.caddy` set, validate and reload,
then run `upload off` after the last active
invitation. Expiry is enforced by the application on every request; a sweep is
cleanup and convergence, never the only expiry mechanism.

```bash
cd /srv/photo-share
mv drops.d/00-drop.caddy drops.d/.00-drop.caddy.disabled
docker compose exec -T caddy caddy validate --config /etc/caddy/Caddyfile
docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile
```

The NAS operator can use the application CLI locally without exposing an admin
HTTP route. Prefer a hidden custom password and select the least permissive
media profile:

```bash
docker compose -f docker-compose.upload.yml exec upload-drop \
  python dropctl.py open --label "Event incoming" --folder "Event incoming" \
  --profile photos --ttl 24h --max-file 512MiB --max-files 200 \
  --quota 1GiB --prompt-password
docker compose -f docker-compose.upload.yml exec upload-drop python dropctl.py list
docker compose -f docker-compose.upload.yml exec upload-drop python dropctl.py close <INVITATION_ID>
docker compose -f docker-compose.upload.yml exec upload-drop python dropctl.py sweep
```

### Remote invitation administration from the separate controller

The forced SSH key also supports exactly `upload admin open`, `list`, `close`,
and `sweep`. Each command requires one UTF-8 JSON object on stdin, limited to
4,096 bytes and completed within ten seconds. Duplicate keys, unknown fields,
control characters, partial IDs and booleans used as integers are rejected
before Docker runs. No password is
accepted in JSON or argv: `open` generates a strong password inside the NAS
container and returns it once in the JSON response. Treat that response as a
secret and do not log it, paste it into chat, or save it in shell history.

```bash
# Creates only the private backend invitation. It does not start the filter or
# install the public Caddy snippet.
printf '%s' '{"label":"Family event","profile":"photos","ttlSeconds":86400}' \
  | ssh nas-photo-gate 'upload admin open'

printf '%s' '{}' | ssh nas-photo-gate 'upload admin list'

# close requires the complete canonical UUID returned by open/list.
printf '%s' '{"inviteId":"01234567-89ab-cdef-0123-456789abcdef"}' \
  | ssh nas-photo-gate 'upload admin close'

printf '%s' '{}' | ssh nas-photo-gate 'upload admin sweep'
```

`open` requires `label`. Optional fields are `folder`, `profile`, `ttlSeconds`,
`maxFileBytes`, `maxFiles`, and `quotaBytes`. Remote administration deliberately
caps TTL at seven days, individual files at 512 MiB, 500 files, and invitation
quota at 1 GiB; TTL must be whole minutes. Profiles are `photos`, `videos`,
`both`, or `live`. These three resource ceilings are always sent explicitly,
including when omitted from JSON, so raising container defaults cannot bypass
the remote-administration policy. Use the local interactive CLI when a custom
password is required.

After remote `open`, keep following the fail-closed sequence: `upload on`,
`upload doctor`, then atomically install and reload the VPS Caddy snippet.
Remote `close` revokes the invitation in the backend only; remove and reload
the Caddy snippet before `upload off` when the last invitation closes. The
helper never changes public routing or starts a container implicitly.

The profile may be `photos`, `videos`, `photos+videos`, or `photos+live`; RAW is
not accepted by the initial public contract. The backend must verify both the
normalized extension and media signature. The folder is a display/manifest
label under a server-generated invitation directory, never a visitor-supplied
host path.

The `PATCH` body is a raw, resumable chunk capped at eight MiB by the
application and nine MiB by both nginx guards. Both proxies use
`proxy_request_buffering off`; their only cache directories are bounded tmpfs,
so the VPS has no persistent upload copy. `HEAD` returns the committed offset,
and the final chunk is atomically promoted by the application. There is no ZIP,
archive extraction, public listing, or public download route.

Each application PATCH has an absolute 180-second deadline in addition to the
proxy inactivity timeouts; a slow-drip client receives 408 and cannot retain
one of the three upload slots indefinitely. The application also owns the
single internal incomplete-upload sweeper, every 300 seconds by default. Do not
install a second cron/timer sweeper; operator `sweep` remains an explicit
maintenance/reconciliation command, not another scheduled owner.

The application computes SHA-256 only after a complete file has been received
and its media signature has passed. Within that invitation only, a later file
with the same size, category and digest is discarded, its quota is released,
and the browser reports that it was already received. This saves quarantine
space but not ingress bandwidth. `UPLOAD_DROP_WORK_MULTIPLIER` defaults to `3`
and is captured into each new invitation to bound cumulative upload-creation
attempts, chunk requests and declared chunk bytes; values above `10` are
refused. No client hash oracle or cross-invitation comparison exists.

Closing the public path does not remove completed quarantine files and the
separate controller has no filesystem or import permission. Perform review and
Immich upload locally on the NAS using the isolated workflow in
[`UPLOAD_IMPORT.md`](UPLOAD_IMPORT.md); keep the upload tunnel stopped during
that work unless another active invitation requires it.

### Download limits and resumable ZIPs

Caddy sends only individual originals, the legacy `/share/<key>/download`
endpoint, and prepared `/share/<key>/download/jobs/<id>/file` responses to the
nginx download guard. Gallery HTML, thumbnails, preview zoom, metadata, and the
bounded queue-control endpoints go directly to IPP. Caddy rate-limits the
planning endpoint separately because it performs bounded upstream header reads.

The HTTPS listener uses HTTP/1.1 and HTTP/2. Long ZIP downloads were observed to
be unreliable in Safari iOS over HTTP/3, while TCP-based HTTP/2 completed and
supports standard range retries.

Small-VPS defaults in `vps/.env.example`:

- `DOWNLOAD_RATE=2m`: 2 MiB/s per individual response after the first MiB.
- `DOWNLOAD_PER_IP=2`: two active individual downloads per client address.
- `DOWNLOAD_GLOBAL=6`: six active individual downloads globally.
- `DOWNLOAD_LIMIT_DRY_RUN=off`: excess requests receive HTTP 429.
- `ZIP_GLOBAL=3`: hard nginx backstop allowing three prepared ZIP transfers.
- `ZIP_PER_IP=1`: ZIP transfers a single client address may hold at once, so a
  slow reader cannot occupy every `ZIP_GLOBAL` slot.
- `ZIP_RATE=2m`: 2 MiB/s per ZIP after the first MiB.
- `ZIP_MAX_PARALLEL_DOWNLOADS=3`: matching IPP ready/transfer slot ceiling.
- `ZIP_DISK_BUDGET_PERCENT=50`: staged files plus the STORE archive may use at
  most half of the free space remaining after the fixed reserve.
- `ZIP_SPLIT_THRESHOLD_BYTES=1073741824`: albums above 1 GiB show a part picker.
- `ZIP_PART_TARGET_BYTES=536870912`: deterministic parts target 512 MiB.
- `ZIP_PLAN_CONCURRENCY=12`: bounded concurrent size-header checks.

ZIP defaults in `vps/ipp-config.json`:

- `maxDownloadZipBytes`: maximum aggregate source size, 2 GiB by default.
- `minDownloadZipFreeBytes`: disk reserve, 5 GiB by default.
- `downloadZipCacheTtlSeconds`: private cache lifetime, 1,800 seconds.
- `downloadFromImmichConcurrencyLimit`: three simultaneous source fetches.
- `downloadZipPlanTtlSeconds`: visitor-bound part plans expire after one hour.
- `downloadZipPlanMaxAssets`: reject plans above 5,000 unique assets before
  issuing any upstream size requests.
- `downloadZipMaxParts`: reject plans needing more than 64 parts.
- `downloadZipQueueMaxWaiting`: three waiting visitors in the process-local FIFO.
- `downloadZipQueueHeartbeatSeconds`: remove a waiting job after five minutes
  without status polling.
- `downloadZipReadyLeaseSeconds`: reserve a prepared ZIP for two minutes while
  the visitor starts the download.
- `downloadZipMaxReadyLeaseSeconds`: absolute five-minute ceiling for the
  ready/retry lifecycle; HEAD and Range probes cannot extend it.

IPP first reads the selected endpoints' exact sizes. Albums at or below the
threshold proceed automatically; larger albums are split by stable capture-time
order and the visitor chooses an independent part. IPP stages one part at a
time, creates an immutable STORE archive, and only then sends headers with exact
`Content-Length` and `Accept-Ranges: bytes`. A canceled mobile download can
resume while the private cache remains valid. Startup and TTL cleanup remove
stale files. The disk preflight accounts for staged originals, the final
archive, the fixed reserve, and the percentage budget.

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

The controller CLI supports macOS and Linux with Python 3.9 or newer. On
Windows, run it inside WSL with an Ubuntu or another Linux environment; the
controller relies on Unix file permissions, `fcntl`, SSH and local shell
commands and is not currently a native Windows application. The public gallery
itself remains usable from any current browser on macOS, Linux, Windows,
Android or iOS.

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

Create the key while signed in as the Immich account designated to manage
public shares. An API key belongs to that account: album lookup and shared-link
creation, listing, and deletion all run with its Immich permissions. Seeing an
album shared by another Immich user does not guarantee permission to publish
it, so confirm the operation with a non-sensitive test album owned or managed
by the designated account.

The current controller supports one Immich account per deployment. Keep one API
key and one `managed_state_file` authoritative for the shared VPS
`shares_dir`. Do not run separate account configurations against that directory:
`sync`, `close`, and `sweep` may remove routes absent from the current profile
or stop the NAS forward even though another profile still has active shares.
On a multi-user NAS, centralize the albums intended for public sharing under
the designated account until a coordinator that merges all account states is
implemented. Never work around this limitation with an administrator API key.

The API key is used only between the trusted controller and Immich. The second
half of publication writes the generated Caddy route over the configured SSH
transport, so the API key is never installed on or sent to the VPS.

Use HTTPS between a separate controller and Immich. Plain HTTP is accepted only
on loopback; when an encrypted WireGuard, Tailscale, or SSH tunnel carries the
whole connection, set `allow_http_over_private_tunnel = true` explicitly. This
option is an acknowledgement, not encryption by itself.

```bash
./immich-share list
./immich-share open "Test album" --ttl 24h --for "Alex"
./immich-share open "Test album" --ttl 24h --for "Alex" --qr
./immich-share open "Test album" --ttl 24h --for "Alex" --qr-with-password
./immich-share doctor
```

`open` generates a password unless `--password` requests a hidden confirmation
prompt or `--password-file` points to a private mode-0600 file. Never place a
password value directly in a command line.

The optional QR modes require the `qrencode` executable in `PATH`; all other
commands remain dependency-free beyond Python and the controller's existing
system tools:

```bash
# macOS
brew install qrencode

# Ubuntu, Debian, or Ubuntu under WSL
sudo apt update
sudo apt install qrencode
```

`--qr` generates a QR locally from the link only, so the separately printed
password should travel through another channel. `--qr-with-password` is an
explicit convenience tradeoff: it places the password in the URL fragment
`#ipp-password=...`. The browser removes that fragment before submitting the
password through the existing HTTPS-protected unlock request. The fragment is
not part of the initial HTTP request or the access-log URL. Anyone who obtains
the combined QR can nevertheless unlock the share, so treat the image as a
credential and keep the TTL short. A missing or failing `qrencode` never rolls
back an otherwise valid share.

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
# installation path and <CONTROLLER_HOME> with the controller account's home
# directory: launchd does not expand ~. The same two placeholders apply to
# macmini/local.photo-share-monitor.plist and macmini/local.photo-tripwire.plist.
mkdir -p ~/Library/Logs/immich-share
cp local.immich-share-sweep.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/local.immich-share-sweep.plist
```

Agent logs are written under `~/Library/Logs/immich-share/` (mode 0600
directory recommended: `chmod 700 ~/Library/Logs/immich-share`) rather than
world-writable `/tmp`.

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

When the optional upload stack is installed, repeat from cellular data with a
short-lived, non-sensitive invitation:

- [ ] With an empty `drops.d/`, `/drop/i/<token>` returns 404.
- [ ] A wrong password reveals neither policy nor upload state; policy returns
      401 until the password-bound session is established.
- [ ] Only the configured photo/video policy is accepted; extension and media
      signature must both match. Archives, SVG, PDF, and executables fail.
- [ ] Per-file, file-count, invitation-byte, global-byte, disk-reserve and
      concurrency limits fail closed without leaving an unaccounted partial.
- [ ] Interrupting a chunk and resuming from the `HEAD` offset works on iOS.
- [ ] Uploading the same media twice in one invitation reports it as already
      received, leaves one manifest/file entry, and releases the second quota
      reservation; the same media in another invitation remains independent.
- [ ] Expiry blocks new and resumed chunks even before a sweep runs.
- [ ] No route lists or downloads received files; `/healthz`, admin paths and
      unexpected methods return 404 externally.
- [ ] The session cookie is `Secure`, `HttpOnly`, `SameSite` and scoped to
      `/drop`; no frontend asset, telemetry or CDN request leaves the domain.
- [ ] Forced `upload doctor` passes while the controlled invitation is active.

In the separate-controller profile, run `doctor` while the controlled test
share is active. Its forced NAS check tests the effective nginx configuration,
a forbidden route, and a fresh query sentinel; it deliberately fails when the
filter is stopped because a live redaction check would otherwise be impossible.

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
- [ ] The share doctor certifies exactly four steady-state OUTPUT accepts:
      loopback, established replies, the literal WireGuard UDP endpoint, and
      the current `immich_server:2283` address. nginx reaches it only through
      the `127.0.0.1:18080` relay and public DNS resolution fails. In the
      NAS-controller profile a fifth accept, TCP/22 to `<WG_VPS_ADDRESS>`, is
      certified only because the root-owned `/etc/immich-share/doctor.env`
      names that address and `wg-tunnel` carries the identical
      `WG_CONTROLLER_SSH_PEER`; the upload doctor rejects the variable outright.
- [ ] `docker exec wg-tunnel ip6tables -S OUTPUT` prints exactly
      `-P OUTPUT DROP` (or ip6tables reports that the kernel has no IPv6); the
      OUTPUT allowlist is IPv4-only and both doctors refuse an IPv6 namespace
      that is not fail-closed. Neither doctor depends on
      `/proc/sys/net/ipv6`, which is absent on IPv6-less kernels.
- [ ] `/var/log/immich-share/denied.log` exists and resolves into the deployed
      `nas/logs` directory; the share doctor fails otherwise.
- [ ] `tripwire follow` through the gate streams a fresh denied entry to the
      Mac mini tripwire, while `tail`, `cat`, or any other command is refused.
- [ ] `ping <WG_CONTROLLER_ADDRESS>` and `nc -vz <WG_CONTROLLER_ADDRESS> 22`
      fail because of the admin-host
      packet-filter rule.
- [ ] After closing every share, `curl http://<WG_NAS_ADDRESS>:2283/` is refused because
      the NAS forward is stopped.
- [ ] `sudo iptables -S FORWARD` contains `-i wg0 -o wg0 -j DROP`, and
      `sudo iptables -S DOCKER-USER` lists the `immich-tunnel` and
      `immich-uptun` ACCEPT rules, the `-o wg0` DROP and the two bridge DROPs
      tagged `--comment immich-share` in the order shown in section 5, and
      nothing else from this project.
- [ ] `systemctl is-enabled immich-share-containment` prints `enabled`, the unit
      is `active (exited)`, and `/etc/wireguard/wg0.conf` contains no
      `DOCKER-USER` line.
- [ ] After `sudo systemctl restart wg-quick@wg0`, `sudo iptables -S DOCKER-USER`
      is unchanged and the throwaway-container refusals below still hold.
- [ ] From a throwaway container on `photo-share_tunnel_net`,
      `<WG_CONTROLLER_ADDRESS>:22`, `<UPLOAD_NAS_WG_ADDRESS>:2383` and a public
      address are all refused; only `<WG_NAS_ADDRESS>:2283` connects while a
      share is active.

For the optional upload peer, also verify from the VPS:

- [ ] The `immich_drop` network contains only `wg-upload-tunnel` and
      `immich-upload-drop`; it has no Immich, PostgreSQL, Redis, read tunnel or
      unrelated NAS service.
- [ ] `immich_drop` reports `Internal: true`; the separate egress network
      contains only `wg-upload-tunnel`, and `immich-upload-drop` is absent from
      it.
- [ ] The upload doctor reports OUTPUT-DROP, certifies that the only four
      steady-state ACCEPT rules are loopback, established replies, the literal
      WireGuard UDP endpoint and the exact `upload-drop:8080` address, reaches
      that service through `127.0.0.1:18080` from the nginx sidecar, and refuses
      public DNS plus external and LAN connection probes.
- [ ] `upload-guard` has no published port or persistent writable mount and can
      reach only the dedicated upload filter address through WireGuard.
- [ ] `photo-share_upload_net` contains only `caddy` and `upload-guard`;
      `upload-guard` is absent from `photo-share_app_net` and
      `photo-share_tunnel_net`, and a throwaway container on
      `photo-share_upload_tunnel_net` is refused everywhere except
      `<UPLOAD_NAS_WG_ADDRESS>:2383`.
- [ ] The NAS upload filter allows only the documented GET/POST/HEAD/PATCH/DELETE
      contract; probes for `/healthz`, `/api`, `/admin`, traversal and unexpected
      methods return 404.
- [ ] A request containing a unique invitation-token/query sentinel leaves
      neither value in Caddy, upload-guard, NAS filter or application logs.
      Upload logs contain only normalized action, status and byte counts.
- [ ] With no active invitation, `drops.d/` is empty and `wg-upload-filter` is
      stopped; the read-only gallery remains unaffected.

## 8. Operations

- Review IPP routes in `logs/allowed.log` during a complete test. Any route
  introduced by an IPP update must first hit `denied.log`, be audited, and only
  then be added explicitly to the allowlist.
- Confirm Docker log limits and the isolated NAS `immich-share-logrotate`
  service remain active; never switch the route log format back to `$request`
  or `$request_uri`.
- Alert on proxy failure, tunnel failure, disk reserve, and tripwire events.
- Treat the upload dataset quota, application global budget and disk reserve as
  independent ceilings. Alert before any one is exhausted; never weaken the
  fixed reserve to make a current invitation fit.
- Review every new upload application route against both nginx allowlists
  before upgrading its immutable image. Unknown routes must fail 404 first.
  Re-run the token/query log sentinel after every application, Caddy or nginx
  change. Keep partial-data cleanup active, but never run two invitation sweep
  owners during a controller migration.
- Keep the monitor on loopback where possible. It always requires a mode-0600
  password file and rate-limits failed authentication. A non-loopback bind also
  requires `allow_http_over_private_tunnel = true`, and is valid only inside an
  encrypted private tunnel. The monitor sends no wildcard CORS response.
- Back up configuration without private keys, API keys, share keys, or passwords.
