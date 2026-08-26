# NAS-controller profile

This optional profile runs the `immich-share` CLI on the NAS instead of a
separate administrator machine. The VPS still receives no Immich API key.

## Security trade-off

The NAS is always on and already hosts Immich, so expiry sweeps become simpler
and more reliable. The cost is credential concentration: a root compromise of
the NAS gains the photo library, the scoped Immich API key, and a VPS controller
SSH key. A separate controller keeps those privileges in different trust zones
and remains the recommended high-isolation profile.

Membership in the Docker group is root-equivalent. This profile runs the CLI on
the NAS host and uses local `docker start`/`docker stop`; it never mounts the
Docker socket into another container.

## Transport

The NAS host does not have a route to `<WG_VPS_ADDRESS>` because WireGuard lives in
`wg-tunnel`. OpenSSH solves this without moving the tunnel to the host:

```text
immich-share → ssh → ProxyCommand → docker exec wg-tunnel nc → <WG_VPS_ADDRESS>:22
```

Run the read-only prerequisite check first:

```bash
WG_CONTAINER=wg-tunnel \
FILTER_CONTAINER=wg-nginx-filter \
LOGROTATE_CONTAINER=immich-share-logrotate \
IMMICH_CONTAINER=immich_server \
IMMICH_SHARE_NETWORK=immich_share \
VPS_WG_ADDRESS=<WG_VPS_ADDRESS> \
./doctor-preflight.sh
```

## Installation

1. Copy `immich-share` and this directory to a private location on the NAS.
2. Copy `config.example.ini` to `~/.config/immich-share/config.ini` and set mode
   600. Replace the domain and any host-specific paths.
3. Merge `ssh-config.example` into `~/.ssh/config` and set mode 600.
4. Generate a dedicated key locally on the NAS. Never copy a private key from
   another controller:

   ```bash
   ssh-keygen -t ed25519 -f ~/.config/immich-share/vps-controller-key -C immich-share-nas-controller
   ```

5. Verify the VPS host-key fingerprint through the existing trusted controller,
   then make the first SSH connection through the alias. Authorize only the new
   public key on the VPS and restrict its source to the NAS WireGuard address.
6. Create a new scoped Immich API key or securely install an existing scoped
   key at `api_key_file`; set mode 600.
7. Run `immich-share doctor --mode nas`. Do not run `open`, `close`, `sync`, or
   `sweep` until every read-only check passes.
8. Install the cron entry only after deciding to make the NAS the active
   controller. Never run expiry sweep from two controllers during migration.

The managed-share registry starts empty. Existing Immich links remain
`external` and cannot be published or deleted by this controller until the
operator explicitly runs `immich-share adopt <key-prefix>`. Before adopting,
confirm out of band that the link has a strong password and finite expiry.

Keep the Mac mini controller active while testing this profile. A preflight or
`doctor` run is read-only and can safely coexist; operational commands must have
one owner at a time.
