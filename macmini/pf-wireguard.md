# Make the administrator WireGuard tunnel one-way with macOS pf

WireGuard is symmetric. Allowing the administrator peer at
`<WG_CONTROLLER_ADDRESS>` also
allows the VPS to initiate traffic toward the Mac mini, which holds the VPS SSH
key and Immich API key. Without a packet-filter rule, claiming that the VPS
cannot reach the admin machine would be incorrect.

## Filter by address, not interface

The macOS WireGuard implementation creates a `utunN` interface whose number can
change on every activation. A rule bound to a fixed interface such as `utun12`
is therefore fragile. Filter on the private tunnel network (`<WG_CIDR>`)
instead. Substitute the real CIDR only in the private deployed anchor.

Create `/etc/pf.anchors/wg-inbound`:

```pf
# Allow replies to connections initiated by the Mac mini. Block and log every
# connection initiated from the tunnel toward the Mac mini.
pass out quick inet proto { tcp udp icmp } from any to <WG_CIDR> keep state
block in log quick inet from <WG_CIDR> to any
```

Append to `/etc/pf.conf`:

```pf
anchor "wg-inbound"
load anchor "wg-inbound" from "/etc/pf.anchors/wg-inbound"
```

The explicit `pass out … keep state` rule is essential. Without state creation,
replies from the VPS to outbound SSH or ping traffic would hit `block in`.

## Persistence after reboot

Do not start WireGuard and pf from independent LaunchDaemons: scheduler order is
not guaranteed, so the tunnel can briefly exist before the inbound block.

The starter runs as root, so it executes only root-owned copies of the
WireGuard tools. Homebrew's prefix is owned by the operator account: a root
daemon that ran `wg-quick` from there would let any compromise of that account
(for example through the photo-share-monitor process) become root at the next
boot. Copy the four executables `wg-quick` needs into a root-owned directory
and keep the tunnel config outside the Homebrew prefix:

```bash
sudo install -d -o root -g wheel -m 0755 /usr/local/libexec/immich-share-wireguard
for tool in wg-quick wg wireguard-go bash; do
  sudo install -o root -g wheel -m 0755 "$(readlink -f "$(brew --prefix)/bin/$tool")" \
    /usr/local/libexec/immich-share-wireguard/
done
# The copies must not load libraries from the operator-writable prefix.
# This must print nothing.
otool -L /usr/local/libexec/immich-share-wireguard/bash \
  /usr/local/libexec/immich-share-wireguard/wg \
  /usr/local/libexec/immich-share-wireguard/wireguard-go | grep /opt/homebrew || true
sudo install -d -o root -g wheel -m 0700 /etc/wireguard
sudo install -o root -g wheel -m 0600 <FILLED_IN_WG0_CONF> /etc/wireguard/wg0.conf
```

Repeat the copy step after every `brew upgrade` of `wireguard-tools`,
`wireguard-go` or `bash`; the copies do not follow Homebrew. Then install the
fail-closed starter and its single LaunchDaemon:

```bash
sudo install -o root -g wheel -m 0755 macmini/start-wireguard-fail-closed.sh \
  /usr/local/sbin/immich-share-wireguard-start
sudo install -o root -g wheel -m 0644 macmini/local.immich-share-wireguard.plist \
  /Library/LaunchDaemons/local.immich-share-wireguard.plist
sudo plutil -lint /Library/LaunchDaemons/local.immich-share-wireguard.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/local.immich-share-wireguard.plist
```

Remove or disable any previous independent WireGuard/pf LaunchDaemons and the
WireGuard GUI auto-connect setting first. The starter refuses to start unless
the tool directory, each of the four tools, `/etc/wireguard` and `wg0.conf` are
root-owned, free of symlinks and writable by neither group nor others, and it
never searches the Homebrew prefix. It then validates and enables pf, verifies
the effective anchor, and only then calls `wg-quick up`. If any check fails, it
leaves the tunnel down. The config path defaults to `/etc/wireguard/wg0.conf`
(mode 0600); override it with `WG_CONFIG`, and the tool directory with
`TOOL_DIR`, in the plist if needed.

## Validation

On the Mac mini:

```bash
sudo pfctl -a wg-inbound -sr
sudo pfctl -s info | head -1
ssh vps-photos hostname
```

The anchor must be loaded, pf must report `Status: Enabled`, and outbound SSH
must work. From the VPS, both commands below must fail:

```bash
ping -c 2 <WG_CONTROLLER_ADDRESS>
nc -vz -w 3 <WG_CONTROLLER_ADDRESS> 22
```

Inspect blocked packets with `sudo tcpdump -n -e -i pflog0`. Treat any such
packet as a tripwire event, just like an entry in the NAS `denied.log`.
