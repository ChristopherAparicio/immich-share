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

| LaunchDaemon | Role |
|---|---|
| `/Library/LaunchDaemons/local.wg-quick-wg0.plist` | Run `wg-quick up wg0` at boot using `/opt/homebrew/etc/wireguard/wg0.conf` |
| `/Library/LaunchDaemons/local.pf-wg.plist` | Run `pfctl -f /etc/pf.conf && pfctl -e` after a short boot delay |

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
