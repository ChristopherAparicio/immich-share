# immich-share

**Share photo albums from your self-hosted [Immich](https://immich.app) with anyone — via a simple browser link, without exposing Immich, and without handing your photos to a US or Chinese cloud.**

`immich-share` is a small layer of Python, configuration, and a web console around existing free software. It turns a cheap, sovereign VPS into a **closed-by-default sharing edge** for your home NAS: a friend gets a link + a password, sees a gallery, downloads, and the door closes on its own when the share expires.

> **Why this exists.** Your NAS vendor nudges you toward *its* cloud. The easy way to send photos — Google Photos, iCloud, WeTransfer — hands your pictures to foreign infrastructure, at rest, permanently. This project keeps the photo library on **your** NAS, terminates TLS on **your** machines, and routes through a **Swiss** (or wherever you choose) VPS over WireGuard. Only resumable bulk ZIPs are cached temporarily at the edge and deleted automatically.

---

## What it is (and isn't)

| | |
|---|---|
| ✅ Share Immich albums by link + password | ❌ Not a second photo library — Immich stays the single source of truth |
| ✅ Immich is never exposed to the internet | ❌ Not zero-knowledge — the edge sees photos in RAM *during a share* (see [Threat model](#threat-model)) |
| ✅ Ephemeral edge — only short-lived resumable ZIPs touch disk | ❌ Not a Google Photos replacement — it's a *sharing* tool |
| ✅ Closed by default — 404 on everything when no share is active | |

## Architecture

```
┌─ HOME (no inbound ports) ─────────────────────────┐
│  NAS ── Immich  ← source of truth, never exposed  │
│      └─ WireGuard container + filtering nginx     │
│  Admin machine ── immich-share CLI + web console  │
└──────────────────┬─────────────────────────────────┘
                   │  HOME dials OUT to the VPS
                   │  (WireGuard, PersistentKeepalive → traverses NAT)
                   ▼
┌─ Sovereign VPS (e.g. 🇨🇭 / 🇪🇺) ────────────────────┐
│  Caddy :443 → Let's Encrypt (TLS on your machine) │
│  immich-public-proxy → serves ONLY shared links   │
│  ⚠️ short-lived ZIP cache; automatic deletion     │
└──────────────────┬─────────────────────────────────┘
                   ▼
      friends: link + password → gallery → download
```

**The trust boundary is enforced at home, never on the VPS.** A compromised VPS can reach exactly one filtered route to Immich (and only while a share is open) — never the LAN, never the admin machine. See [`SETUP.md`](SETUP.md) and [`macmini/pf-wireguard.md`](macmini/pf-wireguard.md).

## Components

**Third-party (you configure, you don't fork):**
- [Immich](https://immich.app) — your photo library (the source of truth)
- [`immich-public-proxy`](https://github.com/alangrainger/immich-public-proxy) — stateless proxy that serves only shared links (AGPL-3.0)
- [Caddy](https://caddyserver.com) + [`caddy-ratelimit`](https://github.com/mholt/caddy-ratelimit) — TLS + rate limiting
- [WireGuard](https://www.wireguard.com) — the home↔VPS tunnel

**This repo:**
- `immich-share` — the CLI: `open` / `list` / `adopt` / `sync` / `close` / `sweep` / `doctor`. Creates an Immich share link **and** opens the matching Caddy path + home-side forward, then closes everything on expiry. `doctor` is read-only.
- `macmini/photo-share-monitor.py` — an authenticated, rate-limited web console (create/list/close shares, per-album telemetry) + a `/devhub` endpoint for dashboards/alerts. It binds to loopback by default; remote use requires an explicitly acknowledged encrypted private tunnel. Self-contained HTML/CSS/JS, no framework, no external CDN.
- `nas/`, `vps/`, `macmini/` — the deployment artifacts (compose, Caddyfile, WireGuard, nginx filter, pf rules).
- `nas/controller/` — an optional NAS-hosted controller profile with a
  no-secret preflight, SSH-over-container transport, configuration, and cron
  example. The separate admin-machine profile remains the isolation default.

## Quickstart

Full, reproducible runbook (human- or agent-executable): **[`SETUP.md`](SETUP.md)**.
Repository-aware coding agents also receive the safety and discovery workflow in
[`AGENTS.md`](AGENTS.md). Initial infrastructure deployment is intentionally a
reviewable runbook rather than a one-command installer; the CLI manages shares
after setup.

In short:
1. A cheap VPS + a domain (`A photos.example.com → <VPS_PUBLIC_IP>`).
2. A WireGuard tunnel your **home** dials out to the VPS (no port-forward).
3. Caddy + `immich-public-proxy` on the VPS; a filtering nginx on the NAS.
4. `immich-share open "My Album" --ttl 48h --for "Alex"` → link + password.

The controller may run on a separate trusted machine or directly on the NAS.
The separate profile splits the photo library, Immich API key, and VPS SSH
administration across trust zones. The NAS-controller profile needs fewer
machines and gives reliable always-on sweeps, but concentrates those privileges
on the NAS. The VPS never receives the Immich API key in either profile.

Public templates deliberately contain no real RFC1918/CGNAT address plan,
operator home path, NAS volume path, or credential. Choose WireGuard addresses
and ports only in ignored deployment copies. Before publishing a change, run
`python3 scripts/check-public-tree.py` plus a secret scanner against the full
Git history.

## Threat model (the honest part)

Most tutorials wave security away. This one has a real model — read [`SETUP.md`](SETUP.md) and the inline docs:

- **The provider *can* technically read RAM and a short-lived ZIP cache during a share window.** We don't pretend otherwise. The window is narrow and the cache is deleted automatically. True zero-knowledge requires a different design (e.g. [Ente](https://ente.io)) with export friction.
- **A compromised VPS is contained by topology, not by the VPS itself:** filtering nginx (fail-closed) on the trusted side, no route to the LAN, `pf` blocking the admin machine, and a `denied.log` tripwire that pings you on the first probe.
- **Caveat on "stateless":** the proxy writes no photos, but Caddy keeps a short-lived access log on the VPS that contains the share URLs — i.e. the share *keys*. The share key also crosses WireGuard to IPP/Immich as part of the request. A compromised VPS can therefore read a key during an active share, but a key alone is useless without its password. The NAS nginx logs deliberately retain only method + normalized path and never the query string; its error log is disabled because nginx error entries can echo the raw `?key=` request.
- **The Immich API key never goes to the VPS.** It is used only by the controller to call Immich. A separate controller must use HTTPS to Immich, loopback, or explicitly confirm that clear-text HTTP is carried inside a private encrypted tunnel.
- **The real weak point is the link itself** (a friend forwarding it). Hence: always a password, short TTL, and the two-channel rule (link one way, password another).

## Configuration

Copy `config.example.ini` to `~/.config/immich-share/config.ini` and fill it in. Secrets (`config.ini`, `api-key`, `*.key`) are gitignored — **never commit them**. Create a **scoped** Immich API key (shared-links + album read only), never the admin key.

Sharing defaults live in `[sharing]`:

```ini
[sharing]
default_ttl = 24h
default_allow_download = true
max_ttl = 30d
managed_state_file = ~/.config/immich-share/managed-shares.json
```

`--ttl`, `--download`, and `--no-download` override these defaults for one
share. Image quality is global to the public proxy and is configured in
`vps/ipp-config.json`:

| Setting | Values | Effect |
|---|---|---|
| `maxZoomQuality` | `preview`, `fullsize` | Quality displayed when zooming in the gallery |
| `maxDownloadQuality` | `preview`, `fullsize`, `original` | Highest quality offered by the download buttons |

The shipped profile uses `preview` for gallery zoom and `original` for
downloads. Original files can include embedded EXIF/GPS metadata. Use `preview`
when metadata removal matters more than full-resolution downloads; `fullsize`
is an intermediate, browser-displayable tier and is not guaranteed to return
the original bytes for every asset.

Recent Immich versions require shared-link metadata permission when original
downloads are enabled, because the original itself may contain EXIF/GPS. The
CLI therefore sends `showMetadata: true` with `--download` and `false` with
`--no-download`. IPP's shipped configuration keeps every metadata field hidden
in the public gallery; this does not remove metadata embedded in a downloaded
original.

Bulk ZIP downloads are enabled with a small-VPS safety profile. IPP stages the
source files in the disk-backed `vps/zip-staging/` directory, never in its RAM
tmpfs, and a version-pinned build patch enforces a 2 GiB aggregate ceiling plus
a 5 GiB free-disk reserve. It then builds an immutable archive with an exact
`Content-Length` and byte-range support. The private cache lives for 30 minutes
so a mobile client can resume, then it is deleted automatically. Worst-case
disk preflight accounts for staged originals and the final ZIP. Fetch
concurrency from Immich is three files.

Individual `.../original` responses pass through a dedicated nginx download
guard. Defaults are 2 MiB/s per response, two active downloads per public IP,
and six globally. Caddy explicitly overwrites the internal client-IP header;
the guard has no published port and rejects every non-download route. Gallery
HTML, thumbnails, preview zoom and metadata bypass it, so normal browsing is
not throttled. Caddy does not otherwise perform fair bandwidth sharing: without
this guard, concurrent TCP streams simply compete for the available link.

ZIP responses pass through the same guard at 2 MiB/s, with exactly one active
ZIP globally. A concurrent request receives HTTP 429, `Retry-After: 30`, and a
small internal HTML page; there is deliberately no persistent queue. Oversized
archives receive 413, while an insufficient disk reserve receives 507. These
pages contain no share, visitor, size, progress, or throughput information.

### Small-VPS resource profile

The Compose defaults cap Caddy at 128 MB, IPP at 512 MB and the download guard
at 64 MB, with a 256 MB IPP tmpfs used only for ordinary transient data. ZIP
staging is disk-backed and bounded separately. These values are ceilings, not
reservations: idle consumption does not increase. Copy `vps/.env.example` to
`vps/.env` to override them. The NAS has equivalent optional ceilings in
`nas/.env.example`.

Docker stdout/stderr logs rotate at 10 MB with three files per container. The
NAS bind-mounted sanitized route logs rotate automatically at 10 MB with three
compressed generations through the isolated `immich-share-logrotate` service.

Only links created by this CLI, or explicitly imported with `immich-share
adopt <key-prefix>`, are written to the public portal or deleted by `sweep`.
This prevents an unrelated/manual Immich shared link from being published or
revoked accidentally. Adoption is intentionally explicit: first confirm that
the existing link has a strong password and an expiry, because the API cannot
return its password for the CLI to verify.

`scripts/benchmark-downloads.py` performs a bounded staircase benchmark without
storing the downloaded files. It prompts for the credential-bearing URL and
password without echo. Run it only with a temporary, non-sensitive test album
and while monitoring both hosts; the detailed procedure is in `SETUP.md`.

## License

See [`LICENSE`](LICENSE). This is your original code; `immich-public-proxy` (AGPL-3.0) is a separate program you run alongside it, not linked into this code.

## Credits

Built on the shoulders of Immich, immich-public-proxy, Caddy, and WireGuard — thank you to their authors. Assembled and documented as a sovereignty case study.
