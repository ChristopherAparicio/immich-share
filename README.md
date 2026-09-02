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
| ✅ Optional password-protected upload invitations into NAS quarantine | ❌ Uploaded files never enter Immich automatically |

## Architecture

```
┌─ HOME (no inbound ports) ─────────────────────────┐
│  NAS ── Immich  ← source of truth, never exposed  │
│      └─ WireGuard container + filtering nginx     │
│      └─ optional upload quarantine (isolated)      │
│  Admin machine ── immich-share CLI + web console  │
└──────────────────┬─────────────────────────────────┘
                   │  HOME dials OUT to the VPS
                   │  (WireGuard, PersistentKeepalive → traverses NAT)
                   ▼
┌─ Sovereign VPS (e.g. 🇨🇭 / 🇪🇺) ────────────────────┐
│  Caddy :443 → Let's Encrypt (TLS on your machine) │
│  immich-public-proxy → serves ONLY shared links   │
│  optional upload guard → streams bounded chunks   │
│  ⚠️ short-lived ZIP cache; automatic deletion     │
└──────────────────┬─────────────────────────────────┘
                   ▼
      friends: link + password → gallery → download
```

The optional write path deliberately does not reverse the read path. It has a
second NAS WireGuard peer, its own nginx allowlist and Docker network, and a
quarantine dataset that is not mounted into Immich:

```text
browser /drop → Caddy → VPS upload-guard → dedicated WireGuard peer
              → NAS upload-filter → upload-drop → quarantine dataset

local operator/importer ───────────────────────────→ Immich (separate action)
```

**The trust boundary is enforced at home, never on the VPS.** A compromised VPS
can reach only the read-side Immich filter while a share is open. When uploads
are enabled, its second peer reaches only the separate upload filter and
quarantine service—not Immich, the LAN, or the admin machine. See
[`SETUP.md`](SETUP.md) and [`macmini/pf-wireguard.md`](macmini/pf-wireguard.md).

## Components

**Third-party and separately licensed components:**
- [Immich](https://immich.app) — your photo library (the source of truth)
- [`immich-public-proxy`](https://github.com/ChristopherAparicio/immich-public-proxy) — our separately maintained, security-focused fork of the stateless public gallery, with resumable ZIPs and deterministic multipart downloads (AGPL-3.0)
- [`immich-drop`](https://github.com/ChristopherAparicio/immich-drop) — our
  separately released MIT upload application: invitation UI, resumable
  eight-MiB chunks, policy enforcement and quarantine storage. The deployment
  pins its multi-architecture image by immutable digest; no application source
  or image is bundled in this repository.
- [Caddy](https://caddyserver.com) + [`caddy-ratelimit`](https://github.com/mholt/caddy-ratelimit) — TLS + rate limiting
- [WireGuard](https://www.wireguard.com) — the home↔VPS tunnel

**This repo:**
- `immich-share` — the CLI: `open` / `list` / `adopt` / `sync` / `close` / `sweep` / `doctor`. Creates an Immich share link **and** opens the matching Caddy path + home-side forward, then closes everything on expiry. `open --json` and `list --json` emit machine-readable output (progress goes to stderr) so other tools never parse the human text. `doctor` is read-only and, in separate-controller mode, uses a narrow forced NAS command to certify the deployed trust boundary.
- `macmini/photo-share-monitor.py` — an authenticated, rate-limited web console (create/list/close shares, per-album telemetry) + a `/devhub` endpoint for dashboards/alerts. It binds to loopback by default; remote use requires an explicitly acknowledged encrypted private tunnel. Self-contained HTML/CSS/JS, no framework, no external CDN. It drives the CLI through `open --json`/`close` and imports the CLI module for configuration, secrets and the Immich client, so there is one implementation of each. Console API (version 2.1): `/devhub` reports `status` `ok`/`warn`/`error`, a `telemetry` object (`status` `ok`/`stale`/`unknown`, `peers` nullable, `expected_peers`) and the metric `ratelimit_429` (formerly `auth_fail`, which counted Caddy 429s all along); `/shares` answers HTTP 502 with a generic error while Immich is unreachable.
- `nas/`, `vps/`, `macmini/` — the deployment artifacts (compose, Caddyfile, WireGuard, nginx filter, pf rules).
- `nas/docker-compose.upload.yml` and `vps/docker-compose.upload.yml` — optional
  write-side deployment overlays, kept separate so a gallery update cannot
  accidentally enable uploads.
- `nas/upload-admin-helper.py` — root-owned, forced-command JSON bridge for
  remote invitation `open`/`list`/`close`/`sweep`; it exposes neither a shell,
  arbitrary Docker commands, password arguments, `init`, nor `purge`.
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
4. `immich-share open "My Album" --ttl 48h --for "Alex"` → link + generated password.

### Common sharing workflows

`immich-share` publishes albums. Use Immich's [advanced search
filters](https://docs.immich.app/features/searching) to prepare an album when
the starting point is a person or a selection of assets:

| What to share | Prepare it in Immich |
|---|---|
| An existing album | No preparation; open it directly with `immich-share open`. |
| One person | Filter by that face, select the matching assets, and add them to a new or existing album. |
| Several people together | Filter for all selected faces, then add the results to an album. |
| Any of several people | Filter for any selected face, then add the combined results to an album. |
| An event or manual selection | Select the assets and add them to an album. |

Albums reference the existing assets, so placing a photo in several albums does
not duplicate its media file. A face-search album is a point-in-time selection:
add newly recognized photos to it when needed. The `--for` option labels the
link's recipient; it does not select a person shown in the photos.

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
- **A compromised VPS is contained by topology, not by the VPS itself:** filtering nginx (fail-closed) on the trusted side, no route to the LAN, `pf` blocking the admin machine, and a `denied.log` tripwire that pings you on the first probe (it follows the log through the exact `tripwire follow` forced command, so the admin machine holds no NAS shell). On the VPS itself, a compromised IPP container shares no Docker network with the upload guard and its bridge may forward only to the two NAS filter ports (`DOCKER-USER` rules installed by the `vps/containment/` systemd unit, independent of the tunnel's lifecycle and verified by `doctor`); the VPS never relays between WireGuard peers.
- **Caveat on "stateless":** the proxy writes no photos, but Caddy keeps a
  short-lived access log on the VPS. The complete request URI is redacted before
  that log is written; per-album telemetry uses a truncated one-way SHA-256
  reference plus a coarse action rather than the share key. The share key still
  crosses the VPS and WireGuard to IPP/Immich as part of a live request, so a
  compromised VPS can read it in transit; a key alone remains insufficient
  without its password. IPP also redacts keys from application logs. The NAS
  nginx logs retain only method + normalized path and never the query string;
  its error log is disabled because nginx error entries can echo raw queries.
- **The Immich API key never goes to the VPS.** It is used only by the controller to call Immich. A separate controller must use HTTPS to Immich, loopback, or explicitly confirm that clear-text HTTP is carried inside a private encrypted tunnel.
- **The separate controller key is an invitation administrator.** If stolen, it
  can create, list, close and sweep upload invitations within fixed limits and
  operate the two filters. It still cannot request an arbitrary Docker command,
  supply a password, purge data, initialize storage or obtain a general NAS
  shell. Protect and revoke this dedicated key independently.
- **The real weak point is the link itself** (a friend forwarding it). Hence: always a password, short TTL, and the two-channel rule (link one way, password another).
- **Uploads accept untrusted bytes.** Extension and media-signature checks,
  quotas and quarantine prevent ordinary abuse and library pollution; they do
  not make a valid but malicious media file harmless. Keep Immich and its media
  parsers current before a separate local import. The upload service never
  invokes ffmpeg, metadata tools, archives, or Immich on the public path.

## Configuration

Copy `config.example.ini` to `~/.config/immich-share/config.ini` and fill it in. Secrets (`config.ini`, `api-key`, `*.key`) are gitignored — **never commit them**. Create a **scoped** Immich API key (shared-links + album read only), never the admin key.

### Immich account scope

An Immich API key belongs to the Immich account that created it. The controller
uses that identity to discover albums and to create, list, and delete shared
links. It can therefore operate only on albums and links that Immich makes
available to that account. Access to a shared album does not necessarily grant
permission to publish it; Immich remains responsible for enforcing the album's
permissions.

The current controller is single-account: one configuration selects one API
key and one managed-share registry. Do not run independent account profiles
against the same VPS `shares_dir`. Each profile would treat its own registry as
authoritative, so `sync`, `close`, or `sweep` could remove another profile's
Caddy routes or disable the NAS forward while its shares are still active. For
a NAS with several Immich users, designate one account to manage the albums
published through Immich Share. Proper multi-account support requires one
coordinator that reconciles the union of every account's active shares.

The API key remains on the trusted controller. Creating the Immich shared link
uses that key, while publishing its route on the VPS uses the configured SSH
transport. The VPS never receives the Immich API key.

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

A share password is generated by default. For a custom value, use `--password`
to enter and confirm it through a hidden prompt, or `--password-file` with a
mode-0600 regular file owned by the current user. Password values are never
accepted as command-line arguments because process listings and shell history
can expose them.

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

Every generated Caddy route is an anchored, case-insensitive regular expression
and the routes of one share are mutually exclusive, so neither Caddy's handle
ordering nor a differently cased URL (`/share/Photo/…/Original`) can steer an
original past the guard; `scripts/test-immich-share.py` asserts this. One
documented exemption remains: video playback uses the size-less
`/share/video/<key>/<id>` route, on which the proxy streams the original video
bytes without the guard so that playback is not throttled or capped per IP.

ZIP responses pass through the same guard at 2 MiB/s. Up to three prepared
archives may transfer concurrently (`ZIP_GLOBAL`), while only one new archive
is staged at a time. The gallery shows an English progress dialog while the
archive is fetched and finalized, then exposes an explicit download button with
the exact size. Up to three additional visitors wait in a process-local FIFO;
closing the dialog keeps the request queued, while **Leave queue** cancels it.
The fourth waiting request receives HTTP 429 and `Retry-After: 30`. The queue is
intentionally ephemeral and is cleared by an IPP restart. Oversized archives
receive 413, while an insufficient disk reserve receives 507; neither response
reveals visitor, share, progress, or throughput information.

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

## Optional sovereign upload drop

The upload deployment uses the existing domain under `/drop`; it requires no
new public port or DNS record. It is closed at three independent layers:

- an empty VPS `drops.d/` directory exposes no Caddy handler;
- a stopped `wg-upload-filter` closes the dedicated NAS WireGuard address;
- the application checks the invitation expiry, password-bound session, media
  policy, file/count/byte quotas and upload ownership on every request.

The browser receives a self-contained UI from the three local assets
`/drop/assets/app.js`, `drop.css`, and `favicon.png`. It creates an
upload and sends raw resumable chunks of at most eight MiB with `PATCH`; `HEAD`
discovers the committed offset after a mobile interruption and `DELETE`
cancels it. Chunk requests interleave naturally, so saturation returns bounded
HTTP 429 responses instead of maintaining a resource-heavy server queue. An
absolute per-chunk deadline prevents slow clients from holding upload slots;
one application-owned periodic sweeper removes stale incomplete work.

Files are written under server-generated invitation and upload identifiers,
first as partial data and then atomically into `completed/`. Visitor-provided
paths are never used. Configure a dedicated host dataset with an operating-
system quota in addition to the application quota and free-space reserve.

Completed media is hashed by the server and deduplicated only inside the same
invitation. The first copy remains canonical; a later identical upload is
removed, its quota reservation is released, and the UI says it was already
received. The complete file must still cross the network before this decision,
so immutable per-invitation attempt, request, and ingress-byte work budgets
bound repeated work. No content hash or cross-invitation match is exposed.

The VPS has no upload volume and the NAS application has no Immich API key,
Immich network, Docker socket, Internet egress, download/listing route, or
access to the photo library. Its Docker network is internal; only the separate
WireGuard namespace joins a second egress network. Its OUTPUT policy uses Docker
DNS only long enough to resolve the exact internal upload service, starts a
loopback-only TCP relay to that resolved address, then closes DNS; only that
service, established replies and the literal WireGuard UDP endpoint remain
reachable. The nginx sidecar connects only to the relay in their shared network
namespace and does not depend on shared resolver files.
Import is intentionally a later, local operator action. See the
optional deployment section and security checklist in [`SETUP.md`](SETUP.md).
The complete close, review, Immich CLI import and purge procedure—including why
the separate controller cannot read the NAS quarantine—is documented in
[`UPLOAD_IMPORT.md`](UPLOAD_IMPORT.md).

A separate controller can administer invitations through the existing
restricted NAS SSH key. The helper consumes a bounded JSON object on stdin and
executes the container's local CLI with fixed argv; it never exposes an HTTP
admin route. Creating an invitation does not start the NAS filter or install
the Caddy handler, so the public path remains closed until the explicit
fail-closed activation sequence completes.

## License

Original orchestration code is MIT under [`LICENSE`](LICENSE). The separately
maintained IPP fork and historical derived patch material are AGPL-3.0-only;
see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for the exact boundary.

## Credits

Built on the shoulders of Immich, immich-public-proxy, Caddy, and WireGuard — thank you to their authors. Assembled and documented as a sovereignty case study.
