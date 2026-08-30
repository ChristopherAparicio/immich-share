# Agent instructions for immich-share

Read `README.md` and `SETUP.md` before changing deployment files. Treat the NAS,
administrator machine, and VPS as separate trust zones.

The optional upload-drop stack is a fourth, write-side trust zone. It must use
its dedicated WireGuard peer, Docker network, nginx filter, state directory,
and quarantine dataset. Never attach `upload-drop` to `immich_share`, mount the
Immich library or Docker socket into it, or install an Immich API key in the
public upload service. The data network must be Docker-internal; only the
WireGuard namespace may join the separate egress network. Its OUTPUT-DROP flow
may use Docker DNS only to resolve the exact internal upstream and start the
loopback-only relay before removing DNS access; the steady-state allowlist
contains only that upstream, established replies and the literal tunnel
endpoint. The nginx sidecar must proxy only to that relay, never to a Docker
service name. Import into Immich is a separate local operation.

Remote upload administration must pass through `nas/upload-admin-helper.py` and
the exact forced-command cases. Keep its 4-KiB stdin JSON bound, fixed container
and executable, strict field/limit validation, full-UUID close requirement and
argv-only execution with a fixed local Docker socket and sanitized environment.
Never add password input, arbitrary CLI flags, `init`,
`purge`, a Docker socket for the controller, or an HTTP administration route.
Invitation mutations must not implicitly change Caddy or filter state.
Keep the application's absolute chunk timeout and its single internal periodic
sweeper enabled. Do not install a second cron or timer for upload sweeps.

Review and import are NAS-local trusted operations described in
`UPLOAD_IMPORT.md`. Keep an importer separate from `upload-drop`: read-only
quarantine mount, scoped Immich key file, no public route, no Docker socket and
no automatic purge. The separate controller has no quarantine read permission
or import permission. Any future remote trigger must be a distinct exact
forced-command helper taking only a full invitation UUID; never broaden the
existing upload administration bridge into filesystem, shell, Docker or
arbitrary CLI access.

## Installation workflow

1. Run read-only discovery first and reuse values already present in the local
   configuration, SSH aliases, and target hosts.
2. Use the questionnaire in `SETUP.md`. Ask one concise batch of questions only
   for values that cannot be discovered safely.
3. Never ask the operator to paste a WireGuard private key, SSH private key,
   Immich API key, share key, or password into chat. Ask for a local file path
   or have the operator create the secret directly on its target machine.
4. Explain public firewall, DNS, SSH, and routing changes before applying them.
5. Back up existing target files before deployment. Preserve unrelated changes.
6. Keep the portal closed until the NAS filter, WireGuard tunnel, Caddy
   validation, and fail-closed tests all pass.
7. Validate Compose, Caddy, nginx, Python, and the ZIP regression tests before
   deploying. Repeat the external security checklist after deployment.
8. For upload changes, validate the dedicated tunnel/network membership,
   storage reserve, token redaction, exact route/method allowlists, chunk and
   quota ceilings, and a forbidden-route probe before installing a drop route.

## Configuration sources

- Operator CLI: `~/.config/immich-share/config.ini`, based on
  `config.example.ini`.
- VPS domain and resource limits: `/srv/photo-share/.env`, based on
  `vps/.env.example`.
- IPP quality, ZIP ceiling, reserve, and cache TTL: `vps/ipp-config.json`.
- NAS Docker network and ceilings: `nas/.env`, based on `nas/.env.example`.
- Optional NAS controller: `nas/controller/`, using its dedicated config, SSH
  transport, preflight, and cron examples.
- Optional upload edge: `vps/docker-compose.upload.yml`, `vps/drops.d/`, and
  the upload ceilings in `/srv/photo-share/.env`.
- Optional NAS upload stack: `nas/docker-compose.upload.yml`, using the ignored
  `nas/.env`, a dedicated `wg0-upload-nas.conf`, private state directory, and
  quarantine dataset. `UPLOAD_DROP_IMAGE` must be an immutable image digest.

Do not hardcode operator usernames, domains, public addresses, API keys, or
private keys in tracked files.

## Operations

The `immich-share` CLI manages shares with `open`, `list`, `sync`, `close`, and
`sweep`; `doctor` performs read-only checks. It is not an interactive
infrastructure installer. Follow `SETUP.md` for initial deployment and use
mutating CLI commands only after configuration and validation. Never run sweep
from both a separate controller and a NAS controller during migration.
