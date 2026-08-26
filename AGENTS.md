# Agent instructions for immich-share

Read `README.md` and `SETUP.md` before changing deployment files. Treat the NAS,
administrator machine, and VPS as separate trust zones.

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

## Configuration sources

- Operator CLI: `~/.config/immich-share/config.ini`, based on
  `config.example.ini`.
- VPS domain and resource limits: `/srv/photo-share/.env`, based on
  `vps/.env.example`.
- IPP quality, ZIP ceiling, reserve, and cache TTL: `vps/ipp-config.json`.
- NAS Docker network and ceilings: `nas/.env`, based on `nas/.env.example`.
- Optional NAS controller: `nas/controller/`, using its dedicated config, SSH
  transport, preflight, and cron examples.

Do not hardcode operator usernames, domains, public addresses, API keys, or
private keys in tracked files.

## Operations

The `immich-share` CLI manages shares with `open`, `list`, `sync`, `close`, and
`sweep`; `doctor` performs read-only checks. It is not an interactive
infrastructure installer. Follow `SETUP.md` for initial deployment and use
mutating CLI commands only after configuration and validation. Never run sweep
from both a separate controller and a NAS controller during migration.
