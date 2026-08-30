# Reviewing and importing Immich Drop media

Immich Drop deliberately stops at NAS quarantine. Closing an invitation, removing
the public Caddy route, or stopping the upload WireGuard filter does not move or
delete completed media. Review and import are separate trusted NAS-side
operations and do not require the VPS or upload tunnel to be running.

## Trust boundary

```text
public visitor -> VPS -> upload tunnel -> Immich Drop -> quarantine

separate controller -> forced open/list/close/sweep commands only
NAS operator/importer -> read-only quarantine + scoped Immich key -> Immich
```

The recommended separate controller cannot read quarantine files, preview
media, purge invitations, or call the Immich upload API. Its forced SSH key is
an invitation administrator, not a NAS filesystem credential. This is
intentional: compromising the controller must not expose received media or turn
it into an unrestricted NAS shell.

If the controller runs directly on the NAS, the host can also run a local
import process, but the controller and importer remain logically separate. Do
not add an Immich API key, the Immich network, the Immich library, or a Docker
socket to the public `upload-drop` service.

## Storage layout

The private `UPLOAD_DROP_STORAGE_PATH` contains one opaque directory per
invitation:

```text
<staging-root>/
  .immich-drop-root
  <full-invitation-uuid>/
    partial/          # incomplete data; never import
    completed/        # validated canonical media
    manifest.json     # local import metadata
    .locks/           # application coordination
```

The manifest records the invitation label, requested `targetFolder`, media
profile and, for every canonical file, its application-generated relative path,
bounded original name, exact size and server-computed SHA-256. `targetFolder`
is a destination label; Immich Drop does not create that directory or an Immich
album. Duplicate receipts are not manifest entries and contain no media.

## Safe review procedure

1. Close the invitation locally or through the forced controller command.
2. Remove the Caddy drop snippet and stop the upload filter after the last
   active invitation, following the reverse order in `SETUP.md`.
3. On the NAS, resolve the complete invitation UUID with the local CLI and
   select exactly `<UPLOAD_DROP_STORAGE_PATH>/<full-uuid>`.
4. Confirm that `manifest.json` is a regular file inside that directory and
   that every listed path stays below its `completed/` directory.
5. Recompute each listed SHA-256 and compare its byte size with the manifest.
6. Review the media from a trusted NAS console or a temporary read-only share
   restricted to the home LAN/private administration tunnel. Never add a
   public preview or file-download route to Immich Drop.
7. Import only manifest entries whose checks pass. Never import `partial/`, a
   symlink, an unlisted file, an archive, or a path supplied outside the
   manifest.

On a Linux NAS with `jq` and `sha256sum`, the integrity check can be performed
from the reviewed invitation directory:

```bash
test -f manifest.json && test ! -L manifest.json
jq -e '.version == 1 and (.files | type == "array")' manifest.json >/dev/null
jq -r '.files[] | "\(.sha256)  \(.path)"' manifest.json \
  | sha256sum --check --strict -
```

Immich Drop has already checked the configured extension and basic media
signature. That is format gating, not antivirus or a guarantee that a complex
decoder cannot contain a vulnerability. Keep Immich and the trusted review
tools current, and do not execute or unpack received content.

Closing or expiry removes abandoned partial work through the embedded sweeper,
but completed files remain until a local operator imports or explicitly purges
the closed invitation. A failed review or import should leave quarantine
untouched for investigation or retry.

## Import with the official Immich CLI

For the simplest workflow, run a short-lived official Immich CLI container on
the NAS. Mount only the selected invitation's `completed/` directory read-only.
Store a dedicated API key and the trusted local Immich API URL in a private
mode-0600 environment file; never place the key in argv, shell history,
Immich Drop, the VPS, or this repository.

The key should have only the permissions required by the pinned CLI version to
upload assets and create/add to albums. Pin the CLI image by immutable digest
and use a local or encrypted private Immich endpoint. A typical Linux NAS
invocation is:

```bash
docker run --rm --network host \
  --env-file <PRIVATE_IMPORT_ENV_FILE> \
  --mount type=bind,src=<INVITATION_COMPLETED_DIRECTORY>,dst=/import,readonly \
  <PINNED_IMMICH_CLI_IMAGE> \
  upload --dry-run --album-name "<REVIEWED_ALBUM_NAME>" --concurrency 2 /import
```

Review the dry-run, then repeat without `--dry-run` and add `--json-output`.
Do not use `--delete` initially. Verify the returned new/duplicate counts and
the target album in the Immich UI before deleting quarantine. The official CLI
hashes files before upload, and Immich also performs server-side deduplication,
so retrying a failed import is expected to converge instead of creating another
asset. See the official [Immich CLI documentation](https://docs.immich.app/features/command-line-interface/).

The files in `completed/` intentionally use UUID names. Direct CLI import is
therefore safe and simple, but Immich may retain that UUID as the displayed
original filename. A future purpose-built importer can read `originalName` from
the manifest and pass a sanitized value as upload metadata without ever using
it as a host path. It can also record an import receipt and create the album
deterministically.

Do not mount quarantine as an Immich External Library for this workflow.
External-library scanning would make files visible before the explicit import
decision, couples Immich records to quarantine retention, and does not provide
the same official folder-to-album workflow. See the official
[External Libraries documentation](https://docs.immich.app/features/libraries/).

## Purge after verification

After the import result and album have been checked, purge locally on the NAS:

```bash
docker compose -f docker-compose.upload.yml exec upload-drop \
  python -m app.cli purge <FULL_INVITATION_UUID> --yes
```

`purge` requires a closed invitation and removes its staged files and database
records. It is intentionally unavailable through the existing separate-controller
forced command. Keep a backup or leave quarantine intact until Immich and its
database/media backups cover the new assets.

## Optional future automation

A production importer can remain small, but it is a new trusted component. The
safe contract is one NAS-local process with:

- a read-only mount of one closed invitation directory;
- no public HTTP route and no VPS/WireGuard dependency;
- no Docker socket;
- a scoped Immich API-key file;
- argv-only execution using a complete invitation UUID;
- manifest path, size and SHA-256 validation before upload;
- bounded concurrency, an idempotent import receipt, and no automatic purge;
- coarse logs that exclude API keys, visitor filenames and NAS paths.

If remote triggering is later required, add a separate exact forced command
such as `upload import <full-uuid>` that runs this fixed NAS-local helper. Do not
grant the current controller key arbitrary filesystem, shell, Docker, CLI, or
API access merely to make imports convenient.
