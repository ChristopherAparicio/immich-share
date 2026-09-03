#!/usr/bin/python3 -I
"""Narrow stdin-JSON bridge to the upload application's local-only CLI.

Install root-owned as /usr/local/sbin/immich-share-upload-admin. The forced SSH
gate selects the action; this helper accepts no container name or executable
from its caller and never invokes a shell.
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import uuid
from typing import BinaryIO, NoReturn


MAX_REQUEST_BYTES = 4096
REQUEST_TIMEOUT_SECONDS = 10
MAX_LABEL_CHARS = 120
MAX_LABEL_BYTES = 256
MIN_TTL_SECONDS = 300
MAX_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_FILES = 500
MAX_QUOTA_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = MAX_FILE_BYTES
DEFAULT_QUOTA_BYTES = MAX_QUOTA_BYTES
CONTAINER = "immich-upload-drop"
DOCKER = "/usr/bin/docker"
DOCKER_ENV = {
    "DOCKER_HOST": "unix:///var/run/docker.sock",
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
}
ACTIONS = frozenset({"open", "list", "close", "sweep"})
# A folder is exactly one path segment: no separators, no leading dot, no
# leading/trailing whitespace. "." and ".." are additionally refused below.
FOLDER_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,119}$")


class RequestError(ValueError):
    """Safe validation failure whose message never includes request values."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RequestError("duplicate field")
        result[key] = value
    return result


def read_request(stream: BinaryIO) -> dict[str, object]:
    raw = stream.read(MAX_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise RequestError("request must be a bounded JSON object")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RequestError("request must be valid UTF-8 JSON") from exc
    if type(value) is not dict:
        raise RequestError("request must be a JSON object")
    return value


def _exact_fields(payload: dict[str, object], required: set[str], optional: set[str]) -> None:
    fields = set(payload)
    if not required <= fields or fields - required - optional:
        raise RequestError("request fields do not match the action schema")


def _text(payload: dict[str, object], name: str) -> str:
    value = payload[name]
    if type(value) is not str:
        raise RequestError(f"{name} must be text")
    if not value or value != value.strip() or len(value) > MAX_LABEL_CHARS:
        raise RequestError(f"{name} is outside its allowed length")
    if len(value.encode("utf-8")) > MAX_LABEL_BYTES:
        raise RequestError(f"{name} is outside its allowed length")
    # str.isprintable() rejects every control, format, separator and
    # unassigned code point (C0/C1 controls, U+202E RLO, U+2028 LS, U+200B ...),
    # not only ASCII controls. Such characters can hide or reorder argv text.
    if not value.isprintable():
        raise RequestError(f"{name} contains non-printable characters")
    return value


def _folder(payload: dict[str, object], name: str) -> str:
    value = _text(payload, name)
    if value in {".", ".."} or "/" in value or "\\" in value \
            or FOLDER_SEGMENT.fullmatch(value) is None:
        raise RequestError(f"{name} must be a single safe path segment")
    return value


def _integer(payload: dict[str, object], name: str, minimum: int, maximum: int) -> int:
    value = payload[name]
    if type(value) is not int or not minimum <= value <= maximum:
        raise RequestError(f"{name} is outside its allowed range")
    return value


def request_to_argv(action: str, payload: dict[str, object]) -> list[str]:
    if action not in ACTIONS:
        raise RequestError("unsupported action")

    base = [DOCKER, "exec", CONTAINER, "python", "-m", "app.cli", "--json"]
    if action in {"list", "sweep"}:
        _exact_fields(payload, set(), set())
        return [*base, action]

    if action == "close":
        _exact_fields(payload, {"inviteId"}, set())
        invite_id = payload["inviteId"]
        if type(invite_id) is not str:
            raise RequestError("inviteId must be a UUID")
        try:
            canonical = str(uuid.UUID(invite_id))
        except (ValueError, AttributeError) as exc:
            raise RequestError("inviteId must be a UUID") from exc
        if invite_id != canonical:
            raise RequestError("inviteId must be a canonical UUID")
        return [*base, "close", canonical]

    required = {"label"}
    optional = {
        "folder",
        "profile",
        "ttlSeconds",
        "maxFileBytes",
        "maxFiles",
        "quotaBytes",
    }
    _exact_fields(payload, required, optional)
    label = _text(payload, "label")
    profile = payload.get("profile", "photos")
    if type(profile) is not str or profile not in {"photos", "videos", "both", "live"}:
        raise RequestError("profile is not allowed")
    ttl = _integer(payload, "ttlSeconds", MIN_TTL_SECONDS, MAX_TTL_SECONDS) \
        if "ttlSeconds" in payload else 24 * 60 * 60
    if ttl % 60:
        raise RequestError("ttlSeconds must be whole minutes")

    max_file = _integer(payload, "maxFileBytes", 1, MAX_FILE_BYTES) \
        if "maxFileBytes" in payload else DEFAULT_MAX_FILE_BYTES
    max_files = _integer(payload, "maxFiles", 1, MAX_FILES) \
        if "maxFiles" in payload else MAX_FILES
    quota = _integer(payload, "quotaBytes", 1, MAX_QUOTA_BYTES) \
        if "quotaBytes" in payload else DEFAULT_QUOTA_BYTES
    if max_file > quota:
        raise RequestError("maxFileBytes cannot exceed quotaBytes")

    argv = [
        *base,
        "open",
        f"--label={label}",
        f"--profile={profile}",
        f"--ttl={ttl // 60}m",
        f"--max-file={max_file}b",
        f"--max-files={max_files}",
        f"--quota={quota}b",
    ]
    if "folder" in payload:
        argv.append(f'--folder={_folder(payload, "folder")}')
    return argv


def fail(message: str) -> NoReturn:
    print(f"Upload administration request rejected: {message}", file=sys.stderr)
    raise SystemExit(64)


def _stdin_timeout(_signum: int, _frame: object) -> NoReturn:
    raise RequestError("request body timed out")


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ACTIONS:
        fail("unsupported action")
    try:
        signal.signal(signal.SIGALRM, _stdin_timeout)
        signal.alarm(REQUEST_TIMEOUT_SECONDS)
        try:
            payload = read_request(sys.stdin.buffer)
        finally:
            signal.alarm(0)
        argv = request_to_argv(sys.argv[1], payload)
    except RequestError as exc:
        fail(str(exc))
    # Do not inherit DOCKER_HOST/DOCKER_CONTEXT/DOCKER_CONFIG or any other
    # caller-controlled client setting across sudo.
    os.execve(DOCKER, argv, DOCKER_ENV)
    return 70


if __name__ == "__main__":
    raise SystemExit(main())
