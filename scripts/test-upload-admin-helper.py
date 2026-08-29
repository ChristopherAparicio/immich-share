#!/usr/bin/env python3
"""Regression tests for the forced-command upload administration bridge."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "nas" / "upload-admin-helper.py"
loader = importlib.machinery.SourceFileLoader("upload_admin_helper", str(HELPER_PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


class UploadAdminHelperTests(unittest.TestCase):
    def test_bounded_unique_json_object(self) -> None:
        self.assertEqual(helper.read_request(io.BytesIO(b"{}")), {})
        for raw in (
            b"",
            b"[]",
            b'{"label":"one","label":"two"}',
            b"{",
            b"\xff",
            b" " * (helper.MAX_REQUEST_BYTES + 1),
        ):
            with self.subTest(raw=raw[:30]), self.assertRaises(helper.RequestError):
                helper.read_request(io.BytesIO(raw))

    def test_read_only_actions_accept_no_parameters(self) -> None:
        for action in ("list", "sweep"):
            argv = helper.request_to_argv(action, {})
            self.assertEqual(argv[-1], action)
            self.assertEqual(argv[:7], [
                "/usr/bin/docker", "exec", "immich-upload-drop", "python",
                "-m", "app.cli", "--json",
            ])
            with self.assertRaises(helper.RequestError):
                helper.request_to_argv(action, {"extra": True})

    def test_open_builds_only_literal_argv(self) -> None:
        injection = "Family $(touch /tmp/not-executed); photos"
        argv = helper.request_to_argv("open", {
            "label": injection,
            "folder": "Incoming family",
            "profile": "both",
            "ttlSeconds": 3600,
            "maxFileBytes": 10_000_000,
            "maxFiles": 25,
            "quotaBytes": 20_000_000,
        })
        self.assertIn(f"--label={injection}", argv)
        self.assertNotIn("sh", argv)
        self.assertNotIn("-c", argv)
        self.assertNotIn("--password", argv)
        self.assertNotIn("--password-file", argv)
        self.assertEqual(argv[7:9], ["open", f"--label={injection}"])
        self.assertIn("--ttl=60m", argv)
        self.assertIn("--max-file=10000000b", argv)
        self.assertIn("--quota=20000000b", argv)

    def test_open_schema_and_limits_fail_closed(self) -> None:
        secret = "must-not-cross-ssh"
        with self.assertRaises(helper.RequestError) as caught:
            helper.request_to_argv("open", {"label": "Event", "password": secret})
        self.assertNotIn(secret, str(caught.exception))
        rejected = [
            {},
            {"label": " Event"},
            {"label": "Event\nInjected"},
            {"label": "x" * 121},
            {"label": "Event", "profile": "archives"},
            {"label": "Event", "ttlSeconds": 299},
            {"label": "Event", "ttlSeconds": 301},
            {"label": "Event", "ttlSeconds": 604801},
            {"label": "Event", "ttlSeconds": True},
            {"label": "Event", "maxFileBytes": 536870913},
            {"label": "Event", "maxFiles": 501},
            {"label": "Event", "quotaBytes": 1073741825},
            {"label": "Event", "maxFileBytes": 20, "quotaBytes": 10},
        ]
        for payload in rejected:
            with self.subTest(payload=payload), self.assertRaises(helper.RequestError):
                helper.request_to_argv("open", payload)

    def test_open_omitted_limits_are_still_pinned_in_argv(self) -> None:
        argv = helper.request_to_argv("open", {"label": "Pinned defaults"})
        self.assertIn("--max-file=536870912b", argv)
        self.assertIn("--max-files=500", argv)
        self.assertIn("--quota=1073741824b", argv)

    def test_close_requires_a_canonical_full_uuid(self) -> None:
        invite_id = "01234567-89ab-cdef-0123-456789abcdef"
        argv = helper.request_to_argv("close", {"inviteId": invite_id})
        self.assertEqual(argv[-2:], ["close", invite_id])
        for value in ("01234567", "--help", "$(id)", invite_id.upper(), 12):
            with self.subTest(value=value), self.assertRaises(helper.RequestError):
                helper.request_to_argv("close", {"inviteId": value})

    def test_gate_and_sudoers_expose_only_exact_actions(self) -> None:
        gate = (ROOT / "nas" / "forward-command.sh").read_text(encoding="utf-8")
        sudoers = (ROOT / "nas" / "sudoers-forward-gate.example").read_text(encoding="utf-8")
        for action in helper.ACTIONS:
            command = f"upload admin {action}"
            self.assertIn(f'"{command}")', gate)
            self.assertIn(f"/usr/local/sbin/immich-share-upload-admin {action}", sudoers)
        self.assertNotIn("upload admin purge", gate)
        self.assertNotIn("immich-share-upload-admin *", sudoers)
        self.assertNotIn("exec sudo ", gate)
        self.assertIn("exec /usr/bin/sudo -n", gate)

    def test_helper_uses_execv_not_a_shell(self) -> None:
        source = HELPER_PATH.read_text(encoding="utf-8")
        self.assertTrue(source.startswith("#!/usr/bin/python3 -I\n"))
        self.assertIn("os.execve(DOCKER, argv, DOCKER_ENV)", source)
        self.assertIn('"DOCKER_HOST": "unix:///var/run/docker.sock"', source)
        self.assertNotIn("os.environ", source)
        for unsafe in ("shell=True", "os.system(", "subprocess.", "docker exec -i"):
            self.assertNotIn(unsafe, source)


if __name__ == "__main__":
    unittest.main()
