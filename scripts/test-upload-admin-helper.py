#!/usr/bin/env python3
"""Regression tests for the forced-command upload administration bridge."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import re
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

    def test_folder_is_a_single_safe_path_segment(self) -> None:
        for folder in ("Incoming family", "2026-08 trip.raw", "a", "x" * 120):
            with self.subTest(folder=folder):
                argv = helper.request_to_argv("open", {"label": "Event", "folder": folder})
                self.assertIn(f"--folder={folder}", argv)
        for folder in (
            "../x", "/abs", "a/b", "..", ".", ".hidden", "a\\b", "x" * 121,
            "-flag", " lead", "trail ", "", "caf\u00e9", "a\tb", 12,
        ):
            with self.subTest(folder=folder), self.assertRaises(helper.RequestError):
                helper.request_to_argv("open", {"label": "Event", "folder": folder})

    def test_text_rejects_every_non_printable_code_point(self) -> None:
        for bad in (
            "Event\u202eevil",  # right-to-left override
            "Ev\u009bent",  # C1 control (CSI)
            "Line\u2028break",  # line separator
            "Zero\u200bwidth",  # zero-width space (format)
            "Bell\x07",  # C0 control
            "Del\x7f",  # DEL
            "Nbsp\u00a0here",  # non-breaking space is not printable
        ):
            for field in ("label", "folder"):
                payload = {"label": "Event", field: bad}
                with self.subTest(field=field, bad=bad), self.assertRaises(helper.RequestError):
                    helper.request_to_argv("open", payload)
        argv = helper.request_to_argv("open", {"label": "Caf\u00e9 2026 (family)"})
        self.assertIn("--label=Caf\u00e9 2026 (family)", argv)

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
        self.assertIn('"tripwire follow")', gate)
        self.assertIn('/usr/bin/sudo -n /usr/bin/test -f "$denied_log"', gate)
        self.assertIn("/usr/bin/test -f /var/log/immich-share/denied.log", sudoers)
        self.assertIn("/usr/bin/tail -F -n0 /var/log/immich-share/denied.log", sudoers)
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", gate)

    def test_gate_sudo_targets_and_sudoers_commands_stay_in_sync(self) -> None:
        gate = (ROOT / "nas" / "forward-command.sh").read_text(encoding="utf-8")
        sudoers = (ROOT / "nas" / "sudoers-forward-gate.example").read_text(encoding="utf-8")
        variables = dict(re.findall(r"^(\w+)=(\S+)$", gate, flags=re.MULTILINE))
        gate_commands = set()
        for line in gate.splitlines():
            command = line.strip()
            if command.startswith("exec /usr/bin/sudo -n "):
                command = command.removeprefix("exec /usr/bin/sudo -n ")
            elif command.startswith("/usr/bin/sudo -n "):
                command = command.removeprefix("/usr/bin/sudo -n ").split(" || {", 1)[0]
            else:
                continue
            for name, value in variables.items():
                command = command.replace(f'"${name}"', value)
            gate_commands.add(command.replace("'", "").strip())
        alias = sudoers.split("Cmnd_Alias IMMICH_SHARE_FORWARD =", 1)[1]
        alias = alias.split("\n\n", 1)[0].replace("\\\n", " ")
        sudoers_commands = {item.strip() for item in alias.split(",") if item.strip()}
        self.assertEqual(gate_commands, sudoers_commands)
        for command in sudoers_commands:
            self.assertTrue(command.startswith("/"), command)
            for wildcard in ("*", "?", "[", "$"):
                self.assertNotIn(wildcard, command)
        self.assertIn("/usr/bin/tail -F -n0 /var/log/immich-share/denied.log", sudoers_commands)
        self.assertNotIn("Defaults", sudoers)
        self.assertIn("NOPASSWD: IMMICH_SHARE_FORWARD", sudoers)

    def test_tripwire_uses_the_forced_command_without_a_nas_shell(self) -> None:
        tripwire = (ROOT / "macmini" / "denied-tripwire.sh").read_text(encoding="utf-8")
        # Trust boundary only: the exact forced command, no remote shell command
        # line, and no forwarding options that a gate would have to honour.
        self.assertIn('"tripwire follow"', tripwire)
        self.assertNotIn('"tail -F', tripwire)  # no remote shell command line
        self.assertNotIn("ExitOnForwardFailure", tripwire)
        # SSH diagnostics must reach the launchd log, never /dev/null.
        self.assertIsNone(re.search(r"ssh -o BatchMode=yes[^&]*2>/dev/null", tripwire))
        # The doctor's loopback probe is the only 127.0.0.1 source that can
        # reach denied.log; the tripwire must skip exactly that prefix.
        self.assertIn('"127.0.0.1 "*', tripwire)
        gate = (ROOT / "nas" / "forward-command.sh").read_text(encoding="utf-8")
        # A missing denied.log must refuse the follow instead of tailing nothing.
        self.assertIn('/usr/bin/sudo -n /usr/bin/test -f "$denied_log" || {', gate)
        self.assertIn("exit 65", gate)
        gate_example = (ROOT / "nas" / "ssh-forward-gate.example").read_text(encoding="utf-8")
        # from= pins the LAN/tailnet source the NAS sshd sees, never the
        # controller WireGuard address (the host sshd can never observe it).
        self.assertIn('restrict,from="<CONTROLLER_LAN_ADDRESS>",command=', gate_example)
        self.assertNotIn("CONTROLLER_WG_ADDRESS", gate_example)

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
