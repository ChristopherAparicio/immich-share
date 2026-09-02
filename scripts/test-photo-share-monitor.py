#!/usr/bin/env python3
"""Regression tests for macmini/photo-share-monitor.py (stdlib only, no network).

Run: python3 scripts/test-photo-share-monitor.py
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "test-test-test-test-test"

_tmp = tempfile.TemporaryDirectory(prefix="psm-test-")
HOME = Path(_tmp.name) / "home"
CONFIG_DIR = HOME / ".config" / "immich-share"
CONFIG_DIR.mkdir(parents=True, mode=0o700)
(CONFIG_DIR / "api-key").write_text("test-api-key-value\n")
(CONFIG_DIR / "api-key").chmod(0o600)
(CONFIG_DIR / "monitor-password").write_text(PASSWORD + "\n")
(CONFIG_DIR / "monitor-password").chmod(0o600)
(CONFIG_DIR / "config.ini").write_text(
    """[immich]
url = http://127.0.0.1:9
api_key_file = ~/.config/immich-share/api-key
public_base_url = https://photos.example.com

[vps]
ssh = vps-test
caddy_validate_cmd = true
caddy_reload_cmd = true

[nas]
forward_on_cmd = true
forward_off_cmd = true

[controller]
expected_wireguard_peers = 2

[monitor]
bind = 127.0.0.1
password_file = ~/.config/immich-share/monitor-password
"""
)
(CONFIG_DIR / "config.ini").chmod(0o600)
os.environ["HOME"] = str(HOME)
os.environ.pop("PHOTO_SHARE_BIND", None)
os.environ.pop("PHOTO_SHARE_PORT", None)

_loader = importlib.machinery.SourceFileLoader(
    "photo_share_monitor", str(ROOT / "macmini" / "photo-share-monitor.py")
)
_spec = importlib.util.spec_from_loader(_loader.name, _loader)
mod = importlib.util.module_from_spec(_spec)
_loader.exec_module(mod)
IMPORT_CREATED_DATA_DIR = (HOME / "photo-share-monitor").exists()

SERVER = None
PORT = None


def setUpModule():
    global SERVER, PORT
    settings = mod.load_settings()
    mod.activate(settings)
    # Immich is never contacted in these tests.
    mod.S.immich.list_links = lambda: []
    SERVER = mod.make_server("127.0.0.1", 0)
    PORT = SERVER.server_address[1]
    threading.Thread(target=SERVER.serve_forever, daemon=True).start()


def tearDownModule():
    if SERVER is not None:
        SERVER.shutdown()
        SERVER.server_close()
    _tmp.cleanup()


def auth_header(password=PASSWORD, user="immich-share"):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def request(method, path, headers=None, body=None, auth=True):
    h = {"Host": "127.0.0.1"}
    if auth:
        h["Authorization"] = auth_header()
    if headers:
        h.update(headers)
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
    try:
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, dict(resp.getheaders()), data
    finally:
        conn.close()


def raw_request(payload: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", PORT), timeout=5) as sock:
        sock.sendall(payload)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


TRIMMED_CONFIG = """[immich]
url = http://127.0.0.1:9
api_key_file = ~/.config/immich-share/api-key
public_base_url = https://photos.example.com

[vps]
ssh = vps-test
"""


def write_config(name, text):
    """A private config file under the fake HOME; returns its path."""
    path = CONFIG_DIR / name
    path.write_text(text)
    path.chmod(0o600)
    return path


def run_main_with_config(path):
    """Run main() against ``path``; returns (exit code, stderr text)."""
    real_load = mod.cli.load_config
    err = io.StringIO()
    with mock.patch.object(
        mod.cli, "load_config", lambda explicit_path=None: real_load(str(path))
    ), redirect_stderr(err):
        rc = mod.main()
    return rc, err.getvalue()


def clear_meta():
    with mod._conn() as c:
        c.execute("DELETE FROM meta")
        c.execute("DELETE FROM events")
        c.execute("DELETE FROM shares")


class MonitorTestCase(unittest.TestCase):
    def setUp(self):
        with mod._auth_lock:
            mod._auth_failures.clear()
        with mod._log_lock:
            mod._log_last.clear()
            mod._log_suppressed.clear()
        clear_meta()
        mod.S.immich.list_links = lambda: []


class TestImportAndSettings(MonitorTestCase):
    def test_import_has_no_side_effects(self):
        self.assertFalse(IMPORT_CREATED_DATA_DIR)

    def test_reuses_cli_module(self):
        self.assertIs(mod.KEY_RE, mod.cli.KEY_RE)
        self.assertTrue(hasattr(mod.cli, "load_config"))
        self.assertIsInstance(mod.S.immich, mod.cli.Immich)

    def test_wildcard_binds_are_refused(self):
        for bind in ("0.0.0.0", "::", "*", "[::]"):
            with self.assertRaises(RuntimeError):
                mod.load_settings(environ={"PHOTO_SHARE_BIND": bind})

    def test_salt_created_privately(self):
        salt = mod.S.data_dir / "ip.salt"
        self.assertEqual(stat.S_IMODE(salt.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(mod.S.data_dir.stat().st_mode), 0o700)
        self.assertEqual(len(mod.S.salt), 32)

    def test_ipv6_server_family(self):
        server = mod.make_server("::1", 0)
        try:
            self.assertEqual(server.address_family, socket.AF_INET6)
        finally:
            server.server_close()

    def test_trimmed_config_without_edge_keys_loads(self):
        # A monitor-only host has no caddy_*_cmd / [nas] forward_*_cmd keys.
        path = write_config(
            "trimmed.ini",
            TRIMMED_CONFIG
            + "\n[monitor]\npassword_file = ~/.config/immich-share/monitor-password\n",
        )
        settings = mod.load_settings(config_path=str(path))
        self.assertEqual(settings.vps_ssh, "vps-test")
        self.assertEqual(settings.bind, "127.0.0.1")

    def test_ssh_target_validated_like_the_cli(self):
        path = write_config("bad-ssh.ini", TRIMMED_CONFIG.replace("vps-test", "host; rm -rf /"))
        with self.assertRaises(RuntimeError) as ctx:
            mod.load_settings(config_path=str(path))
        self.assertIn("ssh target", str(ctx.exception))
        path = write_config("no-vps.ini", TRIMMED_CONFIG.split("[vps]")[0])
        with self.assertRaises(RuntimeError) as ctx:
            mod.load_settings(config_path=str(path))
        self.assertIn("[vps] ssh", str(ctx.exception))

    def test_main_reports_config_problems_without_traceback(self):
        cases = {
            # Only [immich] and [vps] ssh: refused for the missing password file.
            "only-immich-vps.ini": (TRIMMED_CONFIG, "password_file"),
            # Missing [immich]: a KeyError deep in the CLI client.
            "no-immich.ini": ("[vps]\nssh = vps-test\n", "missing configuration key"),
            # A non-numeric option: ValueError from configparser getters.
            "bad-int.ini": (
                TRIMMED_CONFIG
                + "[monitor]\npassword_file = ~/.config/immich-share/monitor-password\n"
                "telemetry_retention_days = many\n",
                "invalid literal",
            ),
        }
        for name, (text, expected) in cases.items():
            with self.subTest(name):
                rc, err = run_main_with_config(write_config(name, text))
                self.assertEqual(rc, 1)
                self.assertNotIn("Traceback", err)
                self.assertIn("❌", err)
                self.assertIn(expected, err)

    def test_main_startup_die_exits_cleanly(self):
        def die_salt(path):
            mod.cli.die("telemetry salt file must be regular, owned by the current user, and private")

        err = io.StringIO()
        with mock.patch.object(mod, "_load_salt", die_salt), redirect_stderr(err):
            rc = mod.main()
        self.assertEqual(rc, 1)
        self.assertNotIn("Traceback", err.getvalue())
        self.assertIn("❌ telemetry salt", err.getvalue())

    def test_empty_salt_file_is_regenerated(self):
        data_dir = Path(_tmp.name) / "salt-regen"
        data_dir.mkdir(mode=0o700)
        salt_path = data_dir / "ip.salt"
        salt_path.touch(mode=0o600)
        salt = mod._load_salt(salt_path)
        self.assertRegex(salt, r"^[0-9a-f]{32}$")
        self.assertEqual(salt_path.read_text().strip(), salt)
        self.assertEqual(stat.S_IMODE(salt_path.stat().st_mode), 0o600)
        self.assertEqual(sorted(p.name for p in data_dir.iterdir()), ["ip.salt"], "no temp left behind")
        # A populated salt is never rewritten.
        self.assertEqual(mod._load_salt(salt_path), salt)


class TestAuthLockout(MonitorTestCase):
    def test_headerless_requests_do_not_count_toward_lockout(self):
        for _ in range(mod.LOCKOUT_FAILURES + 2):
            status, headers, _ = request("GET", "/health", auth=False)
            self.assertEqual(status, 401)
            self.assertIn("WWW-Authenticate", headers)
        self.assertEqual(mod._auth_failures, {})
        status, _, body = request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})

    def test_wrong_credentials_lock_out(self):
        err = io.StringIO()
        with redirect_stderr(err):
            for index in range(mod.LOCKOUT_FAILURES):
                status, _, _ = request(
                    "GET", "/health", headers={"Authorization": auth_header(f"wrong-{index}")}
                )
                self.assertEqual(status, 401)
            for _ in range(3):
                status, _, _ = request(
                    "GET", "/health", headers={"Authorization": auth_header("another-guess")}
                )
                self.assertEqual(status, 401)
        # Once locked, further wrong guesses are refused but no longer counted,
        # so a stale tab cannot renew the lockout indefinitely.
        self.assertEqual(len(mod._auth_failures["127.0.0.1"]), mod.LOCKOUT_FAILURES)
        self.assertIn("locked out", err.getvalue())
        # The three refused-while-locked attempts are logged in the same
        # rate-limited category, hence suppressed rather than printed.
        self.assertEqual(mod._log_suppressed["auth"], 3)
        status, _, _ = request("GET", "/health")
        self.assertEqual(status, 401, "a lockout must also block the right credential")
        with mod._auth_lock:
            mod._auth_failures["127.0.0.1"] = [
                (stamp - mod.LOCKOUT_WINDOW - 1, digest)
                for stamp, digest in mod._auth_failures["127.0.0.1"]
            ]
        status, _, _ = request("GET", "/health")
        self.assertEqual(status, 200, "the right credential works after lockout expiry")
        self.assertEqual(mod._auth_failures, {})

    def test_repeated_stale_tab_credential_counts_once(self):
        # A forgotten tab replays an old password every 15 s; the operator on
        # the same address must still be able to log in with the current one.
        with redirect_stderr(io.StringIO()):
            for _ in range(mod.LOCKOUT_FAILURES):
                request("GET", "/health", headers={"Authorization": auth_header("old-pw")})
        self.assertEqual(len(mod._auth_failures["127.0.0.1"]), 1)
        status, _, body = request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})
        self.assertEqual(mod._auth_failures, {})
        # The stale tab itself keeps getting 401, but its repeated credential
        # remains one distinct guess.
        with redirect_stderr(io.StringIO()):
            for _ in range(mod.LOCKOUT_FAILURES + 1):
                status, _, _ = request(
                    "GET", "/health", headers={"Authorization": auth_header("old-pw")}
                )
                self.assertEqual(status, 401)
        self.assertEqual(len(mod._auth_failures["127.0.0.1"]), 1)

    def test_wrong_then_right_clears_failures(self):
        request("GET", "/health", headers={"Authorization": auth_header("nope")})
        self.assertEqual(len(mod._auth_failures["127.0.0.1"]), 1)
        status, _, _ = request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(mod._auth_failures, {})

    def test_non_ascii_authorization_is_401_not_dropped(self):
        payload = (
            b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Authorization: Basic \xff\xfe\xc3\xa9\r\nConnection: close\r\n\r\n"
        )
        with redirect_stderr(io.StringIO()):
            response = raw_request(payload)
        self.assertTrue(response.startswith(b"HTTP/1."), response[:40])
        self.assertIn(b" 401 ", response.split(b"\r\n", 1)[0])
        self.assertEqual(len(mod._auth_failures["127.0.0.1"]), 1)

    def test_forbidden_host(self):
        status, _, body = request("GET", "/health", headers={"Host": "evil.example"})
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "forbidden host"})


class TestResponseHygiene(MonitorTestCase):
    def test_server_header_does_not_leak_python(self):
        status, headers, _ = request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Server"), "photo-share-monitor")
        self.assertNotIn("Python", headers.get("Server", ""))
        self.assertEqual(headers.get("Cache-Control"), "no-store")

    def test_csp_hash_matches_inline_script(self):
        status, headers, body = request("GET", "/")
        self.assertEqual(status, 200)
        csp = headers["Content-Security-Policy"]
        script_src = re.search(r"script-src ([^;]+)", csp).group(1)
        self.assertNotIn("unsafe-inline", script_src)
        scripts = re.findall(rb"<script>(.*?)</script>", body, re.S)
        self.assertEqual(len(scripts), 1)
        digest = base64.b64encode(hashlib.sha256(scripts[0]).digest()).decode()
        self.assertEqual(script_src, f"'sha256-{digest}'")
        self.assertNotIn(b" onclick=", body)
        self.assertIn(b"esc(x[1]", body)
        self.assertIn(b"rate-limit hits", body)

    def test_unknown_path(self):
        status, _, _ = request("GET", "/nope")
        self.assertEqual(status, 404)

    def test_malformed_request_line_does_not_leak_share_key(self):
        key = "test_test_test_test"
        err = io.StringIO()
        with redirect_stderr(err):
            response = raw_request(
                f"GET /shares/{key}/close x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode()
            )
        self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])
        self.assertNotIn(key.encode(), response, "the 400 body must not echo the request line")
        self.assertNotIn(key, err.getvalue(), "stderr must not echo the request line")
        self.assertIn("http: code 400", err.getvalue())


class TestPostValidation(MonitorTestCase):
    def post(self, path, body, headers=None):
        h = {"X-PS": "1", "Content-Type": "application/json"}
        if headers:
            h.update(headers)
        return request("POST", path, headers=h, body=body)

    def test_csrf_header_required(self):
        status, _, _ = request("POST", "/shares/open", body=b"{}")
        self.assertEqual(status, 403)

    def test_non_object_json_is_400(self):
        for payload in (b"[1,2]", b'"text"', b"42", b"null", b"not json"):
            status, _, body = self.post("/shares/open", payload)
            self.assertEqual(status, 400, payload)
            self.assertEqual(json.loads(body)["message"], "bad request body")

    def test_negative_content_length_is_400(self):
        status, _, body = self.post(
            "/shares/open", None, headers={"Content-Length": "-5"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["message"], "bad length")
        status, _, _ = self.post("/shares/open", None, headers={"Content-Length": "abc"})
        self.assertEqual(status, 400)

    def test_oversized_body_is_413(self):
        status, _, _ = self.post(
            "/shares/open", None, headers={"Content-Length": str(mod.MAX_BODY + 1)}
        )
        self.assertEqual(status, 413)

    def test_open_requires_album_and_valid_ttl(self):
        status, _, _ = self.post("/shares/open", b'{"album": ""}')
        self.assertEqual(status, 400)
        status, _, body = self.post(
            "/shares/open", b'{"album": "A", "ttl": "48h; rm -rf"}'
        )
        self.assertEqual(status, 400)
        self.assertNotIn("rm -rf", body.decode())


class TestOpenHandler(MonitorTestCase):
    def post_open(self, body):
        return request(
            "POST",
            "/shares/open",
            headers={"X-PS": "1", "Content-Type": "application/json"},
            body=json.dumps(body).encode(),
        )

    def fake_run(self, stdout="", stderr="", rc=0):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr=stderr)

        return calls, run

    def test_open_parses_json_output(self):
        payload = {
            "key": "test_test_test_test",
            "link": "https://photos.example.com/share/test_test_test_test",
            "password": "secret-pass-word",
            "expiresAt": "2030-01-01T00:00:00.000Z",
            "description": "Alex",
            "album": {"name": "-Leading Dash", "assetCount": 3},
            "allowDownload": True,
        }
        calls, run = self.fake_run(stdout=json.dumps(payload) + "\n", stderr="  ✓ progress\n")
        with mock.patch.object(mod.subprocess, "run", run):
            status, _, body = self.post_open(
                {"album": "-Leading Dash", "ttl": "48h", "for": "Alex"}
            )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["link"], payload["link"])
        self.assertEqual(data["password"], payload["password"])
        self.assertEqual(data["album"], "-Leading Dash")
        self.assertEqual(len(calls), 1)
        argv = calls[0]
        self.assertEqual(argv[0], mod.CLI)
        self.assertEqual(argv[1], "open")
        self.assertIn("--json", argv)
        self.assertIn("--ttl=48h", argv)
        self.assertIn("--for=Alex", argv)
        self.assertEqual(argv[-2:], ["--", "-Leading Dash"])

    def test_open_rejects_human_output(self):
        human = "  Link     : https://photos.example.com/share/x\n  Password : hunter2-hunter2\n"
        _, run = self.fake_run(stdout=human)
        with mock.patch.object(mod.subprocess, "run", run), redirect_stderr(io.StringIO()) as err:
            status, _, body = self.post_open({"album": "A", "ttl": "48h"})
        self.assertEqual(status, 502)
        text = body.decode()
        self.assertNotIn("hunter2", text)
        self.assertNotIn("hunter2", err.getvalue(), "stdout must never be logged")
        self.assertIn("unexpected output", json.loads(body)["message"])

    def test_open_rejects_incomplete_or_non_object_json(self):
        for stdout in ("[1, 2]", '{"link": "https://x"}', '{"key": "test_test_test_test", "link": "https://x", "password": ""}', ""):
            _, run = self.fake_run(stdout=stdout)
            with mock.patch.object(mod.subprocess, "run", run), redirect_stderr(io.StringIO()):
                status, _, body = self.post_open({"album": "A", "ttl": "48h"})
            self.assertEqual(status, 502, stdout)
            self.assertNotIn("link", json.loads(body))

    def test_open_cli_failure_reports_last_stderr_line(self):
        _, run = self.fake_run(stdout="", stderr="  ✓ step\n❌ album 'A' not found\n", rc=1)
        with mock.patch.object(mod.subprocess, "run", run), redirect_stderr(io.StringIO()):
            status, _, body = self.post_open({"album": "A", "ttl": "48h"})
        self.assertEqual(status, 502)
        self.assertEqual(json.loads(body)["message"], "❌ album 'A' not found")

    def test_close_passes_double_dash(self):
        calls, run = self.fake_run(stdout="closed\n")
        with mock.patch.object(mod.subprocess, "run", run):
            status, _, _ = request(
                "POST", "/shares/-abcdefgh1234567/close", headers={"X-PS": "1"}
            )
        self.assertEqual(status, 200)
        self.assertEqual(calls[0][1:], ["close", "--", "-abcdefgh1234567"])


class TestTelemetry(MonitorTestCase):
    def test_unknown_when_never_ingested(self):
        status, _, body = request("GET", "/shares")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["telemetry"]["status"], "unknown")
        self.assertIsNone(data["peers"])
        self.assertEqual(data["tunnel"], "unknown")
        self.assertIn("ratelimit_15m", data)
        self.assertNotIn("auth_fail", data)

    def test_stale_when_ingest_is_old(self):
        mod._meta_set("peers_up", 2)
        mod._meta_set("last_ingest", int(time.time()) - mod.STALE_AFTER - 60)
        status, _, body = request("GET", "/shares")
        data = json.loads(body)
        self.assertEqual(data["telemetry"]["status"], "stale")
        self.assertIsNone(data["peers"], "stale peers must not be trusted")
        self.assertTrue(data["tunnel"].startswith("stale"))
        status, _, body = request("GET", "/devhub")
        hub = json.loads(body)
        self.assertEqual(hub["status"], "warn")
        labels = {m["id"]: m for m in hub["metrics"]}
        self.assertEqual(labels["telemetry"]["value"], "stale")
        self.assertIn("429", labels["ratelimit_429"]["label"])
        self.assertNotIn("auth_fail", labels)

    def test_ok_when_fresh(self):
        mod._meta_set("peers_up", 2)
        mod._meta_set("last_ingest", int(time.time()))
        status, _, body = request("GET", "/shares")
        data = json.loads(body)
        self.assertEqual(data["telemetry"]["status"], "ok")
        self.assertEqual(data["peers"], 2)
        self.assertEqual(data["tunnel"], "2/2")
        _, _, body = request("GET", "/devhub")
        self.assertEqual(json.loads(body)["status"], "ok")

    def test_ingest_failure_is_logged_and_not_fresh(self):
        def boom():
            raise RuntimeError("ssh exit 255: connection refused")

        err = io.StringIO()
        with mock.patch.object(mod, "_vps_fetch", boom), redirect_stderr(err):
            self.assertFalse(mod._ingest_once())
            self.assertFalse(mod._ingest_once())
        self.assertIsNone(mod._meta_get("last_ingest"))
        lines = [ln for ln in err.getvalue().splitlines() if "ingest" in ln]
        self.assertEqual(len(lines), 1, "repeated failures are rate limited")
        self.assertIn("connection refused", lines[0])

    def test_immich_failure_during_ingest_leaves_telemetry_unstamped(self):
        stale = int(time.time()) - mod.STALE_AFTER - 60
        mod._meta_set("peers_up", 2)
        mod._meta_set("last_ingest", stale)

        def die_links():
            mod.cli.die("Immich GET /shared-links → HTTP 503")

        mod.S.immich.list_links = die_links
        now = int(time.time())
        with mock.patch.object(mod, "_vps_fetch", lambda: (f"peerA\t{now - 5}\n", "")), \
                redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            mod._ingest_once()
        self.assertEqual(mod._meta_get("last_ingest"), str(stale), "must not look fresh")
        self.assertEqual(mod._telemetry()["status"], "stale")
        mod.S.immich.list_links = lambda: []
        _, _, body = request("GET", "/devhub")
        self.assertEqual(json.loads(body)["status"], "warn")

    def test_shares_poll_opens_few_sqlite_connections(self):
        keys = [f"key{i:013d}" for i in range(12)]
        mod.S.immich.list_links = lambda: [
            {
                "key": k,
                "description": f"guest {i}",
                "album": {"albumName": "Trip"},
                "expiresAt": "2099-01-01T00:00:00.000Z",
            }
            for i, k in enumerate(keys)
        ]
        ts = time.time()
        with mod._conn() as c:
            c.executemany(
                "INSERT INTO events VALUES(?,?,?,?,?)",
                [
                    (ts, keys[3], "h1", "gallery", 200),
                    (ts, keys[3], "h2", "gallery", 200),
                    (ts, keys[3], "h2", "download", 200),
                    (ts, keys[7], "h3", "view", 200),
                    (ts, "otherkey12345678", "h9", "download", 200),
                    (ts, "", "h4", "ratelimit", 429),
                ],
            )
        opened = []
        real_db = mod._db

        def counting_db():
            opened.append(1)
            return real_db()

        with mock.patch.object(mod, "_db", counting_db):
            status, _, body = request("GET", "/shares")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data["shares"]), 12)
        self.assertLessEqual(len(opened), 2, "N+1 sqlite connections per /shares poll")
        by_key = {s["key"]: s for s in data["shares"]}
        self.assertEqual(
            {k: by_key[keys[3]][k] for k in ("opens", "views", "downloads", "visitors")},
            {"opens": 2, "views": 0, "downloads": 1, "visitors": 2},
        )
        self.assertEqual(by_key[keys[7]]["views"], 1)
        self.assertEqual(by_key[keys[0]]["downloads"], 0)
        self.assertEqual(data["ratelimit_15m"], 1)
        self.assertEqual(data["telemetry"]["status"], "unknown")

    def test_ingest_success_upserts_shares_without_events(self):
        now = int(time.time())
        wg = f"peerA\t{now - 10}\npeerB\t{now - 900}\n"
        mod.S.immich.list_links = lambda: [
            {
                "key": "test_test_test_test",
                "description": "Alex",
                "album": {"albumName": "Trip"},
                "expiresAt": "2099-01-01T00:00:00.000Z",
            },
            {"key": "expiredkey123456", "expiresAt": "2000-01-01T00:00:00.000Z"},
        ]
        with mock.patch.object(mod, "_vps_fetch", lambda: (wg, "")):
            self.assertTrue(mod._ingest_once())
        self.assertEqual(mod._meta_get("peers_up"), "1")
        self.assertIsNotNone(mod._meta_get("last_ingest"))
        with mod._conn() as c:
            rows = c.execute("SELECT key, album, for_label FROM shares").fetchall()
        self.assertEqual([tuple(r) for r in rows], [("test_test_test_test", "Trip", "Alex")])

    def test_purge_keeps_shares_with_remaining_events(self):
        old = time.time() - (mod.S.retention_days + 5) * 86400
        with mod._conn() as c:
            c.execute(
                "INSERT INTO shares VALUES(?,?,?,?,?)", ("keepkeep12345678", "A", "", old, old)
            )
            c.execute(
                "INSERT INTO shares VALUES(?,?,?,?,?)", ("dropdrop12345678", "B", "", old, old)
            )
            c.execute(
                "INSERT INTO events VALUES(?,?,?,?,?)",
                (time.time(), "keepkeep12345678", "h", "gallery", 200),
            )
        mod._purge_old_events()
        with mod._conn() as c:
            keys = sorted(r["key"] for r in c.execute("SELECT key FROM shares"))
        self.assertEqual(keys, ["keepkeep12345678"])

    def test_shares_upstream_failure_is_generic(self):
        def die_like():
            mod.cli.die("Immich GET /shared-links → HTTP 500 : secret detail")

        mod.S.immich.list_links = die_like
        with redirect_stderr(io.StringIO()):
            status, _, body = request("GET", "/shares")
        self.assertEqual(status, 502)
        data = json.loads(body)
        self.assertEqual(data["error"], "Immich unavailable")
        self.assertNotIn("secret detail", body.decode())
        self.assertIn("telemetry", data)

    def test_albums_upstream_exception_is_generic(self):
        def explode(*a, **k):
            raise ValueError("stack detail /private/path")

        with mock.patch.object(mod.S.immich, "_call", explode), redirect_stderr(io.StringIO()):
            status, _, body = request("GET", "/albums")
        self.assertEqual(status, 500)
        self.assertNotIn("/private/path", body.decode())
        self.assertEqual(json.loads(body), {"error": "internal error"})

    def test_album_choices_carry_uuid_to_disambiguate_duplicate_names(self):
        first = "0f9c6d1e-2b3a-4c5d-8e7f-a1b2c3d4e5f6"
        second = "11111111-2222-4333-8444-555555555555"
        albums = [
            {"id": first, "albumName": "Summer", "assetCount": 2},
            {"id": second, "albumName": "Summer", "assetCount": 3},
        ]
        with mock.patch.object(mod.S.immich, "_call", return_value=albums):
            status, _, body = request("GET", "/albums")
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body),
            [["Summer", 2, first], ["Summer", 3, second]],
        )
        self.assertIn(b'option value="${esc(x[2])}', mod.PAGE.encode())


class TestLogging(MonitorTestCase):
    def test_rate_limit_and_suppression_count(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertTrue(mod.log("t", "one", every=60))
            self.assertFalse(mod.log("t", "two", every=60))
            self.assertFalse(mod.log("t", "three", every=60))
            self.assertTrue(mod.log("other", "four", every=60))
        text = err.getvalue()
        self.assertIn("t: one", text)
        self.assertNotIn("two", text)
        self.assertIn("other: four", text)
        self.assertEqual(mod._log_suppressed["t"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
