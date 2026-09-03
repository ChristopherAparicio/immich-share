#!/usr/bin/env python3
import configparser
import hashlib
import io
import importlib.machinery
import importlib.util
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader(
    "immich_share_cli", str(ROOT / "immich-share")
)
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


def link(key, *, expired=False):
    when = datetime.now(timezone.utc) + (
        timedelta(hours=-1) if expired else timedelta(hours=1)
    )
    return {
        "id": f"id-{key}",
        "key": key,
        "expiresAt": when.isoformat().replace("+00:00", "Z"),
        "description": "test",
    }


class FakeImmich:
    def __init__(self, links):
        self.links = links
        self.deleted = []

    def list_links(self):
        return list(self.links)

    def delete_link(self, link_id):
        self.deleted.append(link_id)
        self.links = [item for item in self.links if item["id"] != link_id]


class OpenImmich(FakeImmich):
    public_base = "https://photos.example.com"

    def find_album(self, name):
        return {"id": "album-id", "albumName": name, "assetCount": 1}

    def create_link(self, album_id, password, expires_at, description, allow_download):
        created = {
            "id": "id-new_share_key_1234",
            "key": "new_share_key_1234",
            "expiresAt": expires_at,
            "description": description,
        }
        self.links.append(created)
        return created


class FakeEdge:
    upstream = "ipp:3000"
    download_upstream = "download-guard:8080"

    def __init__(self, snippets=None):
        self.snippets = list(snippets or [])
        self.written = []
        self.removed = []
        self.forward = []
        self.reloads = 0

    def nas_forward(self, on):
        self.forward.append(on)

    def write_snippet(self, name, content):
        self.written.append(name)
        if name not in self.snippets:
            self.snippets.append(name)

    def list_snippets(self):
        return list(self.snippets)

    def remove_snippets(self, names):
        self.removed.extend(names)
        self.snippets = [name for name in self.snippets if name not in names]

    def reload(self):
        self.reloads += 1


class FailingReloadEdge(FakeEdge):
    def reload(self):
        self.reloads += 1
        if self.reloads == 1:
            raise RuntimeError("simulated reload failure")


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        cfg = configparser.ConfigParser()
        cfg.read_dict(
            {
                "sharing": {
                    "managed_state_file": str(Path(self.temp.name) / "state.json")
                }
            }
        )
        self.state = module.ManagedShares(cfg)

    def tearDown(self):
        self.temp.cleanup()

    def test_sync_exposes_only_managed_links(self):
        managed = link("managed_key_1234")
        external = link("external_key_123")
        self.state.add(managed)
        edge = FakeEdge()
        args = SimpleNamespace(managed_state=self.state)

        module.cmd_sync(args, FakeImmich([managed, external]), edge)

        self.assertIn("managed_key_1234.caddy", edge.written)
        self.assertNotIn("external_key_123.caddy", edge.written)

    def test_sweep_deletes_only_managed_expired_link(self):
        managed = link("managed_key_1234", expired=True)
        external = link("external_key_123", expired=True)
        self.state.add(managed)
        immich = FakeImmich([managed, external])
        args = SimpleNamespace(managed_state=self.state)

        module.cmd_sweep(
            args, immich, FakeEdge(["managed_key_1234.caddy", "00-globals.caddy"])
        )

        self.assertEqual(immich.deleted, ["id-managed_key_1234"])
        self.assertNotIn("external_key_123", self.state.keys())

    def test_state_file_is_private(self):
        self.state.add(link("managed_key_1234"))
        self.assertEqual(self.state.path.stat().st_mode & 0o777, 0o600)

    def test_secret_file_must_not_be_group_or_world_readable(self):
        secret = Path(self.temp.name) / "api-key"
        secret.write_text("test-secret")
        secret.chmod(0o644)
        with self.assertRaises(SystemExit):
            module.read_private_secret(secret, "test secret")

    def test_config_must_not_be_group_or_world_readable(self):
        config = Path(self.temp.name) / "config.ini"
        config.write_text("[sharing]\ndefault_ttl = 24h\n")
        config.chmod(0o644)
        with self.assertRaises(SystemExit):
            module.load_config(str(config))

    def test_config_symlink_is_refused(self):
        config = Path(self.temp.name) / "config.ini"
        target = Path(self.temp.name) / "target.ini"
        target.write_text("[sharing]\ndefault_ttl = 24h\n")
        target.chmod(0o600)
        config.symlink_to(target)
        with self.assertRaises(SystemExit):
            module.load_config(str(config))

    def test_private_config_is_loaded_from_validated_descriptor(self):
        config = Path(self.temp.name) / "config.ini"
        config.write_text("[sharing]\ndefault_ttl = 48h\n")
        config.chmod(0o600)
        loaded = module.load_config(str(config))
        self.assertEqual(loaded["sharing"]["default_ttl"], "48h")

    def test_cleartext_remote_immich_requires_explicit_tunnel_acknowledgement(self):
        secret = Path(self.temp.name) / "api-key"
        secret.write_text("test-secret")
        secret.chmod(0o600)
        cfg = configparser.ConfigParser()
        cfg.read_dict(
            {
                "immich": {
                    "url": "http://192.0.2.10:2283",
                    "api_key_file": str(secret),
                    "public_base_url": "https://photos.example.com",
                }
            }
        )
        with self.assertRaises(SystemExit):
            module.Immich(cfg)

    def test_failed_open_rolls_back_link_state_route_and_forward(self):
        immich = OpenImmich([])
        edge = FailingReloadEdge()
        args = SimpleNamespace(
            album="Test album",
            ttl="24h",
            max_ttl=timedelta(days=30),
            prompt_password=False,
            password_file=None,
            for_="recipient",
            allow_download=True,
            managed_state=self.state,
        )
        with self.assertRaises(RuntimeError):
            module.cmd_open(args, immich, edge)

        self.assertEqual(immich.deleted, ["id-new_share_key_1234"])
        self.assertEqual(self.state.keys(), set())
        self.assertIn("new_share_key_1234.caddy", edge.removed)
        self.assertEqual(edge.forward, [True, False])

    def test_open_qr_contains_public_link_only(self):
        immich = OpenImmich([])
        args = SimpleNamespace(
            album="Test album",
            ttl="24h",
            max_ttl=timedelta(days=30),
            prompt_password=False,
            password_file=None,
            for_="recipient",
            allow_download=True,
            managed_state=self.state,
            qr=True,
        )
        password = "fixed.share.password.123"
        with mock.patch.object(module, "gen_password", return_value=password):
            with mock.patch.object(module, "print_terminal_qr", return_value=True) as qr:
                with redirect_stdout(io.StringIO()):
                    module.cmd_open(args, immich, FakeEdge())

        qr.assert_called_once_with(
            "https://photos.example.com/share/new_share_key_1234"
        )
        self.assertNotIn(password, qr.call_args.args[0])

    def test_open_qr_with_password_uses_fragment_not_query_string(self):
        immich = OpenImmich([])
        args = SimpleNamespace(
            album="Test album",
            ttl="24h",
            max_ttl=timedelta(days=30),
            prompt_password=False,
            password_file=None,
            for_="recipient",
            allow_download=True,
            managed_state=self.state,
            qr=False,
            qr_with_password=True,
        )
        password = "fixed&share=password#123"
        output = io.StringIO()
        with mock.patch.object(module, "gen_password", return_value=password):
            with mock.patch.object(module, "print_terminal_qr", return_value=True) as qr:
                with redirect_stdout(output):
                    module.cmd_open(args, immich, FakeEdge())

        qr.assert_called_once_with(
            "https://photos.example.com/share/new_share_key_1234"
            "#ipp-password=fixed%26share%3Dpassword%23123"
        )
        self.assertNotIn("?", qr.call_args.args[0])
        self.assertIn("One-scan mode", output.getvalue())
        self.assertNotIn("Two-channel rule", output.getvalue())

    def test_terminal_qr_passes_link_on_stdin_not_process_arguments(self):
        url = "https://photos.example.com/share/secret_share_key"
        completed = SimpleNamespace(returncode=0, stdout="terminal-qr\n", stderr="")
        with mock.patch.object(module.shutil, "which", return_value="/usr/bin/qrencode"):
            with mock.patch.object(module.subprocess, "run", return_value=completed) as run:
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertTrue(module.print_terminal_qr(url))

        command = run.call_args.args[0]
        self.assertNotIn(url, command)
        self.assertEqual(run.call_args.kwargs["input"], url)
        self.assertEqual(output.getvalue(), "terminal-qr\n")

    def test_missing_qrencode_does_not_invalidate_share(self):
        errors = io.StringIO()
        with mock.patch.object(module.shutil, "which", return_value=None):
            with redirect_stderr(errors):
                self.assertFalse(
                    module.print_terminal_qr(
                        "https://photos.example.com/share/secret_share_key"
                    )
                )

        self.assertIn("QR code unavailable", errors.getvalue())

    def test_password_file_must_be_private(self):
        password = Path(self.temp.name) / "share-password"
        password.write_text("correct-horse-battery-staple")
        password.chmod(0o644)
        args = SimpleNamespace(password_file=str(password), prompt_password=False)
        with self.assertRaises(SystemExit):
            module.resolve_open_password(args)

    def test_share_snippet_exposes_only_bounded_zip_queue_routes(self):
        rendered = module.render_share_snippet(
            FakeEdge(), "managed_key_1234", "album", "2026-08-27T00:00:00Z"
        )

        self.assertIn("/share/managed_key_1234/download/prepare", rendered)
        self.assertIn("/share/managed_key_1234/download/plan", rendered)
        self.assertIn(
            f"log_append share_ref {hashlib.sha256(b'managed_key_1234').hexdigest()[:16]}",
            rendered,
        )
        self.assertIn("log_append share_action gallery", rendered)
        self.assertIn("log_append share_action view", rendered)
        self.assertIn("log_append share_action download", rendered)
        self.assertIn(
            "(?i)^/share/managed_key_1234/download/jobs/[a-z0-9_-]{24}/file/?$",
            rendered,
        )
        self.assertIn("method GET DELETE", rendered)
        self.assertNotIn("\tpath /share/managed_key_1234/*", rendered)


class DeploymentBoundaryTests(unittest.TestCase):
    def test_ipp_uses_external_agpl_image_pinned_by_digest(self):
        compose = (ROOT / "vps" / "docker-compose.yml").read_text()
        self.assertRegex(
            compose,
            re.compile(
                r"image: ghcr\.io/christopheraparicio/immich-public-proxy:"
                r"3\.2\.1-immich-share\.6@sha256:[0-9a-f]{64}"
            ),
        )
        self.assertFalse((ROOT / "vps" / "Dockerfile.ipp").exists())
        self.assertFalse((ROOT / "vps" / "patch-ipp-download-limit.mjs").exists())
        self.assertIn(
            "AGPL-3.0-only",
            (ROOT / "THIRD_PARTY_NOTICES.md").read_text(),
        )

    def test_zip_retry_has_an_absolute_deadline(self):
        config = json.loads((ROOT / "vps" / "ipp-config.json").read_text())
        self.assertEqual(config["ipp"]["downloadZipReadyLeaseSeconds"], 120)
        self.assertEqual(config["ipp"]["downloadZipMaxReadyLeaseSeconds"], 300)

    def test_zip_resource_budget_and_parallel_backstops_are_aligned(self):
        config = json.loads((ROOT / "vps" / "ipp-config.json").read_text())["ipp"]
        compose = (ROOT / "vps" / "docker-compose.yml").read_text()
        caddy = (ROOT / "vps" / "Caddyfile").read_text()
        self.assertEqual(config["downloadZipDiskBudgetPercent"], 50)
        self.assertEqual(config["downloadZipMaxParallelDownloads"], 3)
        self.assertIn("IPP_ZIP_DISK_BUDGET_PERCENT=${ZIP_DISK_BUDGET_PERCENT:-50}", compose)
        self.assertIn("IPP_ZIP_MAX_PARALLEL_DOWNLOADS=${ZIP_MAX_PARALLEL_DOWNLOADS:-3}", compose)
        self.assertIn("ZIP_GLOBAL: ${ZIP_GLOBAL:-3}", compose)
        self.assertIn("path /share/*/download/plan", caddy)
        self.assertIn("events 6", caddy)

    def test_nas_logs_never_include_the_raw_request_or_query(self):
        config = (ROOT / "nas" / "nginx-filter.conf").read_text()
        log_format = "\n".join(
            line for line in config.splitlines() if "log_format" in line or "status=" in line
        )
        self.assertIn('"$request_method $uri"', log_format)
        self.assertNotIn("$request_uri", log_format)
        self.assertNotIn("$request ", log_format)
        self.assertIn("error_log /dev/null", config)

    def test_download_guard_disables_credential_bearing_error_logs(self):
        global_config = (ROOT / "vps" / "download-guard-nginx.conf").read_text()
        server_config = (ROOT / "vps" / "download-guard.conf.template").read_text()
        self.assertIn("error_log /dev/null", global_config)
        self.assertIn("error_log /dev/null", server_config)
        self.assertNotRegex(global_config, r"error_log\s+/dev/stderr")
        self.assertNotRegex(server_config, r"error_log\s+/dev/stderr")

    def test_nas_images_apply_security_updates_before_packages(self):
        for filename in ("Dockerfile.wireguard", "Dockerfile.logrotate", "Dockerfile.nginx"):
            contents = (ROOT / "nas" / filename).read_text()
            self.assertIn("apk upgrade --no-cache", contents, filename)

    def test_wireguard_can_read_only_the_private_bind_mount(self):
        compose = (ROOT / "nas" / "docker-compose.yml").read_text()
        wireguard = compose.split("  nginx-filter:", 1)[0]
        self.assertIn("- NET_ADMIN", wireguard)
        self.assertIn("- DAC_READ_SEARCH", wireguard)
        self.assertIn("cap_drop:\n      - ALL", wireguard)
        self.assertIn("./wg0-nas.conf:/config/wg0.conf:ro", wireguard)
        self.assertNotIn("DAC_OVERRIDE", wireguard)
        doctor = (ROOT / "nas" / "security-doctor.sh").read_text()
        self.assertIn(r'\[\"NET_ADMIN\",\"DAC_READ_SEARCH\"\]', doctor)
        self.assertIn("sed '/^[[:space:]]*#/d'", doctor)

    def test_docker_build_contexts_are_closed_by_default(self):
        for directory in ("nas", "vps"):
            patterns = (ROOT / directory / ".dockerignore").read_text().splitlines()
            effective = [line for line in patterns if line and not line.startswith("#")]
            self.assertEqual(effective[0], "*", directory)
            self.assertFalse(any(".env" in line and line.startswith("!") for line in effective))
            self.assertFalse(any("backup" in line and line.startswith("!") for line in effective))
            self.assertFalse(any("wg0" in line and line.startswith("!") for line in effective))

    def test_immich_network_override_attaches_only_the_server(self):
        override = (ROOT / "nas" / "immich-network.override.yml").read_text()
        self.assertIn("  immich-server:", override)
        self.assertIn("aliases:", override)
        self.assertIn("- immich_server", override)
        self.assertNotIn("redis:", override)
        self.assertNotIn("database:", override)

    def test_separate_doctor_includes_all_trust_zones(self):
        class FakeConfig(configparser.ConfigParser):
            pass

        cfg = FakeConfig()
        cfg.read_dict(
            {
                "controller": {
                    "mode": "separate",
                    "expected_wireguard_peers": "2",
                    "controller_wireguard_address": "192.0.2.3",
                },
                "nas": {"doctor_cmd": "true"},
            }
        )
        labels = []

        class DoctorEdge:
            def __getattr__(self, _name):
                return lambda *args: "ok"

        class DoctorImmich:
            api_key_file = Path("/tmp/not-used")
            public_base = "https://photos.example.com"

            def probe(self):
                return "ok"

        args = SimpleNamespace(
            config_object=cfg,
            mode=None,
            managed_state=SimpleNamespace(path=Path("/tmp/not-used")),
        )
        original_gate = module.probe_nas_gate
        original_pf = module.probe_pf_filter
        original_api = module.probe_api_key_permissions
        original_state = module.probe_state_permissions
        original_public = module.probe_public_root
        try:
            module.probe_nas_gate = lambda _cfg: "ok"
            module.probe_pf_filter = lambda _anchor: "ok"
            module.probe_api_key_permissions = lambda _path: "ok"
            module.probe_state_permissions = lambda _state: "ok"
            module.probe_public_root = lambda _url: "ok"
            import builtins

            original_print = builtins.print
            builtins.print = lambda message="", *a, **k: labels.append(str(message))
            try:
                result = module.cmd_doctor(args, DoctorImmich(), DoctorEdge())
            finally:
                builtins.print = original_print
        finally:
            module.probe_nas_gate = original_gate
            module.probe_pf_filter = original_pf
            module.probe_api_key_permissions = original_api
            module.probe_state_permissions = original_state
            module.probe_public_root = original_public
        self.assertEqual(result, 0)
        output = "\n".join(labels)
        self.assertIn("NAS trust-boundary gate", output)
        self.assertIn("Controller packet filter", output)
        self.assertIn("VPS-to-controller isolation", output)
        self.assertIn("VPS published ports", output)
        self.assertIn("Download-guard runtime logging", output)
        self.assertIn("VPS live refusal and log redaction", output)
        self.assertIn("VPS bridge containment", output)

    def test_mac_wireguard_boot_is_ordered_fail_closed(self):
        script = (ROOT / "macmini" / "start-wireguard-fail-closed.sh").read_text()
        self.assertLess(script.index('"$pfctl_bin" -f'), script.index('"$wg_quick_bin" up'))
        self.assertIn("anchor has no inbound block rule", script)
        guide = (ROOT / "macmini" / "pf-wireguard.md").read_text()
        self.assertIn("single LaunchDaemon", guide)
        self.assertNotIn("after a short boot delay", guide)


MATCHER_BLOCK_RE = re.compile(r"^@(\w+) \{\n((?:\t.*\n)+?)\}$", re.MULTILINE)


def parse_snippet_matchers(rendered):
    """Return {name: (methods or None, compiled path regexp)} for a snippet."""
    matchers = {}
    for name, body in MATCHER_BLOCK_RE.findall(rendered):
        methods = None
        pattern = None
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("method "):
                methods = set(line.split()[1:])
            elif line.startswith("path_regexp "):
                pattern = re.compile(line.split(" ", 1)[1])
            elif line.startswith("path "):
                raise AssertionError(f"@{name} uses a prefix path matcher: {line}")
        if pattern is None:
            raise AssertionError(f"@{name} has no path_regexp")
        matchers[name] = (methods, pattern)
    return matchers

    def test_nas_filter_forwards_only_the_share_token_cookie(self):
        config = (ROOT / "nas" / "nginx-filter.conf").read_text()
        upload = (ROOT / "nas" / "upload-filter.conf").read_text()
        # The gate evaluates the normalized $uri; the same path must be proxied.
        self.assertIn("proxy_pass http://${IMMICH_UPSTREAM}$uri$is_args$args;", config)
        self.assertIn("proxy_set_header Cookie $immich_share_cookie;", config)
        self.assertRegex(config, r'"~\(\?:\^\|;\\s\*\)immich_shared_link_token=')
        for header in (
            "Authorization",
            "Proxy-Authorization",
            "x-api-key",
            "x-immich-user-token",
            "x-immich-session-token",
        ):
            self.assertIn(f'proxy_set_header {header} "";', config, header)
        # `$` matches before a trailing newline that nginx decodes from %0A.
        for text, name in ((config, "nginx-filter.conf"), (upload, "upload-filter.conf")):
            patterns = [
                line for line in text.splitlines() if line.lstrip().startswith(("~^", '"~^'))
            ]
            self.assertTrue(patterns, name)
            for line in patterns:
                self.assertNotRegex(line, r"\$\"? [^ ]+;$", f"{name}: {line}")
                self.assertRegex(line, r"\\z\"? [^ ]+;$", f"{name}: {line}")

    def test_caddy_logs_drop_credential_headers(self):
        caddy = (ROOT / "vps" / "Caddyfile").read_text()
        # Both the runtime logger and the access log carry the same filter.
        for field in (
            "request>uri replace REDACTED",
            "request>headers>X-Ipp-Csrf-Token delete",
            "request>headers>Cookie delete",
            "request>headers>Authorization delete",
            "request>headers>Proxy-Authorization delete",
            "resp_headers>Set-Cookie delete",
        ):
            self.assertEqual(caddy.count(field), 2, field)

    def test_download_guard_limits_zip_transfers_per_client(self):
        template = (ROOT / "vps" / "download-guard.conf.template").read_text()
        compose = (ROOT / "vps" / "docker-compose.yml").read_text()
        env = (ROOT / "vps" / ".env.example").read_text()
        self.assertIn("limit_conn_zone $download_client_key zone=zip_per_ip:1m;", template)
        self.assertEqual(template.count("limit_conn zip_global ${ZIP_GLOBAL};"), 2)
        self.assertEqual(template.count("limit_conn zip_per_ip ${ZIP_PER_IP};"), 2)
        self.assertIn("ZIP_PER_IP: ${ZIP_PER_IP:-1}", compose)
        self.assertRegex(env, r"(?m)^ZIP_PER_IP=1$")

    def test_vps_containment_drops_every_other_bridge_toward_wg0(self):
        script = (ROOT / "vps" / "containment" / "immich-share-containment.sh").read_text()
        setup = (ROOT / "SETUP.md").read_text()
        self.assertIn("insert_rule -o wg0 -j DROP\n", script)
        # The unconditional wg0 DROP sits after the ACCEPTs and before the bridge DROPs.
        self.assertLess(
            script.index("insert_rule -o wg0 -j DROP"),
            script.index('insert_rule -i "$read_bridge" -j DROP'),
        )
        rule = "-A DOCKER-USER -o wg0 -m comment --comment immich-share -j DROP"
        self.assertIn(rule, script)
        self.assertIn(rule, setup)

    def test_macmini_wireguard_daemon_runs_only_root_owned_tools(self):
        plist = (ROOT / "macmini" / "local.immich-share-wireguard.plist").read_text()
        script = (ROOT / "macmini" / "start-wireguard-fail-closed.sh").read_text()
        self.assertNotIn("/opt/homebrew", plist)
        self.assertNotIn("/opt/homebrew", script)
        self.assertIn(
            "<string>/usr/local/libexec/immich-share-wireguard:/usr/bin:/bin:/usr/sbin:/sbin</string>",
            plist,
        )
        self.assertIn("PATH=$tool_dir:/usr/bin:/bin:/usr/sbin:/sbin", script)
        for tool in ("wg-quick", "bash", "wg", "wireguard-go"):
            self.assertIn(tool, script)
        self.assertIn('require_root_owned "$wg_config" "WireGuard config"', script)
        self.assertIn('require_root_owned "$(dirname "$wg_config")"', script)


class RouteMatcherTests(unittest.TestCase):
    """The guard must not depend on Caddy's handle ordering or case folding."""

    KEY = "managed_key_1234"
    OTHER = "other_key_12345"
    UUID = "0f9c6d1e-2b3a-4c5d-8e7f-a1b2c3d4e5f6"
    JOB = "abcdefghijklmnopqrstuvwx"

    def setUp(self):
        self.rendered = module.render_share_snippet(
            FakeEdge(), self.KEY, "album", "2026-08-27T00:00:00Z"
        )
        self.matchers = parse_snippet_matchers(self.rendered)

    def handles(self, method, path):
        return sorted(
            name
            for name, (methods, pattern) in self.matchers.items()
            if (methods is None or method in methods) and pattern.fullmatch(path)
        )

    def test_every_matcher_is_an_anchored_case_insensitive_regexp(self):
        self.assertGreaterEqual(len(self.matchers), 11)
        for name, (_methods, pattern) in self.matchers.items():
            self.assertTrue(pattern.pattern.startswith("(?i)^"), name)
            self.assertTrue(pattern.pattern.endswith("$"), name)
        self.assertNotIn("\tpath ", self.rendered)

    def test_originals_reach_only_the_download_guard_whatever_the_case(self):
        for path in (
            f"/share/photo/{self.KEY}/{self.UUID}/original",
            f"/share/Photo/{self.KEY}/{self.UUID}/original",
            f"/share/photo/{self.KEY}/{self.UUID.upper()}/ORIGINAL",
            f"/share/video/{self.KEY}/{self.UUID}/original/",
            f"/SHARE/VIDEO/{self.KEY}/{self.UUID}/Original",
        ):
            self.assertEqual(self.handles("GET", path), [f"dl_{self.KEY}"], path)
            self.assertEqual(self.handles("HEAD", path), [f"dl_{self.KEY}"], path)
            self.assertEqual(self.handles("POST", path), [], path)

    def test_gallery_routes_each_match_exactly_one_handler(self):
        k, u, j = self.KEY, self.UUID, self.JOB
        expectations = {
            ("GET", f"/share/{k}"): "gallery_",
            ("GET", f"/share/{k}/"): "gallery_",
            ("GET", f"/share/photo/{k}/{u}/thumbnail"): "thumb_",
            ("GET", f"/share/video/{k}/{u}/preview"): "preview_",
            ("GET", f"/share/video/{k}/{u}"): "media_",
            ("GET", f"/share/photo/{k}/{u}/fullsize"): "media_",
            ("GET", f"/share/meta/{k}/{u}"): "meta_",
            ("GET", f"/share/{k}/download"): "zip_",
            ("POST", f"/share/{k}/download"): "zip_",
            ("POST", f"/share/{k}/download/prepare"): "zip_prepare_",
            ("POST", f"/share/{k}/download/plan"): "zip_plan_",
            ("GET", f"/share/{k}/download/jobs/{j}"): "zip_job_",
            ("DELETE", f"/share/{k}/download/jobs/{j}"): "zip_job_",
            ("GET", f"/share/{k}/download/jobs/{j}/file"): "zip_file_",
        }
        for (method, path), prefix in expectations.items():
            self.assertEqual(self.handles(method, path), [prefix + k], (method, path))

    def test_foreign_keys_and_unknown_paths_match_nothing(self):
        k, u = self.KEY, self.UUID
        for path in (
            f"/share/photo/{self.OTHER}/{u}/original",
            f"/share/{self.OTHER}",
            f"/share/{k}/anything",
            f"/share/photo/{k}/not-a-uuid/original",
            f"/share/photo/{k}/{u}/original/extra",
            f"/share/{k}/download/jobs/short/file",
            f"/s/{k}",
            "/share/static/style.css",
            "/share/unlock",
        ):
            self.assertEqual(self.handles("GET", path), [], path)


class MachineOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        cfg = configparser.ConfigParser()
        cfg.read_dict(
            {"sharing": {"managed_state_file": str(Path(self.temp.name) / "state.json")}}
        )
        self.state = module.ManagedShares(cfg)

    def tearDown(self):
        self.temp.cleanup()

    def test_open_json_puts_one_object_on_stdout_and_progress_on_stderr(self):
        immich = OpenImmich([])
        args = SimpleNamespace(
            album="Test album",
            ttl="24h",
            max_ttl=timedelta(days=30),
            prompt_password=False,
            password_file=None,
            for_="recipient",
            allow_download=True,
            managed_state=self.state,
            json_output=True,
        )
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(module, "gen_password", return_value="fixed.pass.word.1234"):
            with redirect_stdout(out), redirect_stderr(err):
                module.cmd_open(args, immich, FakeEdge())
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        self.assertEqual(payload["key"], "new_share_key_1234")
        self.assertEqual(payload["link"], "https://photos.example.com/share/new_share_key_1234")
        self.assertEqual(payload["password"], "fixed.pass.word.1234")
        self.assertEqual(payload["description"], "recipient")
        self.assertEqual(payload["album"], {"name": "Test album", "assetCount": 1})
        self.assertTrue(payload["allowDownload"])
        self.assertIn("Immich link created", err.getvalue())
        self.assertNotIn("Immich link created", out.getvalue())

    def test_list_json_reports_ownership_and_portal_state(self):
        immich = FakeImmich([link("managed_key_1234"), link("external_key_123", expired=True)])
        self.state.add(link("managed_key_1234"))
        edge = FakeEdge(["00-globals.caddy", "managed_key_1234.caddy", "orphan_orphan_orphan.caddy"])
        args = SimpleNamespace(managed_state=self.state, json_output=True)
        out = io.StringIO()
        with redirect_stdout(out):
            module.cmd_list(args, immich, edge)
        payload = json.loads(out.getvalue())
        by_key = {row["key"]: row for row in payload["shares"]}
        self.assertTrue(by_key["managed_key_1234"]["managed"])
        self.assertTrue(by_key["managed_key_1234"]["portalOpen"])
        self.assertFalse(by_key["external_key_123"]["managed"])
        self.assertTrue(by_key["external_key_123"]["expired"])
        self.assertEqual(payload["orphanSnippets"], ["orphan_orphan_orphan"])


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def _state(self, name):
        cfg = configparser.ConfigParser()
        cfg.read_dict({"sharing": {"managed_state_file": str(Path(self.temp.name) / name)}})
        return module.ManagedShares(cfg)

    def test_state_file_symlink_or_shared_mode_is_refused(self):
        real = Path(self.temp.name) / "real.json"
        real.write_text('{"version": 1, "shares": {}}')
        real.chmod(0o600)
        (Path(self.temp.name) / "link.json").symlink_to(real)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self._state("link.json")._read()
        real.chmod(0o644)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self._state("real.json")._read()
        real.chmod(0o600)
        self.assertEqual(self._state("real.json")._read()["shares"], {})

    def test_immich_client_never_follows_redirects_with_the_api_key(self):
        import http.server
        import threading

        leaked = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                if self.path.startswith("/api/"):
                    self.send_response(302)
                    self.send_header(
                        "Location", f"http://127.0.0.1:{self.server.server_port}/leak"
                    )
                    self.end_headers()
                    return
                leaked.append(self.headers.get("x-api-key"))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"[]")

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            immich = module.Immich.__new__(module.Immich)
            immich.url = f"http://127.0.0.1:{server.server_port}"
            immich.api_key = "secret-api-key"
            with redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit):
                    immich._call("GET", "/albums")
            self.assertIn("redirect", err.getvalue())
            with self.assertRaises(RuntimeError) as ctx:
                immich.probe()
            self.assertIn("redirect", str(ctx.exception))
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(leaked, [])

    def test_find_album_accepts_an_album_uuid(self):
        immich = module.Immich.__new__(module.Immich)
        albums = [
            {"id": "0f9c6d1e-2b3a-4c5d-8e7f-a1b2c3d4e5f6", "albumName": "Summer"},
            {"id": "11111111-2222-4333-8444-555555555555", "albumName": "Summer"},
        ]
        immich._call = lambda method, path, body=None: albums
        self.assertEqual(
            immich.find_album("0F9C6D1E-2B3A-4C5D-8E7F-A1B2C3D4E5F6")["albumName"], "Summer"
        )
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                immich.find_album("Summer")  # ambiguous by name
            with self.assertRaises(SystemExit):
                immich.find_album("99999999-2222-4333-8444-555555555555")

    def test_forward_containment_probe_maps_exit_codes_to_reasons(self):
        edge = module.Edge.__new__(module.Edge)
        for code, fragment in ((41, "DOCKER-USER"), (42, "immich-tunnel")):
            edge._ssh = lambda *_a, code=code, **_k: SimpleNamespace(returncode=code, stdout="", stderr="")
            with self.assertRaises(RuntimeError) as ctx:
                edge.probe_forward_containment()
            self.assertIn(fragment, str(ctx.exception))
        commands = []
        rules = "\n".join(
            (
                "-A DOCKER-USER -d 192.0.2.10/32 -i immich-tunnel -o wg0 -p tcp -m tcp --dport 2283 -m comment --comment immich-share -j ACCEPT",
                "-A DOCKER-USER -d 192.0.2.11/32 -i immich-uptun -o wg0 -p tcp -m tcp --dport 2383 -m comment --comment immich-share -j ACCEPT",
                "-A DOCKER-USER -o wg0 -m comment --comment immich-share -j DROP",
                "-A DOCKER-USER -i immich-tunnel -m comment --comment immich-share -j DROP",
                "-A DOCKER-USER -i immich-uptun -m comment --comment immich-share -j DROP",
                "-A DOCKER-USER -j RETURN",
            )
        )

        def ok(remote, stdin=None):
            commands.append(remote)
            return SimpleNamespace(returncode=0, stdout=rules, stderr="")

        edge._ssh = ok
        self.assertIn("NAS filter", edge.probe_forward_containment())
        self.assertIn("iptables -S DOCKER-USER", commands[0])
        self.assertIn("immich-tunnel", commands[0])

        # Any broader rule placed before the owned rules could bypass their
        # DROP, and any extra option on an owned ACCEPT broadens the contract.
        for bad in (
            "-A DOCKER-USER -j ACCEPT\n" + rules,
            rules.replace("--dport 2283", "--dport 22"),
            rules.replace("-d 192.0.2.10/32 ", ""),
            rules.replace("-i immich-uptun -m comment", "-i immich-uptun -s 0.0.0.0/0 -m comment"),
            # Without the bridge-to-wg0 DROP, Caddy's public bridge reaches the tunnel.
            rules.replace("-A DOCKER-USER -o wg0 -m comment --comment immich-share -j DROP\n", ""),
            rules.replace("-A DOCKER-USER -o wg0 -m comment", "-A DOCKER-USER -i immich-tunnel -o wg0 -m comment"),
        ):
            edge._ssh = lambda *_a, bad=bad, **_k: SimpleNamespace(
                returncode=0, stdout=bad, stderr=""
            )
            with self.assertRaises(RuntimeError):
                edge.probe_forward_containment()

    def test_nas_doctor_expects_the_deployed_wireguard_capabilities(self):
        cfg = configparser.ConfigParser()
        cfg.read_dict({"controller": {"mode": "nas"}})
        checks = dict(module.probe_nas_controller(cfg))
        hardening = checks["NAS tunnel hardening"]
        deployed = 'true|["ALL"]|["NET_ADMIN","DAC_READ_SEARCH"]|["no-new-privileges:true"]'
        with mock.patch.object(module, "run_local", return_value=deployed):
            self.assertIn("DAC_READ_SEARCH", hardening())
        with mock.patch.object(
            module, "run_local", return_value='true|["ALL"]|["NET_ADMIN"]|["no-new-privileges:true"]'
        ):
            with self.assertRaises(RuntimeError):
                hardening()
        with mock.patch.object(
            module,
            "run_local",
            return_value='true|["ALL"]|["NET_ADMIN","DAC_READ_SEARCH","SYS_ADMIN"]|["no-new-privileges:true"]',
        ):
            with self.assertRaises(RuntimeError):
                hardening()


if __name__ == "__main__":
    unittest.main()
