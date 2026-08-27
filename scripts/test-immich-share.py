#!/usr/bin/env python3
import configparser
import hashlib
import importlib.machinery
import importlib.util
import json
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace


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
        self.assertIn(
            f"log_append share_ref {hashlib.sha256(b'managed_key_1234').hexdigest()[:16]}",
            rendered,
        )
        self.assertIn("log_append share_action gallery", rendered)
        self.assertIn("log_append share_action view", rendered)
        self.assertIn("log_append share_action download", rendered)
        self.assertIn(
            "^/share/managed_key_1234/download/jobs/[A-Za-z0-9_-]{24}/file/?$",
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
                r"3\.2\.1-immich-share\.4@sha256:[0-9a-f]{64}"
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

    def test_mac_wireguard_boot_is_ordered_fail_closed(self):
        script = (ROOT / "macmini" / "start-wireguard-fail-closed.sh").read_text()
        self.assertLess(script.index('"$pfctl_bin" -f'), script.index('"$wg_quick_bin" up'))
        self.assertIn("anchor has no inbound block rule", script)
        guide = (ROOT / "macmini" / "pf-wireguard.md").read_text()
        self.assertIn("single LaunchDaemon", guide)
        self.assertNotIn("after a short boot delay", guide)


if __name__ == "__main__":
    unittest.main()
