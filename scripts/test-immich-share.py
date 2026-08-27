#!/usr/bin/env python3
import configparser
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
            password=None,
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

    def test_share_snippet_exposes_only_bounded_zip_queue_routes(self):
        rendered = module.render_share_snippet(
            FakeEdge(), "managed_key_1234", "album", "2026-08-27T00:00:00Z"
        )

        self.assertIn("/share/managed_key_1234/download/prepare", rendered)
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
                r"3\.2\.1-immich-share\.3@sha256:[0-9a-f]{64}"
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


if __name__ == "__main__":
    unittest.main()
