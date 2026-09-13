from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from helpers import make_target
from lucx_post_configurator.discovery import audit_system
from lucx_post_configurator.models import default_manifest
from lucx_post_configurator.questionnaire import refresh_manifest_from_audit
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import synchronize_lucx_publication, rollback_lucx_publication


class PublicationEndpointTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        db = make_target(root)
        with closing(sqlite3.connect(db)) as connection:
            connection.execute("DELETE FROM inbounds WHERE id != 1")
            connection.execute("UPDATE inbounds SET share_addr=?, stream_settings=? WHERE id=1", (
                "vpn.example.test", json.dumps({"network": "ws", "security": "tls",
                    "tlsSettings": {"serverName": "vpn.example.test"}, "wsSettings": {"path": "/vpn"}})))
            connection.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER, sni TEXT, host TEXT)")
            connection.executemany("INSERT INTO hosts VALUES (?,1,?,0,?,?,?,?)", [
                (11, 0, "vpn.example.test", 443, "vpn.example.test", ""),
                (12, 1, "alias.example.test", 8443, "tls.example.test", "http.example.test"),
            ])
            connection.commit()
        return db

    def snapshot(self, db: Path) -> tuple:
        with closing(sqlite3.connect(db)) as connection:
            return (list(connection.execute("SELECT * FROM hosts ORDER BY id")),
                    list(connection.execute("SELECT * FROM inbounds ORDER BY id")))

    def test_extended_refresh_never_authorizes_publication_as_a_side_effect(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = self.fixture(root)
            audit = audit_system(root)
            manifest = default_manifest(audit)
            manifest["decoys"]["routing_mode"] = "extended"
            manifest["protocols"] = [{"inbound_id": 1, "domain": "vpn.example.test"}]
            before = self.snapshot(db)
            refreshed, _ = refresh_manifest_from_audit(manifest, audit)
            self.assertFalse(refreshed["lucx"]["settings_management"]["sync_public_endpoints"])
            self.assertFalse(refreshed["protocols"][0]["sync_public_endpoint"])
            self.assertEqual(self.snapshot(db), before)

    def test_primary_publication_noop_preserves_secondary_hosts_verbatim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = self.fixture(root)
            before = self.snapshot(db)
            changes = synchronize_lucx_publication(TargetFS(root), "/etc/x-ui/x-ui.db",
                panel_domain=None, subscription_domain=None,
                public_publications=[{"inbound_id": 1, "domain": "vpn.example.test", "public_port": 443}])
            self.assertEqual(self.snapshot(db), before)
            self.assertEqual(changes, [])

    def test_scalar_migration_cannot_flatten_multiple_enabled_hosts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = self.fixture(root)
            before = self.snapshot(db)
            with self.assertRaisesRegex(RuntimeError, "Host|endpoint"):
                synchronize_lucx_publication(TargetFS(root), "/etc/x-ui/x-ui.db",
                    panel_domain=None, subscription_domain=None,
                    public_publications=[{"inbound_id": 1, "domain": "new.example.test", "public_port": 443}])
            self.assertEqual(self.snapshot(db), before)

    def test_primary_sync_can_update_only_legacy_share_addr_and_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = self.fixture(root)
            with closing(sqlite3.connect(db)) as connection:
                connection.execute("UPDATE inbounds SET share_addr='stale.example.test' WHERE id=1")
                connection.commit()
            before = self.snapshot(db)
            changes = synchronize_lucx_publication(TargetFS(root), "/etc/x-ui/x-ui.db",
                panel_domain=None, subscription_domain=None,
                public_publications=[{"inbound_id": 1, "domain": "vpn.example.test", "public_port": 443}])
            self.assertEqual(self.snapshot(db)[0], before[0])
            self.assertEqual([change["kind"] for change in changes], ["inbound_share_addr"])
            rollback_lucx_publication(TargetFS(root), "/etc/x-ui/x-ui.db", changes)
            self.assertEqual(self.snapshot(db), before)
