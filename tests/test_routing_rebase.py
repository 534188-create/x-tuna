from __future__ import annotations

import json
import copy
import sqlite3
import tempfile
import unittest
from contextlib import closing, ExitStack
from pathlib import Path
from unittest.mock import patch, PropertyMock

from helpers import make_target
from lucx_post_configurator.discovery import audit_system
from lucx_post_configurator.routing_profiles import source_routing_fingerprint
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import synchronize_lucx_publication, synchronize_lucx_inbound_changes


class RoutingRebaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.db = make_target(self.root)
        self.fs = TargetFS(self.root)
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("DELETE FROM inbounds WHERE id != 1")
            connection.execute("UPDATE inbounds SET share_addr=?, settings=?, stream_settings=? WHERE id=1", (
                "old.example.test", json.dumps({"clients": [{"id": "synthetic-preserved"}], "domain": "old.example.test"}),
                json.dumps({"network": "xhttp", "security": "tls", "tlsSettings": {"serverName": "old.example.test", "certificates": [{"certificateFile": "/cert/old.pem", "keyFile": "/cert/old.key"}]},
                            "xhttpSettings": {"path": "/old", "mode": "auto"}})))
            connection.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER, override_sni_from_address INTEGER)")
            connection.execute("INSERT INTO hosts VALUES (11,1,0,0,'old.example.test',443,1)")
            connection.commit()
        self.audit = audit_system(self.root)

    def baseline(self):
        from lucx_post_configurator.routing_rebase import capture_rebase_baseline
        return capture_rebase_baseline(self.fs, "/etc/x-ui/x-ui.db", self.audit)

    def verify(self, baseline, receipts):
        from lucx_post_configurator.routing_rebase import verify_authorized_rebase
        return verify_authorized_rebase(self.fs, "/etc/x-ui/x-ui.db", baseline, receipts)

    def publication(self):
        return synchronize_lucx_publication(self.fs, "/etc/x-ui/x-ui.db", panel_domain=None,
            subscription_domain=None, public_publications=[{"inbound_id": 1, "domain": "new.example.test", "public_port": 443}])

    def change_stream(self, key, value):
        with closing(sqlite3.connect(self.db)) as connection:
            stream = json.loads(connection.execute("SELECT stream_settings FROM inbounds WHERE id=1").fetchone()[0])
            stream[key] = value
            connection.execute("UPDATE inbounds SET stream_settings=? WHERE id=1", (json.dumps(stream),))
            connection.commit()

    def test_exact_publication_rebases_only_to_its_verified_new_source(self):
        baseline = self.baseline()
        receipts = self.publication()
        expected = {item.id: source_routing_fingerprint(item) for item in audit_system(self.root).inbounds}
        self.assertEqual(self.verify(baseline, receipts), expected)
        self.assertNotEqual(expected[1], source_routing_fingerprint(self.audit.inbounds[0]))

    def created_host(self):
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("DELETE FROM hosts")
            connection.commit()
        self.audit = audit_system(self.root)
        baseline = self.baseline()
        with closing(sqlite3.connect(self.db)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("INSERT INTO hosts VALUES (12,1,0,0,'old.example.test',443,0)")
            connection.commit()
            row = dict(connection.execute("SELECT * FROM hosts WHERE id=12").fetchone())
        return baseline, {"kind": "inbound_host_created", "inbound_id": 1,
                          "host_id": 12, "new_row": row}

    def test_created_host_receipt_rebases_exact_row_and_refreshes_endpoint(self):
        from lucx_post_configurator.engine import Engine
        baseline, receipt = self.created_host()
        expected = {item.id: source_routing_fingerprint(item) for item in audit_system(self.root).inbounds}
        self.assertEqual(self.verify(baseline, [receipt]), expected)
        manifest = {"lucx": {"db_path": "/etc/x-ui/x-ui.db"}, "decoys": {},
                    "protocols": [{"inbound_id": 1, "domain": "old.example.test"}]}
        Engine(self.root)._refresh_authorized_routing(manifest, baseline, [receipt])
        self.assertEqual(manifest["protocols"][0]["public_endpoints"][0]["host_id"], 12)
        self.assertEqual(manifest["protocols"][0]["public_endpoints"][0]["port"], 443)

    def test_created_host_receipt_rejects_changed_metadata_or_another_row(self):
        baseline, receipt = self.created_host()
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("UPDATE hosts SET override_sni_from_address=1 WHERE id=12")
            connection.commit()
        with self.assertRaises(ValueError):
            self.verify(baseline, [receipt])
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("UPDATE hosts SET override_sni_from_address=0 WHERE id=12")
            connection.execute("INSERT INTO hosts VALUES (13,1,0,0,'extra.example.test',443,0)")
            connection.commit()
        with self.assertRaisesRegex(ValueError, "вне разрешённых"):
            self.verify(baseline, [receipt])

    def test_created_host_receipt_cannot_discard_an_existing_row(self):
        baseline = self.baseline()
        with closing(sqlite3.connect(self.db)) as connection:
            connection.row_factory = sqlite3.Row
            row = dict(connection.execute("SELECT * FROM hosts WHERE id=11").fetchone())
        receipt = {"kind": "inbound_host_created", "inbound_id": 1, "host_id": 11, "new_row": row}
        with self.assertRaises(ValueError):
            self.verify(baseline, [receipt])

    def test_created_host_preserves_all_confirmed_reality_snis_after_refresh(self):
        from lucx_post_configurator.engine import Engine
        from test_transport_routing_regressions import topology
        names = ["cover-one.example.test", "cover-two.example.test"]
        with closing(sqlite3.connect(self.db)) as connection:
            stream = {"network": "xhttp", "security": "reality",
                      "realitySettings": {"serverNames": names},
                      "xhttpSettings": {"path": "/vpn", "mode": "auto"}}
            connection.execute("UPDATE inbounds SET settings=?, stream_settings=? WHERE id=1",
                               (json.dumps({"clients": [{"id": "synthetic-preserved"}]}), json.dumps(stream)))
            connection.commit()
        baseline, receipt = self.created_host()
        manifest = topology("xhttp", inbound_id=1, security="reality",
                            domain="old.example.test", internal_port=self.audit.inbounds[0].port,
                            sni_names=names)
        fresh = Engine(self.root)._refresh_authorized_routing(manifest, baseline, [receipt])
        self.assertEqual(manifest["protocols"][0]["sni_names"], names)
        self.assertEqual(fresh.inbounds[0].server_names, names)
        from lucx_post_configurator.renderers import render_haproxy
        rendered = render_haproxy(manifest)
        for name in names:
            self.assertIn("req.ssl_sni -i " + name, rendered)
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertEqual(connection.execute("SELECT override_sni_from_address FROM hosts WHERE id=12").fetchone()[0], 0)

    def test_engine_refreshes_facts_only_after_exact_receipt_verification(self):
        from lucx_post_configurator.engine import Engine
        from lucx_post_configurator.questionnaire import _inbound_routing_metadata
        engine = Engine(self.root)
        refresh = getattr(engine, "_refresh_authorized_routing", None)
        self.assertTrue(callable(refresh), "Engine ещё не подключает проверку exact receipt")
        baseline = self.baseline()
        manifest = {"lucx": {"db_path": "/etc/x-ui/x-ui.db"}, "decoys": {},
                    "protocols": [{"inbound_id": 1, "domain": "new.example.test",
                                   **_inbound_routing_metadata(self.audit.inbounds[0])}]}
        receipts = self.publication()
        fresh = refresh(manifest, baseline, receipts)
        self.assertEqual(manifest["protocols"][0]["source_routing_fingerprint"],
                         source_routing_fingerprint(fresh.inbounds[0]))
        self.assertEqual(manifest["protocols"][0]["public_endpoints"][0]["address"], "new.example.test")

    def test_engine_does_not_replace_manifest_with_unapproved_transport_facts(self):
        from lucx_post_configurator.engine import ApplyError, Engine
        from lucx_post_configurator.questionnaire import _inbound_routing_metadata
        engine = Engine(self.root)
        refresh = getattr(engine, "_refresh_authorized_routing", None)
        self.assertTrue(callable(refresh), "Engine ещё не подключает проверку exact receipt")
        baseline = self.baseline()
        manifest = {"lucx": {"db_path": "/etc/x-ui/x-ui.db"}, "decoys": {},
                    "protocols": [{"inbound_id": 1, **_inbound_routing_metadata(self.audit.inbounds[0])}]}
        before = copy.deepcopy(manifest)
        receipts = self.publication()
        self.change_stream("network", "grpc")
        with self.assertRaises(ApplyError):
            refresh(manifest, baseline, receipts)
        self.assertEqual(manifest, before)

    def test_publication_plus_unapproved_transport_change_is_rejected(self):
        baseline = self.baseline()
        receipts = self.publication()
        self.change_stream("network", "grpc")
        with self.assertRaisesRegex(ValueError, "receipt|измен|сним"):
            self.verify(baseline, receipts)

    def test_sql_receipt_never_authorizes_naive_source_drift_or_manifest_replacement(self):
        from lucx_post_configurator.engine import ApplyError, Engine
        from lucx_post_configurator.questionnaire import _inbound_routing_metadata
        path = "/usr/local/x-ui/bin/tunnel/naive-test.caddyfile"
        self.fs.atomic_write_text(path, "synthetic source before\n")
        self.audit.naive_caddyfile = {"found": True, "path": path,
            "files": [{"found": True, "path": path, "sha256": self.fs.sha256(path)}]}
        baseline = self.baseline()
        manifest = {"lucx": {"db_path": "/etc/x-ui/x-ui.db"}, "decoys": {},
                    "protocols": [{"inbound_id": 1, **_inbound_routing_metadata(self.audit.inbounds[0])}]}
        before = copy.deepcopy(manifest)
        receipts = synchronize_lucx_publication(self.fs, "/etc/x-ui/x-ui.db",
            panel_domain="new-panel.example.test", subscription_domain=None)
        self.fs.atomic_write_text(path, "independent source change\n")
        fresh = audit_system(self.root)
        fresh.naive_caddyfile = copy.deepcopy(self.audit.naive_caddyfile)
        fresh.naive_caddyfile["files"][0]["sha256"] = self.fs.sha256(path)
        engine = Engine(self.root)
        with patch.object(engine, "audit", return_value=fresh), self.assertRaisesRegex(ApplyError, "Naive"):
            engine._refresh_authorized_routing(manifest, baseline, receipts)
        self.assertEqual(manifest, before)
        self.assertEqual(self.fs.read_text(path), "independent source change\n")

    def test_sql_receipt_for_naive_authorizes_naive_caddyfile_update(self):
        from lucx_post_configurator.engine import Engine
        from lucx_post_configurator.questionnaire import _inbound_routing_metadata
        path = "/usr/local/x-ui/bin/tunnel/naive-test.caddyfile"
        self.fs.atomic_write_text(path, "synthetic naive source before\n")
        self.audit.naive_caddyfile = {
            "found": True,
            "path": path,
            "files": [{"found": True, "path": path, "sha256": self.fs.sha256(path), "kind": "file", "mode": 0o600, "uid": 0, "gid": 0}],
        }
        baseline = self.baseline()
        manifest = {
            "lucx": {
                "db_path": "/etc/x-ui/x-ui.db",
                "settings_management": {"sync_naive_endpoint": True},
            },
            "decoys": {},
            "protocols": [
                {
                    "inbound_id": 1,
                    "protocol": "naive",
                    "sync_naive_endpoint": True,
                    **_inbound_routing_metadata(self.audit.inbounds[0]),
                }
            ],
        }
        receipts = self.publication()
        self.fs.atomic_write_text(path, "synthetic naive source regenerated after x-ui restart\n")
        fresh = audit_system(self.root)
        fresh.naive_caddyfile = copy.deepcopy(self.audit.naive_caddyfile)
        fresh.naive_caddyfile["files"][0]["sha256"] = self.fs.sha256(path)
        engine = Engine(self.root)
        with patch.object(engine, "audit", return_value=fresh):
            updated_audit = engine._refresh_authorized_routing(manifest, baseline, receipts)
        self.assertIsNotNone(updated_audit)
        self.assertEqual(baseline.naive_integrity["sha256"], self.fs.sha256(path))


    def test_apply_path_change_rebuilds_current_cache_after_real_sql_receipt(self):
        from lucx_post_configurator.engine import Engine
        from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
        from lucx_post_configurator.renderers import GeneratedFile, render_haproxy
        from lucx_post_configurator.routing_profiles import inbound_routing_metadata
        from lucx_post_configurator.runner import Runner
        from test_transport_routing_regressions import topology
        actual = self.audit.inbounds[0]
        manifest = topology("xhttp", inbound_id=1, domain="old.example.test", internal_port=actual.port,
            **{key: value for key, value in inbound_routing_metadata(actual).items() if key != "transport"})
        manifest["protocols"][0]["sni_names"] = list(actual.server_names)
        manifest["lucx"]["panel"].update(domain=self.audit.settings["webDomain"], path_prefix=self.audit.settings["webBasePath"])
        manifest["lucx"]["subscription"]["domain"] = self.audit.settings["subDomain"]
        manifest["lucx"]["inbound_changes"] = [{"inbound_id": 1, "field": "transport_path", "value": "/new"}]
        manifest["lucx"]["settings_management"] = {"allow_inbound_changes": True}
        manifest["decoys"]["sites"][0] = {"domain": "old.example.test", "root": "/var/www/lucx-decoys/old.example.test"}
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest, self.audit)
        manifest["components"] = {key: False for key in manifest["components"]}
        manifest["components"].update(haproxy=True, nginx=True, extended_tls_split=True)
        manifest["dns"]["enabled"] = False
        engine = Engine(self.root, runner=Runner(dry_run=True))
        target = "/etc/haproxy/haproxy.cfg"
        staged_configs = []
        def render(current, **kwargs):
            return {target: GeneratedFile(render_haproxy(current).encode(), component="haproxy")}
        def validate(fs, generated, staged, *_):
            staged_configs.append(staged[target].read_text())
            return []
        with ExitStack() as stack:
            stack.enter_context(patch.object(TargetFS, "is_live", new_callable=PropertyMock, return_value=True))
            stack.enter_context(patch.object(engine, "_activate"))
            stack.enter_context(patch("lucx_post_configurator.engine._managed_decoy_directories", return_value={}))
            stack.enter_context(patch.object(engine, "_register_acme_hook", side_effect=lambda m, complete=None: (complete() if complete else None) or []))
            for name in ("validate_public_bind_conflicts", "validate_certificate", "validate_lucx_tls_coverage", "validate_live_configuration"):
                stack.enter_context(patch("lucx_post_configurator.engine." + name, return_value=[]))
            stack.enter_context(patch("lucx_post_configurator.engine.render_files", side_effect=render))
            stack.enter_context(patch("lucx_post_configurator.engine.validate_generated", side_effect=validate))
            report = engine._apply_locked(manifest)
        self.assertEqual(report["status"], "complete")
        self.assertIn("/new", staged_configs[0])
        self.assertEqual(self.fs.read_text(target), staged_configs[0])
        refreshed = audit_system(self.root).inbounds[0]
        self.assertEqual(refreshed.transport_path, "/new")
        self.assertEqual(refreshed.port, actual.port)
        self.assertEqual(report["manifest"]["protocols"][0]["source_routing_fingerprint"], source_routing_fingerprint(refreshed))
        with closing(sqlite3.connect(self.db)) as connection:
            settings = json.loads(connection.execute("SELECT settings FROM inbounds WHERE id=1").fetchone()[0])
        self.assertEqual(settings["clients"], [{"id": "synthetic-preserved"}])

    def test_exact_path_receipt_rebases_and_extra_stream_field_never_does(self):
        baseline = self.baseline()
        receipts = synchronize_lucx_inbound_changes(self.fs, "/etc/x-ui/x-ui.db", [
            {"inbound_id": 1, "field": "transport_path", "value": "/new"}])
        expected = {item.id: source_routing_fingerprint(item) for item in audit_system(self.root).inbounds}
        self.assertEqual(self.verify(baseline, receipts), expected)
        self.change_stream("finalmask", {"tcp": [{"type": "synthetic-mask"}]})
        with self.assertRaises(ValueError):
            self.verify(baseline, receipts)

    def test_endpoint_hostname_and_certificate_receipts_preserve_credentials(self):
        baseline = self.baseline()
        receipts = synchronize_lucx_publication(self.fs, "/etc/x-ui/x-ui.db", panel_domain=None,
            subscription_domain=None, endpoint_updates=[{"inbound_id": 1,
                "domain": "new.example.test", "old_domain": "old.example.test"}],
            certificate_paths={"cert_path": "/cert/new.pem", "key_path": "/cert/new.key"})
        expected = {item.id: source_routing_fingerprint(item) for item in audit_system(self.root).inbounds}
        self.assertEqual(self.verify(baseline, receipts), expected)
        with closing(sqlite3.connect(self.db)) as connection:
            settings = json.loads(connection.execute("SELECT settings FROM inbounds WHERE id=1").fetchone()[0])
            settings["clients"][0]["id"] = "unexpected-client-change"
            connection.execute("UPDATE inbounds SET settings=? WHERE id=1", (json.dumps(settings),))
            connection.commit()
        with self.assertRaises(ValueError):
            self.verify(baseline, receipts)

    def test_baseline_refuses_drift_from_pre_audit(self):
        self.change_stream("network", "grpc")
        with self.assertRaises(ValueError):
            self.baseline()

    def test_baseline_refuses_credentials_drift_since_pre_audit_without_exposing_them(self):
        with closing(sqlite3.connect(self.db)) as connection:
            settings = json.loads(connection.execute("SELECT settings FROM inbounds WHERE id=1").fetchone()[0])
            settings["clients"][0]["id"] = "changed-before-baseline"
            connection.execute("UPDATE inbounds SET settings=? WHERE id=1", (json.dumps(settings),))
            connection.commit()
        with self.assertRaises(ValueError) as caught:
            self.baseline()
        self.assertNotIn("changed-before-baseline", str(caught.exception))
        refreshed = audit_system(self.root)
        self.assertNotIn("changed-before-baseline", repr(refreshed.inbounds[0].transport_details))

    def test_receipt_cannot_authorize_an_arbitrary_complete_stream_replacement(self):
        baseline = self.baseline()
        with closing(sqlite3.connect(self.db)) as connection:
            old = connection.execute("SELECT stream_settings FROM inbounds WHERE id=1").fetchone()[0]
        stream = json.loads(old)
        stream["network"] = "grpc"
        self.change_stream("network", "grpc")
        receipt = {"kind": "inbound_transport_path", "inbound_id": 1,
                   "old_value": old, "new_value": json.dumps(stream)}
        with self.assertRaises(ValueError):
            self.verify(baseline, [receipt])

    def test_baseline_repr_contains_no_raw_credentials_or_transport_json(self):
        baseline = self.baseline()
        self.assertNotIn("synthetic-preserved", repr(baseline))
        self.assertNotIn("xhttpSettings", repr(baseline))

    def test_unknown_or_malformed_receipt_never_leaks_values_in_errors(self):
        baseline = self.baseline()
        for receipt in ({"kind": "future", "inbound_id": 1},
                        {"kind": "inbound_share_addr", "inbound_id": "synthetic-secret-value"}):
            with self.subTest(kind=receipt["kind"]):
                with self.assertRaises(ValueError) as caught:
                    self.verify(baseline, [receipt])
                self.assertNotIn("synthetic-secret-value", str(caught.exception))

    def test_only_registered_traffic_counters_can_change_without_receipts(self):
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("ALTER TABLE inbounds ADD COLUMN up INTEGER DEFAULT 0")
            connection.commit()
        self.audit = audit_system(self.root)
        baseline = self.baseline()
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("UPDATE inbounds SET up=42 WHERE id=1")
            connection.commit()
        self.assertEqual(self.verify(baseline, []), baseline.source_fingerprints)
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("UPDATE inbounds SET port=29999 WHERE id=1")
            connection.commit()
        with self.assertRaises(ValueError):
            self.verify(baseline, [])

    def test_disabled_host_changes_are_not_hidden_by_enabled_endpoint_audit(self):
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("INSERT INTO hosts VALUES (12,1,1,1,'disabled.example.test',8443,0)")
            connection.commit()
        self.audit = audit_system(self.root)
        baseline = self.baseline()
        receipts = self.publication()
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("UPDATE hosts SET address='changed.example.test' WHERE id=12")
            connection.commit()
        with self.assertRaises(ValueError):
            self.verify(baseline, receipts)

    def test_ordered_publication_and_path_receipts_can_be_verified_together(self):
        baseline = self.baseline()
        receipts = self.publication()
        receipts.extend(synchronize_lucx_inbound_changes(self.fs, "/etc/x-ui/x-ui.db", [
            {"inbound_id": 1, "field": "transport_path", "value": "/new"}]))
        expected = {item.id: source_routing_fingerprint(item) for item in audit_system(self.root).inbounds}
        self.assertEqual(self.verify(baseline, receipts), expected)

    def test_forged_endpoint_receipt_cannot_authorize_client_changes(self):
        baseline = self.baseline()
        with closing(sqlite3.connect(self.db)) as connection:
            settings = json.loads(connection.execute("SELECT settings FROM inbounds WHERE id=1").fetchone()[0])
            settings["clients"][0]["id"] = "unexpected-client-change"
            connection.execute("UPDATE inbounds SET settings=? WHERE id=1", (json.dumps(settings),))
            connection.commit()
        receipts = [{"kind": "inbound_endpoint", "inbound_id": 1, "protocol": "vless", "rewrites": [
            {"column": "settings", "fields": [{"path": ["clients", 0, "id"],
                "old": "synthetic-preserved", "new": "unexpected-client-change", "existed": True}]}]}]
        with self.assertRaises(ValueError):
            self.verify(baseline, receipts)
