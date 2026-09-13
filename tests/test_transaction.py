from __future__ import annotations

import tempfile
import unittest
import os
import json
from contextlib import closing
import sqlite3
from pathlib import Path
from unittest import mock

from lucx_post_configurator.renderers import GeneratedFile
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import (
    backup_lucx_database,
    commit_files,
    create_backup,
    managed_target_digest,
    rollback_lucx_publication,
    synchronize_lucx_inbound_changes,
    restore_backup,
    synchronize_lucx_publication,
    stage_files,
)

from helpers import make_target


def create_publication_host_table(connection: sqlite3.Connection) -> None:
    connection.execute("""CREATE TABLE hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT, inbound_id INTEGER NOT NULL,
        sort_order INTEGER DEFAULT 0, remark TEXT, server_description TEXT,
        is_disabled numeric DEFAULT 0, is_hidden numeric DEFAULT 0, tags TEXT,
        address TEXT, port INTEGER DEFAULT 0, security TEXT DEFAULT 'same', sni TEXT,
        host_header TEXT, path TEXT, alpn TEXT, fingerprint TEXT,
        override_sni_from_address numeric, keep_sni_blank numeric,
        pinned_peer_cert_sha256 TEXT, verify_peer_cert_by_name TEXT, allow_insecure numeric,
        ech_config_list TEXT, mux_params TEXT, sockopt_params TEXT, final_mask TEXT,
        vless_route TEXT, exclude_from_sub_types TEXT, mihomo_ip_version TEXT,
        mihomo_x25519 numeric, shuffle_host numeric, node_guids TEXT,
        created_at INTEGER, updated_at INTEGER
    )""")


class HostCreationTests(unittest.TestCase):
    def test_host_insert_trigger_cannot_authorize_unrequested_overrides(self) -> None:
        with closing(sqlite3.connect(self.db)) as connection, connection:
            before = connection.execute("SELECT share_addr FROM inbounds WHERE id=1").fetchone()
            connection.execute("CREATE TRIGGER unexpected_host_override AFTER INSERT ON hosts BEGIN UPDATE hosts SET override_sni_from_address=1, allow_insecure=1 WHERE id=NEW.id; END")
        with self.assertRaises(RuntimeError):
            self.publish()
        self.assertEqual(self.rows(), [])
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertEqual(connection.execute("SELECT share_addr FROM inbounds WHERE id=1").fetchone(), before)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.db = make_target(self.root)
        self.fs = TargetFS(self.root)
        with closing(sqlite3.connect(self.db)) as connection, connection:
            create_publication_host_table(connection)
        self.publication = {"inbound_id": 1, "domain": "vpn.example.test", "public_port": 443}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def publish(self) -> list[dict]:
        return synchronize_lucx_publication(
            self.fs, "/etc/x-ui/x-ui.db", panel_domain=None, subscription_domain=None,
            public_publications=[self.publication],
        )

    def rows(self) -> list[dict]:
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute("SELECT * FROM hosts ORDER BY id")]

    def test_zero_hosts_creates_explicit_endpoint_preserving_inbound_settings(self) -> None:
        with closing(sqlite3.connect(self.db)) as connection, connection:
            before = connection.execute("SELECT port, settings, stream_settings FROM inbounds WHERE id=1").fetchone()
        changes = self.publish()
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["inbound_id"], row["address"], row["port"], row["is_disabled"]),
                         (1, "vpn.example.test", 443, 0))
        self.assertEqual(row["security"], "same")
        for field in ("sni", "host_header", "path", "fingerprint", "vless_route"):
            self.assertEqual(row[field], "", field)
        for field in ("override_sni_from_address", "keep_sni_blank", "allow_insecure"):
            self.assertEqual(row[field], 0, field)
        self.assertEqual(row["exclude_from_sub_types"], "[]")
        self.assertEqual([c for c in changes if c["kind"] == "inbound_host_created"], [{
            "kind": "inbound_host_created", "inbound_id": 1, "host_id": row["id"], "new_row": row,
        }])
        with closing(sqlite3.connect(self.db)) as connection, connection:
            after = connection.execute("SELECT port, settings, stream_settings FROM inbounds WHERE id=1").fetchone()
        self.assertEqual(before, after)
        self.assertEqual(self.publish(), [])

    def test_host_publication_keeps_share_addr_bare_for_nonstandard_port(self) -> None:
        self.publication["public_port"] = 8443
        self.publish()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            address = connection.execute("SELECT share_addr FROM inbounds WHERE id=1").fetchone()[0]
        self.assertEqual(address, "vpn.example.test")
        self.assertEqual(self.rows()[0]["port"], 8443)

    def test_created_host_rollback_removes_only_its_exact_row(self) -> None:
        changes = self.publish()
        self.assertEqual(len(self.rows()), 1)
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("INSERT INTO hosts (inbound_id,address,port) VALUES (2,'other.example.test',9443)")
        rollback_lucx_publication(self.fs, "/etc/x-ui/x-ui.db", changes)
        self.assertEqual([(r["inbound_id"], r["address"]) for r in self.rows()], [(2, "other.example.test")])

    def test_created_host_rollback_refuses_metadata_drift_atomically(self) -> None:
        changes = self.publish()
        self.assertEqual(len(self.rows()), 1)
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("UPDATE hosts SET sni='changed.example.test'")
        with self.assertRaisesRegex(RuntimeError, "changed after apply"):
            rollback_lucx_publication(self.fs, "/etc/x-ui/x-ui.db", changes)
        self.assertEqual(len(self.rows()), 1)
        with closing(sqlite3.connect(self.db)) as connection, connection:
            self.assertEqual(connection.execute("SELECT share_addr FROM inbounds WHERE id=1").fetchone()[0],
                             "vpn.example.test")

    def test_created_host_rollback_refuses_missing_row(self) -> None:
        changes = self.publish()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("DELETE FROM hosts")
        with self.assertRaisesRegex(RuntimeError, "changed after apply"):
            rollback_lucx_publication(self.fs, "/etc/x-ui/x-ui.db", changes)

    def test_created_host_rollback_refuses_typed_receipt_mismatch(self) -> None:
        changes = self.publish()
        for change in changes:
            if change["kind"] == "inbound_host_created":
                change["new_row"]["port"] = 443.0
        with self.assertRaisesRegex(RuntimeError, "changed after apply"):
            rollback_lucx_publication(self.fs, "/etc/x-ui/x-ui.db", changes)
        self.assertEqual(len(self.rows()), 1)

    def test_unrecognized_host_column_type_refuses_creation(self) -> None:
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("DROP TABLE hosts")
            create_publication_host_table(connection)
            connection.execute("ALTER TABLE hosts DROP COLUMN allow_insecure")
            connection.execute("ALTER TABLE hosts ADD COLUMN allow_insecure TEXT")
        with self.assertRaisesRegex(RuntimeError, "schema"):
            self.publish()
        self.assertEqual(self.rows(), [])

    def test_disabled_hosts_do_not_get_reenabled_or_shadowed(self) -> None:
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("INSERT INTO hosts (inbound_id,is_disabled,address,port) VALUES (1,1,'disabled.example.test',443)")
        before = self.rows()
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            self.publish()
        self.assertEqual(self.rows(), before)

    def test_missing_hosts_table_refuses_publication_without_schema_changes(self) -> None:
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("DROP TABLE hosts")
        with self.assertRaisesRegex(RuntimeError, "hosts"):
            self.publish()
        with closing(sqlite3.connect(self.db)) as connection, connection:
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='hosts'").fetchone())

    def test_unknown_host_column_or_type_refuses_creation(self) -> None:
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("ALTER TABLE hosts ADD COLUMN future_tls_override TEXT")
        with self.assertRaisesRegex(RuntimeError, "schema"):
            self.publish()
        self.assertEqual(self.rows(), [])

    def test_legacy_external_proxy_refuses_host_creation(self) -> None:
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("UPDATE inbounds SET stream_settings=? WHERE id=1", (
                json.dumps({"network": "tcp", "externalProxy": [{"dest": "legacy.example.test", "port": 443}]}),
            ))
        with self.assertRaisesRegex(RuntimeError, "externalProxy"):
            self.publish()
        self.assertEqual(self.rows(), [])


class TransactionTests(unittest.TestCase):
    def test_manual_rollback_reports_failed_stop_of_new_service(self) -> None:
        from lucx_post_configurator.engine import ApplyError, Engine
        from lucx_post_configurator.models import default_manifest
        from lucx_post_configurator.runner import CommandResult, Runner
        from lucx_post_configurator.transaction import new_run_id, save_state

        class FailedStop(Runner):
            def run(self, args, **kwargs):
                return CommandResult(list(args), 1 if "disable" in args else 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_target(root)
            engine = Engine(root, runner=FailedStop(dry_run=True))
            manifest = default_manifest()
            manifest["components"] = {name: False for name in manifest["components"]}
            manifest["dns"]["enabled"] = False
            run_id = new_run_id()
            create_backup(engine.fs, {}, run_id)
            save_state(engine.fs, {"run_id": run_id, "manifest": manifest,
                "installed_hashes": {}, "installed_packages": ["haproxy"]})
            with self.assertRaisesRegex(ApplyError, "stop/disable"):
                engine.rollback()

    def test_rollback_rejects_failed_stop_without_confirmed_absent_inactive_unit(self) -> None:
        from lucx_post_configurator.engine import Engine
        from lucx_post_configurator.runner import CommandResult, Runner
        from lucx_post_configurator.validation import rollback_health_status

        for evidence in ("", "LoadState=not-found\nActiveState=active\nMainPID=123\n",
                         "LoadState=loaded\nActiveState=inactive\nMainPID=0\n"):
            with self.subTest(evidence=evidence), tempfile.TemporaryDirectory() as directory:
                class FailedStop(Runner):
                    def run(self, args, **kwargs):
                        return CommandResult(list(args), 1 if "disable" in args else 0,
                            evidence if "show" in args else "", "")

                engine = Engine(directory, runner=FailedStop())
                errors = engine._reactivate_after_restore(
                    {"/etc/haproxy/haproxy.cfg": GeneratedFile(b"", component="haproxy")},
                    "resolvconf", ["haproxy"]
                )
                self.assertTrue(errors)
                self.assertNotEqual(rollback_health_status(errors, [], []), "complete")

    def test_rollback_allows_failed_disable_only_for_confirmed_absent_inactive_unit(self) -> None:
        from lucx_post_configurator.engine import Engine
        from lucx_post_configurator.runner import CommandResult, Runner

        class AbsentUnit(Runner):
            def run(self, args, **kwargs):
                return CommandResult(list(args), 1 if "disable" in args else 0,
                    "LoadState=not-found\nActiveState=inactive\nMainPID=0\n" if "show" in args else "", "")

        with tempfile.TemporaryDirectory() as directory:
            errors = Engine(directory, runner=AbsentUnit())._reactivate_after_restore({}, "resolvconf", [])
        self.assertEqual(errors, [])

    def test_manual_rollback_checks_protected_identity_after_restore(self) -> None:
        from lucx_post_configurator.engine import ApplyError, Engine
        from lucx_post_configurator.models import default_manifest
        from lucx_post_configurator.runner import Runner
        from lucx_post_configurator.transaction import new_run_id, save_state

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = make_target(root)
            engine = Engine(root, runner=Runner(dry_run=True))
            manifest = default_manifest()
            manifest["components"] = {name: False for name in manifest["components"]}
            manifest["dns"]["enabled"] = False
            manifest["lucx"]["db_path"] = "/etc/x-ui/x-ui.db"
            run_id = new_run_id()
            create_backup(engine.fs, {}, run_id)
            save_state(engine.fs, {"run_id": run_id, "manifest": manifest, "installed_hashes": {}})
            actual_restore = restore_backup

            def damaged_restore(fs, backup):
                actual_restore(fs, backup)
                with sqlite3.connect(database) as connection:
                    connection.execute("UPDATE inbounds SET port=59999 WHERE id=1")
                connection.close()

            with mock.patch("lucx_post_configurator.transaction.restore_backup", side_effect=damaged_restore):
                with self.assertRaisesRegex(ApplyError, "integrity"):
                    engine.rollback()

    def test_restore_reports_failed_external_service_restart(self) -> None:
        from lucx_post_configurator.engine import Engine
        from lucx_post_configurator.runner import CommandError, CommandResult, Runner

        class FailedRestart(Runner):
            def run(self, args, *, check=True, **kwargs):
                result = CommandResult(list(args), 1 if "reload-or-restart" in args else 0, "", "")
                if check and result.returncode:
                    raise CommandError(result)
                return result

        with tempfile.TemporaryDirectory() as directory:
            engine = Engine(directory, runner=FailedRestart())
            engine.fs.atomic_write_text("/etc/haproxy/haproxy.cfg", "restored\n")
            errors = engine._reactivate_after_restore(
                {"/etc/haproxy/haproxy.cfg": GeneratedFile(b"", component="haproxy")}, "resolvconf", []
            )
        self.assertTrue(errors, "Ошибка возврата внешнего listener не должна исчезать")

    def test_rollback_never_completes_with_service_integrity_or_health_errors(self) -> None:
        from lucx_post_configurator.validation import rollback_health_status

        self.assertEqual(rollback_health_status([], [], []), "complete")
        self.assertNotEqual(rollback_health_status(["service"], [], []), "complete")
        self.assertNotEqual(rollback_health_status([], ["identity changed"], []), "complete")
        self.assertNotEqual(rollback_health_status([], [], ["old site missing"]), "complete")

    def test_state_does_not_persist_backend_passwords(self) -> None:
        from lucx_post_configurator.transaction import load_state, save_state

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "var/lib/lucx-post-configurator").mkdir(parents=True)
            fs = TargetFS(root)
            state = {
                "manifest": {
                    "trusttunnel_backend": {
                        "credentials": [{"username": "alice", "password": "secret"}],
                    }
                }
            }
            save_state(fs, state)
            saved = (root / "var/lib/lucx-post-configurator/state.json").read_text(encoding="utf-8")
            self.assertNotIn("secret", saved)
            self.assertIn('"credentials": []', saved)
            self.assertIn('"credentials_file": "/etc/x-tuna/trusttunnel/credentials.toml"', saved)
    def test_xhttp_path_change_preserves_clients_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = make_target(root)
            connection = sqlite3.connect(db)
            original_settings = connection.execute(
                "SELECT settings FROM inbounds WHERE id = 1"
            ).fetchone()[0]
            original_stream = '{"network":"xhttp","security":"tls","xhttpSettings":{"path":"/","mode":"auto"},"tlsSettings":{"serverName":"example.com"}}'
            connection.execute(
                "UPDATE inbounds SET protocol = 'vless', stream_settings = ? WHERE id = 1",
                (original_stream,),
            )
            connection.commit()
            connection.close()
            fs = TargetFS(root)
            changes = synchronize_lucx_inbound_changes(
                fs,
                "/etc/x-ui/x-ui.db",
                [{"inbound_id": 1, "field": "transport_path", "value": "/xhttp-1"}],
            )
            connection = sqlite3.connect(db)
            changed_stream, changed_settings = connection.execute(
                "SELECT stream_settings, settings FROM inbounds WHERE id = 1"
            ).fetchone()
            connection.close()
            self.assertEqual(changed_settings, original_settings)
            self.assertEqual(json.loads(changed_stream)["xhttpSettings"]["path"], "/xhttp-1")
            self.assertEqual(json.loads(changed_stream)["tlsSettings"]["serverName"], "example.com")
            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = sqlite3.connect(db)
            restored = connection.execute(
                "SELECT stream_settings FROM inbounds WHERE id = 1"
            ).fetchone()[0]
            connection.close()
            self.assertEqual(restored, original_stream)

    def test_inbound_and_publication_changes_can_share_one_rollback_list(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = make_target(root)
            connection = sqlite3.connect(db)
            create_publication_host_table(connection)
            connection.execute(
                "UPDATE inbounds SET protocol = 'vless', stream_settings = ? WHERE id = 1",
                ('{"xhttpSettings":{"path":"/"}}',),
            )
            connection.commit()
            connection.close()
            fs = TargetFS(root)
            changes = synchronize_lucx_inbound_changes(
                fs,
                "/etc/x-ui/x-ui.db",
                [{"inbound_id": 1, "field": "transport_path", "value": "/xhttp-1"}],
            )
            changes.extend(
                synchronize_lucx_publication(
                    fs,
                    "/etc/x-ui/x-ui.db",
                    panel_domain="panel.example.com",
                    subscription_domain="sub.example.com",
                    public_publications=[
                        {"inbound_id": 1, "domain": "new.example.com", "public_port": 443}
                    ],
                )
            )
            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = sqlite3.connect(db)
            try:
                stream, share_addr = connection.execute(
                    "SELECT stream_settings, share_addr FROM inbounds WHERE id = 1"
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual(stream, '{"xhttpSettings":{"path":"/"}}')
            self.assertEqual(share_addr, "api.example.com")

    def test_public_endpoint_sync_updates_all_selected_inbounds_and_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = make_target(root)
            connection = sqlite3.connect(db)
            connection.execute(
                "CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER)"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (11, 1, 0, 0, 'api.example.com', 443)"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (12, 2, 0, 0, 'cloud.example.com', 443)"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (13, 2, 1, 1, 'disabled.example.com', 8443)"
            )
            connection.commit()
            connection.close()
            fs = TargetFS(root)
            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain="panel.example.com",
                subscription_domain="sub.example.com",
                public_publications=[
                    {"inbound_id": 1, "domain": "one.new.example", "public_port": 443},
                    {"inbound_id": 2, "domain": "two.new.example", "public_port": 443},
                ],
            )
            connection = sqlite3.connect(db)
            try:
                values = dict(connection.execute("SELECT id, share_addr FROM inbounds WHERE id IN (1,2)"))
                hosts = list(connection.execute("SELECT id, address, port FROM hosts ORDER BY id"))
                ports = dict(connection.execute("SELECT id, port FROM inbounds WHERE id IN (1,2)"))
            finally:
                connection.close()
            self.assertEqual(values, {1: "one.new.example", 2: "two.new.example"})
            self.assertEqual(hosts, [(11, "one.new.example", 443), (12, "two.new.example", 443), (13, "disabled.example.com", 8443)])
            self.assertEqual(ports, {1: 54703, 2: 443})
            self.assertEqual(
                {change["kind"] for change in changes},
                {"inbound_share_addr", "inbound_host_endpoint"},
            )

    def test_certificate_path_sync_is_targeted_and_rollback_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = make_target(root)
            fs = TargetFS(root)
            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain="panel.example.com",
                subscription_domain="sub.example.com",
                certificate_paths={
                    "cert_path": "/etc/letsencrypt/live/example.com/fullchain.pem",
                    "key_path": "/etc/letsencrypt/live/example.com/privkey.pem",
                },
            )
            connection = sqlite3.connect(db)
            try:
                values = dict(connection.execute("SELECT key, value FROM settings"))
            finally:
                connection.close()
            self.assertEqual(values["webCertFile"], "/etc/letsencrypt/live/example.com/fullchain.pem")
            self.assertEqual(values["subKeyFile"], "/etc/letsencrypt/live/example.com/privkey.pem")
            self.assertEqual(
                {item["key"] for item in changes},
                {"webCertFile", "webKeyFile", "subCertFile", "subKeyFile"},
            )
            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = sqlite3.connect(db)
            try:
                restored = dict(connection.execute("SELECT key, value FROM settings"))
            finally:
                connection.close()
            self.assertEqual(restored["webCertFile"], "/cert/fullchain.pem")
            self.assertEqual(restored["subKeyFile"], "/cert/privkey.pem")

    def test_backup_commit_and_restore_existing_and_new_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            fs.atomic_write_text("/etc/existing.conf", "old\n", mode=0o600)
            generated = {
                "/etc/existing.conf": GeneratedFile(b"new\n", 0o644),
                "/etc/new.conf": GeneratedFile(b"created\n", 0o640),
            }
            backup = create_backup(fs, generated, "run-test")
            commit_files(fs, generated)
            self.assertEqual(fs.read_text("/etc/existing.conf"), "new\n")
            self.assertTrue(fs.exists("/etc/new.conf"))
            restore_backup(fs, backup)
            self.assertEqual(fs.read_text("/etc/existing.conf"), "old\n")
            self.assertFalse(fs.exists("/etc/new.conf"))

    def test_partial_commit_rollback_preserves_unwritten_and_later_external_edits(self):
        from lucx_post_configurator.transaction import commit_managed_transition
        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            generated = {f"/etc/{name}.conf": GeneratedFile(b"new\n") for name in ("first", "second", "last")}
            for target in generated:
                fs.atomic_write_text(target, "old\n")
            backup = create_backup(fs, generated, "partial-commit")
            journal = {}
            actual_write = fs.atomic_write
            def failing_write(target, *args, **kwargs):
                if target == "/etc/last.conf":
                    actual_write("/etc/second.conf", b"external after commit\n")
                    actual_write(target, b"external before commit\n")
                    raise OSError("synthetic failure before last replacement")
                return actual_write(target, *args, **kwargs)
            with mock.patch.object(fs, "atomic_write", side_effect=failing_write):
                with self.assertRaises(OSError):
                    commit_managed_transition(fs, generated, [], {}, mutation_journal=journal)
            conflicts = restore_backup(fs, backup, expected_current=journal)
            self.assertEqual(fs.read_text("/etc/first.conf"), "old\n")
            self.assertEqual(fs.read_text("/etc/second.conf"), "external after commit\n")
            self.assertEqual(fs.read_text("/etc/last.conf"), "external before commit\n")
            self.assertEqual(conflicts, ["/etc/second.conf"])

    def test_commit_rejects_managed_file_drift_since_backup_before_any_write(self):
        from lucx_post_configurator.transaction import commit_managed_transition
        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            generated = {"/etc/first.conf": GeneratedFile(b"new\n"), "/etc/last.conf": GeneratedFile(b"new\n")}
            for target in generated:
                fs.atomic_write_text(target, "old\n")
            backup = create_backup(fs, generated, "pre-commit-drift")
            fs.atomic_write_text("/etc/last.conf", "external\n")
            journal = {}
            with self.assertRaisesRegex(RuntimeError, "измен"):
                commit_managed_transition(fs, generated, [], {}, baseline=backup, mutation_journal=journal)
            self.assertEqual(journal, {})
            self.assertEqual(fs.read_text("/etc/first.conf"), "old\n")
            self.assertEqual(fs.read_text("/etc/last.conf"), "external\n")

    def test_journal_does_not_adopt_external_bytes_written_after_our_replace(self):
        from lucx_post_configurator.transaction import commit_managed_transition
        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            target = "/etc/raced.conf"
            fs.atomic_write_text(target, "old\n")
            generated = {target: GeneratedFile(b"ours\n")}
            backup = create_backup(fs, generated, "raced-replace")
            journal = {}
            actual_write = fs.atomic_write
            def racing_write(*args, **kwargs):
                receipt = actual_write(*args, **kwargs)
                actual_write(target, b"external replacement\n")
                return receipt
            with mock.patch.object(fs, "atomic_write", side_effect=racing_write):
                with self.assertRaisesRegex(RuntimeError, "измен"):
                    commit_managed_transition(fs, generated, [], {}, mutation_journal=journal)
            self.assertEqual(restore_backup(fs, backup, expected_current=journal), [target])
            self.assertEqual(fs.read_text(target), "external replacement\n")

    def test_directory_creation_is_journalled_even_when_chmod_fails(self):
        from lucx_post_configurator.transaction import commit_managed_transition
        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            directories = {"/var/www/new.example.test": 0o755}
            backup = create_backup(fs, {}, "mkdir-failure", directory_targets=directories)
            journal = {}
            with mock.patch("lucx_post_configurator.transaction.os.chmod", side_effect=OSError("synthetic chmod failure")):
                with self.assertRaises(OSError):
                    commit_managed_transition(fs, {}, [], {}, directory_targets=directories, mutation_journal=journal)
            self.assertEqual(restore_backup(fs, backup, expected_current=journal), [])
            self.assertFalse(fs.path("/var/www/new.example.test").exists())
            self.assertFalse(fs.path("/var/www").exists())

    def test_managed_decoy_directory_modes_are_committed_and_rollback_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "var/www/lucx-decoys/existing.example.net").mkdir(parents=True)
            existing = root / "var/www/lucx-decoys/existing.example.net"
            os.chmod(root / "var/www/lucx-decoys", 0o700)
            os.chmod(existing, 0o700)
            fs = TargetFS(root)
            generated = {
                "/var/www/lucx-decoys/existing.example.net/index.html": GeneratedFile(
                    b"existing\n"
                ),
                "/var/www/lucx-decoys/new.example.net/index.html": GeneratedFile(b"new\n"),
            }
            directories = {
                "/var/www/lucx-decoys": 0o755,
                "/var/www/lucx-decoys/existing.example.net": 0o755,
                "/var/www/lucx-decoys/new.example.net": 0o755,
            }

            backup = create_backup(
                fs,
                generated,
                "directory-run",
                directory_targets=directories,
            )
            with mock.patch(
                "lucx_post_configurator.transaction.os.chmod", wraps=os.chmod
            ) as chmod:
                commit_files(fs, generated, directory_targets=directories)
                for target in directories:
                    chmod.assert_any_call(fs.path(target), 0o755)

                if os.name != "nt":
                    self.assertEqual(
                        (root / "var/www/lucx-decoys").stat().st_mode & 0o777,
                        0o755,
                    )
                    self.assertEqual(existing.stat().st_mode & 0o777, 0o755)

                restore_backup(fs, backup)

            if os.name != "nt":
                self.assertEqual((root / "var/www/lucx-decoys").stat().st_mode & 0o777, 0o700)
                self.assertEqual(existing.stat().st_mode & 0o777, 0o700)
            self.assertFalse((root / "var/www/lucx-decoys/new.example.net").exists())

    def test_backup_and_restore_preserves_a_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            available = root / "etc/nginx/sites-available"
            enabled = root / "etc/nginx/sites-enabled"
            available.mkdir(parents=True)
            enabled.mkdir(parents=True)
            (available / "default").write_text("stock\n", encoding="utf-8")
            link = enabled / "default"
            try:
                os.symlink("../sites-available/default", link)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            fs = TargetFS(root)
            generated = {"/etc/nginx/sites-enabled/default": GeneratedFile(b"disabled\n")}
            backup = create_backup(fs, generated, "symlink-run")
            commit_files(fs, generated)
            self.assertFalse(link.is_symlink())
            restore_backup(fs, backup)
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), "../sites-available/default")

    def test_managed_tls_symlinks_are_staged_committed_and_rollback_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "cert").mkdir(parents=True)
            (root / "cert/fullchain.pem").write_text("certificate-one\n", encoding="utf-8")
            (root / "cert/privkey.pem").write_text("key-one\n", encoding="utf-8")
            fs = TargetFS(root)
            generated = {
                "/etc/lucx-post-configurator/tls/certificate.pem": GeneratedFile(
                    symlink_target="/cert/fullchain.pem", mode=0o640, component="haproxy"
                ),
                "/etc/lucx-post-configurator/tls/certificate.pem.key": GeneratedFile(
                    symlink_target="/cert/privkey.pem", mode=0o640, component="haproxy"
                ),
            }
            backup = create_backup(fs, generated, "tls-links")
            try:
                staged = stage_files(fs, generated, "tls-links-stage")
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            self.assertTrue(staged["/etc/lucx-post-configurator/tls/certificate.pem"].is_symlink())

            installed = commit_files(fs, generated)
            cert_link = fs.path("/etc/lucx-post-configurator/tls/certificate.pem")
            key_link = fs.path("/etc/lucx-post-configurator/tls/certificate.pem.key")
            self.assertTrue(cert_link.is_symlink())
            self.assertTrue(key_link.is_symlink())
            self.assertEqual(os.readlink(cert_link), "/cert/fullchain.pem")
            before = installed["/etc/lucx-post-configurator/tls/certificate.pem"]
            (root / "cert/fullchain.pem").write_text("certificate-renewed\n", encoding="utf-8")
            self.assertEqual(
                managed_target_digest(fs, "/etc/lucx-post-configurator/tls/certificate.pem"),
                before,
            )

            restore_backup(fs, backup)
            self.assertFalse(cert_link.exists() or cert_link.is_symlink())
            self.assertFalse(key_link.exists() or key_link.is_symlink())

    def test_consistent_lucx_database_snapshot_is_sensitive_and_manual_restore_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            fs = TargetFS(root)
            backup = create_backup(fs, {}, "db-run")
            record = backup_lucx_database(fs, backup, "/etc/x-ui/x-ui.db")
            snapshot = backup.directory / record["path"]
            self.assertTrue(snapshot.is_file())
            self.assertTrue(record["sensitive"])
            self.assertIn("manual", record["restore_policy"])
            self.assertGreater(record["size"], 0)

    def test_domain_synchronization_touches_only_two_settings_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            fs = TargetFS(root)
            connection = __import__("sqlite3").connect(database)
            create_publication_host_table(connection)
            connection.execute("UPDATE settings SET value = '' WHERE key = 'subDomain'")
            connection.execute(
                "UPDATE inbounds SET protocol = 'naive', share_addr = 'old-naive.example.com' WHERE id = 1"
            )
            before_other = connection.execute(
                "SELECT value FROM settings WHERE key = 'webPort'"
            ).fetchone()[0]
            connection.commit()
            connection.close()

            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain="new-panel.example.com",
                subscription_domain="new-sub.example.com",
                panel_path="/",
                naive_publications=[
                    {"inbound_id": 1, "domain": "naive.example.com", "public_port": 443}
                ],
            )
            self.assertEqual(
                {item.get("key") for item in changes if item["kind"] == "setting"},
                {"webDomain", "subDomain", "webBasePath"},
            )
            connection = __import__("sqlite3").connect(database)
            values = dict(connection.execute("SELECT key, value FROM settings"))
            connection.close()
            self.assertEqual(values["webDomain"], "new-panel.example.com")
            self.assertEqual(values["subDomain"], "new-sub.example.com")
            self.assertEqual(values["webPort"], before_other)
            connection = __import__("sqlite3").connect(database)
            try:
                self.assertEqual(
                    connection.execute("SELECT share_addr FROM inbounds WHERE id=1").fetchone()[0],
                    "naive.example.com",
                )
            finally:
                connection.close()

            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = __import__("sqlite3").connect(database)
            values = dict(connection.execute("SELECT key, value FROM settings"))
            connection.close()
            self.assertEqual(values["webDomain"], "panel.example.com")
            self.assertEqual(values["subDomain"], "")
            connection = __import__("sqlite3").connect(database)
            try:
                self.assertEqual(
                    connection.execute("SELECT share_addr FROM inbounds WHERE id=1").fetchone()[0],
                    "old-naive.example.com",
                )
            finally:
                connection.close()

    def test_subscription_base_url_sync_writes_sub_uris_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            fs = TargetFS(root)
            connection = __import__("sqlite3").connect(database)
            connection.execute("UPDATE settings SET value = '' WHERE key = 'subURI'")
            connection.commit()
            connection.close()

            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain=None,
                subscription_domain=None,
                subscription_base_url="https://sub.example.com/",
            )
            self.assertEqual(
                {item.get("key") for item in changes if item["kind"] == "setting"},
                {"subURI", "subJsonURI", "subClashURI", "subAwgURI"},
            )
            connection = __import__("sqlite3").connect(database)
            values = dict(connection.execute("SELECT key, value FROM settings"))
            connection.close()
            self.assertEqual(values["subURI"], "https://sub.example.com/sub/")
            self.assertEqual(values["subJsonURI"], "https://sub.example.com/json/")
            self.assertEqual(values["subClashURI"], "https://sub.example.com/clash/")
            self.assertEqual(values["subAwgURI"], "https://sub.example.com/awg/")

            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = __import__("sqlite3").connect(database)
            values = dict(connection.execute("SELECT key, value FROM settings"))
            connection.close()
            self.assertNotIn("subURI", values)

    def test_subscription_base_url_requires_absolute_url(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            fs = TargetFS(root)
            for bad in ("sub.example.com", "ftp://sub.example.com/", "https://"):
                with self.assertRaises(RuntimeError):
                    synchronize_lucx_publication(
                        fs,
                        "/etc/x-ui/x-ui.db",
                        panel_domain=None,
                        subscription_domain=None,
                        subscription_base_url=bad,
                    )

    def test_naive_sync_updates_enabled_hosts_and_rolls_them_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            fs = TargetFS(root)
            connection = __import__("sqlite3").connect(database)
            connection.execute(
                "UPDATE inbounds SET protocol = 'naive', share_addr = 'old.example.com:8443' WHERE id = 1"
            )
            connection.execute(
                "CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER, remark TEXT)"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (10,1,0,0,'old.example.com',8443,'keep-me')"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (11,1,1,1,'disabled.example.com',2053,'disabled')"
            )
            connection.commit()
            connection.close()

            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain="panel.example.com",
                subscription_domain="sub.example.com",
                naive_publications=[
                    {"inbound_id": 1, "domain": "naive.example.com", "public_port": 443}
                ],
            )
            self.assertEqual(
                len([item for item in changes if item["kind"] == "inbound_host_endpoint"]),
                1,
            )
            connection = __import__("sqlite3").connect(database)
            try:
                enabled = connection.execute(
                    "SELECT address, port, remark FROM hosts WHERE id = 10"
                ).fetchone()
                disabled = connection.execute(
                    "SELECT address, port FROM hosts WHERE id = 11"
                ).fetchone()
                self.assertEqual(enabled, ("naive.example.com", 443, "keep-me"))
                self.assertEqual(disabled, ("disabled.example.com", 2053))
            finally:
                connection.close()

            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = __import__("sqlite3").connect(database)
            try:
                enabled = connection.execute(
                    "SELECT address, port, remark FROM hosts WHERE id = 10"
                ).fetchone()
                self.assertEqual(enabled, ("old.example.com", 8443, "keep-me"))
            finally:
                connection.close()

    def test_naive_endpoint_sync_writes_three_fields_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            fs = TargetFS(root)
            connection = __import__("sqlite3").connect(database)
            connection.execute(
                "UPDATE inbounds SET protocol = 'naive', settings = ? WHERE id = 1",
                (
                    json.dumps(
                        {
                            "clients": [{"password": "must-not-leak"}],
                            "domain": "old.example.com",
                            "certFile": "/old/fullchain.pem",
                            "keyFile": "/old/privkey.pem",
                            "useAcme": False,
                            "routeThroughXray": True,
                        }
                    ),
                ),
            )
            connection.commit()
            connection.close()

            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain=None,
                subscription_domain=None,
                endpoint_updates=[
                    {
                        "inbound_id": 1,
                        "domain": "naive.new-zone.example",
                        "old_domain": "old.example.com",
                        "cert_path": "/etc/letsencrypt/live/new-zone.example/fullchain.pem",
                        "key_path": "/etc/letsencrypt/live/new-zone.example/privkey.pem",
                    }
                ],
            )
            self.assertEqual(len(changes), 1)
            change = changes[0]
            self.assertEqual(change["kind"], "inbound_endpoint")
            self.assertEqual(change["protocol"], "naive")
            fields = {
                tuple(item["path"]): item
                for rewrite in change["rewrites"] if rewrite["column"] == "settings"
                for item in rewrite["fields"]
            }
            self.assertEqual(fields[("domain",)]["old"], "old.example.com")
            self.assertEqual(fields[("domain",)]["new"], "naive.new-zone.example")
            self.assertEqual(fields[("certFile",)]["old"], "/old/fullchain.pem")
            self.assertEqual(fields[("certFile",)]["new"], "/etc/letsencrypt/live/new-zone.example/fullchain.pem")
            self.assertEqual(fields[("keyFile",)]["old"], "/old/privkey.pem")
            self.assertEqual(fields[("keyFile",)]["new"], "/etc/letsencrypt/live/new-zone.example/privkey.pem")

            connection = __import__("sqlite3").connect(database)
            raw = connection.execute("SELECT settings FROM inbounds WHERE id = 1").fetchone()[0]
            connection.close()
            parsed = json.loads(raw)
            self.assertEqual(parsed["domain"], "naive.new-zone.example")
            self.assertEqual(parsed["certFile"], "/etc/letsencrypt/live/new-zone.example/fullchain.pem")
            self.assertEqual(parsed["keyFile"], "/etc/letsencrypt/live/new-zone.example/privkey.pem")
            # Other Naive settings and secrets must be preserved verbatim.
            self.assertEqual(parsed["useAcme"], False)
            self.assertEqual(parsed["routeThroughXray"], True)
            self.assertEqual(parsed["clients"], [{"password": "must-not-leak"}])

            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = __import__("sqlite3").connect(database)
            raw = connection.execute("SELECT settings FROM inbounds WHERE id = 1").fetchone()[0]
            connection.close()
            parsed = json.loads(raw)
            self.assertEqual(parsed["domain"], "old.example.com")
            self.assertEqual(parsed["certFile"], "/old/fullchain.pem")
            self.assertEqual(parsed["keyFile"], "/old/privkey.pem")
            self.assertEqual(parsed["clients"], [{"password": "must-not-leak"}])

    def test_naive_endpoint_sync_refuses_non_naive_inbound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            fs = TargetFS(root)
            with self.assertRaises(RuntimeError):
                synchronize_lucx_publication(
                    fs,
                    "/etc/x-ui/x-ui.db",
                    panel_domain=None,
                    subscription_domain=None,
                    endpoint_updates=[
                        {
                            "inbound_id": 999,
                            "domain": "naive.new-zone.example",
                            "old_domain": "old.example.com",
                            "cert_path": "/cert/fullchain.pem",
                            "key_path": "/cert/privkey.pem",
                        }
                    ],
                )

    def test_naive_endpoint_sync_is_idempotent_when_fields_already_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            fs = TargetFS(root)
            connection = __import__("sqlite3").connect(database)
            connection.execute(
                "UPDATE inbounds SET protocol = 'naive', settings = ? WHERE id = 1",
                (
                    json.dumps(
                        {
                            "domain": "naive.new-zone.example",
                            "certFile": "/cert/fullchain.pem",
                            "keyFile": "/cert/privkey.pem",
                        }
                    ),
                ),
            )
            connection.commit()
            connection.close()

            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain=None,
                subscription_domain=None,
                endpoint_updates=[
                    {
                        "inbound_id": 1,
                        "domain": "naive.new-zone.example",
                        "old_domain": "old.example.com",
                        "cert_path": "/cert/fullchain.pem",
                        "key_path": "/cert/privkey.pem",
                    }
                ],
            )
            self.assertEqual(changes, [])

    def test_endpoint_sync_updates_trusttunnel_anytls_and_xray_tls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            fs = TargetFS(root)
            connection = __import__("sqlite3").connect(database)
            connection.execute(
                "UPDATE inbounds SET protocol = 'trusttunnel', settings = ?, share_addr = ? WHERE id = 1",
                (
                    json.dumps(
                        {
                            "hostname": "old.example.com",
                            "certFile": "/old/fullchain.pem",
                            "keyFile": "/old/privkey.pem",
                            "clientRandomPrefix": "2e08e767/ffffffff",
                            "clients": [{"password": "secret"}],
                        }
                    ),
                    "old.example.com",
                ),
            )
            connection.execute(
                "UPDATE inbounds SET protocol = 'anytls', settings = ? WHERE id = 2",
                (
                    json.dumps(
                        {
                            "sni": "old.example.com",
                            "certFile": "/old/fullchain.pem",
                            "keyFile": "/old/privkey.pem",
                        }
                    ),
                ),
            )
            connection.execute(
                "UPDATE inbounds SET protocol = 'trojan', stream_settings = ? WHERE id = 3",
                (
                    json.dumps(
                        {
                            "security": "tls",
                            "tlsSettings": {
                                "serverName": "old.example.com",
                                "certificates": [
                                    {
                                        "certificateFile": "/old/fullchain.pem",
                                        "keyFile": "/old/privkey.pem",
                                    }
                                ],
                            },
                        }
                    ),
                ),
            )
            connection.execute(
                "UPDATE inbounds SET protocol = 'vless', stream_settings = ? WHERE id = 4",
                (
                    json.dumps(
                        {
                            "security": "reality",
                            "realitySettings": {"serverNames": ["www.nvidia.com"]},
                        }
                    ),
                ),
            )
            connection.commit()
            connection.close()

            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain=None,
                subscription_domain=None,
                endpoint_updates=[
                    {
                        "inbound_id": 1,
                        "domain": "new.example.com",
                        "old_domain": "old.example.com",
                        "cert_path": "/new/fullchain.pem",
                        "key_path": "/new/privkey.pem",
                    },
                    {
                        "inbound_id": 2,
                        "domain": "new.example.com",
                        "old_domain": "old.example.com",
                        "cert_path": "/new/fullchain.pem",
                        "key_path": "/new/privkey.pem",
                    },
                    {
                        "inbound_id": 3,
                        "domain": "new.example.com",
                        "old_domain": "old.example.com",
                        "cert_path": "/new/fullchain.pem",
                        "key_path": "/new/privkey.pem",
                    },
                    {
                        # Reality inbound: must be ignored entirely.
                        "inbound_id": 4,
                        "domain": "new.example.com",
                        "old_domain": "old.example.com",
                        "cert_path": "/new/fullchain.pem",
                        "key_path": "/new/privkey.pem",
                    },
                ],
            )
            kinds = sorted(change["inbound_id"] for change in changes)
            self.assertEqual(kinds, [1, 2, 3])
            connection = __import__("sqlite3").connect(database)
            rows = {
                row[0]: (row[1], row[2])
                for row in connection.execute(
                    "SELECT id, settings, stream_settings FROM inbounds ORDER BY id"
                )
            }
            connection.close()
            tt = json.loads(rows[1][0])
            self.assertEqual(tt["hostname"], "new.example.com")
            self.assertEqual(tt["certFile"], "/new/fullchain.pem")
            self.assertEqual(tt["keyFile"], "/new/privkey.pem")
            self.assertEqual(tt["clientRandomPrefix"], "2e08e767/ffffffff")
            self.assertEqual(tt["clients"], [{"password": "secret"}])
            anytls = json.loads(rows[2][0])
            self.assertEqual(anytls["sni"], "new.example.com")
            trojan = json.loads(rows[3][1])
            self.assertEqual(trojan["tlsSettings"]["serverName"], "new.example.com")
            self.assertEqual(
                trojan["tlsSettings"]["certificates"][0]["certificateFile"], "/new/fullchain.pem"
            )
            self.assertEqual(trojan["tlsSettings"]["certificates"][0]["keyFile"], "/new/privkey.pem")
            reality = json.loads(rows[4][1])
            self.assertEqual(reality["realitySettings"]["serverNames"], ["www.nvidia.com"])

            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = __import__("sqlite3").connect(database)
            rows = {
                row[0]: (row[1], row[2])
                for row in connection.execute(
                    "SELECT id, settings, stream_settings FROM inbounds ORDER BY id"
                )
            }
            connection.close()
            self.assertEqual(json.loads(rows[1][0])["hostname"], "old.example.com")
            self.assertEqual(json.loads(rows[1][0])["certFile"], "/old/fullchain.pem")
            self.assertEqual(json.loads(rows[2][0])["sni"], "old.example.com")
            trojan = json.loads(rows[3][1])
            self.assertEqual(trojan["tlsSettings"]["serverName"], "old.example.com")
            self.assertEqual(
                trojan["tlsSettings"]["certificates"][0]["certificateFile"], "/old/fullchain.pem"
            )


if __name__ == "__main__":
    unittest.main()
