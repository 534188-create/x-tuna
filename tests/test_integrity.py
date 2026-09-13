from __future__ import annotations

import json
from contextlib import closing
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lucx_post_configurator.integrity import (
    capture_integrity,
    compare_caddy,
    compare_integrity,
    compare_lucx,
)
from lucx_post_configurator.targetfs import TargetFS

from helpers import make_target


class IntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.db = make_target(self.root)
        caddy = self.root / "etc/caddy/Caddyfile"
        caddy.parent.mkdir(parents=True)
        caddy.write_text("naive.example.com { respond ok }\n", encoding="utf-8")
        os.chmod(caddy, 0o640)
        self.fs = TargetFS(self.root)
        self.caddy_info = {"found": True, "path": "/etc/caddy/Caddyfile"}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def capture(self) -> dict:
        return capture_integrity(self.fs, "/etc/x-ui/x-ui.db", self.caddy_info)

    def test_created_host_receipt_allows_only_exact_added_row(self) -> None:
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, address TEXT, port INTEGER, sni TEXT)")
        before = self.capture()["protected_lucx"]
        row = {"id": 11, "inbound_id": 1, "address": "vpn.example.test", "port": 443, "sni": ""}
        changes = [{"kind": "inbound_host_created", "inbound_id": 1, "host_id": 11, "new_row": row}]
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("INSERT INTO hosts VALUES (11,1,'vpn.example.test',443,'')")
        self.assertEqual(compare_lucx(before, self.capture()["protected_lucx"], changes), [])
        for field, value in (("sni", "changed.example.test"), ("inbound_id", 2), ("port", 8443)):
            with self.subTest(field=field):
                with closing(sqlite3.connect(self.db)) as connection, connection:
                    connection.execute(f"UPDATE hosts SET {field}=? WHERE id=11", (value,))
                self.assertTrue(compare_lucx(before, self.capture()["protected_lucx"], changes))
                with closing(sqlite3.connect(self.db)) as connection, connection:
                    connection.execute(f"UPDATE hosts SET {field}=? WHERE id=11", (row[field],))
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("INSERT INTO hosts VALUES (12,1,'extra.example.test',443,'')")
        self.assertIn("host #12 was added", compare_lucx(before, self.capture()["protected_lucx"], changes))

    def test_created_host_receipt_cannot_authorize_inbound_or_existing_host_change(self) -> None:
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, address TEXT, port INTEGER)")
            connection.execute("INSERT INTO hosts VALUES (11,1,'old.example.test',8443)")
        before = self.capture()["protected_lucx"]
        row = {"id": 11, "inbound_id": 1, "address": "vpn.example.test", "port": 443}
        changes = [{"kind": "inbound_host_created", "inbound_id": 1, "host_id": 11, "new_row": row}]
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("UPDATE hosts SET address='vpn.example.test',port=443 WHERE id=11")
            connection.execute("UPDATE inbounds SET port=8443 WHERE id=1")
        errors = compare_lucx(before, self.capture()["protected_lucx"], changes)
        self.assertIn("host #11 port changed", errors)
        self.assertIn("inbound #1 port changed", errors)

    def test_caddy_content_change_is_rejected(self) -> None:
        before = self.capture()["naive_caddyfile"]
        (self.root / "etc/caddy/Caddyfile").write_text("changed\n", encoding="utf-8")
        after = self.capture()["naive_caddyfile"]

        errors = compare_caddy(before, after)

        self.assertIn("Naive Caddyfile content sha256 changed", errors)

    def test_every_discovered_naive_caddyfile_is_hash_guarded(self) -> None:
        second = self.root / "usr/local/x-ui/bin/tunnel/naive-12.caddyfile"
        second.parent.mkdir(parents=True)
        second.write_text("second.example.com {}\n", encoding="utf-8")
        self.caddy_info = {
            "found": True,
            "path": "/etc/caddy/Caddyfile",
            "files": [
                {"found": True, "path": "/etc/caddy/Caddyfile"},
                {"found": True, "path": "/usr/local/x-ui/bin/tunnel/naive-12.caddyfile"},
            ],
        }
        before = self.capture()["naive_caddyfile"]
        second.write_text("changed\n", encoding="utf-8")
        after = self.capture()["naive_caddyfile"]

        errors = compare_caddy(before, after)

        self.assertTrue(
            any(
                "naive-12.caddyfile content sha256 changed" in error
                for error in errors
            ),
            errors,
        )

    def test_unapproved_inbound_port_change_is_rejected(self) -> None:
        before = self.capture()["protected_lucx"]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE inbounds SET port = 443 WHERE id = 5")
            connection.commit()
        finally:
            connection.close()
        after = self.capture()["protected_lucx"]

        errors = compare_lucx(before, after, [])

        self.assertIn("inbound #5 port changed", errors)

    def test_approved_share_address_change_is_the_only_allowed_inbound_difference(self) -> None:
        before = self.capture()["protected_lucx"]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "UPDATE inbounds SET share_addr = ? WHERE id = 5",
                ("new.example.com:443",),
            )
            connection.commit()
        finally:
            connection.close()
        after = self.capture()["protected_lucx"]
        changes = [
            {
                "kind": "inbound_share_addr",
                "inbound_id": 5,
                "old_value": "userapi.example.com",
                "new_value": "new.example.com:443",
            }
        ]

        self.assertEqual(compare_lucx(before, after, changes), [])

    def test_snapshot_contains_hashes_but_no_database_secrets(self) -> None:
        snapshot = self.capture()
        serialized = json.dumps(snapshot, sort_keys=True)

        self.assertNotIn("must-not-leak", serialized)
        self.assertIn("sha256", serialized)

    def test_combined_comparison_reports_caddy_and_lucx_drift(self) -> None:
        before = self.capture()
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE inbounds SET remark = 'changed' WHERE id = 1")
            connection.commit()
        finally:
            connection.close()
        (self.root / "etc/caddy/Caddyfile").write_text("changed\n", encoding="utf-8")
        after = self.capture()

        errors = compare_integrity(before, after, [])

        self.assertIn("inbound #1 remark changed", errors)
        self.assertIn("Naive Caddyfile content sha256 changed", errors)

    def test_standard_https_share_address_is_canonicalized(self) -> None:
        before = self.capture()["protected_lucx"]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "UPDATE inbounds SET share_addr = ? WHERE id = 5",
                ("new.example.com",),
            )
            connection.commit()
        finally:
            connection.close()
        after = self.capture()["protected_lucx"]
        changes = [{
            "kind": "inbound_share_addr",
            "inbound_id": 5,
            "old_value": "userapi.example.com",
            "new_value": "new.example.com:443",
        }]
        self.assertEqual(compare_lucx(before, after, changes), [])

    def test_trusttunnel_http3_to_http2_normalization_is_ignored(self) -> None:
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "UPDATE inbounds SET protocol = 'trusttunnel', settings = ? WHERE id = 1",
                (json.dumps({"upstreamProtocol": "http3", "clients": []}),),
            )
            connection.commit()
        finally:
            connection.close()
        before = self.capture()["protected_lucx"]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "UPDATE inbounds SET settings = ? WHERE id = 1",
                (json.dumps({"upstreamProtocol": "http2", "clients": []}),),
            )
            connection.commit()
        finally:
            connection.close()
        after = self.capture()["protected_lucx"]
        self.assertEqual(compare_lucx(before, after, []), [])

    def test_awg_legacy_false_defaults_are_ignored_for_any_awg_version(self) -> None:
        for version in ("2", "3.0", "3.1", "9.7"):
            with self.subTest(version=version):
                connection = sqlite3.connect(self.db)
                try:
                    connection.execute(
                        "UPDATE inbounds SET protocol = 'awg', settings = ? WHERE id = 1",
                        (json.dumps({"awgVersion": version, "randomTrailers": False, "disableCookies": False}),),
                    )
                    connection.commit()
                finally:
                    connection.close()
                before = self.capture()["protected_lucx"]
                connection = sqlite3.connect(self.db)
                try:
                    connection.execute(
                        "UPDATE inbounds SET settings = ? WHERE id = 1",
                        (json.dumps({"awgVersion": version}),),
                    )
                    connection.commit()
                finally:
                    connection.close()
                after = self.capture()["protected_lucx"]
                self.assertEqual(compare_lucx(before, after, []), [])

    def test_protocol_settings_changes_are_allowed(self) -> None:
        before = self.capture()["protected_lucx"]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "UPDATE inbounds SET settings = ? WHERE id = 5",
                (json.dumps({"clients": [], "network": "xhttp", "path": "/new-path"}),),
            )
            connection.commit()
        finally:
            connection.close()

        self.assertEqual(compare_lucx(before, self.capture()["protected_lucx"], []), [])

    def test_client_identity_changes_are_allowed(self) -> None:
        before = self.capture()["protected_lucx"]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "UPDATE inbounds SET settings = ? WHERE id = 5",
                (json.dumps({"clients": [{"id": "changed-client"}], "network": "tcp"}),),
            )
            connection.commit()
        finally:
            connection.close()

        self.assertEqual(compare_lucx(before, self.capture()["protected_lucx"], []), [])

    def test_client_removal_between_updates_is_allowed(self) -> None:
        before = self.capture()["protected_lucx"]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE inbounds SET settings = '{}' WHERE id = 5")
            connection.commit()
        finally:
            connection.close()

        self.assertEqual(compare_lucx(before, self.capture()["protected_lucx"], []), [])

    def test_structural_inbound_changes_remain_blocked(self) -> None:
        before = self.capture()["protected_lucx"]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE inbounds SET port = 12345 WHERE id = 5")
            connection.commit()
        finally:
            connection.close()
        self.assertIn(
            "inbound #5 port changed",
            compare_lucx(before, self.capture()["protected_lucx"], []),
        )

    def test_inbound_removal_remains_blocked(self) -> None:
        before = self.capture()["protected_lucx"]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("DELETE FROM inbounds WHERE id = 5")
            connection.commit()
        finally:
            connection.close()

        self.assertIn(
            "inbound #5 was removed",
            compare_lucx(before, self.capture()["protected_lucx"], []),
        )

if __name__ == "__main__":
    unittest.main()
