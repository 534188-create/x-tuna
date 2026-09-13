from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import sqlite3
import tempfile
import time
import unittest
import uuid
from contextlib import closing
from unittest import mock

from lucx_post_configurator.discovery import read_lucx_database
from lucx_post_configurator.routing_profiles import (
    inbound_routing_metadata,
    routing_fingerprint,
)
from lucx_post_configurator.targetfs import TargetFS


class LucXXraySourceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("lucx_post_configurator.vpn_probe_source"),
                             "Источник credentials должен существовать")
        from lucx_post_configurator import vpn_probe_source
        self.module = vpn_probe_source
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-source-")
        self.addCleanup(self.temp.cleanup)
        self.fs = TargetFS(self.temp.name)
        self.path = self.fs.path("/etc/x-ui/x-ui.db")
        self.path.parent.mkdir(parents=True)
        self.uuid = str(uuid.uuid4())
        self.client = {"id": self.uuid, "email": "synthetic-client", "enable": True,
                       "totalGB": 0, "expiryTime": 0, "limitIp": 0, "flow": "", "security": "auto"}
        self.settings = {"clients": [self.client], "decryption": "none", "encryption": "none"}
        self.stream = {"network": "ws", "security": "tls", "wsSettings": {"path": "/vpn"},
            "tlsSettings": {"serverName": "vpn.example.test", "alpn": ["http/1.1"],
                "certificates": [{"certificateFile": "/cert/cert.pem", "keyFile": "/cert/key.pem"}], "settings": {}}}
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executescript('''
                CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT);
                CREATE TABLE inbounds (id INTEGER PRIMARY KEY, protocol TEXT, enable INTEGER,
                    listen TEXT, port INTEGER, settings TEXT, stream_settings TEXT, share_addr TEXT,
                    total INTEGER, expiry_time INTEGER, node_id INTEGER);
                CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, address TEXT, port INTEGER,
                    sni TEXT, override_sni_from_address INTEGER, keep_sni_blank INTEGER,
                    host_header TEXT, is_disabled INTEGER, security TEXT);
                CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INTEGER, email TEXT,
                    enable INTEGER, total INTEGER, expiry_time INTEGER, up INTEGER, down INTEGER);
            ''')
            db.execute("INSERT INTO inbounds VALUES (7,'vless',1,'127.0.0.1',18443,?,?,?,0,0,NULL)",
                       (json.dumps(self.settings), json.dumps(self.stream), "vpn.example.test"))
            db.execute("INSERT INTO hosts VALUES (1,7,'vpn.example.test',443,'',1,0,'',0,'same')")
            db.execute("INSERT INTO client_traffics VALUES (1,7,'synthetic-client',1,0,0,0,0)")
        self.source = vpn_probe_source.LucXXrayCredentialSource(self.fs, "/etc/x-ui/x-ui.db", 443)
        self.protocol = self.current_protocol()

    def current_protocol(self):
        _, inbounds, supported, _warnings = read_lucx_database(self.fs, "/etc/x-ui/x-ui.db")
        self.assertTrue(supported)
        item = inbounds[0]
        return {"inbound_id": item.id, "protocol": item.protocol, "network": item.network,
            "security": item.security, "exposure": "tcp_sni", "domain": item.share_addr,
            "internal_host": item.listen, "internal_port": item.port,
            "public_port": item.suggested_public_port, "sni_names": item.server_names,
            "port_bindings": item.port_bindings, **inbound_routing_metadata(item)}

    def write_json(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE inbounds SET settings=?,stream_settings=? WHERE id=7",
                       (json.dumps(self.settings), json.dumps(self.stream)))

    def relational_client(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executescript('''CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, uuid TEXT,
                enable INTEGER, total_gb INTEGER, expiry_time INTEGER, flow TEXT, security TEXT,
                limit_ip INTEGER, limit_hwid INTEGER, reset INTEGER DEFAULT 0,
                reset_day INTEGER DEFAULT 0, reset_max INTEGER DEFAULT 0,
                traffic_reset TEXT DEFAULT 'never', traffic_reset_day INTEGER DEFAULT 0,
                comment TEXT DEFAULT '', created_at INTEGER DEFAULT 0, updated_at INTEGER DEFAULT 0);
                CREATE TABLE client_inbounds (client_id INTEGER,inbound_id INTEGER,flow_override TEXT,
                    created_at INTEGER DEFAULT 0);''')
            db.execute('''INSERT INTO clients
                (id,email,uuid,enable,total_gb,expiry_time,flow,security,limit_ip,limit_hwid)
                VALUES (3,'synthetic-client',?,1,0,0,'','auto',0,0)''', (self.uuid,))
            db.execute("INSERT INTO client_inbounds (client_id,inbound_id,flow_override) VALUES (3,7,'')")

    def policy_credential(self, protocol=None):
        credential = self.source(self.protocol if protocol is None else protocol)
        self.assertIsNotNone(credential)
        self.assertRegex(getattr(credential, 'policy_fingerprint', ''), r'^sha256:[0-9a-f]{64}$',
                         'Источник должен возвращать внутренний отпечаток политики')
        self.assertNotIn(credential.policy_fingerprint, repr(credential))
        return credential

    def test_policy_fingerprint_survives_traffic_counters_and_relational_metadata(self):
        self.relational_client()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executescript('''ALTER TABLE inbounds ADD COLUMN up INTEGER DEFAULT 0;
                ALTER TABLE inbounds ADD COLUMN down INTEGER DEFAULT 0;
                ALTER TABLE inbounds ADD COLUMN last_traffic_reset_time INTEGER DEFAULT 0;
                ALTER TABLE client_traffics ADD COLUMN reset_count INTEGER DEFAULT 0;
                ALTER TABLE client_traffics ADD COLUMN last_online INTEGER DEFAULT 0;
                ALTER TABLE client_traffics ADD COLUMN last_sub_fetch INTEGER DEFAULT 0;''')
        before = self.policy_credential()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE inbounds SET up=400,down=900,last_traffic_reset_time=50')
            db.execute('UPDATE client_traffics SET up=100,down=200,reset_count=2,last_online=30,last_sub_fetch=40')
            db.execute("UPDATE clients SET comment='changed metadata',created_at=20,updated_at=60")
            db.execute('UPDATE client_inbounds SET created_at=80')
        after = self.policy_credential()
        self.assertEqual(after.profile_fingerprint, before.profile_fingerprint)
        self.assertEqual(after.policy_fingerprint, before.policy_fingerprint)
        self.assertEqual(self.policy_credential().policy_fingerprint, after.policy_fingerprint)

    def test_future_expiry_policy_changes_without_changing_route(self):
        self.relational_client()
        future = int(time.time() * 1000) + 3600000
        for table in ('clients', 'client_traffics', 'inbounds'):
            with self.subTest(table=table):
                before = self.policy_credential()
                with closing(sqlite3.connect(self.path)) as db, db:
                    db.execute(f'UPDATE {table} SET expiry_time=?', (future,))
                after = self.policy_credential()
                self.assertEqual(after.profile_fingerprint, before.profile_fingerprint)
                self.assertNotEqual(after.policy_fingerprint, before.policy_fingerprint)

    def test_policy_identity_detects_replacement_of_relational_attachment(self):
        self.relational_client()
        before = self.policy_credential()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE clients SET id=4 WHERE id=3')
            db.execute('UPDATE client_inbounds SET client_id=4 WHERE client_id=3')
        after = self.policy_credential()
        self.assertEqual(after.user_id, before.user_id)
        self.assertEqual(after.profile_fingerprint, before.profile_fingerprint)
        self.assertNotEqual(after.policy_fingerprint, before.policy_fingerprint)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE clients SET enable=0')
        self.assertIsNone(self.source(self.protocol))

    def test_attachment_flow_and_reset_policy_are_bound_to_credential(self):
        self.relational_client()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("ALTER TABLE inbounds ADD COLUMN traffic_reset TEXT DEFAULT 'never'")
            db.execute('ALTER TABLE inbounds ADD COLUMN traffic_reset_day INTEGER DEFAULT 0')
        for statement in ('UPDATE client_inbounds SET flow_override=NULL',
                          'UPDATE clients SET traffic_reset_day=12',
                          'UPDATE inbounds SET traffic_reset_day=15'):
            with self.subTest(statement=statement):
                before = self.policy_credential()
                with closing(sqlite3.connect(self.path)) as db, db:
                    db.execute(statement)
                after = self.policy_credential()
                self.assertNotEqual(after.policy_fingerprint, before.policy_fingerprint)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE client_inbounds SET flow_override='xtls-rprx-vision'")
        self.assertIsNone(self.source(self.protocol))

    def test_limit_or_enable_revocation_cannot_reuse_policy_credential(self):
        self.relational_client()
        changes = (('clients', 'total_gb', 1), ('clients', 'limit_ip', 1),
                   ('clients', 'limit_hwid', 1), ('clients', 'reset_max', 1),
                   ('client_traffics', 'total', 1), ('inbounds', 'total', 1),
                   ('client_traffics', 'enable', 0), ('inbounds', 'enable', 0))
        for table, field, value in changes:
            with self.subTest(table=table, field=field):
                self.policy_credential()
                with closing(sqlite3.connect(self.path)) as db, db:
                    db.execute(f'UPDATE {table} SET {field}=?', (value,))
                self.assertIsNone(self.source(self.protocol))
                with closing(sqlite3.connect(self.path)) as db, db:
                    db.execute(f'UPDATE {table} SET {field}=?', (1 if field == 'enable' else 0,))

    def test_embedded_policy_ignores_metadata_but_binds_future_expiry(self):
        before = self.policy_credential()
        self.client.update(comment='metadata only', created_at=1, updated_at=2)
        self.write_json()
        after = self.policy_credential(self.current_protocol())
        self.assertEqual(after.policy_fingerprint, before.policy_fingerprint)
        self.client['expiryTime'] = int(time.time() * 1000) + 3600000
        self.write_json()
        changed = self.policy_credential(self.current_protocol())
        self.assertNotEqual(changed.policy_fingerprint, before.policy_fingerprint)

    def test_existing_enabled_client_is_returned_without_database_change(self):
        before = hashlib.sha256(self.path.read_bytes()).digest()
        names = set(self.path.parent.iterdir())
        credential = self.source(self.protocol)
        self.assertIsNotNone(credential)
        self.assertTrue(credential.user_id == self.uuid, "Выбран неверный существующий клиент")
        self.assertEqual(credential.profile_fingerprint, routing_fingerprint(self.protocol, 443))
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)
        self.assertEqual(set(self.path.parent.iterdir()), names)
        self.assertNotIn(self.uuid, repr(credential) + repr(self.source))

    def test_source_metadata_is_accepted_by_the_pinned_observer(self):
        from lucx_post_configurator import vpn_probes
        binary = self.path.with_name("synthetic-xray")
        binary.write_bytes(b"synthetic-executable")
        binary.chmod(0o700)
        context = vpn_probes.XrayProbeContext(binary, hashlib.sha256(binary.read_bytes()).hexdigest(),
            self.source, "127.0.0.1", 19600)
        with mock.patch.object(vpn_probes.sys, "platform", "linux"):
            self.assertTrue(vpn_probes.XrayVPNObserver(context).supports(self.protocol))

    def test_disabled_or_malformed_inbound_enable_is_rejected(self):
        for enable in (0, "unknown"):
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute("UPDATE inbounds SET enable=?", (enable,))
            self.assertIsNone(self.source(self.current_protocol()))

    def test_unknown_xhttp_mode_cannot_produce_a_credential(self):
        self.stream.pop("wsSettings")
        self.stream.update(network="xhttp", xhttpSettings={"path": "/vpn", "mode": "future"})
        self.stream["tlsSettings"]["alpn"] = ["h2"]
        self.write_json()
        self.assertIsNone(self.source(self.current_protocol()))

    def test_fresh_database_snapshot_rejects_source_profile_and_endpoint_drift(self):
        original = copy.deepcopy(self.protocol)
        for change in ("path", "host", "uuid", "transport"):
            with self.subTest(change=change):
                if change == "path": self.stream["wsSettings"]["path"] = "/changed"
                if change == "host": self.stream["wsSettings"]["host"] = "different.example.test"
                if change == "uuid": self.client["id"] = str(uuid.uuid4())
                if change == "transport": self.stream["network"] = "xhttp"
                self.write_json()
                self.assertIsNone(self.source(original))

    def test_current_source_hash_does_not_authorize_forged_manifest_metadata(self):
        for name, value in (("transport_path", "/changed"), ("internal_port", 18444),
                            ("public_port", 8443), ("domain", "changed.example.test"),
                            ("security", "reality"), ("sni_names", ["changed.example.test"])):
            altered = {**self.protocol, name: value}
            with self.subTest(field=name):
                self.assertIsNone(self.source(altered))
        altered = copy.deepcopy(self.protocol)
        altered["public_endpoints"][0]["port"] = 8443
        self.assertIsNone(self.source(altered))

    def test_disabled_revoked_expired_and_quota_clients_are_not_selected(self):
        for update in ({"enable": False}, {"expiryTime": int(time.time() * 1000) - 1},
                       {"expiryTime": -1}, {"totalGB": 1}, {"limitIp": 1}, {"flow": "xtls-rprx-vision"}):
            client = copy.deepcopy(self.client)
            client.update(update)
            self.settings["clients"] = [client]
            self.write_json()
            with self.subTest(fields=list(update)):
                self.assertIsNone(self.source(self.current_protocol()))
        self.settings["clients"] = []
        self.write_json()
        self.assertIsNone(self.source(self.current_protocol()))

    def test_effective_traffic_disable_is_not_ignored(self):
        for field, value in (("enable", 0), ("total", 1), ("expiry_time", -1)):
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute(f"UPDATE client_traffics SET {field}=?", (value,))
            self.assertIsNone(self.source(self.protocol))

    def test_unknown_stream_tls_client_and_host_overrides_are_blocked(self):
        for update in ({"allowInsecure": True}, {"settings": {"fingerprint": "chrome"}},
                       {"settings": {"pinnedPeerCertSha256": ["unknown"]}},
                       {"unknown_tls_field": "unsupported"}):
            baseline = copy.deepcopy(self.stream)
            self.stream["tlsSettings"].update(update)
            self.write_json()
            self.assertIsNone(self.source(self.current_protocol()))
            self.stream = baseline
        self.write_json()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE hosts SET host_header='different.example.test'")
        self.assertIsNone(self.source(self.current_protocol()))

    def test_relational_authority_cannot_fall_back_to_stale_embedded_client(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executescript('''CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, uuid TEXT,
                enable INTEGER, total_gb INTEGER, expiry_time INTEGER, flow TEXT, security TEXT,
                limit_ip INTEGER, limit_hwid INTEGER);
                CREATE TABLE client_inbounds (client_id INTEGER,inbound_id INTEGER,flow_override TEXT);''')
            db.execute("INSERT INTO clients VALUES (3,'synthetic-client',?,0,0,0,'','auto',0,0)", (self.uuid,))
            db.execute("INSERT INTO client_inbounds VALUES (3,7,'')")
        self.assertIsNone(self.source(self.protocol))
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE clients SET enable=1")
        self.assertIsNotNone(self.source(self.protocol))
        replacement = str(uuid.uuid4())
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE clients SET uuid=?", (replacement,))
        selected = self.source(self.protocol)
        self.assertIsNotNone(selected)
        self.assertTrue(selected.user_id == replacement, "Embedded snapshot подменил действующего клиента")
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DELETE FROM client_inbounds")
        self.assertIsNone(self.source(self.protocol))

    def test_malformed_json_schema_and_duplicate_keys_fail_without_raw_error(self):
        for payload in ('{"clients":', '{"clients":[],"clients":[]}', '[1]', 'null'):
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute("UPDATE inbounds SET settings=?", (payload,))
            self.assertIsNone(self.source(self.protocol))
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DROP TABLE inbounds")
        self.assertIsNone(self.source(self.protocol))

    def test_private_ca_provider_is_code_owned_and_errors_are_hidden(self):
        callback = mock.Mock(side_effect=ValueError(self.uuid))
        source = self.module.LucXXrayCredentialSource(self.fs, "/etc/x-ui/x-ui.db", 443, ca_provider=callback)
        self.assertIsNone(source(self.protocol))
        self.assertNotIn(self.uuid, repr(source))

    def test_missing_or_escaped_path_does_not_create_database(self):
        for path in ("/etc/x-ui/missing.db", "/../escape.db", "relative.db"):
            source = self.module.LucXXrayCredentialSource(self.fs, path, 443)
            self.assertIsNone(source(self.protocol))
        self.assertFalse(self.fs.path("/etc/x-ui/missing.db").exists())

    def test_same_connection_has_read_transaction_and_query_only(self):
        original = self.module.read_lucx_connection
        seen = []
        def inspect_connection(db):
            seen.append((db.in_transaction, db.execute("PRAGMA query_only").fetchone()[0]))
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("UPDATE inbounds SET enable=0")
            return original(db)
        with mock.patch.object(self.module, "read_lucx_connection", side_effect=inspect_connection):
            self.assertIsNotNone(self.source(self.protocol))
        self.assertEqual(seen, [(True, 1)])

    def test_wal_writer_cannot_mix_new_secret_with_old_discovery_snapshot(self):
        writer = sqlite3.connect(self.path)
        self.addCleanup(writer.close)
        self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        writer.execute("UPDATE inbounds SET enable=1")
        writer.commit()
        original = self.module.read_lucx_connection
        replacement = str(uuid.uuid4())
        def change_after_discovery(db):
            audit = original(db)
            altered = copy.deepcopy(self.settings)
            altered["clients"][0]["id"] = replacement
            writer.execute("UPDATE inbounds SET settings=?", (json.dumps(altered),))
            writer.commit()
            return audit
        with mock.patch.object(self.module, "read_lucx_connection", side_effect=change_after_discovery):
            selected = self.source(self.protocol)
        self.assertIsNotNone(selected)
        self.assertTrue(selected.user_id == self.uuid, "Секрет прочитан за границей discovery snapshot")
        self.assertIsNone(self.source(self.protocol))

    def test_wal_without_sidecars_is_read_without_creating_them(self):
        with closing(sqlite3.connect(self.path)) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
        before = {p.name: hashlib.sha256(p.read_bytes()).digest()
                  for p in self.path.parent.iterdir()}
        self.assertIsNotNone(self.source(self.protocol))
        after = {p.name: hashlib.sha256(p.read_bytes()).digest()
                 for p in self.path.parent.iterdir()}
        self.assertEqual(after, before, 'Чтение не должно создавать WAL/SHM')

    def test_live_wal_read_preserves_all_source_files_and_sees_committed_revocation(self):
        with closing(sqlite3.connect(self.path)) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('UPDATE client_traffics SET up=42')
            writer.commit()
            before = {p.name: hashlib.sha256(p.read_bytes()).digest()
                      for p in self.path.parent.iterdir()}
            self.assertIsNotNone(self.source(self.protocol))
            after = {p.name: hashlib.sha256(p.read_bytes()).digest()
                     for p in self.path.parent.iterdir()}
            self.assertEqual(after, before, 'Reader не должен менять SHM read marks')
            writer.execute('UPDATE client_traffics SET enable=0')
            writer.commit()
            self.assertIsNone(self.source(self.protocol), 'WAL commit нельзя игнорировать')

    def test_aligned_wal_truncation_cannot_resurrect_committed_revocation(self):
        with closing(sqlite3.connect(self.path)) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('UPDATE client_traffics SET up=42')
            writer.commit()
            wal = self.path.with_name(self.path.name + '-wal')
            prefix_size = wal.stat().st_size
            writer.execute('UPDATE client_traffics SET enable=0')
            writer.commit()
            complete = wal.read_bytes()
            self.assertGreater(len(complete), prefix_size)
            self.assertIsNone(self.source(self.protocol))
            try:
                with wal.open('r+b') as stream:
                    stream.truncate(prefix_size)
                self.assertEqual(writer.execute('SELECT enable FROM client_traffics').fetchone(), (0,))
                with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True)) as native, \
                        self.assertRaises(sqlite3.DatabaseError):
                    native.execute('SELECT enable FROM client_traffics').fetchone()
                before = {p.name: hashlib.sha256(p.read_bytes()).digest() for p in self.path.parent.iterdir()}
                self.assertIsNone(self.source(self.protocol), 'Старый committed prefix не подтверждает актуальную авторизацию')
                self.assertEqual(before, {p.name: hashlib.sha256(p.read_bytes()).digest() for p in self.path.parent.iterdir()})
            finally:
                wal.write_bytes(complete)

    def test_missing_partial_authority_or_unknown_column_is_closed(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("CREATE TABLE clients (id INTEGER)")
        self.assertIsNone(self.source(self.protocol))
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DROP TABLE clients")
            db.execute("ALTER TABLE inbounds ADD COLUMN unknown_auth_override TEXT")
        self.assertIsNone(self.source(self.protocol))

    def test_sqlite_never_receives_original_path_and_private_files_are_gone_before_queries(self):
        connect = sqlite3.connect
        opened, memory_connections = [], []
        before = {p.name: hashlib.sha256(p.read_bytes()).digest() for p in self.path.parent.iterdir()}
        def private_connect(database, *args, **kwargs):
            if str(database) != ':memory:':
                from pathlib import Path
                self.assertNotIn(str(self.path.parent), str(database))
                self.assertNotIn(self.path.as_uri(), str(database))
                opened.append(Path(database))
            connection = connect(database, *args, **kwargs)
            if str(database) == ':memory:':
                memory_connections.append(connection)
            return connection
        original = self.module.read_lucx_connection
        def inspect(db):
            self.assertTrue(opened)
            self.assertTrue(all(not path.parent.exists() for path in opened))
            self.assertEqual(memory_connections, [db])
            self.assertEqual(db.execute('PRAGMA query_only').fetchone()[0], 1)
            with self.assertRaises(sqlite3.OperationalError):
                db.execute('UPDATE inbounds SET enable=0')
            return original(db)
        with mock.patch.object(sqlite3, 'connect', side_effect=private_connect), \
                mock.patch.object(self.module, 'read_lucx_connection', side_effect=inspect):
            self.assertIsNotNone(self.source(self.protocol))
        self.assertEqual(before, {p.name: hashlib.sha256(p.read_bytes()).digest() for p in self.path.parent.iterdir()})

    def test_hot_rollback_journal_is_rejected_before_metadata_queries(self):
        journal = self.path.with_name(self.path.name + '-journal')
        journal.write_bytes(b'\xd9\xd5\x05\xf9\x20\xa1\x63\xd7' + bytes(512))
        with mock.patch.object(self.module, 'read_lucx_connection') as read:
            self.assertIsNone(self.source(self.protocol))
            read.assert_not_called()

    def test_fresh_relational_wal_client_and_revocation_are_used_without_source_writes(self):
        with closing(sqlite3.connect(self.path)) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.executescript('''CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, uuid TEXT,
                enable INTEGER, total_gb INTEGER, expiry_time INTEGER, flow TEXT, security TEXT,
                limit_ip INTEGER, limit_hwid INTEGER);
                CREATE TABLE client_inbounds (client_id INTEGER,inbound_id INTEGER,flow_override TEXT);''')
            replacement = str(uuid.uuid4())
            writer.execute("INSERT INTO clients VALUES (3,'synthetic-client',?,1,0,0,'','auto',0,0)", (replacement,))
            writer.execute("INSERT INTO client_inbounds VALUES (3,7,'')")
            writer.commit()
            before = {p.name: hashlib.sha256(p.read_bytes()).digest() for p in self.path.parent.iterdir()}
            selected = self.source(self.protocol)
            self.assertIsNotNone(selected)
            self.assertTrue(selected.user_id == replacement)
            self.assertEqual(before, {p.name: hashlib.sha256(p.read_bytes()).digest() for p in self.path.parent.iterdir()})
            writer.execute('DELETE FROM client_inbounds')
            writer.commit()
            self.assertIsNone(self.source(self.protocol))
    def test_vmess_requires_the_confirmed_simple_security(self):
        self.settings = {"clients": [self.client]}
        self.write_json()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE inbounds SET protocol='vmess'")
        self.assertIsNotNone(self.source(self.current_protocol()))
        for key, value in (("security", "none"), ("alterId", 64), ("futureAuth", "unsupported")):
            altered = copy.deepcopy(self.client)
            altered[key] = value
            self.settings["clients"] = [altered]
            self.write_json()
            self.assertIsNone(self.source(self.current_protocol()))

    def test_expiry_future_and_explicit_unlimited_are_supported(self):
        self.client["expiryTime"] = int(time.time() * 1000) + 120000
        self.write_json()
        self.assertIsNotNone(self.source(self.current_protocol()))

    def test_global_mux_or_mask_is_not_silently_ignored(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT INTO settings(key,value) VALUES ('subJsonMux',?)", ('{"enabled":true}',))
        self.assertIsNone(self.source(self.protocol))

    def test_oversized_secret_field_is_rejected_before_discovery(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE inbounds SET settings=?", ("x" * (256 * 1024 + 1),))
        with mock.patch.object(self.module, "read_lucx_connection") as read:
            self.assertIsNone(self.source(self.protocol))
            read.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Проверка POSIX symlink")
    def test_symlink_database_is_rejected(self):
        linked = self.path.with_name("alias.db")
        linked.symlink_to(self.path)
        source = self.module.LucXXrayCredentialSource(self.fs, "/etc/x-ui/alias.db", 443)
        self.assertIsNone(source(self.protocol))


if __name__ == "__main__":
    unittest.main()
