"""Настоящая политика LucX и исходная auth Naive связываются только чтением."""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from lucx_post_configurator import naive_probe_source
from lucx_post_configurator.discovery import read_lucx_database
from lucx_post_configurator.models import Audit
from lucx_post_configurator.routing_profiles import inbound_routing_metadata, routing_fingerprint
from lucx_post_configurator.targetfs import TargetFS
from test_naive_connect_frontend import candidate_fixture


class LucXNaiveSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='naive-policy-')
        self.addCleanup(self.temporary.cleanup)
        self.fs = TargetFS(self.temporary.name)
        self.db_path = '/etc/x-ui/x-ui.db'
        self.path = self.fs.path(self.db_path)
        self.path.parent.mkdir(parents=True)
        self.caddy_path = self.fs.path('/etc/example/naive-7.caddyfile')
        self.caddy_path.parent.mkdir(parents=True)
        self.panel_secret = 'synthetic-panel-secret'
        self.clients = [dict(email=email, enable=True, totalGB=0, expiryTime=0,
            limitIp=0, reset=0, resetDay=0, resetMax=0, trafficReset='never',
            trafficResetDay=1, comment='') for email in ('NaiveAlpha', 'NaiveBeta')]
        self.settings = dict(domain='vpn.example.test', clients=self.clients,
            authUser='synthetic-service', authPass='synthetic-service-pass',
            certFile='/cert/cert.pem', keyFile='/cert/key.pem', useRawConfig=False,
            probeResistance=False, routeThroughXray=False, extraArgs='')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executescript('''
                CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT);
                CREATE TABLE inbounds (id INTEGER PRIMARY KEY, protocol TEXT, enable INTEGER,
                    listen TEXT, port INTEGER, settings TEXT, stream_settings TEXT, share_addr TEXT,
                    total INTEGER, expiry_time INTEGER, node_id INTEGER, origin_node_guid TEXT,
                    traffic_reset TEXT, traffic_reset_day INTEGER, up INTEGER, down INTEGER);
                CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, address TEXT,
                    port INTEGER, sni TEXT, override_sni_from_address INTEGER,
                    keep_sni_blank INTEGER, host_header TEXT, is_disabled INTEGER, security TEXT);
                CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, uuid TEXT, enable INTEGER,
                    total_gb INTEGER, expiry_time INTEGER, flow TEXT, security TEXT,
                    limit_ip INTEGER, limit_hwid INTEGER, reset INTEGER, reset_day INTEGER,
                    reset_max INTEGER, traffic_reset TEXT, traffic_reset_day INTEGER,
                    sync_orphaned_at INTEGER, comment TEXT, created_at INTEGER, updated_at INTEGER);
                CREATE TABLE client_inbounds (client_id INTEGER, inbound_id INTEGER,
                    flow_override TEXT, created_at INTEGER);
                CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INTEGER,
                    email TEXT, enable INTEGER, total INTEGER, expiry_time INTEGER,
                    reset INTEGER, reset_day INTEGER, reset_max INTEGER, reset_count INTEGER,
                    up INTEGER, down INTEGER, last_online INTEGER);
            ''')
            db.execute("INSERT INTO settings VALUES (1,'secret',?)", (self.panel_secret,))
            db.execute("INSERT INTO inbounds VALUES (7,'naive',1,'127.0.0.1',18443,?,'{}',"
                "'vpn.example.test',0,0,NULL,'','never',1,0,0)", (json.dumps(self.settings),))
            db.execute("INSERT INTO hosts VALUES (1,7,'vpn.example.test',443,'',1,0,'',0,'same')")
            for number, client in enumerate(self.clients, 1):
                db.execute("INSERT INTO clients VALUES (?,?,?,1,0,0,'','auto',0,0,0,0,0,'never',1,0,'',0,0)",
                           (number, client['email'], f'synthetic-unused-uuid-{number}'))
                db.execute("INSERT INTO client_inbounds VALUES (?,7,'',0)", (number,))
                # Поле inbound_id статистики намеренно не совпадает: это не связь клиента.
                db.execute("INSERT INTO client_traffics VALUES (?,999,?,1,0,0,0,0,0,0,0,0,0)",
                           (number, client['email']))
        self.write_caddy()
        self.refresh_manifest()

    def sql(self, statement, values=()):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(statement, values)

    def write_settings(self):
        self.sql('UPDATE inbounds SET settings=? WHERE id=7', (json.dumps(self.settings),))

    def auth(self, email):
        seed = self.settings.get('authSeed', '').strip()
        key, number = (seed, 0) if seed else (self.panel_secret, 7)
        identity = f'{number}:{email.strip()}'
        user = hmac.new(key.encode(), ('lucx-naive-user:' + identity).encode(), hashlib.sha256)
        password = hmac.new(key.encode(), ('lucx-naive-pass:' + identity).encode(), hashlib.sha256)
        return 'nx' + user.hexdigest()[:10], base64.urlsafe_b64encode(password.digest()).decode().rstrip('=')[:27]

    def write_caddy(self, pairs=None, *, probe_resistance=None, upstream=None):
        if pairs is None:
            pairs = [(self.settings['authUser'], self.settings['authPass'])]
            pairs += [self.auth(c['email']) for c in self.clients if c['enable']]
        auth = ''.join(f' basic_auth {user} {password}\n' for user, password in pairs)
        resistance = (self.settings.get('probeResistance', False)
                      if probe_resistance is None else probe_resistance)
        if resistance:
            auth += ' probe_resistance\n'
        if upstream is None and self.settings.get('routeThroughXray') is True:
            upstream = 'socks5://lucx:' + 'a' * 24 + '@127.0.0.1:' + str(self.settings.get('routeXrayPort'))
        if upstream:
            auth += ' upstream ' + upstream + '\n'
        self.caddy_path.write_text('vpn.example.test {\n route {\n forward_proxy {\n'
                                  + auth + ' }\n }\n}\n', encoding='utf-8')
        self.caddy_path.chmod(0o600)

    def refresh_manifest(self):
        _, inbounds, supported, warnings = read_lucx_database(self.fs, self.db_path)
        self.assertTrue(supported)
        self.assertEqual(warnings, [])
        item = next(i for i in inbounds if i.id == 7)
        self.protocol = dict(inbound_id=item.id, protocol=item.protocol, network=item.network,
            security=item.security, exposure='tcp_sni', enable=True, domain=item.share_addr,
            internal_host=item.listen, internal_port=item.port, public_port=item.suggested_public_port,
            sni_names=item.server_names, port_bindings=item.port_bindings, **inbound_routing_metadata(item))
        self.manifest = candidate_fixture()[0]
        self.manifest['protocols'] = [self.protocol]
        info = self.caddy_path.stat()
        self.audit = Audit(naive_caddyfile={'files': [dict(path='/etc/example/naive-7.caddyfile',
            kind='file', mode=info.st_mode & 0o7777, uid=info.st_uid, gid=info.st_gid,
            sha256=hashlib.sha256(self.caddy_path.read_bytes()).hexdigest(),
            capabilities=dict(forward_proxy=True, native_decoy=False))]})

    def source(self):
        cls = getattr(naive_probe_source, 'LucXNaiveCredentialSource', None)
        self.assertIsNotNone(cls, 'Нужен Naive source с доказанной политикой LucX')
        return cls(self.fs, self.db_path, self.manifest, self.audit)

    def snapshot(self):
        return {p.name: (p.read_bytes(), tuple(getattr(p.stat(), field) for field in
                ('st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_mtime_ns')))
                for p in (*self.path.parent.iterdir(), self.caddy_path) if p.is_file()}

    def test_real_client_auth_not_service_pair_and_all_sources_unchanged(self):
        before = self.snapshot()
        source = self.source()
        credential = source(self.protocol)
        self.assertIsNotNone(credential)
        self.assertEqual((credential.username, credential.password),
                         ('nxb368cba228', 'hRAVXrZTMxI4FD5cwAbYT8Fu4Tv'))
        self.assertEqual(credential.profile_fingerprint, routing_fingerprint(self.protocol, 443))
        self.assertRegex(credential.policy_fingerprint, r'^sha256:[0-9a-f]{64}$')
        self.assertEqual(before, self.snapshot())
        for secret in (self.panel_secret, credential.password, self.settings['authPass']):
            self.assertNotIn(secret, repr(source) + repr(credential))

    def test_probe_resistance_preserves_client_auth_and_pins_the_setting(self):
        self.settings['probeResistance'] = True
        self.write_settings()
        self.write_caddy()
        self.refresh_manifest()
        before = self.snapshot()
        source = self.source()
        credential = source(self.protocol)
        self.assertIsNotNone(credential)
        self.assertEqual((credential.username, credential.password), self.auth('NaiveAlpha'))
        self.assertEqual(before, self.snapshot())
        self.settings['probeResistance'] = False
        self.write_settings()
        self.assertIsNone(source(self.protocol))

    def test_probe_resistance_requires_exact_boolean_and_source_agreement(self):
        for setting, directive in ((True, False), (False, True), (None, False),
                                   (0, False), (1, True), ('true', True)):
            with self.subTest(setting=setting, directive=directive):
                self.settings['probeResistance'] = setting
                self.write_settings()
                self.write_caddy(probe_resistance=directive)
                self.refresh_manifest()
                with self.assertRaisesRegex(ValueError, 'Naive'):
                    self.source()

    def test_canonical_lucx_bridge_does_not_replace_client_credentials(self):
        self.sql("ALTER TABLE inbounds ADD COLUMN tag TEXT DEFAULT 'synthetic-naive'")
        self.settings.update(routeThroughXray=True, routeXrayPort=19400, probeResistance=True)
        self.write_settings()
        self.write_caddy()
        self.refresh_manifest()
        before = self.snapshot()
        source = self.source()
        credential = source(self.protocol)
        self.assertIsNotNone(credential)
        self.assertEqual((credential.username, credential.password), self.auth('NaiveAlpha'))
        self.assertEqual(before, self.snapshot())
        self.assertNotIn('a' * 24, repr(credential))
        self.settings['routeXrayPort'] = 19401
        self.write_settings()
        self.assertIsNone(source(self.protocol))

    def test_bridge_source_requires_exact_lucx_settings_and_url_shape(self):
        self.sql("ALTER TABLE inbounds ADD COLUMN tag TEXT DEFAULT 'synthetic-naive'")
        good = 'socks5://lucx:' + 'a' * 24 + '@127.0.0.1:19400'
        cases = [(True, 19400, value) for value in (
            '', good.replace('socks5:', 'http:'), good.replace('lucx:', 'other:'),
            good.replace('127.0.0.1', '192.0.2.1'), good.replace('19400', '19401'),
            good + '/', good + '?mode=1', good + '#part', good.replace('a' * 24, ''),
            good.replace('a' * 24, 'lucx-bridge'), good.replace(':19400', ':019400'))]
        cases += [(flag, 19400, good) for flag in (False, 0, 1, None, 'true')]
        cases += [(True, port, good) for port in (None, True, 0, -1, 65536, '19400')]
        for flag, port, upstream in cases:
            with self.subTest(flag=flag, port=port, upstream_shape=len(upstream)):
                self.settings.update(routeThroughXray=flag, routeXrayPort=port)
                self.write_settings()
                self.write_caddy(upstream=upstream)
                self.refresh_manifest()
                with self.assertRaisesRegex(ValueError, 'Naive'):
                    self.source()

    def test_bridge_requires_inbound_tag_and_typed_outbound_selection(self):
        self.sql("ALTER TABLE inbounds ADD COLUMN tag TEXT DEFAULT 'synthetic-naive'")
        for tag, outbound in (('', ''), (None, ''), ('synthetic-naive', None),
                              ('synthetic-naive', 1), ('synthetic-naive', [])):
            with self.subTest(tag_present=bool(tag), outbound_type=type(outbound).__name__):
                self.sql('UPDATE inbounds SET tag=? WHERE id=7', (tag,))
                self.settings.update(routeThroughXray=True, routeXrayPort=19400, outboundTag=outbound)
                self.write_settings()
                self.write_caddy()
                self.refresh_manifest()
                with self.assertRaisesRegex(ValueError, 'Naive'):
                    self.source()

    def test_default_native_https_authority_supplies_sni_without_xray_tls_settings(self):
        self.sql('UPDATE hosts SET override_sni_from_address=0')
        before = self.snapshot()
        self.refresh_manifest()
        endpoint = self.protocol['public_endpoints'][0]
        self.assertEqual(endpoint['sni'], 'vpn.example.test')
        self.assertEqual(endpoint['sni_source'], 'address')
        self.assertEqual(self.protocol['sni_names'], ['vpn.example.test'])
        self.assertIsNotNone(self.source()(self.protocol))
        self.assertEqual(before, self.snapshot())

    def test_explicit_blank_or_raw_naive_config_never_gets_invented_sni(self):
        for raw, keep_blank in ((False, 1), (True, 0)):
            with self.subTest(raw=raw, keep_blank=keep_blank):
                self.settings['useRawConfig'] = raw
                self.write_settings()
                self.sql('UPDATE hosts SET override_sni_from_address=0,keep_sni_blank=?', (keep_blank,))
                self.refresh_manifest()
                self.assertEqual(self.protocol['public_endpoints'][0]['sni'], '')
                with self.assertRaises(ValueError):
                    self.source()

    def test_native_https_aliases_keep_their_own_authority_and_xray_has_no_fallback(self):
        self.sql('UPDATE hosts SET override_sni_from_address=0')
        self.sql("INSERT INTO hosts VALUES (2,7,'alias.example.test',8443,'',0,0,'',0,'same')")
        self.refresh_manifest()
        self.assertEqual([(row['address'], row['sni']) for row in self.protocol['public_endpoints']],
                         [('vpn.example.test', 'vpn.example.test'), ('alias.example.test', 'alias.example.test')])
        self.assertEqual(self.protocol['sni_names'], ['vpn.example.test', 'alias.example.test'])
        self.sql("UPDATE inbounds SET protocol='vless' WHERE id=7")
        self.refresh_manifest()
        self.assertEqual([row['sni'] for row in self.protocol['public_endpoints']], ['', ''])
        self.assertEqual(self.protocol['sni_names'], [])

    def test_auth_seed_uses_utf8_key_and_zero_inbound_scope(self):
        self.settings['authSeed'] = ' synthetic-auth-seed '
        self.write_settings()
        self.write_caddy()
        self.refresh_manifest()
        credential = self.source()(self.protocol)
        self.assertIsNotNone(credential)
        self.assertEqual((credential.username, credential.password),
                         ('nx28089e67de', 'wJrOOhJRUlQHv_WCIiWoQCEfBA-'))

    def test_global_traffic_row_is_selected_by_email_not_stale_inbound_id(self):
        self.assertIsNotNone(self.source()(self.protocol))
        self.sql("INSERT INTO client_traffics SELECT 3,7,email,enable,total,expiry_time,"
                 "reset,reset_day,reset_max,reset_count,up,down,last_online FROM client_traffics WHERE id=1")
        with self.assertRaisesRegex(ValueError, '^Источник Naive не подтверждён$'):
            self.source()

    def test_missing_or_duplicate_saved_secret_never_creates_a_replacement(self):
        self.sql("DELETE FROM settings WHERE key='secret'")
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, '^Источник Naive не подтверждён$'):
            self.source()
        self.assertEqual(before, self.snapshot())
        self.sql("INSERT INTO settings VALUES (1,'secret',?)", (self.panel_secret,))
        self.sql("INSERT INTO settings VALUES (2,'secret',?)", (self.panel_secret,))
        with self.assertRaises(ValueError):
            self.source()

    def test_service_only_or_extra_caddy_user_cannot_replace_panel_clients(self):
        for pairs in ([(self.settings['authUser'], self.settings['authPass'])],
                      [self.auth(c['email']) for c in self.clients] + [('synthetic-orphan', 'synthetic-orphan-pass')]):
            with self.subTest(size=len(pairs)):
                self.write_caddy(pairs)
                self.refresh_manifest()
                with self.assertRaises(ValueError):
                    self.source()

    def test_nonselected_client_policy_and_attachment_drift_invalidate_old_source(self):
        source = self.source()
        self.sql('UPDATE clients SET limit_hwid=1 WHERE id=2')
        self.assertIsNone(source(self.protocol))
        self.sql('UPDATE clients SET limit_hwid=0 WHERE id=2')
        self.sql('DELETE FROM client_inbounds WHERE client_id=2')
        self.assertIsNone(source(self.protocol))
        with self.assertRaises(ValueError):
            self.source()

    def test_disabled_client_remains_in_cohort_but_is_not_probe_account(self):
        self.clients[0]['enable'] = False
        self.sql('UPDATE clients SET enable=0 WHERE id=1')
        self.sql('UPDATE client_traffics SET enable=0 WHERE id=1')
        self.write_settings()
        self.write_caddy()
        self.refresh_manifest()
        source = self.source()
        credential = source(self.protocol)
        self.assertIsNotNone(credential)
        self.assertEqual((credential.username, credential.password),
                         ('nxe04c339303', 'EGII2AmLA5rNybQkNe5iDikqHnO'))
        self.sql('UPDATE clients SET enable=1 WHERE id=1')
        self.assertIsNone(source(self.protocol))

    def test_stats_and_relational_comments_do_not_revoke_unlimited_client(self):
        source = self.source()
        before = source(self.protocol)
        self.sql('UPDATE client_traffics SET up=8192,down=8192,last_online=42')
        self.sql('UPDATE inbounds SET up=8192,down=8192')
        self.sql("UPDATE clients SET comment='synthetic-note',updated_at=42")
        after = source(self.protocol)
        self.assertIsNotNone(after)
        self.assertEqual(before, after)

    def test_exact_identity_and_complete_relational_embedded_match_are_required(self):
        for statement in ("UPDATE clients SET email='naivealpha' WHERE id=2",
                          "INSERT INTO client_inbounds VALUES (2,7,'',0)",
                          'DELETE FROM client_traffics WHERE id=2'):
            with self.subTest(statement=statement):
                with closing(sqlite3.connect(self.path)) as db:
                    original = '\n'.join(db.iterdump())
                self.sql(statement)
                with self.assertRaises(ValueError):
                    self.source()
                self.path.unlink()
                with closing(sqlite3.connect(self.path)) as db:
                    db.executescript(original)

    def test_unknown_policy_or_stream_field_fails_closed(self):
        source = self.source()
        self.sql('ALTER TABLE clients ADD COLUMN synthetic_new_policy INTEGER DEFAULT 0')
        self.assertIsNone(source(self.protocol))
        with self.assertRaises(ValueError):
            self.source()

    def test_caddy_or_manifest_replacement_cannot_reuse_source(self):
        source = self.source()
        forged = copy.deepcopy(self.protocol)
        forged['internal_port'] += 1
        self.assertIsNone(source(forged))
        self.manifest['protocols'][0]['internal_port'] += 1
        self.assertIsNotNone(source(copy.deepcopy({**forged, 'internal_port': 18443})))
        self.caddy_path.write_text(self.caddy_path.read_text(encoding='utf-8') + '\n', encoding='utf-8')
        self.assertIsNone(source(copy.deepcopy({**forged, 'internal_port': 18443})))

    def test_policy_change_during_snapshot_cannot_return_old_auth(self):
        source = self.source()
        original = naive_probe_source.read_lucx_connection
        calls = 0
        def change_after_discovery(db):
            nonlocal calls
            result = original(db)
            calls += 1
            if calls == 1:
                self.sql('UPDATE clients SET enable=0 WHERE id=2')
            return result
        with mock.patch.object(naive_probe_source, 'read_lucx_connection', side_effect=change_after_discovery):
            self.assertIsNone(source(self.protocol))

    def test_oversized_unrelated_traffic_identity_is_bounded(self):
        self.sql('INSERT INTO client_traffics VALUES (3,999,?,1,0,0,0,0,0,0,0,0,0)',
                 ('synthetic-' + 'x' * 60000,))
        with self.assertRaises(ValueError):
            self.source()

    def test_python_policy_processing_cannot_outlive_snapshot_deadline(self):
        clock = [0.0]
        original = naive_probe_source._naive_auth
        def expired_after_auth(*args):
            result = original(*args)
            clock[0] = 10.0
            return result
        with mock.patch.object(naive_probe_source.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(naive_probe_source, '_naive_auth', side_effect=expired_after_auth):
            with self.assertRaises(ValueError):
                self.source()

    def test_total_policy_encoding_is_bounded_before_large_allocation(self):
        with mock.patch.object(naive_probe_source, '_COHORT_MAX_BYTES', 32, create=True):
            with self.assertRaises(ValueError):
                self.source()

    def test_caddy_reads_share_one_total_material_budget(self):
        limit = len(self.caddy_path.read_bytes()) + 1
        with mock.patch.object(naive_probe_source, '_SOURCE_MAX_BYTES', limit, create=True):
            with self.assertRaises(ValueError):
                self.source()

    def test_shared_client_attachment_to_missing_inbound_is_rejected(self):
        self.sql("INSERT INTO client_inbounds VALUES (1,999,'',0)")
        with self.assertRaises(ValueError):
            self.source()

    def test_legacy_omitted_reset_fields_preserve_explicit_relational_never(self):
        for client in self.clients:
            for key in ('resetDay', 'resetMax', 'trafficReset', 'trafficResetDay'):
                client.pop(key)
        self.write_settings()
        self.refresh_manifest()
        try:
            source = self.source()
        except ValueError:
            source = None
        self.assertIsNotNone(source, 'Подтверждённый legacy JSON должен сохранять DB policy never')
        self.assertIsNotNone(source(self.protocol))
        self.sql("UPDATE clients SET traffic_reset='daily' WHERE id=2")
        self.assertIsNone(source(self.protocol))
        with self.assertRaises(ValueError):
            self.source()

    def test_explicit_empty_legacy_cycle_cannot_erase_relational_policy(self):
        for client in self.clients:
            client['trafficReset'] = ''
            client['trafficResetDay'] = 0
        self.write_settings()
        self.refresh_manifest()
        try:
            source = self.source()
        except ValueError:
            source = None
        self.assertIsNotNone(source, 'Go guard сохраняет явный relational never при пустом legacy cycle')
        self.sql("UPDATE clients SET traffic_reset='monthly' WHERE id=1")
        self.assertIsNone(source(self.protocol))

    def test_legacy_does_not_default_null_wrong_type_or_missing_core_policy(self):
        original = copy.deepcopy(self.clients[0])
        for key, value in (('resetDay', None), ('resetMax', '0'), ('resetDay', False),
                           ('trafficReset', None), ('trafficResetDay', '1'),
                           ('trafficReset', 'unknown'), ('expiryTime', None)):
            with self.subTest(key=key, kind=type(value).__name__):
                self.clients[0].clear()
                self.clients[0].update(original)
                self.clients[0][key] = value
                self.write_settings()
                self.refresh_manifest()
                with self.assertRaises(ValueError):
                    self.source()
        self.clients[0].clear()
        self.clients[0].update(original)
        del self.clients[0]['expiryTime']
        self.write_settings()
        self.refresh_manifest()
        with self.assertRaises(ValueError):
            self.source()
