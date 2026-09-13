from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lucx_post_configurator.naive_probe_source import _naive_auth
from lucx_post_configurator.naive_runtime import validate_source_binding
from lucx_post_configurator.targetfs import TargetFS

SOURCE = '''{
    admin off
    auto_https off
    servers {
        protocols h1 h2
    }
}
:18443, vpn.example.test:18443 {
    bind 127.0.0.1
    tls /synthetic/cert.pem /synthetic/key.pem
    route {
        forward_proxy {
            basic_auth user-one pass-one
            hide_ip
            hide_via
            probe_resistance
            upstream socks5://bridge:secret@127.0.0.1:1080
        }
    }
}
'''


class NaiveRuntimeTests(unittest.TestCase):
    def test_executable_owner_error_has_actionable_safe_message(self):
        from lucx_post_configurator.naive_runtime import _trusted
        info = SimpleNamespace(st_mode=0o100755, st_nlink=1, st_uid=65534)
        with patch('lucx_post_configurator.naive_runtime.os.name', 'posix'), \
             self.assertRaisesRegex(ValueError, 'владелец'):
            _trusted(info, SimpleNamespace(is_live=True), executable=True)

    @unittest.skipUnless(os.name == 'posix', 'Проверка POSIX владельца исполняемого файла')
    def test_untrusted_xray_executable_reports_owner_remedy_without_credentials(self):
        binary = self.fs.path('/usr/local/bin/xray')
        original = Path.lstat
        def lstat(path):
            result = original(path)
            if path == binary:
                values = list(result)
                values[4] = 65534
                return os.stat_result(values)
            return result
        with patch.object(Path, 'lstat', lstat), self.assertRaisesRegex(ValueError, 'владельц|владелец') as error:
            validate_source_binding(self.fs, self.db_path, 5, SOURCE)
        self.assertIn('0755', str(error.exception))
        self.assertNotIn('secret', str(error.exception))

    def test_unrelated_nonroot_process_does_not_block_root_xray_discovery(self):
        self.write('/proc/202/comm', b'nginx\n', 0o444)
        directory = self.fs.path('/proc/202')
        original = Path.lstat
        def lstat(path):
            result = original(path)
            if path == directory:
                values = list(result)
                values[4] = 65534
                return os.stat_result(values)
            return result
        from lucx_post_configurator import naive_runtime
        original_read = naive_runtime._proc_bytes
        def read(fs, name):
            if name.startswith('/proc/202/'):
                raise ValueError('untrusted process metadata')
            return original_read(fs, name)
        with patch.object(Path, 'lstat', lstat), patch.object(naive_runtime, '_proc_bytes', side_effect=read):
            result = validate_source_binding(self.fs, self.db_path, 5, SOURCE)
        self.assertTrue(result['process_epoch_sha256'])

    def test_lucx_relative_access_log_is_validated_without_reading_or_writing_log(self):
        log = '    log {\n        output file bin/tunnel/naive-5-data/access.json\n        format json\n    }\n'
        source = SOURCE.replace('    route {', log + '    route {')
        result = validate_source_binding(self.fs, self.db_path, 5, source)
        self.assertTrue(result['semantic_sha256'])
        absolute = validate_source_binding(self.fs, self.db_path, 5,
            source.replace('bin/tunnel/naive-5-data/access.json', '/var/log/lucx-naive-source-5.json'))
        self.assertNotEqual(result['semantic_sha256'], absolute['semantic_sha256'])
        self.assertFalse(self.fs.path('/bin/tunnel/naive-5-data/access.json').exists())
        for path in ('bin/tunnel/naive-6-data/access.json', '../naive-5-data/access.json',
                     'bin/tunnel/naive-5-data/other.json', './bin/tunnel/naive-5-data/access.json'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_source_binding(self.fs, self.db_path, 5,
                                        source.replace('bin/tunnel/naive-5-data/access.json', path))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fs = TargetFS(self.tmp.name)
        self.db_path = '/etc/x-ui/x-ui.db'
        self.fs.path(self.db_path).parent.mkdir(parents=True)
        self.settings = {'domain': 'vpn.example.test', 'authUser': 'user-one', 'authPass': 'pass-one',
                         'certFile': '/synthetic/cert.pem', 'keyFile': '/synthetic/key.pem',
                         'routeThroughXray': True, 'routeXrayPort': 1080, 'probeResistance': True,
                         'useAcme': False, 'useRawConfig': False, 'enableH3': False}
        with closing(sqlite3.connect(self.fs.path(self.db_path))) as db, db:
            db.execute('CREATE TABLE inbounds(id INTEGER PRIMARY KEY, protocol TEXT, enable INTEGER, listen TEXT, port INTEGER, settings TEXT, up INTEGER, down INTEGER)')
            db.execute('INSERT INTO inbounds VALUES (5,?,?,?,18443,?,0,0)', ('naive', 1, '127.0.0.1', json.dumps(self.settings)))
            db.execute('CREATE TABLE settings(key TEXT, value TEXT)')
            db.execute('INSERT INTO settings VALUES (?,?)', ('secret', 'synthetic-panel-secret'))
        self.runtime = {'inbounds': [{'protocol': 'socks', 'listen': '127.0.0.1', 'port': 1080,
                                     'settings': {'auth': 'password', 'accounts': [{'user': 'bridge', 'pass': 'secret'}]}}]}
        self.write('/run/xray.json', json.dumps(self.runtime).encode())
        self.write('/usr/local/bin/xray', b'synthetic executable', 0o755)
        self.write('/proc/101/comm', b'xray\n', 0o444)
        self.write('/proc/101/cmdline', b'/usr/local/bin/xray\0run\0-c\0/run/xray.json\0', 0o444)
        os.chmod(self.fs.path(self.db_path), 0o600)

    def write(self, target, value, mode=0o600):
        p = self.fs.path(target)
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            os.chmod(p, 0o600)
        p.write_bytes(value)
        os.chmod(p, mode)

    def update_settings(self, **values):
        self.settings.update(values)
        with closing(sqlite3.connect(self.fs.path(self.db_path))) as db, db:
            db.execute('UPDATE inbounds SET settings=?', (json.dumps(self.settings),))

    def validate(self, source=SOURCE):
        return validate_source_binding(self.fs, self.db_path, 5, source)

    def test_valid_source_returns_only_safe_digests(self):
        result = self.validate()
        self.assertEqual(set(result), {'database_sha256', 'semantic_sha256', 'runtime_sha256', 'process_epoch_sha256'})
        for digest in result.values():
            self.assertRegex(digest, r'^[0-9a-f]{64}$')
        self.assertNotIn('secret', json.dumps(result))

    def test_bridge_password_rotation_changes_only_runtime_digest(self):
        old = self.validate()
        self.runtime['inbounds'][0]['settings']['accounts'][0]['pass'] = 'rotated'
        self.write('/run/xray.json', json.dumps(self.runtime).encode())
        new = self.validate(SOURCE.replace('bridge:secret@', 'bridge:rotated@'))
        self.assertEqual(old['database_sha256'], new['database_sha256'])
        self.assertEqual(old['semantic_sha256'], new['semantic_sha256'])
        self.assertNotEqual(old['runtime_sha256'], new['runtime_sha256'])
        self.assertEqual(old['process_epoch_sha256'], new['process_epoch_sha256'])

    def test_wrong_runtime_auth_or_port_fails_without_secret_output(self):
        for changed in [SOURCE.replace('bridge:secret@', 'bridge:wrong-secret@'), SOURCE.replace(':1080', ':1081')]:
            with self.subTest(changed=changed[-20:]), self.assertRaisesRegex(ValueError, '^Источник Naive не подтверждён$'):
                self.validate(changed)

    def test_extra_or_missing_client_auth_is_rejected(self):
        for changed in [SOURCE.replace('            hide_ip', '            basic_auth extra-user extra-pass\n            hide_ip'),
                        SOURCE.replace('basic_auth user-one pass-one', 'basic_auth user-one wrong-pass')]:
            with self.assertRaises(ValueError):
                self.validate(changed)

    def test_endpoint_and_unknown_directive_changes_are_rejected(self):
        for before, after in [('vpn.example.test', 'other.example.test'), ('18443', '18444'),
                              ('/synthetic/cert.pem', '/other/cert.pem'), ('bind 127.0.0.1', 'bind 0.0.0.0'),
                              ('hide_ip', 'untrusted_option')]:
            with self.subTest(field=before), self.assertRaises(ValueError):
                self.validate(SOURCE.replace(before, after))

    def test_unrelated_traffic_counter_does_not_change_database_proof(self):
        before = self.validate()
        with closing(sqlite3.connect(self.fs.path(self.db_path))) as db, db:
            db.execute('UPDATE inbounds SET up=123,down=456')
        self.assertEqual(before['database_sha256'], self.validate()['database_sha256'])

    def test_unknown_database_column_and_partial_relational_schema_fail_closed(self):
        with closing(sqlite3.connect(self.fs.path(self.db_path))) as db, db:
            db.execute('CREATE TABLE clients(id INTEGER,email TEXT,enable INTEGER)')
        with self.assertRaises(ValueError):
            self.validate()
        with closing(sqlite3.connect(self.fs.path(self.db_path))) as db, db:
            db.execute('DROP TABLE clients')
            db.execute('ALTER TABLE inbounds ADD COLUMN unknown_auth_override TEXT')
        with self.assertRaises(ValueError):
            self.validate()

    def test_embedded_client_uses_seed_scope_zero(self):
        self.update_settings(authSeed='synthetic-seed', clients=[{'email': 'client@example.test', 'enable': True}])
        pair = _naive_auth('synthetic-seed', 0, 'client@example.test')
        text = SOURCE.replace('            hide_ip', f'            basic_auth {pair[0]} {pair[1]}\n            hide_ip')
        self.validate(text)
        wrong = _naive_auth('synthetic-seed', 5, 'client@example.test')
        with self.assertRaises(ValueError):
            self.validate(text.replace(pair[1], wrong[1]))

    def test_relational_client_set_and_disabled_client_are_authoritative(self):
        self.update_settings(clients=[{'email': 'client@example.test', 'enable': True}])
        with closing(sqlite3.connect(self.fs.path(self.db_path))) as db, db:
            db.execute('CREATE TABLE clients(id INTEGER PRIMARY KEY,email TEXT,enable INTEGER)')
            db.execute('CREATE TABLE client_inbounds(client_id INTEGER,inbound_id INTEGER,flow_override TEXT)')
            db.execute('INSERT INTO clients VALUES(1,?,1)', ('client@example.test',))
            db.execute("INSERT INTO client_inbounds VALUES(1,5,'')")
        pair = _naive_auth('synthetic-panel-secret', 5, 'client@example.test')
        text = SOURCE.replace('            hide_ip', f'            basic_auth {pair[0]} {pair[1]}\n            hide_ip')
        self.validate(text)
        with closing(sqlite3.connect(self.fs.path(self.db_path))) as db, db:
            db.execute('DELETE FROM client_inbounds')
        with self.assertRaises(ValueError):
            self.validate(text)

    def test_runtime_config_must_be_explicit_and_unambiguous(self):
        for argv in [b'/usr/local/bin/xray\0run\0', b'/usr/local/bin/xray\0-c\0/run/xray.json\0-c\0/run/xray.json\0']:
            self.write('/proc/101/cmdline', argv, 0o444)
            with self.assertRaises(ValueError):
                self.validate()

    @unittest.skipUnless(os.name == 'posix', 'Проверка Unix metadata')
    def test_untrusted_runtime_mode_or_symlink_is_rejected(self):
        os.chmod(self.fs.path('/run/xray.json'), 0o666)
        with self.assertRaises(ValueError):
            self.validate()
        os.chmod(self.fs.path('/run/xray.json'), 0o600)
        self.fs.path('/run/xray.json').rename(self.fs.path('/run/other.json'))
        self.fs.path('/run/xray.json').symlink_to('other.json')
        with self.assertRaises(ValueError):
            self.validate()

    def test_missing_allocated_bridge_port_fails_closed(self):
        self.update_settings(routeXrayPort=0)
        with self.assertRaises(ValueError):
            self.validate()

    def test_service_only_without_bridge_needs_no_runtime(self):
        self.update_settings(routeThroughXray=False)
        result = self.validate(SOURCE.replace('            upstream socks5://bridge:secret@127.0.0.1:1080\n', ''))
        self.assertEqual(result['runtime_sha256'], '')
        self.assertEqual(result['process_epoch_sha256'], '')

    def test_bridge_username_is_not_excluded_from_semantic_digest(self):
        before = self.validate()
        self.runtime['inbounds'][0]['settings']['accounts'][0]['user'] = 'new-user'
        self.write('/run/xray.json', json.dumps(self.runtime).encode())
        after = self.validate(SOURCE.replace('socks5://bridge:', 'socks5://new-user:'))
        self.assertNotEqual(before['semantic_sha256'], after['semantic_sha256'])

    def test_duplicate_runtime_owner_and_malformed_percent_encoding_fail(self):
        with self.assertRaises(ValueError):
            self.validate(SOURCE.replace('bridge:secret@', 'bridge:%ZZ@'))
        self.write('/proc/102/comm', b'xray\n', 0o444)
        self.write('/proc/102/cmdline', b'/usr/local/bin/xray\0-c\0/run/xray.json\0', 0o444)
        with self.assertRaises(ValueError):
            self.validate()

    def test_database_change_during_runtime_check_fails_closed(self):
        from lucx_post_configurator import naive_runtime
        original = naive_runtime._runtime

        def drift(fs, upstream):
            result = original(fs, upstream)
            self.update_settings(authPass='changed-during-read')
            return result

        with patch.object(naive_runtime, '_runtime', side_effect=drift), self.assertRaises(ValueError):
            self.validate()

    def test_process_starttime_detects_pid_reuse_without_hashing_cpu_counters(self):
        self.write('/proc/101/stat', b'101 (xray) S ' + b'0 ' * 18 + b'123 0\n', 0o444)
        first = self.validate()
        self.write('/proc/101/stat', b'101 (xray) S 1 ' + b'0 ' * 17 + b'123 0\n', 0o444)
        self.assertEqual(first['runtime_sha256'], self.validate()['runtime_sha256'])
        self.assertEqual(first['process_epoch_sha256'], self.validate()['process_epoch_sha256'])
        self.write('/proc/101/stat', b'101 (xray) S ' + b'0 ' * 18 + b'124 0\n', 0o444)
        self.assertNotEqual(first['runtime_sha256'], self.validate()['runtime_sha256'])
        self.assertNotEqual(first['process_epoch_sha256'], self.validate()['process_epoch_sha256'])

    def test_process_epoch_changes_with_pid_but_not_config_argument(self):
        first = self.validate()
        self.write('/run/other.json', json.dumps(self.runtime).encode())
        self.write('/proc/101/cmdline', b'/usr/local/bin/xray\0-c\0/run/other.json\0', 0o444)
        moved = self.validate()
        self.assertNotEqual(first['runtime_sha256'], moved['runtime_sha256'])
        self.assertEqual(first['process_epoch_sha256'], moved['process_epoch_sha256'])
        self.fs.path('/proc/101').rename(self.fs.path('/proc/102'))
        self.assertNotEqual(first['process_epoch_sha256'], self.validate()['process_epoch_sha256'])


if __name__ == '__main__':
    unittest.main()
