from __future__ import annotations

import copy
from contextlib import closing
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from helpers import make_target
from test_endpoint_routing import aliased_topology
from test_naive_frontend import GENERATED_SOURCE
from lucx_post_configurator.discovery import audit_system
from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
from lucx_post_configurator.integrity import capture_integrity
from lucx_post_configurator.routing_profiles import inbound_routing_metadata
from lucx_post_configurator.targetfs import TargetFS


class NaiveGenerationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fs = TargetFS(self.root)
        self.db = make_target(self.root)
        self.source_path = '/usr/local/x-ui/bin/tunnel/naive-7.caddyfile'
        self.text = GENERATED_SOURCE.replace('naive.example.net', 'naive.example.test').replace(
            '            basic_auth "user two" "pass two"\n', '')
        self.settings = {'domain': 'naive.example.test', 'authUser': 'user-one',
                         'authPass': 'pass-one', 'routeThroughXray': True, 'routeXrayPort': 1080,
                         'certFile': '/cert/fullchain.pem', 'keyFile': '/cert/privkey.pem',
                         'clients': [], 'probeResistance': True}
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('DELETE FROM inbounds')
            conn.execute('INSERT INTO inbounds VALUES (7,?,?,1,?,?,?,?,?,?)', (
                'naive', 'synthetic', '127.0.0.1', 47863, json.dumps(self.settings), '{}',
                'naive.example.test', 'custom'))
            conn.commit()
        self.fs.atomic_write_text(self.source_path, self.text, mode=0o600)
        self.fs.atomic_write_text('/opt/caddy-naive', 'synthetic binary', mode=0o755)
        self.fs.atomic_write_text('/opt/xray', 'synthetic binary', mode=0o755)
        self.fs.atomic_write_text('/proc/101/comm', 'xray\n')
        self.fs.atomic_write('/proc/101/cmdline', b'/opt/xray\0-config\0/run/xray.json\0')
        self.runtime('secret')
        self.manifest = aliased_topology()
        self.manifest['components']['naive_frontend'] = True
        self.manifest['protocols'] = [dict(self.manifest['protocols'][0], protocol='naive',
            transport='tcp', internal_port=47863, domain='naive.example.test',
            sni_names=['naive.example.test'], public_endpoints=[])]
        self.manifest['decoys']['sites'] = [{'domain': 'naive.example.test',
            'root': '/var/www/lucx-decoys/naive.example.test'}]
        audit = self.audit()
        self.manifest['protocols'][0].update(inbound_routing_metadata(audit.inbounds[0]))
        self.manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(self.manifest, audit)
        self.manifest['integrity'] = capture_integrity(self.fs, '/etc/x-ui/x-ui.db', audit.naive_caddyfile)

    def runtime(self, password):
        self.fs.atomic_write_text('/run/xray.json', json.dumps({'inbounds': [{
            'protocol': 'socks', 'listen': '127.0.0.1', 'port': 1080,
            'settings': {'auth': 'password', 'accounts': [{'user': 'bridge', 'pass': password}]}
        }]}), mode=0o600)

    def audit(self):
        audit = audit_system(self.root)
        info = self.fs.path(self.source_path).stat()
        audit.naive_caddyfile = {'found': True, 'binary_path': '/opt/caddy-naive', 'files': [{
            'path': self.source_path, 'sha256': self.fs.sha256(self.source_path),
            'kind': 'file', 'mode': info.st_mode & 0o7777, 'uid': info.st_uid, 'gid': info.st_gid,
            'capabilities': {'forward_proxy': True, 'native_decoy': False}}]}
        return audit

    def regenerate(self, password='new-synthetic'):
        self.text = self.text.replace('bridge:secret@', f'bridge:{password}@')
        self.fs.atomic_write_text(self.source_path, self.text, mode=0o600)
        self.runtime(password)

    def prepare(self):
        from lucx_post_configurator.naive_lifecycle import prepare_naive_manifest
        return prepare_naive_manifest(self.fs, self.manifest, self.audit())

    def test_fresh_generation_rebinds_only_evidence_and_preserves_intent(self):
        before = copy.deepcopy(self.manifest)
        self.regenerate()
        candidate = self.prepare()
        route = candidate['decoys']['extended_routes'][0]
        self.assertEqual(route['source_caddyfile_sha256'], self.fs.sha256(self.source_path))
        self.assertEqual(candidate['protocols'], before['protocols'])
        self.assertEqual(candidate['network'], before['network'])
        self.assertEqual(self.manifest, before)
        self.assertIn('7', candidate['naive_generations'])

    def test_runtime_bridge_mismatch_is_rejected_without_secret_in_error(self):
        self.regenerate()
        self.runtime('wrong-secret')
        with self.assertRaisesRegex(ValueError, 'Naive') as caught:
            self.prepare()
        self.assertNotIn('wrong-secret', str(caught.exception))
        self.assertNotIn('new-synthetic', str(caught.exception))

    def test_client_auth_change_in_source_is_rejected(self):
        self.regenerate()
        self.fs.atomic_write_text(self.source_path, self.text.replace('pass-one', 'foreign-secret'), mode=0o600)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_foreign_upstream_and_unknown_directive_are_not_regeneration(self):
        for text in (self.text.replace('127.0.0.1:1080', '192.0.2.2:1080'),
                     self.text.replace('hide_via', 'foreign_directive')):
            with self.subTest(source=hashlib.sha256(text.encode()).hexdigest()[:8]):
                self.fs.atomic_write_text(self.source_path, text, mode=0o600)
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_prepared_generation_still_rejects_changes_after_confirmation(self):
        from lucx_post_configurator.engine import _ephemeral_routing_material, ApplyError
        candidate = self.prepare()
        self.regenerate()
        with self.assertRaises(ApplyError):
            _ephemeral_routing_material(self.fs, self.audit(), candidate)

    def test_existing_generation_rejects_protected_db_drift(self):
        self.manifest = self.prepare()
        with closing(sqlite3.connect(self.db)) as conn:
            changed = dict(self.settings, authPass='new-client-secret')
            conn.execute('UPDATE inbounds SET settings=? WHERE id=7', (json.dumps(changed),))
            conn.commit()
        with self.assertRaises(ValueError):
            self.prepare()

    def test_repeated_preparation_is_stable_and_never_changes_original(self):
        candidate = self.prepare()
        self.manifest = candidate
        before = self.fs.read_bytes(self.source_path)
        self.assertEqual(self.prepare(), candidate)
        self.assertEqual(self.fs.read_bytes(self.source_path), before)


if __name__ == '__main__':
    unittest.main()
