"""Приватный DTO native staging не заменяет live source fences родителя."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import unittest
from dataclasses import FrozenInstanceError, asdict, replace
from unittest import mock

from test_naive_probes import profile

from lucx_post_configurator import staging_native
from lucx_post_configurator.naive_probes import NativeBackendBinding
from lucx_post_configurator.routing_profiles import routing_fingerprint


def fixture():
    protocol = profile()
    protocol.update(domain='vpn.example.test', sni_names=['vpn.example.test'])
    manifest = {'network': {'public_tcp_port': 443}, 'protocols': [protocol]}
    binding = NativeBackendBinding(profile_fingerprint=routing_fingerprint(protocol, 443),
        auth_policy_fingerprint='sha256:' + 'a' * 64, binding_fingerprint='sha256:' + 'b' * 64,
        caddy_pid=42, caddy_sha256='9a8a4d2cf9dd14040086cf5f1762eb8b4304f1dbc0c85784d8bdf27c2587956b',
        xray_pid=0, xray_sha256='', bridge_port=0, probe_resistance=True,
        backend_address='127.0.0.1', backend_port=protocol['internal_port'],
        backend_sni=protocol['sni_names'][0], backend_ca_pem='synthetic-test-ca')
    return manifest, {'echo_address': '192.0.2.10', 'bindings': [
        {'inbound_id': protocol['inbound_id'], 'binding': asdict(binding)}]}, binding


class NativePayloadTests(unittest.TestCase):
    def test_decode_returns_exact_readonly_mapping(self):
        manifest, payload, binding = fixture()
        values, address = staging_native.decode_native_payload(payload, manifest)
        self.assertEqual(values, {manifest['protocols'][0]['inbound_id']: binding})
        self.assertEqual(address, '192.0.2.10')
        with self.assertRaises(TypeError):
            values[10] = binding

    def test_duplicate_missing_extra_and_wrong_field_types_fail_closed(self):
        manifest, payload, _ = fixture()
        mutations = (
            lambda p: p.update(bindings=[]),
            lambda p: p['bindings'].append(copy.deepcopy(p['bindings'][0])),
            lambda p: p['bindings'][0].update(inbound_id=True),
            lambda p: p['bindings'][0].update(unknown='rejected'),
            lambda p: p.update(unknown='rejected'),
            lambda p: p['bindings'][0]['binding'].pop('backend_ca_pem'),
            lambda p: p['bindings'][0]['binding'].update(caddy_pid=True),
            lambda p: p['bindings'][0]['binding'].update(probe_resistance=1),
            lambda p: p['bindings'][0]['binding'].update(backend_port=True),
            lambda p: p['bindings'][0]['binding'].update(xray_pid=43, bridge_port=1080, xray_sha256='e' * 64),
            lambda p: p['bindings'][0]['binding'].update(backend_port=1),
            lambda p: p['bindings'][0]['binding'].update(profile_fingerprint='sha256:' + 'f' * 64),
            lambda p: p.update(echo_address='127.0.0.1'),
            lambda p: p.update(echo_address='::1'),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                changed = copy.deepcopy(payload)
                mutate(changed)
                with self.assertRaisesRegex(ValueError, '^Набор native staging не подтверждён$'):
                    staging_native.decode_native_payload(changed, manifest)

    def test_cohort_must_include_every_active_naive_and_exact_policy(self):
        manifest, payload, binding = fixture()
        second = copy.deepcopy(manifest['protocols'][0])
        second['inbound_id'] = 8
        manifest['protocols'].append(second)
        with self.assertRaises(ValueError):
            staging_native.decode_native_payload(payload, manifest)
        second_binding = replace(binding, profile_fingerprint=routing_fingerprint(second, 443))
        payload['bindings'].append({'inbound_id': 8, 'binding': asdict(second_binding)})
        self.assertEqual(set(staging_native.decode_native_payload(payload, manifest)[0]), {7, 8})
        payload['bindings'][1]['binding']['auth_policy_fingerprint'] = 'sha256:' + 'c' * 64
        with self.assertRaises(ValueError):
            staging_native.decode_native_payload(payload, manifest)

    def test_manifest_cohort_duplicates_disabled_unknown_ids_and_empty_are_rejected(self):
        manifest, payload, _ = fixture()
        for kind in ('duplicate', 'disable', 'empty', 'bool', 'id'):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(manifest)
                if kind == 'duplicate':
                    changed['protocols'].append(copy.deepcopy(changed['protocols'][0]))
                elif kind == 'disable':
                    changed['protocols'][0]['enable'] = False
                elif kind == 'empty':
                    changed['protocols'] = []
                elif kind == 'bool':
                    changed['protocols'][0]['enable'] = 1
                else:
                    changed['protocols'][0]['inbound_id'] = 100
                with self.assertRaises(ValueError):
                    staging_native.decode_native_payload(payload, changed)

    def test_digest_is_exact_canonical_json_and_rejects_untyped_objects(self):
        _, payload, _ = fixture()
        expected = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'),
            ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()
        self.assertEqual(staging_native.native_payload_digest(payload), expected)
        self.assertEqual(staging_native.native_payload_digest(dict(reversed(list(payload.items())))), expected)
        payload['bindings'][0]['binding']['backend_port'] = 19443.0
        with self.assertRaises(ValueError):
            staging_native.native_payload_digest(payload)

    def test_callbacks_cannot_construct_a_genuine_live_native_set(self):
        manifest, _, binding = fixture()
        with self.assertRaises(ValueError):
            staging_native.NativeStagingSet({7: binding}, '192.0.2.10', manifest,
                                            mock.Mock(), mock.Mock(return_value=binding))


@unittest.skipUnless(sys.platform == 'linux' and os.environ.get('XTUNA_TEST_CADDY') == '/usr/local/bin/caddy',
                     'Нужен изолированный Debian native fixture')
class NativeStagingLiveTests(unittest.TestCase):
    def test_real_capture_payload_decode_and_parent_fences_preserve_sources(self):
        import test_naive_native
        helper = test_naive_native.NativeSourceLiveTests()
        self.addCleanup(helper.doCleanups)
        with helper.fixture(resistance=True) as (actual, root, _, pem):
            actual.manifest['lucx'] = {'db_path': actual.db_path}
            actual.audit.public_addresses = ['::1', '127.0.0.1', '192.0.2.10']
            before = actual.snapshot()
            native = staging_native.capture(actual.fs, actual.manifest, actual.audit)
            with self.assertRaises(FrozenInstanceError):
                native.echo_address = '192.0.2.11'
            with self.assertRaises(TypeError):
                native.bindings[7] = None
            self.assertIsNone(native.verify(actual.manifest))
            credential = native.credential(actual.protocol)
            self.assertIsNotNone(credential)
            binding = native.binding(actual.protocol)
            payload = native.private_payload()
            values, address = staging_native.decode_native_payload(payload, actual.manifest)
            self.assertEqual(values, {7: binding})
            self.assertEqual(address, '192.0.2.10')
            self.assertEqual(binding.auth_policy_fingerprint, credential.policy_fingerprint)
            self.assertEqual(binding.backend_ca_pem, pem)
            encoded = json.dumps(payload)
            for value in (str(root), actual.db_path, actual.settings['authPass'], credential.password,
                          credential.username, actual.panel_secret):
                self.assertNotIn(value, encoded)
                self.assertNotIn(value, repr(native))
            self.assertEqual(before, actual.snapshot())
            self.assertRegex(staging_native.native_payload_digest(payload), '^[0-9a-f]{64}$')
            actual.sql('UPDATE clients SET limit_ip=1 WHERE id=2')
            with self.assertRaisesRegex(ValueError, '^Набор native staging не подтверждён$'):
                native.verify(actual.manifest)
            # Старый DTO остаётся синтаксически валидным; свежесть доказывает parent fence.
            self.assertEqual(staging_native.decode_native_payload(payload, actual.manifest)[0], values)
            actual.sql('UPDATE clients SET limit_ip=0 WHERE id=2')
            self.assertIsNone(native.binding(actual.protocol))
            self.assertIsNone(native.credential(actual.protocol))
            with self.assertRaises(ValueError):
                native.private_payload()


if __name__ == '__main__':
    unittest.main()
