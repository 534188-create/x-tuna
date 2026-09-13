"""Искусственные receipts проверяют чистый валидатор, не работу VPN."""
from __future__ import annotations

import copy
import dataclasses
import importlib
import json
import tempfile
import unittest
from unittest import mock

from test_browser_staging_dial import receipt_fixture
from test_endpoint_routing import aliased_topology

from lucx_post_configurator import decoy_health as health
from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
from lucx_post_configurator.render_runtime import (
    ListenerKey,
    RenderRuntime,
    SocketAddress,
)
from lucx_post_configurator.renderers import GeneratedFile
from lucx_post_configurator.staging_integrity import capture_staged_candidate
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import stage_files


class StagingBindingTests(unittest.TestCase):
    def test_echo_address_is_bound_and_requires_complete_direct_cohort(self):
        from lucx_post_configurator.staging_probes import _decode_worker_result
        with mock.patch.object(self.api.secrets, 'token_hex', return_value='0' * 64):
            baseline = self.binding()
            own = self.binding(echo_address='192.0.2.10')
        self.assertNotEqual(baseline.fingerprint, own.fingerprint)
        payload = {'ok': True, 'binding': own.fingerprint, 'browser_rows': [], 'vpn_rows': [],
                   'cleanup_complete': True, 'listeners_verified': True, 'runtime_verified': True}
        with self.assertRaises(ValueError):
            _decode_worker_result(json.dumps(payload), own, self.manifest)
        payload['direct_rows'] = []
        with self.assertRaises(ValueError):
            _decode_worker_result(json.dumps(payload), own, self.manifest)

    def setUp(self):
        self.api = importlib.import_module('lucx_post_configurator.staging_binding')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fs = TargetFS(temporary.name)
        self.manifest = aliased_topology(8443)
        self.manifest['decoys']['require_full_acceptance'] = True
        for endpoint in self.manifest['protocols'][0]['public_endpoints']:
            endpoint.update(sni_source='explicit', keep_sni_blank=False, http_host='')
        self.manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(self.manifest)
        template = receipt_fixture('staging')[1][0]
        self.browser = [{**template, 'domain': target['domain'], 'path': target['path'], 'port': target['port'],
                         'method': method, 'http_version': version,
                         'profile_fingerprint': health._decoy_profile_fingerprint(self.manifest)}
                        for target in health.decoy_probe_targets(self.manifest, '127.0.0.1')
                        for method, version in health._target_matrix(target)]
        self.assertTrue(self.browser)
        targets, errors = health._vpn_targets(self.manifest)
        self.assertEqual(errors, [])
        self.vpn = [{**target['identity'], 'state': 'healthy', 'phase': 'staging',
                     'public': False, 'functional': True, 'authenticated': True,
                     'bytes_sent': 16, 'bytes_received': 32} for target in targets]
        self.generated = {'/etc/haproxy/haproxy.cfg': GeneratedFile(b'candidate\n', component='haproxy')}
        self.run_id = 'synthetic-binding'
        self.staged = stage_files(self.fs, self.generated, self.run_id)
        self.options = {'run_id': self.run_id, 'staged_seal': self.seal(),
            'routing_snapshot': {'enabled': [7]}, 'runtime_configs': {'haproxy': b'frontend\n', 'nginx': b'http {}\n'},
            'runtime': RenderRuntime({ListenerKey('public', 8443): SocketAddress('127.0.0.1', 41001)},
                                  foreground=True, suppress_system_log=True),
            'material_snapshot_digest': 'a' * 64,
            'toolchain': {'haproxy': {'sha256': 'b' * 64}, 'nginx': {'sha256': 'c' * 64}}}

    def seal(self):
        return capture_staged_candidate(self.fs, self.manifest, self.generated, self.staged, self.run_id)

    def binding(self, **changes):
        return self.api.create_candidate_binding(self.manifest, **{**self.options, **changes})

    def receipt(self, binding, *, browser=None, vpn=None, **changes):
        browser = self.browser if browser is None else browser
        vpn = self.vpn if vpn is None else vpn
        options = {'binding': binding, 'browser_rows': [{**r, 'candidate_fingerprint': binding.fingerprint}
                                                      for r in browser],
                       'vpn_rows': [{**r, 'candidate_fingerprint': binding.fingerprint} for r in vpn],
                       'cleanup_complete': True, 'sources_verified': True,
                       'listeners_verified': True, 'runtime_verified': True}
        return self.api.StagingReceipt(**{**options, **changes})

    def summary(self, binding, receipt, manifest=None):
        return self.api.staging_acceptance_summary(self.manifest if manifest is None else manifest,
                                                  receipt, expected_binding=binding)

    def test_fresh_nonce_and_canonical_inputs(self):
        first, second = self.binding(), self.binding()
        self.assertNotEqual(first.fingerprint, second.fingerprint)
        self.assertNotEqual(first.nonce, second.nonce)
        with mock.patch.object(self.api.secrets, 'token_hex', return_value='0' * 64):
            one = self.binding()
            reordered = dict(reversed(list(self.manifest.items())))
            two = self.api.create_candidate_binding(reordered, **self.options)
            self.assertEqual(one, two)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.run_id = 'different'

    def test_ingress_identity_is_bound_and_sorted_without_changing_legacy_layout(self):
        expected = {'listeners': [('public', 8443, '127.0.0.1', 41001)],
                    'paths': {}, 'foreground': True, 'suppress_system_log': True}
        self.assertEqual(self.binding().layout_sha256, self.api._digest(expected))
        first = ListenerKey('split', 7, ingress_port=443)
        second = ListenerKey('split', 7, ingress_port=8443)
        one = SocketAddress('127.0.0.1', 41001)
        two = SocketAddress('127.0.0.1', 41002)
        baseline = self.binding(runtime=RenderRuntime({first: one, second: two}))
        reordered = self.binding(runtime=RenderRuntime({second: two, first: one}))
        swapped = self.binding(runtime=RenderRuntime({first: two, second: one}))
        self.assertEqual(baseline.layout_sha256, reordered.layout_sha256)
        self.assertNotEqual(baseline.layout_sha256, swapped.layout_sha256)
        legacy = self.binding(runtime=RenderRuntime({ListenerKey('split', 7): one}))
        ingress = self.binding(runtime=RenderRuntime({first: one}))
        self.assertNotEqual(legacy.layout_sha256, ingress.layout_sha256)

    def test_native_sources_and_private_routing_material_are_bound_separately(self):
        baseline = self.binding()
        native = self.binding(native_sources={'bindings': ['synthetic']})
        routing = self.binding(routing_material=[{'inbound_id': 7, 'material': {'synthetic': True}}])
        self.assertNotEqual(baseline.native_sources_sha256, native.native_sources_sha256)
        self.assertNotEqual(baseline.routing_material_sha256, routing.routing_material_sha256)
        self.assertEqual(baseline.runtime_config_sha256, native.runtime_config_sha256)
        self.assertFalse(self.summary(baseline, self.receipt(native))['candidate_verified'])

    def test_each_candidate_input_is_bound(self):
        with mock.patch.object(self.api.secrets, 'token_hex', return_value='0' * 64):
            baseline = self.binding()
            variants = [{'run_id': 'different'}, {'routing_snapshot': {'enabled': [8]}},
                {'runtime_configs': {'haproxy': b'changed\n', 'nginx': b'http {}\n'}},
                {'runtime': RenderRuntime({ListenerKey('public', 8443): SocketAddress('127.0.0.1', 41002)})},
                {'material_snapshot_digest': 'd' * 64}, {'toolchain': {'haproxy': {'sha256': 'e' * 64}}}]
            for changes in variants:
                with self.subTest(field=next(iter(changes))):
                    self.assertNotEqual(self.binding(**changes).fingerprint, baseline.fingerprint)
            self.generated['/etc/haproxy/haproxy.cfg'] = GeneratedFile(b'other\n', component='haproxy')
            self.staged['/etc/haproxy/haproxy.cfg'].write_bytes(b'other\n')
            self.assertNotEqual(self.binding(staged_seal=self.seal()).fingerprint, baseline.fingerprint)

    def test_malformed_binding_inputs_are_rejected_without_raw_values(self):
        for changes in ({'run_id': '../sensitive-sentinel'}, {'material_snapshot_digest': 'sensitive-sentinel'},
                        {'runtime_configs': {'haproxy': b'x'}},
                        {'runtime_configs': {'haproxy': b'x', 'nginx': b'y', 'shell': b'z'}},
                        {'routing_snapshot': {'value': float('nan')}}, {'toolchain': {'x': object()}}):
            with self.subTest(field=next(iter(changes))), self.assertRaises(ValueError) as raised:
                self.binding(**changes)
            self.assertNotIn('sensitive-sentinel', str(raised.exception))

    def test_complete_validator_input_is_scoped_to_staging_and_does_not_expose_rows(self):
        binding = self.binding()
        receipt = self.receipt(binding)
        summary = self.summary(binding, receipt)
        self.assertTrue(summary['complete'], summary)
        self.assertTrue(summary['candidate_verified'])
        self.assertFalse(summary['public'])
        self.assertEqual(summary['phase'], 'staging')
        for value in (json.dumps(summary), repr(receipt), repr(binding)):
            self.assertNotIn('example.test', value)
            self.assertNotIn(binding.nonce, value)
        self.assertFalse(health.vpn_acceptance_summary(self.manifest, self.vpn)['complete'])
        self.assertFalse(health.decoy_acceptance_summary(self.manifest, self.browser)['complete'])

    def test_wrong_run_nonce_binding_and_manifest_are_rejected(self):
        expected = self.binding()
        for different in (self.binding(), dataclasses.replace(expected, run_id='another-run'),
                          dataclasses.replace(expected, nonce='0' * 64)):
            with self.subTest(binding=different.fingerprint):
                self.assertFalse(self.summary(expected, self.receipt(different))['complete'])
        changed = copy.deepcopy(self.manifest)
        changed['unrelated_but_committed_setting'] = True
        self.assertFalse(self.summary(expected, self.receipt(expected), changed)['complete'])

    def test_missing_cleanup_sources_listener_or_runtime_proof_cannot_pass(self):
        binding = self.binding()
        for field in ('cleanup_complete', 'sources_verified', 'listeners_verified', 'runtime_verified'):
            with self.subTest(field=field):
                self.assertFalse(self.summary(binding, self.receipt(binding, **{field: False}))['complete'])
            with self.assertRaises(ValueError):
                self.receipt(binding, **{field: 1})

    def test_missing_duplicate_extra_wrong_phase_and_unproven_rows_cannot_pass(self):
        binding = self.binding()
        for name, rows in (('browser', self.browser), ('vpn', self.vpn)):
            variants = [rows[:-1], rows + [copy.deepcopy(rows[0])]]
            fields = ({'phase': 'public', 'port': 9443, 'tls_verified': False, 'content_verified': False}
                      if name == 'browser' else {'phase': 'direct', 'authenticated': False,
                                                'bytes_sent': 0, 'bytes_received': True, 'inbound_id': 999})
            for key, value in fields.items():
                changed = copy.deepcopy(rows)
                changed[0][key] = value
                variants.append(changed)
            for index, variant in enumerate(variants):
                with self.subTest(kind=name, variant=index):
                    self.assertFalse(self.summary(binding, self.receipt(binding, **{name: variant}))['complete'])

    def test_each_row_requires_exact_binding_and_defensive_copy(self):
        binding = self.binding()
        original = self.receipt(binding)
        for field in ('browser_rows', 'vpn_rows'):
            rows = [dict(row) for row in getattr(original, field)]
            for value in (None, 'sha256:' + '0' * 64):
                changed = copy.deepcopy(rows)
                changed[0]['candidate_fingerprint'] = value
                receipt = dataclasses.replace(original, **{field: changed})
                self.assertFalse(self.summary(binding, receipt)['complete'])
            receipt = dataclasses.replace(original, **{field: rows})
            rows[0]['state'] = 'failed'
            self.assertTrue(self.summary(binding, receipt)['complete'])
            with self.assertRaises(TypeError):
                getattr(receipt, field)[0]['state'] = 'failed'

    def test_legacy_non_strict_or_disabled_decoys_cannot_bypass_binding_validator(self):
        for settings in ({'require_full_acceptance': False}, {'enabled': False}):
            self.manifest['decoys'].update(settings)
            binding = self.binding()
            self.assertFalse(self.summary(binding, self.receipt(binding))['complete'])


if __name__ == '__main__':
    unittest.main()
