"""Контракты coordinator: подмена источника и результата не разрешает commit."""
from __future__ import annotations

import copy
import importlib
import json
import unittest
import uuid
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from test_naive_connect_frontend import common_fixture
from test_staging_eligibility import candidate_manifest

from lucx_post_configurator.naive_probes import NaiveProbeCredential
from lucx_post_configurator.render_runtime import (
    ListenerKey,
    RenderRuntime,
    SocketAddress,
)
from lucx_post_configurator.routing_profiles import routing_fingerprint
from lucx_post_configurator.runner import CommandResult
from lucx_post_configurator.vpn_probes import XrayProbeCredential


class InstalledStagingToolTests(unittest.TestCase):
    def test_optional_naive_tool_has_fixed_client_pin_and_no_unknown_roles(self):
        from lucx_post_configurator.naive_probes import NAIVE_SHA256
        api = importlib.import_module('lucx_post_configurator.staging_probes')
        binaries = {role: (Path.cwd() / 'synthetic' / role, 'a' * 64)
                    for role in ('haproxy', 'nginx', 'xray', 'curl', 'naive')}
        binaries['xray'] = (Path.cwd() / 'synthetic/xray', api.XRAY_SHA256)
        binaries['naive'] = (Path.cwd() / 'synthetic/naive', NAIVE_SHA256)
        tools = api.StagingTools(binaries, api.ServiceIdentity(123, 123))
        self.assertIn('naive', tools.binaries)
        with self.assertRaises(ValueError):
            api.StagingTools({**binaries, 'naive': (Path.cwd() / 'synthetic/naive', 'a' * 64)}, tools.identity)
        with self.assertRaises(ValueError):
            api.StagingTools({**binaries, 'future': binaries['naive']}, tools.identity)

    def test_private_material_preserves_numeric_identity_without_duplicate_collapse(self):
        api = importlib.import_module('lucx_post_configurator.staging_probes')
        value = {7: {'naive_caddyfile_text': 'synthetic-source', 'naive_source_metadata': {'sha256': 'a' * 64}}}
        payload = api._material_payload(value)
        self.assertEqual(api._decode_material(payload), value)
        for invalid in (payload + payload, [{'inbound_id': True, 'material': {}}],
                        [{'inbound_id': 7, 'material': {}, 'unexpected': True}], {}):
            with self.assertRaises(ValueError):
                api._decode_material(invalid)
        with self.assertRaises(ValueError):
            api._material_payload({7: {}, '7': {}})

    def test_haproxy_uses_effective_systemd_exec_including_tested_override(self):
        api = importlib.import_module('lucx_post_configurator.staging_probes')
        resolve = getattr(api, '_installed_haproxy_path', None)
        self.assertTrue(callable(resolve), 'Staging должен выбирать фактический ExecStart HAProxy')
        for path in ('/usr/sbin/haproxy', '/usr/local/sbin/haproxy'):
            text = '{ path=' + path + ' ; argv[]=' + path + ' -Ws -f $CONFIG -p $PIDFILE $EXTRAOPTS ; ignore_errors=no ; }\n'
            runner = mock.Mock()
            runner.run_bounded.return_value = CommandResult([], 0, text, '')
            self.assertEqual(resolve(runner), Path(path))

    def test_unknown_ambiguous_or_unavailable_exec_never_falls_back_to_old_binary(self):
        api = importlib.import_module('lucx_post_configurator.staging_probes')
        resolve = getattr(api, '_installed_haproxy_path', None)
        self.assertTrue(callable(resolve))
        good = '{ path=/usr/sbin/haproxy ; argv[]=/usr/sbin/haproxy -Ws ; }'
        for text, status in ((good, 1), ('', 0), (good + ' ' + good, 0),
                (good.replace('/usr/sbin/haproxy', '/tmp/haproxy'), 0),
                (good.replace('path=/usr/sbin/haproxy', 'path=haproxy'), 0)):
            runner = mock.Mock()
            runner.run_bounded.return_value = CommandResult([], status, text, '')
            with self.subTest(text=text, status=status), self.assertRaises(ValueError):
                resolve(runner)

    def test_effective_exec_accepts_systemd_status_without_trailing_semicolon(self):
        api = importlib.import_module('lucx_post_configurator.staging_probes')
        runner = mock.Mock()
        runner.run_bounded.return_value = CommandResult([], 0,
            '{ path=/usr/local/sbin/haproxy ; argv[]=/usr/local/sbin/haproxy -Ws '
            '-f $CONFIG -p $PIDFILE $EXTRAOPTS ; ignore_errors=no ; '
            'start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n', '')
        self.assertEqual(api._installed_haproxy_path(runner), Path('/usr/local/sbin/haproxy'))


class StagingCredentialSetTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('lucx_post_configurator.staging_probes')
        self.manifest = candidate_manifest()
        self.user_id = str(uuid.uuid4())
        self.policy = 'sha256:' + 'a' * 64

    def source(self, protocol):
        return XrayProbeCredential(self.user_id, routing_fingerprint(protocol, 443), '', self.policy)

    def test_capture_preserves_client_for_every_endpoint_without_manifest_mutation(self):
        original = copy.deepcopy(self.manifest)
        selected = self.api.StagingCredentialSet.capture(self.manifest, self.source)
        selected.verify(self.manifest)
        self.assertEqual(self.manifest, original)
        self.assertEqual(len(selected.entries), 2)
        self.assertNotIn(self.user_id, repr(selected))
        with self.assertRaises(TypeError):
            selected.entries['unexpected'] = self.source(self.manifest['protocols'][0])

    def test_changed_client_policy_and_revocation_reject_the_original_candidate(self):
        for change in ('client', 'policy', 'revoked'):
            selected = self.api.StagingCredentialSet.capture(self.manifest, self.source)
            with self.subTest(change=change):
                if change == 'client':
                    self.user_id = str(uuid.uuid4())
                elif change == 'policy':
                    self.policy = 'sha256:' + 'b' * 64
                else:
                    self.policy = ''
                with self.assertRaises(ValueError):
                    selected.verify(self.manifest)

    def test_source_failure_is_scrubbed(self):
        def unavailable(protocol):
            raise ValueError(self.user_id)
        with self.assertRaises(ValueError) as caught:
            self.api.StagingCredentialSet.capture(self.manifest, unavailable)
        self.assertNotIn(self.user_id, str(caught.exception))

    def test_manifest_endpoint_drift_and_missing_credential_block_the_whole_set(self):
        selected = self.api.StagingCredentialSet.capture(self.manifest, self.source)
        self.manifest['protocols'][0]['public_endpoints'].pop()
        with self.assertRaises(ValueError):
            selected.verify(self.manifest)
        self.manifest = candidate_manifest()
        with self.assertRaises(ValueError):
            self.api.StagingCredentialSet.capture(self.manifest, lambda protocol: None)

    def test_wire_payload_contains_only_selected_entries_and_is_not_a_public_report(self):
        selected = self.api.StagingCredentialSet.capture(self.manifest, self.source)
        wire = selected.private_payload()
        self.assertEqual(len(wire), 2)
        self.assertIn(self.user_id, json.dumps(wire))
        wire[0]['credential']['user_id'] = str(uuid.uuid4())
        selected.verify(self.manifest)
        self.assertTrue(all(value.user_id == self.user_id for value in selected.entries.values()))

    def test_xray_private_payload_preserves_legacy_schema_and_bytes(self):
        for protocol in ('vless', 'vmess'):
            self.manifest['protocols'][0]['protocol'] = protocol
            with self.subTest(protocol=protocol):
                selected = self.api.StagingCredentialSet.capture(self.manifest, self.source)
                expected = [{'key': key, 'credential': {'user_id': self.user_id,
                            'profile_fingerprint': value.profile_fingerprint, 'ca_pem': '',
                            'policy_fingerprint': self.policy}} for key, value in selected.entries.items()]
                self.assertEqual(json.dumps(selected.private_payload()), json.dumps(expected))
                decoded = self.api._decode_credentials(json.loads(json.dumps(expected)), self.manifest)
                self.assertEqual(decoded, dict(selected.entries))


class MixedStagingCredentialSetTests(unittest.TestCase):
    """Синтетический callable проверяет typing, но не подтверждает политику LucX DB."""

    def setUp(self):
        self.api = importlib.import_module('lucx_post_configurator.staging_probes')
        self.manifest, _, _ = common_fixture()
        self.manifest['components']['install_packages'] = False
        self.manifest['decoys']['require_full_acceptance'] = True
        self.user_id = str(uuid.uuid4())
        self.policy = 'sha256:' + 'a' * 64
        self.changed_endpoint = None

    def source(self, protocol):
        fingerprint = routing_fingerprint(protocol, 443)
        if protocol['protocol'] == 'naive':
            password = ('synthetic-changed' if protocol['acceptance_endpoint']['host_id'] == self.changed_endpoint
                        else 'synthetic-password')
            return NaiveProbeCredential('synthetic-user', password, fingerprint, '', self.policy)
        return XrayProbeCredential(self.user_id, fingerprint, '', self.policy)

    def capture(self, source=None):
        return self.api.StagingCredentialSet.capture(self.manifest, source or self.source)

    def test_mixed_capture_private_roundtrip_retains_every_exact_target_and_hides_auth(self):
        original = copy.deepcopy(self.manifest)
        selected = self.capture()
        targets, errors = self.api._vpn_targets(self.manifest)
        self.assertFalse(errors)
        self.assertEqual(len(selected.entries), len(targets))
        self.assertEqual(sum(type(value) is NaiveProbeCredential for value in selected.entries.values()), 2)
        wire = selected.private_payload()
        decoded = self.api._decode_credentials(json.loads(json.dumps(wire)), self.manifest)
        self.assertEqual(decoded, dict(selected.entries))
        self.assertEqual(self.manifest, original)
        selected.verify(self.manifest)
        for row in wire:
            value = selected.entries[row['key']]
            if type(value) is NaiveProbeCredential:
                self.assertEqual(set(row), {'key', 'type', 'credential'})
                self.assertEqual(row['type'], 'naive')
            else:
                self.assertEqual(set(row), {'key', 'credential'})
        self.assertNotIn('synthetic-password', repr(selected))
        naive_row = next(row for row in wire if row.get('type') == 'naive')
        naive_row['credential']['password'] = 'synthetic-replaced-wire-only'
        selected.verify(self.manifest)

    def test_wrong_family_and_unknown_protocol_cannot_capture_any_endpoint(self):
        for family in ('wrong-naive', 'wrong-xray'):
            def wrong(protocol, family=family):
                if family == 'wrong-naive' and protocol['protocol'] == 'naive':
                    return XrayProbeCredential(self.user_id, routing_fingerprint(protocol, 443), '', self.policy)
                if family == 'wrong-xray' and protocol['protocol'] != 'naive':
                    return NaiveProbeCredential('synthetic-user', 'synthetic-pass',
                                                routing_fingerprint(protocol, 443), '', self.policy)
                return self.source(protocol)
            with self.subTest(family=family), self.assertRaises(ValueError):
                self.capture(wrong)
        for unknown in ('unknown', True, None):
            manifest = copy.deepcopy(self.manifest)
            manifest['protocols'][1]['protocol'] = unknown
            with self.subTest(unknown=unknown), self.assertRaises(ValueError):
                self.api.StagingCredentialSet.capture(manifest, self.source)

    def test_source_cannot_change_current_protocol_to_switch_credential_family(self):
        def mutating(protocol):
            protocol['protocol'] = 'vless'
            return XrayProbeCredential(self.user_id, routing_fingerprint(protocol, 443), '', self.policy)
        with self.assertRaises(ValueError):
            self.capture(mutating)

    def test_naive_auth_ca_and_fingerprints_are_bounded_and_typed(self):
        targets, _ = self.api._vpn_targets(self.manifest)
        protocol = self.api._probe_protocol(next(t for t in targets if t['protocol']['protocol'] == 'naive'), 'staging')
        original = self.source(protocol)
        fields = {'username': original.username, 'password': original.password,
                  'profile_fingerprint': original.profile_fingerprint, 'ca_pem': original.ca_pem,
                  'policy_fingerprint': original.policy_fingerprint}
        for field in ('username', 'password'):
            for value in ('', True, None, 'x\x00y', 'x\ny', 'x\ry', 'я' * 513):
                with self.subTest(field=field, kind=type(value).__name__):
                    credential = NaiveProbeCredential(**{**fields, field: value})
                    self.assertFalse(self.api._valid_credential(credential, protocol, 443))
        for field, values in (('ca_pem', (True, None, 'x' * 65537, 'я' * 32769)),
                              ('profile_fingerprint', ('', True, 'sha256:' + 'b' * 64)),
                              ('policy_fingerprint', ('', True, None, 'not-a-fingerprint'))):
            for value in values:
                with self.subTest(field=field, kind=type(value).__name__):
                    credential = NaiveProbeCredential(**{**fields, field: value})
                    self.assertFalse(self.api._valid_credential(credential, protocol, 443))
        bounded = NaiveProbeCredential(**{**fields, 'username': 'я' * 512, 'password': 'x' * 1024,
                                         'ca_pem': 'x' * 65536})
        self.assertTrue(self.api._valid_credential(bounded, protocol, 443))

    def test_private_decoder_rejects_missing_extra_duplicate_and_unknown_tags(self):
        wire = self.capture().private_payload()
        variants = [[], wire[:-1], wire + [copy.deepcopy(wire[0])], {}, None, True]
        extra = copy.deepcopy(wire)
        extra.append({**extra[0], 'key': 'f' * 64})
        variants.append(extra)
        for row_index, row in enumerate(wire):
            for invalid in (None, True, [], 'sensitive-sentinel'):
                changed = copy.deepcopy(wire)
                changed[row_index] = invalid
                variants.append(changed)
                changed = copy.deepcopy(wire)
                changed[row_index]['credential'] = invalid
                variants.append(changed)
            for field in row:
                changed = copy.deepcopy(wire)
                del changed[row_index][field]
                variants.append(changed)
            for fields in ({'extra': None}, {'key': True}, {'key': 'sensitive-sentinel'},
                           {'type': 'unknown'}, {'type': True}, {'type': 'xray'}):
                changed = copy.deepcopy(wire)
                changed[row_index].update(fields)
                variants.append(changed)
            for field in row['credential']:
                changed = copy.deepcopy(wire)
                del changed[row_index]['credential'][field]
                variants.append(changed)
                changed = copy.deepcopy(wire)
                changed[row_index]['credential'][field] = True
                variants.append(changed)
            for fields in ({'extra': None}, {'profile_fingerprint': 'sha256:' + 'f' * 64}):
                changed = copy.deepcopy(wire)
                changed[row_index]['credential'].update(fields)
                variants.append(changed)
        for index, variant in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError) as caught:
                self.api._decode_credentials(variant, self.manifest)
            self.assertNotIn('sensitive-sentinel', str(caught.exception))
            self.assertNotIn('synthetic-password', str(caught.exception))

    def test_decoder_selects_family_from_current_target_not_payload_tag(self):
        wire = self.capture().private_payload()
        naive_index = next(i for i, row in enumerate(wire) if row.get('type') == 'naive')
        xray_index = next(i for i, row in enumerate(wire) if 'type' not in row)
        for first, second in ((naive_index, xray_index), (xray_index, naive_index)):
            changed = copy.deepcopy(wire)
            changed[first] = {**changed[second], 'key': changed[first]['key']}
            with self.subTest(first=first), self.assertRaises(ValueError):
                self.api._decode_credentials(changed, self.manifest)

    def test_unselected_endpoint_source_policy_and_manifest_drift_invalidate_full_set(self):
        selected = self.capture()
        naive = self.manifest['protocols'][0]
        self.changed_endpoint = naive['public_endpoints'][1]['host_id']
        with self.assertRaises(ValueError):
            selected.verify(self.manifest)
        self.changed_endpoint = None
        self.policy = 'sha256:' + 'b' * 64
        with self.assertRaises(ValueError):
            selected.verify(self.manifest)
        self.policy = 'sha256:' + 'a' * 64
        wire = selected.private_payload()
        naive['public_endpoints'][1]['port'] = 9443
        with self.assertRaises(ValueError):
            selected.verify(self.manifest)
        with self.assertRaises(ValueError):
            self.api._decode_credentials(wire, self.manifest)

    def test_missing_single_endpoint_credential_and_duplicate_manifest_target_fail_closed(self):
        naive_endpoint = self.manifest['protocols'][0]['public_endpoints'][1]['host_id']
        def missing(protocol):
            if protocol['protocol'] == 'naive' and protocol['acceptance_endpoint']['host_id'] == naive_endpoint:
                return None
            return self.source(protocol)
        with self.assertRaises(ValueError):
            self.capture(missing)
        wire = self.capture().private_payload()
        naive = self.manifest['protocols'][0]
        naive['public_endpoints'].append(copy.deepcopy(naive['public_endpoints'][1]))
        with self.assertRaises(ValueError):
            self.capture()
        with self.assertRaises(ValueError):
            self.api._decode_credentials(wire, self.manifest)

    def test_naive_cohort_does_not_open_production_preflight_or_worker(self):
        # Валидный synthetic cohort сам по себе не разрешает production source/observer.
        self.assertTrue(self.capture().entries)
        self.assertTrue(self.api.staging_eligibility_errors(self.manifest))
        with mock.patch.object(self.api.sys, 'platform', 'linux'), \
                mock.patch.object(self.api.os, 'geteuid', return_value=0, create=True), \
                mock.patch.object(self.api, 'installed_staging_tools') as tools, \
                mock.patch.object(self.api, 'LucXXrayCredentialSource') as source:
            with self.assertRaises(ValueError):
                self.api.prepare_functional_staging(mock.Mock(), mock.Mock(dry_run=False), self.manifest)
            tools.assert_not_called()
            source.assert_not_called()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.api.sys, 'platform', 'linux'))
            for name in ('geteuid', 'getpid', 'getpgrp', 'getsid'):
                stack.enter_context(mock.patch.object(self.api.os, name,
                                   return_value=0 if name == 'geteuid' else 12345, create=True))
            decoder = stack.enter_context(mock.patch.object(self.api, '_decode_credentials'))
            session = stack.enter_context(mock.patch.object(self.api, 'ForegroundSession'))
            result = self.api._worker({'manifest': self.manifest, 'packages_ready': False})
            self.assertEqual(result, {'ok': False, 'reason': 'staging_failed'})
            decoder.assert_not_called()
            session.assert_not_called()


class StagingOrchestrationGuardTests(unittest.TestCase):
    def test_mixed_candidate_without_live_native_set_never_allocates_materials(self):
        manifest, _, material = common_fixture()
        manifest['components']['install_packages'] = False
        manifest['decoys']['require_full_acceptance'] = True
        seal = self.api.StagedCandidateSeal('a' * 64, ())
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.api.sys, 'platform', 'linux'))
            stack.enter_context(mock.patch.object(self.api.os, 'geteuid', return_value=0, create=True))
            stack.enter_context(mock.patch.object(self.api.StagedCandidateSeal, 'verify'))
            stack.enter_context(mock.patch.object(self.api.StagingCredentialSet, 'capture'))
            materials = stack.enter_context(mock.patch.object(self.api, 'create_staging_materials'))
            with self.assertRaises(ValueError):
                self.api.run_functional_staging(mock.Mock(), mock.Mock(dry_run=False), manifest,
                    {}, {}, 'synthetic-run', staged_seal=seal, routing_snapshot={}, routing_material=material,
                    tools=mock.Mock(), credential_source=mock.Mock())
            materials.assert_not_called()

    def test_native_worker_receipt_requires_complete_direct_cohort(self):
        from test_staging_binding import StagingBindingTests
        fixture = StagingBindingTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        binding = fixture.binding(native_sources={'synthetic': True})
        payload = {'ok': True, 'binding': binding.fingerprint,
                   'browser_rows': fixture.browser, 'vpn_rows': fixture.vpn,
                   'cleanup_complete': True, 'listeners_verified': True, 'runtime_verified': True}
        with self.assertRaises(ValueError):
            self.api._decode_worker_result(json.dumps(payload), binding, fixture.manifest)
        direct = [{**row, 'phase': 'direct', 'candidate_fingerprint': binding.fingerprint}
                  for row in fixture.vpn]
        for rows in ([], direct[:-1], [{**row, 'state': 'failed'} for row in direct]):
            with self.assertRaises(ValueError):
                self.api._decode_worker_result(json.dumps({**payload, 'direct_rows': rows}), binding, fixture.manifest)
        self.assertEqual(self.api._decode_worker_result(
            json.dumps({**payload, 'direct_rows': direct}), binding, fixture.manifest).binding, binding)

    def setUp(self):
        self.api = importlib.import_module('lucx_post_configurator.staging_probes')

    def test_coordinator_passes_same_ephemeral_material_to_both_renderers(self):
        manifest = candidate_manifest()
        material = {7: {'synthetic_ephemeral': object()}}
        seal = self.api.StagedCandidateSeal('a' * 64, ())
        runner = mock.Mock(dry_run=False)
        materials = mock.Mock(paths={}, mime_path=Path('/private/mime.types'))
        workspace = mock.Mock(runtime_root=Path('/private/runtime'))
        # Останавливаемся после обоих renderer, до сериализации и запуска worker.
        workspace.write_configs.side_effect = ValueError('synthetic-stop-after-render')
        stream = mock.Mock()
        stream.getsockname.return_value = ('127.0.0.1', 41001)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.api.sys, 'platform', 'linux'))
            stack.enter_context(mock.patch.object(self.api.os, 'geteuid', return_value=0, create=True))
            stack.enter_context(mock.patch.object(self.api.StagedCandidateSeal, 'verify'))
            stack.enter_context(mock.patch.object(self.api.StagingCredentialSet, 'capture'))
            stack.enter_context(mock.patch.object(self.api, 'create_staging_materials', return_value=materials))
            stack.enter_context(mock.patch.object(self.api, 'create_staging_workspace', return_value=workspace))
            inventory = stack.enter_context(mock.patch.object(self.api, 'frontend_listener_inventory',
                                           return_value=(ListenerKey('public', 443),)))
            stack.enter_context(mock.patch.object(self.api.socket, 'socket', return_value=stream))
            haproxy = stack.enter_context(mock.patch.object(self.api, 'render_haproxy', return_value='frontend'))
            nginx = stack.enter_context(mock.patch.object(self.api, 'render_nginx_decoys', return_value='server {}'))
            with self.assertRaises(ValueError):
                self.api.run_functional_staging(mock.Mock(), runner, manifest, {}, {}, 'synthetic-render',
                    staged_seal=seal, routing_snapshot={}, routing_material=material,
                    tools=mock.Mock(), credential_source=mock.Mock())
        inventory.assert_called_once_with(manifest, routing_material=material)
        haproxy.assert_called_once()
        nginx.assert_called_once()
        self.assertIs(haproxy.call_args.kwargs['routing_material'], material)
        self.assertIs(nginx.call_args.kwargs['routing_material'], material)
        self.assertIs(haproxy.call_args.kwargs['runtime'], nginx.call_args.kwargs['runtime'])
        workspace.write_configs.assert_called_once()
        runner.run_bounded.assert_not_called()
        stream.close.assert_called_once()

    def test_listener_ipc_preserves_legacy_and_per_ingress_identity(self):
        legacy = ListenerKey('public', 443)
        first = ListenerKey('split', 7, ingress_port=443)
        second = ListenerKey('split', 7, ingress_port=8443)
        runtime = RenderRuntime({second: SocketAddress('127.0.0.1', 41003),
                                 first: SocketAddress('127.0.0.1', 41002),
                                 legacy: SocketAddress('127.0.0.1', 41001)},
                                foreground=True, suppress_system_log=True)
        wire = self.api._layout(runtime)
        self.assertEqual(wire['listeners'], [('public', 443, '127.0.0.1', 41001),
                         ('split', 7, '127.0.0.1', 41002, 443),
                         ('split', 7, '127.0.0.1', 41003, 8443)])
        decoded = self.api._decode_runtime(json.loads(json.dumps(wire)), set(runtime.listeners))
        self.assertEqual(decoded, runtime)
        wire_digest = self.api._digest(wire)
        reordered = RenderRuntime(dict(reversed(list(runtime.listeners.items()))),
                                  foreground=True, suppress_system_log=True)
        self.assertEqual(wire_digest, self.api._digest(self.api._layout(reordered)))
        variants = []
        for index in (1, 2):
            missing = json.loads(json.dumps(wire))
            missing['listeners'].pop(index)
            variants.append(missing)
        duplicate = json.loads(json.dumps(wire))
        duplicate['listeners'].append(duplicate['listeners'][1].copy())
        variants.append(duplicate)
        for replacement in (['split', 7, '127.0.0.1', 41003],
                            ['split', 7, '127.0.0.1', 41003, 9443],
                            ['split', 7, '127.0.0.1', 41002, 8443]):
            changed = json.loads(json.dumps(wire))
            changed['listeners'][2] = replacement
            variants.append(changed)
        extra = json.loads(json.dumps(wire))
        extra['listeners'].append(['split', 7, '127.0.0.1', 41004, 9443])
        variants.append(extra)
        for index, variant in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.api._decode_runtime(variant, set(runtime.listeners))

    def test_listener_ipc_rejects_ambiguous_noncanonical_and_incomplete_layouts(self):
        expected = {ListenerKey('public', 443), ListenerKey('split', 7)}
        valid = {'listeners': [['public', 443, '127.0.0.1', 41001],
                               ['split', 7, '127.0.0.1', 41002]],
                 'paths': {}, 'foreground': True, 'suppress_system_log': True}
        self.assertEqual(set(self.api._decode_runtime(valid, expected).listeners), expected)
        variants = []
        for rows in (valid['listeners'][:1], valid['listeners'] + [valid['listeners'][1]],
                     valid['listeners'] + [['split', 8, '127.0.0.1', 41003]],
                     [valid['listeners'][0], ['split', 7, '127.0.0.1', 41001]]):
            variants.append({**valid, 'listeners': rows})
        for row in (['split', 7, '127.0.0.1', 41002, 0],
                    ['split', 7, '127.0.0.1', 41002, True],
                    ['split', 7, '127.0.0.1', 41002, False],
                    ['split', 7, '127.0.0.1', 41002, -1],
                    ['split', 7, '127.0.0.1', 41002, 65536],
                    ['split', 7, '127.0.0.1', 41002, '443'],
                    ['public', 443, '127.0.0.1', 41002, 443],
                    ['split', True, '127.0.0.1', 41002],
                    ['split', 7, '127.0.0.1', True], ['split', 7],
                    ['split', 7, '127.0.0.1', 41002, 443, 'extra']):
            variants.append({**valid, 'listeners': [valid['listeners'][0], row]})
        for field in valid:
            variant = copy.deepcopy(valid)
            del variant[field]
            variants.append(variant)
        variants.extend(({**valid, 'extra': None}, {**valid, 'foreground': 1},
                         {**valid, 'suppress_system_log': False}, {**valid, 'listeners': {}}))
        for index, variant in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.api._decode_runtime(variant, expected)

    def test_unsupported_and_dry_run_candidates_cannot_create_runtime_or_fake_acceptance(self):
        from lucx_post_configurator.runner import Runner
        from lucx_post_configurator.targetfs import TargetFS
        for manifest in ({}, candidate_manifest()):
            with mock.patch.object(self.api, 'create_staging_workspace') as workspace, \
                    mock.patch.object(self.api, 'create_staging_materials') as materials:
                with self.assertRaises(ValueError):
                    self.api.run_functional_staging(TargetFS(), Runner(dry_run=True), manifest,
                        {}, {}, 'fixture-run', staged_seal=None, routing_snapshot={})
                workspace.assert_not_called()
                materials.assert_not_called()

    def test_worker_does_not_run_from_unisolated_parent_process(self):
        with mock.patch.object(self.api, 'ForegroundSession') as session:
            result = self.api._worker({})
            self.assertEqual(result, {'ok': False, 'reason': 'staging_failed'})
            session.assert_not_called()

    def test_malformed_ipc_cannot_be_accepted_as_verified(self):
        for value in ('', '{}', '{"ok":true}', '[]', '{"ok":true,"ok":false}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.api._decode_worker_result(value, None)


class LucXMixedStagingSourceTests(unittest.TestCase):
    """Полный mixed набор читается из одной настоящей синтетической БД."""

    def setUp(self):
        import test_naive_lucx_source as fixtures
        self.fixture = fixtures.LucXNaiveSourceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.api = importlib.import_module('lucx_post_configurator.staging_probes')
        self.user_id = str(uuid.uuid4())
        client = dict(id=self.user_id, email='XrayGamma', enable=True, totalGB=0,
                      expiryTime=0, limitIp=0, flow='', security='auto')
        stream = dict(network='ws', security='tls', wsSettings={'path': '/vpn'},
            tlsSettings=dict(serverName='xray.example.test', alpn=['http/1.1'], settings={},
                certificates=[dict(certificateFile='/cert/cert.pem', keyFile='/cert/key.pem')]))
        self.fixture.sql("INSERT INTO inbounds VALUES (9,'vless',1,'127.0.0.1',19443,?,?,"
            "'xray.example.test',0,0,NULL,'','never',1,0,0)",
            (json.dumps(dict(clients=[client], decryption='none', encryption='none')), json.dumps(stream)))
        self.fixture.sql("INSERT INTO hosts VALUES (3,9,'xray.example.test',443,'',1,0,'',0,'same')")
        self.fixture.sql("INSERT INTO clients VALUES (3,'XrayGamma',?,1,0,0,'','auto',0,0,0,0,0,'never',1,0,'',0,0)",
                         (self.user_id,))
        self.fixture.sql("INSERT INTO client_inbounds VALUES (3,9,'',0)")
        self.fixture.sql("INSERT INTO client_traffics VALUES (3,999,'XrayGamma',1,0,0,0,0,0,0,0,0,0)")
        self.fixture.refresh_manifest()
        from lucx_post_configurator.discovery import read_lucx_database
        from lucx_post_configurator.routing_profiles import inbound_routing_metadata
        _, inbounds, _, _ = read_lucx_database(self.fixture.fs, self.fixture.db_path)
        item = next(value for value in inbounds if value.id == 9)
        self.manifest = self.fixture.manifest
        self.manifest['lucx']['db_path'] = self.fixture.db_path
        self.manifest['protocols'].append(dict(inbound_id=item.id, protocol=item.protocol,
            network=item.network, security=item.security, exposure='tcp_sni', enable=True,
            domain=item.share_addr, internal_host=item.listen, internal_port=item.port,
            public_port=item.suggested_public_port, sni_names=item.server_names,
            port_bindings=item.port_bindings, **inbound_routing_metadata(item)))

    def capture(self, *, audit=True):
        factory = getattr(self.api, 'capture_lucx_staging_credentials', None)
        self.assertIsNotNone(factory, 'Нужен общий источник staging credentials из LucX')
        return factory(self.fixture.fs, self.manifest, audit=self.fixture.audit if audit else None)

    def test_complete_real_mixed_set_uses_derived_naive_and_relational_xray_without_writes(self):
        before = self.fixture.snapshot()
        selected = self.capture()
        selected.verify(self.manifest)
        self.assertEqual(len(selected.entries), 2)
        naive = next(value for value in selected.entries.values() if type(value) is NaiveProbeCredential)
        xray = next(value for value in selected.entries.values() if type(value) is XrayProbeCredential)
        self.assertEqual((naive.username, naive.password), self.fixture.auth('NaiveAlpha'))
        self.assertEqual(xray.user_id, self.user_id)
        self.assertEqual(before, self.fixture.snapshot())
        self.assertNotIn(naive.password, repr(selected))

    def test_changed_unselected_naive_policy_invalidates_the_complete_mixed_set(self):
        selected = self.capture()
        self.fixture.sql('UPDATE clients SET total_gb=1 WHERE id=2')
        with self.assertRaises(ValueError):
            selected.verify(self.manifest)

    def test_default_native_sni_survives_the_real_mixed_consumer_and_endpoint_validator(self):
        xray = self.manifest['protocols'][1]
        self.fixture.sql('UPDATE hosts SET override_sni_from_address=0 WHERE inbound_id=7')
        self.fixture.refresh_manifest()
        self.manifest = self.fixture.manifest
        self.manifest['protocols'].append(xray)
        self.manifest['lucx']['db_path'] = self.fixture.db_path
        selected = self.capture()
        self.assertEqual(len(selected.entries), 2)
        from lucx_post_configurator.vpn_probes import _endpoint_valid
        self.assertTrue(_endpoint_valid(self.manifest['protocols'][0]['public_endpoints'][0]))
        selected.verify(self.manifest)

    def test_changed_xray_policy_invalidates_the_complete_mixed_set(self):
        selected = self.capture()
        self.fixture.sql('UPDATE clients SET enable=0 WHERE id=3')
        with self.assertRaises(ValueError):
            selected.verify(self.manifest)

    def test_missing_naive_audit_rejects_before_any_source_is_opened(self):
        with mock.patch.object(self.api, 'LucXXrayCredentialSource') as source:
            with self.assertRaises(ValueError):
                self.capture(audit=False)
            source.assert_not_called()

    def test_xray_only_keeps_working_without_naive_audit(self):
        self.manifest['protocols'] = [self.manifest['protocols'][1]]
        selected = self.capture(audit=False)
        selected.verify(self.manifest)
        self.assertEqual(len(selected.entries), 1)
        self.assertEqual(next(iter(selected.entries.values())).user_id, self.user_id)

    def test_policy_drift_during_initial_family_sweep_never_returns_a_partial_snapshot(self):
        original = self.api.LucXXrayCredentialSource.__call__

        def revoke_earlier_family(source, protocol):
            credential = original(source, protocol)
            self.fixture.sql('UPDATE clients SET total_gb=1 WHERE id=2')
            return credential

        with mock.patch.object(self.api.LucXXrayCredentialSource, '__call__', revoke_earlier_family):
            with self.assertRaises(ValueError):
                self.capture()

    def test_unknown_required_family_rejects_before_opening_any_sources(self):
        self.manifest['protocols'][1]['protocol'] = 'trojan'
        with mock.patch.object(self.api, 'LucXNaiveCredentialSource') as naive, \
                mock.patch.object(self.api, 'LucXXrayCredentialSource') as xray:
            with self.assertRaises(ValueError):
                self.capture()
            naive.assert_not_called()
            xray.assert_not_called()


if __name__ == '__main__':
    unittest.main()
