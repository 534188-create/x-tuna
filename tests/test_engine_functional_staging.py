"""Порядок операций Engine; mock proof здесь не является VPN-доказательством."""
from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from helpers import make_target
from test_staging_eligibility import candidate_manifest

from lucx_post_configurator.engine import ApplyError, Engine, _ephemeral_routing_material as load_routing_material
from lucx_post_configurator.models import Audit
from lucx_post_configurator.renderers import GeneratedFile
from lucx_post_configurator.runner import Runner
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import FAILED_STATE_PATH, STATE_PATH


class EngineFunctionalStagingTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        make_target(self.root)
        self.engine = Engine(self.root, runner=Runner(dry_run=True))
        self.target = '/etc/haproxy/haproxy.cfg'
        self.engine.fs.atomic_write_text(self.target, 'original\n')
        self.manifest = candidate_manifest()
        self.manifest['dns']['enabled'] = False
        self.manifest['components'].update(firewall=False, logrotate=False)
        self.audit = Audit(supported_os=True, db_schema_supported=True)
        self.events = []
        self.patch('validate_audit_against_manifest', return_value=[])
        self.patch('validate_public_bind_conflicts', return_value=[])
        self.patch('required_vpn_probe_errors', return_value=[])
        self.patch('validate_certificate', return_value=[])
        self.patch('validate_lucx_tls_coverage', return_value=[])
        self.patch('validate_generated', return_value=[])
        self.patch('_ephemeral_routing_material', return_value=None)
        self.patch('_managed_decoy_directories', return_value={})
        self.stack.enter_context(mock.patch.object(TargetFS, 'is_live', new_callable=mock.PropertyMock, return_value=True))
        self.stack.enter_context(mock.patch.object(self.engine, 'audit', side_effect=lambda *_: copy.deepcopy(self.audit)))
        self.stack.enter_context(mock.patch.object(self.engine, '_reactivate_after_restore', return_value=[]))
        self.stack.enter_context(mock.patch.object(self.engine, '_activate'))
        self.patch('render_files', return_value={self.target: GeneratedFile(b'candidate\n', component='haproxy')})

    def patch(self, name, **kwargs):
        return self.stack.enter_context(mock.patch('lucx_post_configurator.engine.' + name, **kwargs))

    def test_naive_side_site_reaches_real_backup_without_changing_live_files(self):
        from test_transport_routing_regressions import topology
        from lucx_post_configurator.renderers import render_files
        from lucx_post_configurator.transaction import create_backup

        self.manifest = topology('tcp', inbound_id=5, protocol='naive',
                                 exposure='tcp_direct', public_port=18443)
        self.manifest['dns']['enabled'] = False
        self.manifest['components']['install_packages'] = False
        self.manifest['decoys']['require_full_acceptance'] = False
        source_path = '/etc/example/naive-5.caddyfile'
        source = b'vpn.example.test {\n file_server\n}\n'
        self.engine.fs.atomic_write_text(source_path, source.decode())
        database_before = self.engine.fs.read_bytes(self.manifest['lucx']['db_path'])
        self.patch('_ephemeral_routing_material', side_effect=load_routing_material)
        self.patch('render_files', side_effect=render_files)
        backup = self.patch('create_backup', wraps=create_backup)
        self.patch('backup_lucx_database', side_effect=RuntimeError('preliminary backup reached'))
        stage = self.patch('stage_files')
        commit = self.patch('commit_managed_transition')

        with self.assertRaisesRegex(ApplyError, 'preliminary backup reached'):
            self.engine._apply_locked(self.manifest)

        backup.assert_called_once()
        targets = backup.call_args.args[1]
        self.assertIn('/etc/haproxy/haproxy.cfg', targets)
        self.assertIn('/etc/nginx/conf.d/60-lucx-decoys.conf', targets)
        self.assertNotIn(source_path, targets)
        self.assertEqual(len(list(self.root.rglob('backup.json'))), 1)
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')
        self.assertEqual(self.engine.fs.read_bytes(source_path), source)
        self.assertEqual(self.engine.fs.read_bytes(self.manifest['lucx']['db_path']), database_before)
        stage.assert_not_called()
        commit.assert_not_called()
        self.engine._activate.assert_not_called()

    def native_candidate(self):
        from test_naive_connect_frontend import candidate_fixture
        from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
        source_manifest, source_audit, material = candidate_fixture()
        self.manifest['protocols'] = source_manifest['protocols']
        self.audit.naive_caddyfile = source_audit.naive_caddyfile
        self.manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(self.manifest, self.audit)
        self.manifest['decoys']['require_full_acceptance'] = True
        material = {7: material}
        self.patch('_ephemeral_routing_material', return_value=material)
        return material

    def test_strict_native_candidate_requires_source_preflight_before_backup(self):
        material = self.native_candidate()
        prepare = self.patch('prepare_functional_staging', side_effect=ValueError('source rejected'))
        capture = self.patch('capture_integrity', side_effect=AssertionError('too late'))
        backup = self.patch('create_backup', side_effect=AssertionError('too late'))
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(self.manifest)
        prepare.assert_called_once()
        self.assertEqual(prepare.call_args.kwargs['routing_material'], material)
        self.assertEqual(prepare.call_args.kwargs['audit'], self.audit)
        capture.assert_not_called()
        backup.assert_not_called()

    def test_native_staging_failure_never_commits_even_with_preflight(self):
        self.native_candidate()
        self.patch('prepare_functional_staging', return_value=SimpleNamespace(verify=lambda *_: None))
        stage = self.patch('run_functional_staging', side_effect=ValueError('native rejected'))
        commit = self.patch('commit_managed_transition', side_effect=AssertionError('no commit'))
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(self.manifest)
        stage.assert_called_once()
        commit.assert_not_called()
        self.engine._activate.assert_not_called()
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')

    def test_native_source_drift_after_staging_blocks_commit(self):
        material = self.native_candidate()
        preflight = SimpleNamespace(verify=lambda *_: None)
        self.patch('prepare_functional_staging', return_value=preflight)
        proof = SimpleNamespace(summary={'candidate_verified': True},
                                verify=mock.Mock(side_effect=ValueError('native source drift')))
        stage = self.patch('run_functional_staging', return_value=proof)
        commit = self.patch('commit_managed_transition')
        with self.assertRaisesRegex(ApplyError, 'native source drift'):
            self.engine._apply_locked(self.manifest)
        self.assertIs(stage.call_args.kwargs['preflight'], preflight)
        self.assertEqual(stage.call_args.kwargs['routing_material'], material)
        proof.verify.assert_called_once()
        self.assertEqual(proof.verify.call_args.kwargs['routing_material'], material)
        commit.assert_not_called()
        self.engine._activate.assert_not_called()
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')

    def test_native_staging_success_does_not_replace_public_health(self):
        self.native_candidate()
        self.allow_mock_health()
        health = self.patch('validate_live_configuration', return_value=['public native failed'])
        with self.assertRaisesRegex(ApplyError, 'public native failed'):
            self.engine._apply_locked(self.manifest)
        health.assert_called_once()
        self.engine._activate.assert_called_once()
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')
        self.assertFalse(self.engine.fs.exists(STATE_PATH))

    def test_fresh_naive_candidate_cannot_bypass_preflight_with_optional_acceptance_or_cached_ready(self):
        from test_naive_connect_frontend import candidate_fixture
        from lucx_post_configurator.extended_decoys import classify_naive_connect_candidate
        source_manifest, source_audit, _ = candidate_fixture()
        self.manifest['protocols'] = source_manifest['protocols']
        self.audit.naive_caddyfile = source_audit.naive_caddyfile
        candidate = classify_naive_connect_candidate(self.manifest, self.audit, 7)
        capture = self.patch('capture_integrity', side_effect=AssertionError('integrity reached'))
        backup = self.patch('create_backup', side_effect=AssertionError('backup reached'))
        prepare = self.patch('prepare_functional_staging', side_effect=AssertionError('staging reached'))
        for strict in (None, False, True):
            for cached in ([], [candidate], [dict(candidate, status='ready', managed=True)]):
                with self.subTest(strict=strict, cached=bool(cached)):
                    if strict is None:
                        self.manifest['decoys'].pop('require_full_acceptance', None)
                    else:
                        self.manifest['decoys']['require_full_acceptance'] = strict
                    self.manifest['decoys']['extended_routes'] = copy.deepcopy(cached)
                    with self.assertRaisesRegex(ApplyError, 'Naive CONNECT'):
                        self.engine._apply_locked(self.manifest)
                    capture.assert_not_called()
                    backup.assert_not_called()
                    prepare.assert_not_called()
                    self.assertFalse(self.engine.fs.exists(STATE_PATH))
                    self.assertFalse(self.engine.fs.exists(FAILED_STATE_PATH))
        self.assertEqual(self.engine.runner.history, [])

    def test_naive_candidate_barrier_does_not_block_existing_native_fallback(self):
        from test_naive_connect_frontend import candidate_fixture
        source_manifest, source_audit, _ = candidate_fixture()
        self.manifest['protocols'] = source_manifest['protocols']
        self.audit.naive_caddyfile = source_audit.naive_caddyfile
        self.audit.naive_caddyfile['files'][0]['capabilities']['native_decoy'] = True
        self.manifest['decoys']['require_full_acceptance'] = False
        self.patch('capture_integrity', side_effect=AssertionError('native control reached'))
        with self.assertRaisesRegex(AssertionError, 'native control reached'):
            self.engine._apply_locked(self.manifest)

    def test_naive_guard_cannot_be_bypassed_by_truthy_nonboolean_enabled(self):
        from test_naive_connect_frontend import candidate_fixture
        manifest, audit, _ = candidate_fixture()
        self.manifest['protocols'] = manifest['protocols']
        self.audit.naive_caddyfile = audit.naive_caddyfile
        self.manifest['decoys']['require_full_acceptance'] = False
        capture = self.patch('capture_integrity', side_effect=AssertionError('too late'))
        discover = self.patch('discover_existing_backend_credentials', side_effect=AssertionError('too late'))
        for enabled in (1, 'true'):
            for backend in (False, True):
                self.manifest['decoys']['enabled'] = enabled
                self.manifest['components']['trusttunnel_backend'] = backend
                with self.subTest(enabled=enabled, backend=backend), self.assertRaisesRegex(ApplyError, 'Naive CONNECT'):
                    self.engine._apply_locked(self.manifest)
        capture.assert_not_called()
        discover.assert_not_called()

    def test_missing_staging_prerequisite_stops_before_integrity_and_backup(self):
        prepare = self.patch('prepare_functional_staging', side_effect=ValueError('unavailable'))
        capture = self.patch('capture_integrity', side_effect=AssertionError('too late'))
        backup = self.patch('create_backup', side_effect=AssertionError('too late'))
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(self.manifest)
        prepare.assert_called_once()
        capture.assert_not_called()
        backup.assert_not_called()
        self.assertEqual(self.engine.runner.history, [])

    def test_strict_optional_backend_stops_before_credential_discovery_or_backend_probe(self):
        from lucx_post_configurator.models import validate_manifest
        binary = '/opt/x-tuna/bin/backend'
        payload = b'synthetic executable placeholder'
        self.engine.fs.atomic_write_text(binary, payload.decode('ascii'))
        self.manifest['components']['trusttunnel_backend'] = True
        self.manifest['trusttunnel_backend'].update(user_confirmed=True, listen_port=26444,
            public_domain='vpn.example.test', binary_path=binary, sha256=hashlib.sha256(payload).hexdigest(),
            credentials=[{'username': 'synthetic-user', 'password': 'synthetic-pass'}])
        validate_manifest(self.manifest)
        probe = self.patch('probe_backend', side_effect=ValueError('backend should not run'))
        discover = self.patch('discover_existing_backend_credentials', return_value=[
            {'username': 'synthetic-user', 'password': 'synthetic-pass'}])
        for explicit in (True, False):
            with self.subTest(explicit=explicit):
                if not explicit:
                    self.manifest['trusttunnel_backend']['credentials'] = []
                with self.assertRaises(ApplyError):
                    self.engine._apply_locked(self.manifest)
                probe.assert_not_called()
                discover.assert_not_called()

    def test_naive_candidate_stops_before_optional_backend_even_without_strict_acceptance(self):
        from test_naive_connect_frontend import candidate_fixture
        manifest, audit, _ = candidate_fixture()
        self.manifest['protocols'] = manifest['protocols']
        self.audit.naive_caddyfile = audit.naive_caddyfile
        self.manifest['decoys']['require_full_acceptance'] = False
        self.manifest['components']['trusttunnel_backend'] = True
        self.manifest['trusttunnel_backend']['credentials'] = []
        discover = self.patch('discover_existing_backend_credentials', side_effect=AssertionError('too late'))
        probe = self.patch('probe_backend', side_effect=AssertionError('too late'))
        with self.assertRaisesRegex(ApplyError, 'Naive CONNECT'):
            self.engine._apply_locked(self.manifest)
        discover.assert_not_called()
        probe.assert_not_called()
        self.assertEqual(self.engine.runner.history, [])

    def test_failed_functional_staging_never_commits_or_restarts_services(self):
        self.patch('prepare_functional_staging', return_value=SimpleNamespace(verify=lambda *_: None))
        stage = self.patch('run_functional_staging', side_effect=ValueError('staging rejected'))
        commit = self.patch('commit_managed_transition', side_effect=AssertionError('no commit'))
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(self.manifest)
        stage.assert_called_once()
        commit.assert_not_called()
        self.engine._activate.assert_not_called()
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')

    def test_freshness_rejection_after_staging_blocks_commit(self):
        self.patch('prepare_functional_staging', return_value=SimpleNamespace(verify=lambda *_: None))
        proof = SimpleNamespace(summary={'candidate_verified': True}, verify=mock.Mock(side_effect=ValueError('changed')))
        stage = self.patch('run_functional_staging', return_value=proof)
        commit = self.patch('commit_managed_transition', side_effect=AssertionError('no commit'))
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(self.manifest)
        stage.assert_called_once()
        proof.verify.assert_called_once()
        commit.assert_not_called()
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')

    def test_unsupported_profile_stops_before_staging_preparation(self):
        self.manifest['protocols'][0]['transport_mode'] = 'future'
        prepare = self.patch('prepare_functional_staging', side_effect=AssertionError('unsupported candidate'))
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(self.manifest)
        prepare.assert_not_called()

    def test_packages_disappearing_after_preflight_are_not_installed_before_staging(self):
        self.manifest['components']['install_packages'] = True
        self.patch('missing_packages', side_effect=[[], ['nginx']])
        self.patch('prepare_functional_staging', return_value=SimpleNamespace(verify=lambda *_: None))
        install = self.patch('install_packages', side_effect=AssertionError('no package write'))
        stage = self.patch('run_functional_staging', side_effect=AssertionError('no stage'))
        with self.assertRaisesRegex(ApplyError, 'Пакеты'):
            self.engine._apply_locked(self.manifest)
        install.assert_not_called()
        stage.assert_not_called()

    def test_receipt_is_rechecked_after_fresh_audit_immediately_before_commit(self):
        self.patch('prepare_functional_staging', return_value=SimpleNamespace(verify=lambda *_: None))
        proof = SimpleNamespace(summary={'candidate_verified': True},
                                verify=lambda *_, **__: self.events.append('verify'))

        def stage(*args, **kwargs):
            self.events.append('stage')
            return proof

        def audit(*args):
            self.events.append('audit')
            return copy.deepcopy(self.audit)

        def commit(*args, **kwargs):
            self.assertEqual(self.events[-3:], ['stage', 'audit', 'verify'])
            raise ValueError('fixture stops before writes')

        self.patch('run_functional_staging', side_effect=stage)
        self.stack.enter_context(mock.patch.object(self.engine, 'audit', side_effect=audit))
        transition = self.patch('commit_managed_transition', side_effect=commit)
        with self.assertRaisesRegex(ApplyError, 'fixture stops before writes'):
            self.engine._apply_locked(self.manifest)
        transition.assert_called_once()
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')

    def test_changed_external_manifest_stops_before_backend_discovery_or_preflight(self):
        from lucx_post_configurator.manifest_source import read_manifest_source
        source_path = self.root / 'input.json'
        source_path.write_text(json.dumps(self.manifest), encoding='utf-8')
        manifest, guard = read_manifest_source(source_path)
        source_path.write_text('{}', encoding='utf-8')
        prepare = self.patch('prepare_functional_staging', side_effect=AssertionError('stale input'))
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(manifest, manifest_source=guard)
        prepare.assert_not_called()

    def test_external_manifest_changed_during_staging_blocks_commit(self):
        from lucx_post_configurator.manifest_source import read_manifest_source
        source_path = self.root / 'input.json'
        source_path.write_text(json.dumps(self.manifest), encoding='utf-8')
        manifest, guard = read_manifest_source(source_path)
        self.patch('prepare_functional_staging', return_value=SimpleNamespace(verify=lambda *_: None))
        proof = SimpleNamespace(summary={'candidate_verified': True}, verify=mock.Mock())

        def stage(*args, **kwargs):
            source_path.write_text('{}', encoding='utf-8')
            return proof

        self.patch('run_functional_staging', side_effect=stage)
        commit = self.patch('commit_managed_transition', side_effect=AssertionError('stale input commit'))
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(manifest, manifest_source=guard)
        commit.assert_not_called()
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')

    def test_changed_input_is_rejected_before_stopping_removed_services(self):
        from lucx_post_configurator.manifest_source import read_manifest_source
        self.manifest['decoys']['require_full_acceptance'] = False
        source_path = self.root / 'input.json'
        source_path.write_text(json.dumps(self.manifest), encoding='utf-8')
        manifest, guard = read_manifest_source(source_path)
        self.patch('_component_removal_targets', return_value=['/etc/systemd/system/lucx-sub-sidecar.service'])

        def validate(*args):
            source_path.write_text('{}', encoding='utf-8')
            return []

        self.patch('validate_generated', side_effect=validate)
        commit = self.patch('commit_managed_transition', side_effect=AssertionError('stale input commit'))
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(manifest, manifest_source=guard)
        commit.assert_not_called()
        self.assertFalse(any('disable' in args for args in self.engine.runner.history))

    def resume_source(self, target=FAILED_STATE_PATH):
        from lucx_post_configurator.manifest_source import read_manifest_source
        source = self.engine.fs.path(target)
        self.engine.fs.atomic_write_text(target, json.dumps({
            'status': 'failed', 'run_id': 'synthetic-run', 'manifest': self.manifest}))
        return source, *read_manifest_source(source, envelope='state')

    def test_resume_staging_drift_does_not_overwrite_changed_failed_state_in_error_handler(self):
        source, manifest, guard = self.resume_source()
        changed = b'{"status":"synthetic-external-change"}\n'
        self.patch('prepare_functional_staging', return_value=SimpleNamespace(verify=lambda *_: None))
        proof = SimpleNamespace(summary={'candidate_verified': True}, verify=mock.Mock())

        def stage(*args, **kwargs):
            source.write_bytes(changed)
            return proof

        self.patch('run_functional_staging', side_effect=stage)
        commit = self.patch('commit_managed_transition', side_effect=AssertionError('stale input commit'))
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(manifest, manifest_source=guard)
        commit.assert_not_called()
        self.assertEqual(source.read_bytes(), changed, 'Error handler затёр чужой failed-state')
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')

    def allow_mock_health(self):
        self.patch('prepare_functional_staging', return_value=SimpleNamespace(verify=lambda *_: None))
        self.patch('run_functional_staging', return_value=SimpleNamespace(
            summary={'candidate_verified': True}, verify=mock.Mock()))
        self.patch('validate_required_acceptance', return_value=[])
        self.patch('decoy_acceptance_summary', return_value={'complete': True})
        self.patch('vpn_acceptance_summary', return_value={'complete': True})

    def test_resume_health_drift_does_not_remove_changed_failed_state_or_report_success(self):
        source, manifest, guard = self.resume_source()
        changed = b'{"status":"synthetic-external-change"}\n'
        self.allow_mock_health()

        def health(*args, **kwargs):
            source.write_bytes(changed)
            return []

        self.patch('validate_live_configuration', side_effect=health)
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(manifest, manifest_source=guard)
        self.assertTrue(source.is_file(), 'Success cleanup удалил чужой failed-state')
        self.assertEqual(source.read_bytes(), changed)
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')

    def test_state_input_health_drift_is_preserved_before_final_state_write(self):
        source, manifest, guard = self.resume_source(STATE_PATH)
        changed = b'{"status":"synthetic-external-change"}\n'
        self.allow_mock_health()

        def health(*args, **kwargs):
            source.write_bytes(changed)
            return []

        self.patch('validate_live_configuration', side_effect=health)
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(manifest, manifest_source=guard)
        self.assertEqual(source.read_bytes(), changed, 'Final save_state затёр чужой источник')
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')

    def test_unchanged_resume_source_is_removed_only_after_successful_health(self):
        source, manifest, guard = self.resume_source()
        self.allow_mock_health()

        def health(*args, **kwargs):
            self.assertTrue(source.is_file())
            return []

        self.patch('validate_live_configuration', side_effect=health)
        result = self.engine._apply_locked(manifest, manifest_source=guard)
        self.assertEqual(result['status'], 'complete')
        self.assertFalse(source.exists())
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'candidate\n')

    def test_resume_report_failure_preserves_a_retry_record_and_rolls_back_own_files(self):
        source, manifest, guard = self.resume_source()
        self.allow_mock_health()
        self.patch('validate_live_configuration', return_value=[])
        self.stack.enter_context(mock.patch.object(self.engine, '_write_report',
            side_effect=OSError('synthetic report write failed')))
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(manifest, manifest_source=guard)
        self.assertTrue(source.is_file(), 'Ошибка отчёта потеряла запись для повторной попытки')
        result = json.loads(source.read_bytes())
        self.assertEqual(result['status'], 'failed')
        self.assertNotEqual(result['run_id'], 'synthetic-run')
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')

    def test_unchanged_resume_source_can_be_replaced_with_current_health_failure(self):
        source, manifest, guard = self.resume_source()
        self.allow_mock_health()
        self.patch('validate_live_configuration', return_value=['synthetic health failure'])
        with self.assertRaises(ApplyError):
            self.engine._apply_locked(manifest, manifest_source=guard)
        result = json.loads(source.read_bytes())
        self.assertEqual(result['status'], 'failed')
        self.assertNotEqual(result['run_id'], 'synthetic-run')
        self.assertEqual(self.engine.fs.read_bytes(self.target), b'original\n')


if __name__ == '__main__':
    unittest.main()
