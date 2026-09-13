from __future__ import annotations

import copy
import json
from unittest.mock import Mock, patch

import test_naive_generations as fixtures
from lucx_post_configurator.engine import Engine, ApplyError
from lucx_post_configurator.manifest_source import read_manifest_source
from lucx_post_configurator.runner import Runner
from lucx_post_configurator.transaction import STATE_PATH, save_state, load_state


class EngineNaiveLifecycleTests(fixtures.NaiveGenerationTests):
    def engine(self):
        engine = Engine(self.root, runner=Runner(dry_run=False))
        engine.audit = Mock(side_effect=lambda *args: self.audit())
        return engine

    def test_prepare_is_read_only_and_rebinds_fence_before_confirmation(self):
        engine = self.engine()
        path = self.root / 'manifest.json'
        path.write_text(json.dumps(self.manifest), encoding='utf-8')
        manifest, fence = read_manifest_source(path)
        self.regenerate()
        candidate, rebound = engine.prepare_manifest_source(manifest, fence)
        rebound.verify(manifest=candidate)
        self.assertNotEqual(candidate, manifest)
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            rebound.verify(manifest=candidate)

    def test_settle_waits_for_matching_runtime_generation(self):
        engine = self.engine()
        candidate = engine.prepare_operation(self.manifest)
        self.runtime('new-synthetic')
        def generated(_):
            self.regenerate()
        with patch('lucx_post_configurator.engine.time.sleep', side_effect=generated):
            fresh, _ = engine._settle_naive_generation(candidate, attempts=3)
        self.assertEqual(fresh['naive_generations']['7']['source_sha256'], self.fs.sha256(self.source_path))

    def test_settle_does_not_accept_foreign_client_auth(self):
        engine = self.engine()
        candidate = engine.prepare_operation(self.manifest)
        self.fs.atomic_write_text(self.source_path, self.text.replace('pass-one', 'foreign-secret'), mode=0o600)
        with patch('lucx_post_configurator.engine.time.sleep'), self.assertRaises(ApplyError):
            engine._settle_naive_generation(candidate, attempts=2)

    def test_renewal_does_not_invoke_full_apply_or_change_publication_intent(self):
        engine = self.engine()
        saved = engine.prepare_operation(self.manifest)
        save_state(self.fs, {'status': 'complete', 'manifest': saved, 'installed_hashes': {}})
        saved = load_state(self.fs)['manifest']
        candidate = copy.deepcopy(saved)
        candidate['components']['tls_hook'] = True
        candidate['certificates']['renewal'].update(enabled=True, provider='acme.sh')
        selected = {k: candidate['certificates'][k] for k in ('cert_path', 'key_path')}
        def register(fs, runner, manifest, selected, **callbacks):
            callbacks['post_reload']()
            callbacks['commit_state']()
            return {'registered': True}
        with patch.object(engine, 'apply', side_effect=AssertionError('full apply forbidden')), \
             patch('lucx_post_configurator.certificate_renewal.register_existing_renewal', side_effect=register), \
             patch.object(engine, '_synchronize_naive_generation_locked', side_effect=lambda m, **kw: m), \
             patch('lucx_post_configurator.engine.validate_live_configuration', return_value=[]):
            result = engine.enable_certificate_renewal(candidate, selected=selected)
        state = json.loads(self.fs.read_bytes(STATE_PATH))
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(state['manifest']['lucx'], saved['lucx'])
        self.assertEqual(state['manifest']['protocols'], saved['protocols'])
        self.assertEqual(state['manifest']['network'], saved['network'])
        self.assertTrue(state['manifest']['certificates']['renewal']['enabled'])

    def test_renewal_rejects_smuggled_route_change_before_mutation(self):
        engine = self.engine()
        saved = engine.prepare_operation(self.manifest)
        save_state(self.fs, {'status': 'complete', 'manifest': saved, 'installed_hashes': {}})
        candidate = copy.deepcopy(saved)
        candidate['network']['public_tcp_port'] = 9443
        with patch('lucx_post_configurator.certificate_renewal.register_existing_renewal') as register, \
             self.assertRaises(ApplyError):
            engine.enable_certificate_renewal(candidate, selected=candidate['certificates'])
        register.assert_not_called()

    def test_old_runtime_after_explicit_restart_is_not_ready(self):
        engine = self.engine()
        candidate = engine.prepare_operation(self.manifest)
        engine._expect_naive_restart(candidate)
        with patch('lucx_post_configurator.engine.time.sleep'), self.assertRaises(ApplyError):
            engine._settle_naive_generation(candidate, attempts=3)

    def test_restart_marker_clears_only_after_confirmed_new_runtime(self):
        engine = self.engine()
        candidate = engine.prepare_operation(self.manifest)
        engine._expect_naive_restart(candidate)
        self.regenerate()
        self.fs.atomic_write('/proc/101/stat', b'101 (xray) ' + b'0 ' * 19 + b'200\n')
        with patch('lucx_post_configurator.engine.time.sleep'):
            fresh, _ = engine._settle_naive_generation(candidate, attempts=3)
        self.assertEqual(engine._naive_runtime_before_restart, {})
        self.assertNotEqual(candidate['naive_generations'], fresh['naive_generations'])

    def test_background_worker_rejects_unapproved_legacy_baseline(self):
        engine = self.engine()
        save_state(self.fs, {'status': 'complete', 'manifest': self.manifest, 'installed_hashes': {}})
        with patch.object(engine, '_synchronize_naive_generation_locked') as synchronize, self.assertRaises(ApplyError):
            engine.sync_naive_inbound(7)
        synchronize.assert_not_called()

    def test_legacy_foreground_plan_explains_adoption(self):
        engine = self.engine()
        candidate = engine.prepare_operation(self.manifest)
        self.assertEqual(candidate['naive_generation_adoption'], [7])
        self.assertIn('базов', ' '.join(engine.plan(candidate, self.audit())['warnings']))
        self.assertIn('базов', ' '.join(engine.plan_certificate_renewal(candidate)['warnings']))

    def test_sync_rejects_state_replacement_before_second_read(self):
        from lucx_post_configurator.transaction import managed_target_state
        engine = self.engine()
        candidate = engine.prepare_operation(self.manifest)
        save_state(self.fs, {'status': 'complete', 'manifest': candidate, 'installed_hashes': {}})
        seal = managed_target_state(self.fs, STATE_PATH)
        self.fs.atomic_write_text(STATE_PATH, '{"external": true}')
        with patch('lucx_post_configurator.naive_sync.synchronize_managed_naive') as sync, self.assertRaises(ApplyError):
            engine._synchronize_naive_generation_locked(candidate, expected_state=seal)
        sync.assert_not_called()
        self.assertEqual(self.fs.read_bytes(STATE_PATH), b'{"external": true}')

    def test_repair_reuses_preview_candidate_and_rejects_replaced_state(self):
        from lucx_post_configurator.repair import repair_check, repair_apply
        engine = self.engine()
        save_state(self.fs, {'status': 'complete', 'manifest': self.manifest, 'installed_hashes': {}})
        with patch('lucx_post_configurator.repair.refresh_manifest_from_audit',
                   side_effect=lambda m, a: (m, [])), \
             patch.object(engine, 'validate_installed', return_value={'ok': True}), \
             patch.object(engine, 'apply') as apply:
            repair_check(engine)
            self.fs.atomic_write(STATE_PATH, self.fs.read_bytes(STATE_PATH) + b' ')
            with self.assertRaises(ApplyError):
                repair_apply(engine)
            apply.assert_not_called()
