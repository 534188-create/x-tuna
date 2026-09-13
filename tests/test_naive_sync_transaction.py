from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from lucx_post_configurator.naive_sync import NaiveSyncError, synchronize_managed_naive
from lucx_post_configurator.renderers import GeneratedFile
from lucx_post_configurator.runner import CommandResult
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import managed_target_state


class RecordingRunner:
    def __init__(self):
        self.history = []
        self.effect = None

    def run_bounded(self, args, **kwargs):
        args = [str(x) for x in args]
        self.history.append(args)
        result = self.effect(args) if self.effect else 0
        return CommandResult(args, result, 'sensitive-output-must-not-leak', 'sensitive-error-must-not-leak')


class NaiveSyncTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fs = TargetFS(self.tmp.name)
        self.target = '/etc/lucx-post-configurator/naive/naive-5.caddyfile'
        self.binary = '/usr/local/bin/caddy'
        self.service = 'lucx-naive-decoy-5.service'
        self.fs.atomic_write(self.target, b'old validated config', 0o600)
        self.fs.atomic_write(self.binary, b'synthetic executable', 0o755)
        self.desired = {self.target: GeneratedFile(b'new validated config', 0o600, 'naive')}
        self.hashes = {self.target: hashlib.sha256(b'old validated config').hexdigest()}
        self.bindings = {self.target: {'binary_path': self.binary, 'service': self.service}}
        self.runner = RecordingRunner()
        self.journal = {}
        self.callback = Mock()
        self.fence = Mock(return_value=None)

    def sync(self, **kwargs):
        options = {'bindings': self.bindings, 'installed_hashes': self.hashes, 'source_fence': self.fence,
                   'run_id': 'synthetic-sync', 'commit_state': self.callback, 'mutation_journal': self.journal}
        options.update(kwargs)
        return synchronize_managed_naive(self.fs, self.runner, self.desired, **options)

    def test_success_updates_receipts_only_after_validation_and_health(self):
        result = self.sync()
        self.assertTrue(result['changed'])
        self.assertEqual(self.fs.read_bytes(self.target), b'new validated config')
        self.assertEqual(self.journal[self.target], managed_target_state(self.fs, self.target))
        self.callback.assert_called_once_with(result['hashes'], result['receipts'])
        validate = next(i for i, call in enumerate(self.runner.history) if 'validate' in call)
        restart = next(i for i, call in enumerate(self.runner.history) if 'restart' in call)
        self.assertLess(validate, restart)
        self.assertEqual(self.runner.history[validate][0], str(self.fs.path(self.binary)))
        self.assertIn(['systemctl', 'is-active', '--quiet', self.service], self.runner.history)
        if os.name == 'posix':
            self.assertEqual(self.fs.path(self.target).stat().st_mode & 0o777, 0o600)

    def test_validator_failure_does_not_write_target_or_publish_state(self):
        self.runner.effect = lambda args: 1 if 'validate' in args else 0
        with self.assertRaises(NaiveSyncError) as caught:
            self.sync()
        self.assertNotIn('sensitive', str(caught.exception))
        self.assertEqual(self.fs.read_bytes(self.target), b'old validated config')
        self.callback.assert_not_called()
        self.assertFalse(self.journal)

    def test_restart_failure_restores_owned_file_and_outer_receipt(self):
        calls = 0
        def effect(args):
            nonlocal calls
            if 'restart' in args:
                calls += 1
                return 1 if calls == 1 else 0
            return 0
        self.runner.effect = effect
        with self.assertRaises(NaiveSyncError) as caught:
            self.sync()
        self.assertFalse(caught.exception.rollback_failed)
        self.assertEqual(self.fs.read_bytes(self.target), b'old validated config')
        self.assertEqual(self.journal[self.target], managed_target_state(self.fs, self.target))
        self.callback.assert_not_called()

    def test_foreign_target_write_during_failed_restart_is_not_overwritten(self):
        def effect(args):
            if 'restart' in args:
                self.fs.atomic_write(self.target, b'foreign replacement', 0o600)
                return 1
            return 0
        self.runner.effect = effect
        with self.assertRaises(NaiveSyncError) as caught:
            self.sync()
        self.assertTrue(caught.exception.rollback_failed)
        self.assertEqual(self.fs.read_bytes(self.target), b'foreign replacement')
        self.assertNotEqual(self.journal[self.target], managed_target_state(self.fs, self.target))

    def test_state_callback_failure_rolls_back_file(self):
        self.callback.side_effect = RuntimeError('secret-state-error')
        with self.assertRaises(NaiveSyncError) as caught:
            self.sync()
        self.assertNotIn('secret', str(caught.exception))
        self.assertEqual(self.fs.read_bytes(self.target), b'old validated config')

    def test_false_source_fence_blocks_all_writes(self):
        self.fence.return_value = False
        with self.assertRaises(NaiveSyncError):
            self.sync()
        self.assertFalse(self.runner.history)
        self.assertEqual(self.fs.read_bytes(self.target), b'old validated config')

    def test_source_drift_after_validation_blocks_commit(self):
        self.fence.side_effect = [None, False]
        with self.assertRaises(NaiveSyncError):
            self.sync()
        self.assertEqual(self.fs.read_bytes(self.target), b'old validated config')
        self.callback.assert_not_called()

    def test_target_drift_during_validation_blocks_commit(self):
        def effect(args):
            if 'validate' in args:
                self.fs.atomic_write(self.target, b'foreign replacement', 0o600)
            return 0
        self.runner.effect = effect
        with self.assertRaises(NaiveSyncError):
            self.sync()
        self.assertEqual(self.fs.read_bytes(self.target), b'foreign replacement')
        self.callback.assert_not_called()

    def test_current_exact_desired_accepts_legacy_hash_without_restart(self):
        self.fs.atomic_write(self.target, self.desired[self.target].content, 0o600)
        result = self.sync()
        self.assertFalse(result['changed'])
        self.assertFalse(self.runner.history)
        self.callback.assert_called_once()
        self.assertFalse(result['receipts'])

    def test_unrecognized_changed_target_is_rejected(self):
        self.fs.atomic_write(self.target, b'unexpected config', 0o600)
        with self.assertRaises(NaiveSyncError):
            self.sync()
        self.assertFalse(self.runner.history)

    @unittest.skipUnless(os.name == 'posix', 'Проверка Unix metadata')
    def test_mode_only_repair_is_private_and_does_not_restart(self):
        self.fs.atomic_write(self.target, self.desired[self.target].content, 0o644)
        result = self.sync()
        self.assertTrue(result['changed'])
        self.assertFalse(any('restart' in call for call in self.runner.history))
        self.assertEqual(self.fs.path(self.target).stat().st_mode & 0o777, 0o600)

    def test_inactive_service_is_not_started_and_target_is_untouched(self):
        self.runner.effect = lambda args: 3 if 'is-active' in args else 0
        with self.assertRaises(NaiveSyncError):
            self.sync()
        self.assertFalse(any('restart' in call for call in self.runner.history))
        self.assertEqual(self.fs.read_bytes(self.target), b'old validated config')

    def test_source_and_unrelated_paths_cannot_be_written(self):
        source = '/usr/local/x-ui/bin/tunnel/naive-5.caddyfile'
        self.fs.atomic_write(source, b'original immutable source', 0o600)
        self.sync()
        self.assertEqual(self.fs.read_bytes(source), b'original immutable source')
        self.desired = {source: GeneratedFile(b'forbidden write', 0o600)}
        with self.assertRaises(NaiveSyncError):
            self.sync(run_id='second-sync')
        self.assertEqual(self.fs.read_bytes(source), b'original immutable source')

    def test_service_identity_mismatch_and_unsafe_run_id_fail_closed(self):
        self.bindings[self.target]['service'] = 'x-ui.service'
        with self.assertRaises(NaiveSyncError):
            self.sync()
        self.bindings[self.target]['service'] = self.service
        with self.assertRaises(NaiveSyncError):
            self.sync(run_id='../unsafe')

    def test_staging_cleaned_after_success_and_failed_validation(self):
        self.sync()
        stage = self.fs.path('/var/lib/lucx-post-configurator/staging/synthetic-sync-naive-sync')
        self.assertFalse(stage.exists())
        self.hashes[self.target] = hashlib.sha256(self.desired[self.target].content).hexdigest()
        self.desired[self.target] = GeneratedFile(b'another config', 0o600)
        self.runner.effect = lambda args: 1 if 'validate' in args else 0
        with self.assertRaises(NaiveSyncError):
            self.sync(run_id='failed-sync')
        self.assertFalse(self.fs.path('/var/lib/lucx-post-configurator/staging/failed-sync-naive-sync').exists())

    def test_empty_desired_still_fences_and_publishes_native_generation(self):
        self.desired = {}
        self.bindings = {}
        result = self.sync()
        self.assertEqual(result, {'changed': False, 'hashes': {}, 'receipts': {}})
        self.callback.assert_called_once_with({}, {})
        self.assertGreaterEqual(self.fence.call_count, 2)
        self.assertFalse(self.runner.history)

    def test_failed_health_restores_file_and_rechecks_service(self):
        health_calls = 0
        def effect(args):
            nonlocal health_calls
            if 'is-active' in args:
                health_calls += 1
                return 3 if health_calls == 2 else 0
            return 0
        self.runner.effect = effect
        with self.assertRaises(NaiveSyncError) as caught:
            self.sync()
        self.assertFalse(caught.exception.rollback_failed)
        self.assertEqual(health_calls, 3)
        self.assertEqual(self.fs.read_bytes(self.target), b'old validated config')

    def test_second_service_failure_rolls_back_both_owned_files(self):
        second = '/etc/lucx-post-configurator/naive/naive-6.caddyfile'
        self.fs.atomic_write(second, b'second original', 0o600)
        self.desired[second] = GeneratedFile(b'second desired', 0o600)
        self.hashes[second] = hashlib.sha256(b'second original').hexdigest()
        self.bindings[second] = {'binary_path': self.binary, 'service': 'lucx-naive-decoy-6.service'}
        failed = False
        def effect(args):
            nonlocal failed
            if 'restart' in args and args[-1] == 'lucx-naive-decoy-6.service' and not failed:
                failed = True
                return 1
            return 0
        self.runner.effect = effect
        with self.assertRaises(NaiveSyncError) as caught:
            self.sync()
        self.assertFalse(caught.exception.rollback_failed)
        self.assertEqual(self.fs.read_bytes(self.target), b'old validated config')
        self.assertEqual(self.fs.read_bytes(second), b'second original')
        for target in (self.target, second):
            self.assertEqual(self.journal[target], managed_target_state(self.fs, target))
        self.callback.assert_not_called()

    def test_write_without_returned_receipt_is_not_silently_claimed_as_rolled_back(self):
        atomic = self.fs.atomic_write
        def uncertain(target, data, *args, **kwargs):
            receipt = atomic(target, data, *args, **kwargs)
            if target == self.target:
                raise OSError('uncertain-after-rename')
            return receipt
        with patch.object(self.fs, 'atomic_write', side_effect=uncertain), self.assertRaises(NaiveSyncError) as caught:
            self.sync()
        self.assertTrue(caught.exception.rollback_failed)
        self.assertFalse(self.journal)
        self.callback.assert_not_called()


if __name__ == '__main__':
    unittest.main()
