from __future__ import annotations

import base64
import tempfile
import unittest
from types import SimpleNamespace

from lucx_post_configurator.certificate_renewal import (
    RenewalError,
    decode_reload_command,
    register_existing_renewal,
    renewal_status,
)
from lucx_post_configurator.renderers import GeneratedFile
from lucx_post_configurator.runner import CommandResult
from lucx_post_configurator.targetfs import TargetFS


class RenewalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fs = TargetFS(self.temp.name)
        self.cert = '/root/cert/example.test/fullchain.pem'
        self.key = '/root/cert/example.test/privkey.pem'
        self.record = '/root/.acme.sh/example.test_ecc/example.test.conf'
        self.hook_path = '/usr/local/sbin/lucx-tls-reload'
        self.hook = GeneratedFile(b'#!/bin/sh\nexit 0\n', 0o750)
        self.old = ("Le_Domain='example.test'\n"
                    f"Le_RealFullChainPath='{self.cert}'\n"
                    f"Le_RealKeyPath='{self.key}'\nLe_ReloadCmd=''\n")
        self.fs.atomic_write_text(self.record, self.old, mode=0o600)
        self.fs.atomic_write_text(self.cert, 'synthetic certificate')
        self.fs.atomic_write_text(self.key, 'synthetic key', mode=0o600)
        self.fs.atomic_write_text('/root/.acme.sh/example.test_ecc/fullchain.cer', 'synthetic certificate')
        self.fs.atomic_write_text('/root/.acme.sh/example.test_ecc/example.test.key', 'synthetic key', mode=0o600)
        self.fs.atomic_write_text('/root/.acme.sh/acme.sh', '#!/bin/sh\n', mode=0o700)
        self.manifest = {'certificates': {'cert_path': self.cert, 'key_path': self.key}}
        self.selected = dict(self.manifest['certificates'])
        self.events = []
        self.behavior = lambda: None
        self.code = 0
        def run(args, **kwargs):
            self.events.append('reload')
            self.assertEqual(args, [self.hook_path])
            self.assertTrue(renewal_status(self.fs, self.cert, self.key)['registered'])
            self.behavior()
            return CommandResult(args, self.code, 'secret output', 'secret error')
        self.runner = SimpleNamespace(run=run, dry_run=False)

    def registered(self):
        encoded = base64.b64encode(self.hook_path.encode()).decode()
        return self.old.replace("Le_ReloadCmd=''", f"Le_ReloadCmd='__ACME_BASE64__START_{encoded}__ACME_BASE64__END_'")

    def register(self, **changes):
        options = {'hook': self.hook, 'validate_candidate': lambda: self.events.append('validate'),
                   'post_reload': lambda: self.events.append('health'),
                   'commit_state': lambda: self.events.append('state'), 'run_id': 'renewal-test'}
        options.update(changes)
        return register_existing_renewal(self.fs, self.runner, self.manifest, self.selected, **options)

    def test_encoded_status_without_manifest_flag_or_secret_output(self):
        self.fs.atomic_write_text(self.record, self.registered(), mode=0o600)
        status = renewal_status(self.fs, self.cert, self.key)
        self.assertTrue(status['registered'])
        self.assertFalse(status['schedule_verified'])
        self.assertNotIn('example.test', repr(status))

    def test_decode_rejects_malformed_wrapper(self):
        with self.assertRaises(RenewalError):
            decode_reload_command('__ACME_BASE64__START_!!__ACME_BASE64__END_')

    def test_parser_never_evaluates_shell_and_rejects_duplicate_fields(self):
        for tail in ["Le_ReloadCmd=$(touch /tmp/never)\n", "Le_Domain='other.example.test'\n"]:
            with self.subTest(tail=tail):
                self.fs.atomic_write_text(self.record, self.old + tail, mode=0o600)
                with self.assertRaises(RenewalError):
                    renewal_status(self.fs, self.cert, self.key)

    def test_ambiguous_matching_records_fail(self):
        self.fs.atomic_write_text('/root/.acme.sh/example.test/example.test.conf', self.old, mode=0o600)
        with self.assertRaises(RenewalError):
            renewal_status(self.fs, self.cert, self.key)

    def test_openssl_csr_and_service_configs_are_not_renewal_records(self):
        paths = ['/root/.acme.sh/example.test_ecc/example.test.csr.conf',
                 '/root/.acme.sh/deploy/service.conf']
        content = '[req]\n[req_ext]\nsubjectAltName=DNS:example.test\n'
        for path in paths:
            self.fs.atomic_write_text(path, content, mode=0o600)
        self.assertTrue(renewal_status(self.fs, self.cert, self.key)['record_found'])
        self.assertTrue(self.register()['registered'])
        for path in paths:
            self.assertEqual(self.fs.read_text(path), content)

    def test_malformed_canonical_domain_record_still_blocks(self):
        self.fs.atomic_write_text(self.record, '[req]\n', mode=0o600)
        with self.assertRaises(RenewalError):
            renewal_status(self.fs, self.cert, self.key)

    def test_unchanged_paths_register_health_then_commit(self):
        result = self.register()
        self.assertEqual(self.events, ['validate', 'reload', 'health', 'state'])
        self.assertTrue(result['registered'])
        self.assertTrue(result['reload_verified'])
        self.assertEqual(self.fs.read_bytes(self.hook_path), self.hook.content)

    def test_changed_paths_rejected_before_validation_or_write(self):
        self.selected['cert_path'] = '/root/cert/other.example.test/fullchain.pem'
        with self.assertRaisesRegex(RenewalError, 'отдельн'):
            self.register()
        self.assertEqual(self.events, [])
        self.assertEqual(self.fs.read_text(self.record), self.old)
        self.assertFalse(self.fs.exists(self.hook_path))

    def test_validation_failure_precedes_write(self):
        def fail():
            raise ValueError('bad certificate')
        with self.assertRaises(ValueError):
            self.register(validate_candidate=fail)
        self.assertEqual(self.fs.read_text(self.record), self.old)
        self.assertFalse(self.fs.exists(self.hook_path))

    def test_acme_failure_restores_record_and_hook_without_leaking_output(self):
        self.code = 1
        with self.assertRaises(RenewalError) as caught:
            self.register()
        self.assertNotIn('secret', str(caught.exception))
        self.assertEqual(self.fs.read_text(self.record), self.old)
        self.assertFalse(self.fs.exists(self.hook_path))
        self.assertNotIn('state', self.events)

    def test_post_reload_and_state_failure_restore_metadata(self):
        for callback in ['post_reload', 'commit_state']:
            with self.subTest(callback=callback):
                def fail():
                    raise RuntimeError('callback failed')
                with self.assertRaises(RenewalError):
                    self.register(**{callback: fail, 'run_id': callback})
                self.assertEqual(self.fs.read_text(self.record), self.old)
                self.assertFalse(self.fs.exists(self.hook_path))

    def test_concurrent_record_change_during_callback_is_not_clobbered(self):
        def fail():
            self.fs.atomic_write_text(self.record, self.registered() + "Le_Alt='other.example.test'\n", mode=0o600)
            raise RuntimeError('health')
        with self.assertRaisesRegex(RenewalError, '(?i)конкурент'):
            self.register(post_reload=fail)
        self.assertIn("Le_Alt=", self.fs.read_text(self.record))

    def test_unattributed_change_during_acme_is_preserved(self):
        self.behavior = lambda: self.fs.atomic_write_text(self.record, self.registered() + "Le_Alt='other.example.test'\n", mode=0o600)
        with self.assertRaisesRegex(RenewalError, '(?i)конкурент'):
            self.register()
        self.assertIn('Le_Alt=', self.fs.read_text(self.record))

    def test_registration_preserves_all_other_provider_metadata(self):
        self.old += "Le_RealCertPath='/root/cert/example.test/cert.pem'\nLe_RealCACertPath='/root/cert/example.test/ca.pem'\n"
        self.fs.atomic_write_text(self.record, self.old, mode=0o600)
        self.register()
        self.assertEqual(self.fs.read_text(self.record), self.registered())

    def test_registration_preserves_original_line_endings(self):
        self.old = self.old.replace('\n', '\r\n')
        self.fs.atomic_write(self.record, self.old.encode(), mode=0o600)
        self.register()
        self.assertEqual(self.fs.read_bytes(self.record), self.registered().encode())

    def test_status_is_collected_before_last_state_commit(self):
        def commit():
            self.events.append('state')
            self.fs.atomic_write_text('/root/.acme.sh/unrelated.test/unrelated.test.conf', 'malformed')
        self.assertTrue(self.register(commit_state=commit)['registered'])

    def test_concurrent_hook_change_is_not_clobbered_by_rollback(self):
        def fail():
            self.fs.atomic_write_text(self.hook_path, '#!/bin/sh\nexit 1\n', mode=0o750)
            raise RuntimeError('health')
        with self.assertRaisesRegex(RenewalError, '(?i)конкурент'):
            self.register(post_reload=fail)
        self.assertIn('exit 1', self.fs.read_text(self.hook_path))
        self.assertEqual(self.fs.read_text(self.record), self.old)

    def test_idempotent_repeat_avoids_acme_reload(self):
        self.register()
        self.events.clear()
        result = self.register(run_id='repeat')
        self.assertEqual(self.events, ['validate', 'health', 'state'])
        self.assertFalse(result['changed'])

    def test_before_reload_records_epoch_only_for_actual_activation(self):
        def before():
            self.assertTrue(renewal_status(self.fs, self.cert, self.key)['registered'])
            self.assertEqual(self.fs.read_bytes(self.hook_path), self.hook.content)
            self.events.append('epoch')
        self.register(before_reload=before)
        self.assertEqual(self.events, ['validate', 'epoch', 'reload', 'health', 'state'])
        self.events.clear()
        self.register(before_reload=before, run_id='epoch-repeat')
        self.assertEqual(self.events, ['validate', 'health', 'state'])

    def test_failed_epoch_capture_rolls_back_metadata_without_starting_hook(self):
        def before():
            raise RuntimeError('epoch capture failed')
        with self.assertRaises(RenewalError):
            self.register(before_reload=before)
        self.assertEqual(self.events, ['validate'])
        self.assertEqual(self.fs.read_text(self.record), self.old)
        self.assertFalse(self.fs.exists(self.hook_path))

    def test_validation_race_refuses_stale_record(self):
        def mutate():
            self.fs.atomic_write_text(self.record, self.old + "Le_Alt='new.example.test'\n", mode=0o600)
        with self.assertRaises(RenewalError):
            self.register(validate_candidate=mutate)
        self.assertFalse(self.fs.exists(self.hook_path))

    def test_acme_source_pair_is_not_reinstalled_or_rewritten(self):
        self.fs.atomic_write_text('/root/.acme.sh/example.test_ecc/example.test.key', 'different synthetic key', mode=0o600)
        self.register()
        self.assertEqual(self.fs.read_text(self.key), 'synthetic key')

    def test_failed_registration_restores_only_own_identical_pair_write(self):
        def replace_same_pair():
            self.fs.atomic_write_text(self.key, 'synthetic key', mode=0o600)
        self.behavior = replace_same_pair
        self.code = 1
        with self.assertRaises(RenewalError):
            self.register()
        self.assertEqual(self.fs.read_text(self.key), 'synthetic key')
        self.assertEqual(self.fs.read_text(self.record), self.old)

    def test_acme_timeout_is_failure_and_restores_proven_metadata(self):
        def timeout():
            raise TimeoutError('secret command details')
        self.behavior = timeout
        with self.assertRaises(RenewalError) as caught:
            self.register()
        self.assertNotIn('secret', str(caught.exception))
        self.assertEqual(self.fs.read_text(self.record), self.old)

    def test_unknown_change_during_activation_is_not_clobbered(self):
        self.behavior = lambda: self.fs.atomic_write_text(self.record,
            self.registered() + "Le_RealCertPath=''\nLe_RealCACertPath=''\n", mode=0o600)
        with self.assertRaises(RenewalError):
            self.register()
        self.assertIn('Le_RealCACertPath', self.fs.read_text(self.record))

    def test_symlink_record_rejected(self):
        target = self.fs.path(self.record)
        other = target.with_suffix('.backup')
        target.rename(other)
        try:
            target.symlink_to(other)
        except OSError:
            self.skipTest('Создание symlink недоступно')
        with self.assertRaises(RenewalError):
            renewal_status(self.fs, self.cert, self.key)


if __name__ == '__main__':
    unittest.main()
