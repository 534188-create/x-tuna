from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from lucx_post_configurator.models import default_manifest
from lucx_post_configurator.tui import (
    _apply_prepared,
    _certificate_banner,
    _enable_existing_cert_renewal,
    _explain_operation_error,
    _prepare_plan,
    _renewal_observation,
    _retry_pending_operation,
    run_tui,
)


def empty_plan():
    return {'actions': [], 'files': [], 'warnings': [], 'immutable': [], 'packages': [], 'services': []}


class TuiRecoveryTests(unittest.TestCase):
    def test_renewal_schedule_expression_and_service_shown_automatically(self):
        selected = {'source': 'acme.sh', 'cert_path': '/certificate', 'key_path': '/key'}
        self.engine.runner = object()
        with patch('lucx_post_configurator.tui.observed_renewal_status', return_value={
            'registered': True, 'hook_present': True, 'schedule_found': True,
            'schedule_state': 'found', 'cron_active': True,
            'schedules': [{'expression': '57 0,6,12,18 * * *', 'timezone': 'Etc/UTC'}],
        }) as observed:
            label, _, _ = _renewal_observation(self.engine, selected, self.manifest)
        self.assertIn('ежедневно в 00:57, 06:57, 12:57, 18:57', label)
        self.assertIn('Etc/UTC', label)
        self.assertIn('cron активен', label)
        self.assertIs(observed.call_args.kwargs['runner'], self.engine.runner)

    def test_complex_renewal_schedule_keeps_cron_expression(self):
        with patch('lucx_post_configurator.tui.observed_renewal_status', return_value={
            'registered': True, 'hook_present': True, 'schedule_found': True,
            'schedules': [{'expression': '*/15 0-6 * * 1', 'timezone': None}],
        }):
            label, _, _ = _renewal_observation(self.engine, {'source': 'acme.sh'}, self.manifest)
        self.assertIn('*/15 0-6 * * 1', label)
        self.assertNotIn('ежедневно', label)
        self.assertIn('часовой пояс не проверен', label)

    def test_renewal_absent_and_unknown_schedule_are_distinct(self):
        for state, found, expected in [('absent', False, 'расписание cron не найдено'),
                                       ('unreadable', None, 'не удалось прочитать'),
                                       ('unsupported', None, 'неподдерживаемая запись')]:
            with self.subTest(state=state), patch('lucx_post_configurator.tui.observed_renewal_status',
                    return_value={'registered': True, 'hook_present': True,
                                  'schedule_state': state, 'schedule_found': found}):
                label, _, _ = _renewal_observation(self.engine, {'source': 'acme.sh'}, self.manifest)
                self.assertIn(expected, label)

    def test_error_shows_specific_safe_reason_and_remedy(self):
        output = []
        _explain_operation_error(RuntimeError('Сертификат истёк'), output.append)
        self.assertIn('Сертификат истёк', '\n'.join(output))
        self.assertIn('Повторно проверить', '\n'.join(output))

    def setUp(self):
        self.manifest = default_manifest()
        self.manifest['components']['sidecar'] = True
        self.engine = SimpleNamespace(
            fs=object(), audit=Mock(return_value=object()),
            prepare_operation=Mock(side_effect=lambda m, audit=None: copy.deepcopy(m)),
            plan=Mock(return_value=empty_plan()), apply=Mock(return_value={'status': 'complete'}),
            plan_certificate_renewal=Mock(return_value=empty_plan()),
            enable_certificate_renewal=Mock(return_value={'status': 'complete'}),
        )
        self.output = []

    def test_prepare_changes_only_candidate_before_plan(self):
        def prepare(m, audit=None):
            candidate = copy.deepcopy(m)
            candidate['routing_generation'] = 'new'
            return candidate
        self.engine.prepare_operation.side_effect = prepare
        _prepare_plan(self.engine, self.manifest, object())
        self.assertEqual(self.engine.plan.call_args.args[0]['routing_generation'], 'new')
        self.assertTrue(self.manifest['components']['sidecar'])

    def test_failed_prepare_retry_preserves_requested_sidecar_change(self):
        self.engine.prepare_operation.side_effect = RuntimeError('Naive source changed after audit')
        with self.assertRaises(RuntimeError):
            _prepare_plan(self.engine, self.manifest, object())
        self.manifest['components']['sidecar'] = False
        self.engine.prepare_operation.side_effect = lambda m, audit=None: copy.deepcopy(m)
        _retry_pending_operation(self.engine, lambda _: '1', self.output.append)
        self.assertTrue(self.engine.apply.call_args.args[0]['components']['sidecar'])
        self.assertIsNone(getattr(self.engine, '_tui_pending_operation', None))

    def test_repeated_guard_failure_never_calls_apply(self):
        self.engine.prepare_operation.side_effect = RuntimeError('Naive source changed after audit')
        with self.assertRaises(RuntimeError):
            _prepare_plan(self.engine, self.manifest, object())
        _retry_pending_operation(self.engine, lambda _: '1', self.output.append)
        self.engine.apply.assert_not_called()
        rendered = '\n'.join(self.output)
        self.assertIn('Причина:', rendered)
        self.assertIn('Повторно проверить', rendered)

    def test_failed_apply_retry_requires_new_preview_and_confirmation(self):
        _prepare_plan(self.engine, self.manifest, object())
        self.engine.apply.side_effect = RuntimeError('changed after audit')
        with self.assertRaises(RuntimeError):
            _apply_prepared(self.engine, self.manifest, audit=object())
        self.engine.apply.reset_mock(side_effect=True)
        _retry_pending_operation(self.engine, lambda _: '2', self.output.append)
        self.engine.apply.assert_not_called()
        self.assertEqual(self.engine.plan.call_count, 2)

    def test_certificate_retry_uses_narrow_operation_and_exact_selected_pair(self):
        selected = {'cert_path': '/root/cert/example.test/fullchain.pem',
                    'key_path': '/root/cert/example.test/privkey.pem'}
        self.engine.prepare_operation.side_effect = RuntimeError('busy')
        with self.assertRaises(RuntimeError):
            _prepare_plan(self.engine, self.manifest, object(), kind='renewal', selected=selected)
        self.engine.prepare_operation.side_effect = lambda m, audit=None: copy.deepcopy(m)
        _retry_pending_operation(self.engine, lambda _: '1', self.output.append)
        self.engine.enable_certificate_renewal.assert_called_once()
        self.assertEqual(self.engine.enable_certificate_renewal.call_args.kwargs['selected'], selected)
        self.engine.apply.assert_not_called()

    def test_retry_without_pending_requires_saved_state_plan(self):
        with patch('lucx_post_configurator.tui.load_state', return_value={'manifest': self.manifest}):
            _retry_pending_operation(self.engine, lambda _: '2', self.output.append)
        self.engine.prepare_operation.assert_called_once()
        self.engine.apply.assert_not_called()

    def test_observed_registration_overrides_stale_disabled_manifest(self):
        self.manifest['certificates']['renewal']['enabled'] = False
        with (
            patch('lucx_post_configurator.tui.load_state', return_value={'manifest': self.manifest}),
            patch('lucx_post_configurator.tui.certificate_status', return_value={'selected': {
                'cert_path': '/root/cert/example.test/fullchain.pem', 'key_path': '/root/cert/example.test/privkey.pem',
                'expires_at': '2026-12-31', 'source': 'acme.sh'}}),
            patch('lucx_post_configurator.tui.observed_renewal_status', return_value={
                'provider': 'acme.sh', 'registered': True, 'hook_present': True,
                'schedule_verified': False, 'schedule_found': None}),
        ):
            _, label = _certificate_banner(self.engine)
        self.assertIn('hook зарегистрирован', label)
        self.assertIn('расписание не проверено', label)
        self.assertNotIn('не настроено', label)

    def test_main_menu_recheck_retries_same_action_after_one_failure(self):
        attempts = 0
        def prepare(m, audit=None):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError('Naive source changed after audit')
            return copy.deepcopy(m)
        self.engine.prepare_operation.side_effect = prepare
        answers = iter(['2', '6', '1', '0'])
        with (
            patch('lucx_post_configurator.tui._main_state_banner', return_value=''),
            patch('lucx_post_configurator.tui._config_menu',
                  side_effect=lambda *args: _prepare_plan(self.engine, self.manifest, object())),
        ):
            run_tui(self.engine, input_fn=lambda _: next(answers), output_fn=self.output.append)
        self.engine.apply.assert_called_once()
        self.assertTrue(self.engine.apply.call_args.args[0]['components']['sidecar'])
        self.assertEqual(attempts, 2)

    def test_main_menu_keeps_visible_block_reason_until_successful_recheck(self):
        self.engine.prepare_operation.side_effect = RuntimeError('Naive source changed after audit')
        with self.assertRaises(RuntimeError):
            _prepare_plan(self.engine, self.manifest, object())
        with patch('lucx_post_configurator.tui._main_state_banner', return_value=''):
            run_tui(self.engine, input_fn=lambda _: '0', output_fn=self.output.append)
        self.assertIn('Причина:', '\n'.join(self.output))
        self.assertIn('Дождитесь', '\n'.join(self.output))

    def test_lock_error_guidance_never_suggests_removing_active_lock(self):
        _explain_operation_error(RuntimeError('lock busy'), self.output.append)
        self.assertIn('Активную блокировку удалять нельзя', '\n'.join(self.output))
        self.engine.apply.assert_not_called()

    def test_error_does_not_echo_runtime_credentials(self):
        _explain_operation_error(RuntimeError('upstream=localhost synthetic-private-value'), self.output.append)
        self.assertNotIn('synthetic-private-value', '\n'.join(self.output))

    def test_other_certificate_paths_do_not_enter_narrow_or_full_apply(self):
        with patch('lucx_post_configurator.tui.load_state', return_value={'manifest': self.manifest}):
            _enable_existing_cert_renewal(self.engine, {'cert_path': '/other/cert.pem', 'key_path': '/other/key.pem'},
                                         'acme.sh', lambda _: '1', self.output.append)
        self.engine.prepare_operation.assert_not_called()
        self.engine.apply.assert_not_called()
        self.engine.enable_certificate_renewal.assert_not_called()


if __name__ == '__main__':
    unittest.main()
