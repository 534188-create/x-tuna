from __future__ import annotations

import importlib.util
import tempfile
import unittest
from unittest.mock import PropertyMock, patch

from lucx_post_configurator.engine import Engine
from lucx_post_configurator.runner import Runner
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.models import Audit


class VPNProbeRegistryTests(unittest.TestCase):
    def test_installed_xray_echo_uses_only_lazy_audit_and_requires_own_address(self):
        self.manifest['vpn_probes'] = {'echo_address': '192.0.2.99'}
        runner = Runner()
        with (patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True),
              patch('sys.platform', 'linux'),
              patch.object(self.module, 'audit_system', return_value=Audit(public_addresses=['192.0.2.10'])) as audit):
            with self.module.installed_vpn_probes(self.fs, runner, self.manifest):
                provider = runner.vpn_observers['vless'].context.echo_address_provider
                audit.assert_not_called()
                self.assertEqual(provider(), '192.0.2.10')
                self.assertEqual(provider(), '192.0.2.10')
                audit.assert_called_once()
            with self.module.installed_vpn_probes(self.fs, runner, self.manifest, audit=Audit()):
                with self.assertRaises(ValueError):
                    runner.vpn_observers['vless'].context.echo_address_provider()

    def test_nested_registry_replaces_owned_sources_and_restores_outer_scope(self):
        import copy
        from test_naive_probes import profile
        self.manifest['protocols'] = [profile()]
        restored = copy.deepcopy(self.manifest)
        restored['network']['public_tcp_port'] = 8443
        restored['lucx']['db_path'] = '/etc/x-ui/restored.db'
        audit = Audit(public_addresses=['192.0.2.20'])
        runner = Runner()
        custom = {'vmess': lambda *_: None, 'custom': lambda *_: None}
        runner.vpn_observers = custom
        with (patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True),
              patch('sys.platform', 'linux')):
            with self.module.installed_vpn_probes(self.fs, runner, self.manifest):
                outer = runner.vpn_observers
                with self.assertRaisesRegex(RuntimeError, 'inner failure'):
                    with self.module.installed_vpn_probes(self.fs, runner, restored, audit=audit):
                        inner = runner.vpn_observers
                        self.assertIsNot(inner['vless'], outer['vless'])
                        self.assertIsNot(inner['naive'], outer['naive'])
                        self.assertEqual(inner['vless'].context.shared_tcp_port, 8443)
                        self.assertEqual(inner['naive']._manifest, restored)
                        self.assertEqual(inner['naive']._audit, audit)
                        self.assertIs(inner['vmess'], custom['vmess'])
                        self.assertIs(inner['custom'], custom['custom'])
                        raise RuntimeError('inner failure')
                self.assertIs(runner.vpn_observers, outer)
            self.assertIs(runner.vpn_observers, custom)

    def test_nested_registry_drops_naive_when_restored_cohort_has_none(self):
        from test_naive_probes import profile
        runner = Runner()
        restored = dict(self.manifest)
        self.manifest['protocols'] = [profile()]
        with (patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True),
              patch('sys.platform', 'linux')):
            with self.module.installed_vpn_probes(self.fs, runner, self.manifest):
                with self.module.installed_vpn_probes(self.fs, runner, restored):
                    self.assertNotIn('naive', runner.vpn_observers)

    def test_native_registration_is_lazy_and_never_uses_manifest_echo_override(self):
        from test_naive_probes import profile
        self.manifest['protocols'] = [profile()]
        self.manifest['vpn_probes'] = {'echo_address': '198.51.100.19', 'echo_port': 9999}
        audit = Audit(public_addresses=['192.0.2.10'])
        runner = Runner()
        with (patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True),
              patch('sys.platform', 'linux'),
              patch('lucx_post_configurator.vpn_probe_registry.audit_system', side_effect=AssertionError('eager audit')),
              patch('lucx_post_configurator.vpn_probe_registry.NativeNaiveSource') as native,
              patch('lucx_post_configurator.vpn_probe_registry.LucXNaiveCredentialSource') as auth,
              patch('lucx_post_configurator.vpn_probe_registry.NaiveVPNObserver') as observer):
            with self.module.installed_vpn_probes(self.fs, runner, self.manifest, audit=audit):
                self.assertEqual(set(runner.vpn_observers), {'vless', 'vmess', 'naive'})
                native.assert_not_called()
                auth.assert_not_called()
                observer.return_value.supports.return_value = True
                self.assertTrue(runner.vpn_observers['naive'].supports(self.manifest['protocols'][0]))
                context = observer.call_args.args[0]
                self.assertEqual((context.echo_address, context.echo_port), ('192.0.2.10', 0))
                self.assertIs(context.credential_provider, auth.return_value)
                self.assertIs(context.native_binding_provider, native.return_value)
                self.assertEqual(context.binary_path.as_posix(), self.module.NAIVE_PROBE_PATH)
            self.assertFalse(hasattr(runner, 'vpn_observers'))

    def test_native_audit_failure_is_sticky_and_preserves_other_observers(self):
        from test_naive_probes import profile
        self.manifest['protocols'] = [profile()]
        runner = Runner()
        with (patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True),
              patch('sys.platform', 'linux'),
              patch('lucx_post_configurator.vpn_probe_registry.audit_system', side_effect=ValueError('private-source')) as audit):
            with self.module.installed_vpn_probes(self.fs, runner, self.manifest):
                observer = runner.vpn_observers['naive']
                self.assertFalse(observer.supports(self.manifest['protocols'][0]))
                self.assertFalse(observer.supports(self.manifest['protocols'][0]))
                audit.assert_called_once()
                self.assertIn('vless', runner.vpn_observers)
                self.assertNotIn('private-source', repr(observer))

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('lucx_post_configurator.vpn_probe_registry'),
                             'Нужен штатный реестр функциональных проб')
        from lucx_post_configurator import vpn_probe_registry
        self.module = vpn_probe_registry
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fs = TargetFS(self.temp.name)
        self.manifest = {'lucx': {'db_path': '/etc/x-ui/x-ui.db'},
                         'network': {'public_tcp_port': 443}}

    def test_registry_is_lazy_and_ignores_manifest_tool_and_echo_overrides(self):
        self.manifest['vpn_probes'] = {'binary_path': '/tmp/forged', 'sha256': '0' * 64,
                                       'echo_address': '192.0.2.1', 'echo_port': 9999}
        runner = Runner()
        with patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True), \
                patch('sys.platform', 'linux'), patch('sqlite3.connect', side_effect=AssertionError('eager read')), \
                patch('socket.socket', side_effect=AssertionError('eager listener')):
            with self.module.installed_vpn_probes(self.fs, runner, self.manifest):
                self.assertEqual(set(runner.vpn_observers), {'vless', 'vmess'})
                context = runner.vpn_observers['vless'].context
                self.assertEqual(context.binary_path.as_posix(), self.module.XRAY_PROBE_PATH)
                self.assertEqual(context.echo_address, '127.0.0.1')
                self.assertEqual(context.echo_port, 0)
                self.assertNotEqual(context.binary_sha256, '0' * 64)
            self.assertFalse(hasattr(runner, 'vpn_observers'))
        self.assertEqual(runner.history, [])

    def test_explicit_code_observers_are_restored_after_failure(self):
        runner = Runner()
        custom = {'vless': lambda protocol, run: {'state': 'not_tested'}}
        runner.vpn_observers = custom
        with patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True), \
                patch('sys.platform', 'linux'), self.assertRaisesRegex(RuntimeError, 'synthetic'), \
                self.module.installed_vpn_probes(self.fs, runner, self.manifest):
            self.assertIs(runner.vpn_observers['vless'], custom['vless'])
            raise RuntimeError('synthetic')
        self.assertIs(runner.vpn_observers, custom)

    def test_engine_apply_registers_before_manifest_preflight_and_restores_after_failure(self):
        engine = Engine(self.temp.name, runner=Runner())

        def preflight(manifest):
            self.assertEqual(set(engine.runner.vpn_observers), {'vless', 'vmess'})
            raise RuntimeError('read-only checkpoint')

        with patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True), \
                patch('sys.platform', 'linux'), \
                patch('lucx_post_configurator.engine.validate_manifest', side_effect=preflight):
            with self.assertRaisesRegex(RuntimeError, 'read-only checkpoint'):
                engine._apply_locked(self.manifest)
        self.assertFalse(hasattr(engine.runner, 'vpn_observers'))
        self.assertEqual(engine.runner.history, [])

    def test_offline_root_and_dry_run_do_not_register_live_probes(self):
        for live, dry in ((False, False), (True, True)):
            runner = Runner(dry_run=dry)
            with patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=live), \
                    self.module.installed_vpn_probes(self.fs, runner, self.manifest):
                self.assertFalse(hasattr(runner, 'vpn_observers'))

    def test_engine_installed_validation_has_builtin_probes_only_inside_live_check(self):
        engine = Engine(self.temp.name, runner=Runner())
        def live_check(manifest, runner, **kwargs):
            self.assertEqual(set(runner.vpn_observers), {'vless', 'vmess'})
            return []
        with patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True), \
                patch('sys.platform', 'linux'), patch.object(engine, 'audit'), \
                patch('lucx_post_configurator.engine.load_state', return_value={
                    'manifest': self.manifest, 'run_id': 'synthetic', 'installed_hashes': {}}), \
                patch('lucx_post_configurator.engine.validate_audit_against_manifest', return_value=[]), \
                patch('lucx_post_configurator.engine.validate_certificate', return_value=[]), \
                patch('lucx_post_configurator.engine.validate_lucx_tls_coverage', return_value=[]), \
                patch('lucx_post_configurator.engine.validate_live_configuration', side_effect=live_check) as check:
            self.assertTrue(engine.validate_installed()['ok'])
            self.assertFalse(hasattr(engine.runner, 'vpn_observers'))
            self.assertTrue(engine.validate_installed(include_live=False)['ok'])
            self.assertEqual(check.call_count, 1)


if __name__ == '__main__':
    unittest.main()
