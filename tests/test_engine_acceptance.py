from __future__ import annotations

import copy
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

from helpers import make_target
from test_required_acceptance import functional_result, strict_manifest
from test_transport_routing_regressions import topology

from lucx_post_configurator import validation
from lucx_post_configurator.decoy_health import observe_vpn_capabilities
from lucx_post_configurator.engine import ApplyError, Engine
from lucx_post_configurator.models import Audit, Inbound
from lucx_post_configurator.runner import CommandResult, Runner
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import (
    STATE_PATH,
    create_backup,
    load_state,
    save_state,
)


class EngineAcceptanceTests(unittest.TestCase):
    def rollback_probe_fixture(self):
        """Реальный backup/state; подменены только системные вызовы и probes."""
        stack = ExitStack()
        self.addCleanup(stack.close)
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        make_target(root)
        engine = Engine(root, runner=Runner())
        candidate = topology('grpc')
        candidate['components'] = {name: False for name in candidate['components']}
        candidate['components']['haproxy'] = True
        candidate['dns']['enabled'] = False
        candidate['decoys'].update(enabled=False, routing_mode='strict')
        candidate['lucx']['settings_management'] = {}
        restored = copy.deepcopy(candidate)
        restored['protocols'][0].update(domain='old.example.test', sni_names=['old.example.test'])
        save_state(engine.fs, {'status': 'complete', 'run_id': 'restored-run',
                              'manifest': restored, 'installed_hashes': {}})
        restored = load_state(engine.fs)['manifest']
        events, active, health_checks, audits = [], [], [], []

        @contextmanager
        def registry(fs, runner, manifest, *, audit=None, **_kwargs):
            self.assertIs(fs, engine.fs)
            self.assertIs(runner, engine.runner)
            role = 'candidate' if manifest is candidate else 'restored'
            if role == 'restored':
                self.assertEqual(manifest, restored)
            token = (manifest, audit)
            events.append(('enter', role))
            active.append(token)
            try:
                yield
            finally:
                self.assertIs(active.pop(), token)
                events.append(('exit', role))

        def fresh_audit(*_args):
            audit = Audit(supported_os=True, db_schema_supported=True)
            audits.append(audit)
            return audit

        def health(manifest, runner, *, fs, audit, vpn_phase):
            self.assertEqual(vpn_phase, 'rollback')
            self.assertEqual(manifest, restored)
            self.assertIs(runner, engine.runner)
            self.assertIs(fs, engine.fs)
            self.assertIs(audit, audits[-1])
            events.append(('health', 'restored'))
            health_checks.append(bool(active and active[-1][0] is manifest and active[-1][1] is audit))
            return []

        stack.enter_context(patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True))
        stack.enter_context(patch.object(engine, 'audit', side_effect=fresh_audit))
        stack.enter_context(patch.object(engine.runner, 'run',
            side_effect=lambda args, **_kwargs: CommandResult(list(args), 0, '', '')))
        stack.enter_context(patch('lucx_post_configurator.engine.installed_vpn_probes', side_effect=registry))
        stack.enter_context(patch('lucx_post_configurator.engine.validate_live_configuration', side_effect=health))
        return SimpleNamespace(stack=stack, engine=engine, candidate=candidate, restored=restored,
                               events=events, active=active, health_checks=health_checks)

    def test_automatic_rollback_installs_fresh_restored_probe_scope(self):
        case = self.rollback_probe_fixture()
        for name in ('validate_audit_against_manifest', 'validate_public_bind_conflicts',
                     'required_vpn_probe_errors'):
            case.stack.enter_context(patch('lucx_post_configurator.engine.' + name, return_value=[]))
        case.stack.enter_context(patch('lucx_post_configurator.engine._ephemeral_routing_material', return_value=None))
        case.stack.enter_context(patch('lucx_post_configurator.engine.render_files', return_value={}))
        case.stack.enter_context(patch('lucx_post_configurator.engine.validate_certificate',
                                      return_value=['synthetic candidate certificate failure']))
        case.stack.enter_context(patch('lucx_post_configurator.engine.validate_lucx_tls_coverage', return_value=[]))
        with self.assertRaisesRegex(ApplyError, 'synthetic candidate certificate failure'):
            case.engine._apply_locked(case.candidate)
        self.assertEqual(load_state(case.engine.fs)['manifest'], case.restored)
        self.assertEqual(case.active, [], 'Scope кандидата обязан завершиться после автоматического rollback')
        self.assertEqual(case.health_checks, [True], 'Rollback использовал registry нового manifest')
        self.assertEqual(case.events, [('enter', 'candidate'), ('enter', 'restored'),
            ('health', 'restored'), ('exit', 'restored'), ('exit', 'candidate')])

    def test_manual_rollback_installs_and_exits_fresh_restored_probe_scope(self):
        case = self.rollback_probe_fixture()
        create_backup(case.engine.fs, {}, 'candidate-run', extra_targets=[STATE_PATH])
        save_state(case.engine.fs, {'status': 'complete', 'run_id': 'candidate-run',
            'manifest': case.candidate, 'installed_hashes': {}})
        self.assertEqual(case.engine._rollback_locked(), 'candidate-run')
        self.assertEqual(load_state(case.engine.fs)['manifest'], case.restored)
        self.assertEqual(case.active, [], 'Scope восстановленного manifest не должен утекать')
        self.assertEqual(case.health_checks, [True], 'Ручной rollback не установил registry восстановленного manifest')
        self.assertEqual(case.events, [('enter', 'restored'), ('health', 'restored'), ('exit', 'restored')])

    def test_rollback_receipts_only_satisfy_the_rollback_validation(self):
        manifest = strict_manifest()
        rows = observe_vpn_capabilities(manifest, Runner(),
            observers={'vless':functional_result}, phase='rollback')
        self.assertTrue(any('VPN' in error for error in
                            validation.validate_required_acceptance(manifest, [], rows)))
        errors = validation.validate_required_acceptance(manifest, [], rows, vpn_phase='rollback')
        self.assertFalse(any('VPN' in error for error in errors), errors)

    def test_apply_without_required_adapter_stops_before_integrity_and_backup(self):
        manifest = topology("grpc")
        manifest["decoys"]["require_full_acceptance"] = True
        manifest["protocols"][0]["public_endpoints"] = [{
            "host_id": 1, "address": "vpn.example.test", "port": 443,
            "sni": "vpn.example.test", "sni_source": "address", "keep_sni_blank": False,
            "http_host": "", "valid": True}]
        audit = Audit(supported_os=True, db_schema_supported=True,
            settings={"webDomain": "panel.example.test", "webPort": "2083",
                      "subDomain": "sub.example.test", "subPort": "2096"},
            inbounds=[Inbound(id=7, protocol="vless", remark="", enable=True,
                              listen="127.0.0.1", port=18443, transport="grpc")])
        with tempfile.TemporaryDirectory() as root:
            engine = Engine(root, runner=Runner(dry_run=True))
            with patch.object(TargetFS, "is_live", new_callable=PropertyMock, return_value=True), \
                    patch.object(engine, "audit", return_value=audit), \
                    patch("lucx_post_configurator.engine.validate_public_bind_conflicts", return_value=[]), \
                    patch("lucx_post_configurator.engine.capture_integrity", side_effect=AssertionError("preflight must stop before backup")) as capture:
                with self.assertRaisesRegex(ApplyError, "адаптер"):
                    engine._apply_locked(manifest)
            capture.assert_not_called()
            self.assertEqual(engine.runner.history, [])

    def test_missing_browser_or_vpn_receipts_are_fatal_only_for_required_acceptance(self):
        manifest = topology("grpc")
        self.assertEqual(validation.validate_required_acceptance(manifest, [], []), [])
        manifest["decoys"]["require_full_acceptance"] = True
        errors = validation.validate_required_acceptance(manifest, [], [])
        self.assertTrue(any("сайт" in error.lower() for error in errors))
        self.assertTrue(any("VPN" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
