from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_staging_eligibility import candidate_manifest

from lucx_post_configurator import cli
from lucx_post_configurator.engine import ApplyError, Engine
from lucx_post_configurator.models import Audit
from lucx_post_configurator.runner import Runner
from lucx_post_configurator.transaction import FAILED_STATE_PATH


class CLINaiveLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.engine = Engine(self.root, runner=Runner(dry_run=True))
        self.engine.audit = mock.Mock(return_value=Audit(db_schema_supported=True))
        self.engine.plan = mock.Mock(return_value={'warnings': []})
        self.engine.apply = mock.Mock(return_value={'status': 'complete'})
        self.engine.sync_naive_inbound = mock.Mock(return_value={'status': 'complete'})
        self.engine.prepare_operation = mock.Mock(side_effect=lambda m, audit=None: self.prepared(m))

    @staticmethod
    def prepared(manifest):
        candidate = copy.deepcopy(manifest)
        candidate['naive_generations'] = {'7': {'source_sha256': 'synthetic-new-generation'}}
        return candidate

    def invoke(self, args, confirm=True, uid=0):
        with (
            mock.patch.object(cli, 'Engine', return_value=self.engine),
            mock.patch.object(cli.os, 'geteuid', return_value=uid, create=True),
            mock.patch.object(cli, '_confirm', side_effect=confirm if callable(confirm) else None,
                              return_value=confirm if not callable(confirm) else True),
            mock.patch.object(cli, 'format_plan', return_value='synthetic plan'),
            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()),
        ):
            return cli.main(args)

    def test_apply_and_resume_pass_rebound_fence_for_same_prepared_preview(self):
        for resume in (False, True):
            with self.subTest(resume=resume):
                manifest = candidate_manifest()
                path = self.engine.fs.path(FAILED_STATE_PATH) if resume else self.root / 'manifest.json'
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({'manifest': manifest} if resume else manifest), encoding='utf-8')
                original = path.read_bytes()
                prepared_calls = []
                def prepare_source(m, source, audit=None, prepared_calls=prepared_calls):
                    result = Engine.prepare_manifest_source(self.engine, m, source, audit)
                    prepared_calls.append(result)
                    return result
                self.engine.prepare_manifest_source = mock.Mock(side_effect=prepare_source)
                def apply(m, *, audit=None, manifest_source=None, prepared_calls=prepared_calls):
                    self.assertIs(m, self.engine.plan.call_args.args[0])
                    self.assertIs(m, prepared_calls[0][0])
                    self.assertIs(manifest_source, prepared_calls[0][1])
                    manifest_source.verify(manifest=m)
                    return {'status': 'complete'}
                self.engine.apply.side_effect = apply
                args = ['--resume'] if resume else ['--apply', '--manifest', str(path)]
                self.assertEqual(self.invoke(args), 0)
                self.assertEqual(path.read_bytes(), original)

    def test_confirmation_refusal_prepares_but_never_applies(self):
        path = self.root / 'manifest.json'
        path.write_text(json.dumps(candidate_manifest()), encoding='utf-8')
        self.assertEqual(self.invoke(['--apply', '--manifest', str(path)], confirm=False), 1)
        self.engine.prepare_operation.assert_called_once()
        self.engine.apply.assert_not_called()

    def test_file_change_after_preparation_remains_blocked_by_rebound_fence(self):
        path = self.root / 'manifest.json'
        path.write_text(json.dumps(candidate_manifest()), encoding='utf-8')
        def confirm(*args):
            path.write_bytes(path.read_bytes() + b' ')
            return True
        def apply(m, *, audit=None, manifest_source=None):
            Engine._verify_manifest_source(manifest_source, m)
            self.fail('Нельзя применять изменённый исходник')
        self.engine.apply.side_effect = apply
        self.assertEqual(self.invoke(['--apply', '--manifest', str(path)], confirm=confirm), 2)

    def test_plan_prepares_evidence_before_rendering(self):
        with mock.patch.object(cli, 'build_manifest_interactively', return_value=candidate_manifest()):
            self.assertEqual(self.invoke(['--plan']), 0)
        self.assertIn('naive_generations', self.engine.plan.call_args.args[0])
        self.engine.apply.assert_not_called()

    def test_configure_decoys_prepares_evidence_after_questionnaire(self):
        manifest = candidate_manifest()
        manifest['decoys']['enabled'] = True
        with (
            mock.patch.object(cli, 'load_state', return_value={'manifest': manifest}),
            mock.patch.object(cli, 'configure_protocol_decoys_interactively', return_value=(manifest, [])),
            mock.patch.object(cli, 'configure_decoy_routing_mode', return_value=(manifest, [])),
        ):
            self.assertEqual(self.invoke(['--configure-decoys']), 0)
        self.assertIn('naive_generations', self.engine.plan.call_args.args[0])
        self.assertIs(self.engine.apply.call_args.args[0], self.engine.plan.call_args.args[0])

    def test_internal_sync_never_enters_tui_or_asks_confirmation(self):
        with mock.patch.object(cli, 'run_tui', side_effect=AssertionError('Неинтерактивная служба')):
            self.assertEqual(self.invoke(['--sync-naive-inbound', '7'],
                                        confirm=lambda *args: self.fail('Лишнее подтверждение')), 0)
        self.engine.sync_naive_inbound.assert_called_once_with(7)
        self.engine.prepare_operation.assert_not_called()

    def test_internal_sync_rejects_test_root_before_mutation(self):
        self.assertEqual(self.invoke(['--sync-naive-inbound', '7', '--root', str(self.root)]), 2)
        self.engine.sync_naive_inbound.assert_not_called()

    def test_internal_sync_requires_root_before_calling_engine(self):
        self.assertEqual(self.invoke(['--sync-naive-inbound', '7'], uid=1000), 2)
        self.engine.sync_naive_inbound.assert_not_called()

    def test_internal_sync_does_not_convert_legacy_failure_into_foreground_adoption(self):
        self.engine.sync_naive_inbound.side_effect = ApplyError('Legacy требует нового foreground-плана')
        self.assertEqual(self.invoke(['--sync-naive-inbound', '7']), 2)
        self.engine.prepare_operation.assert_not_called()
        self.engine.apply.assert_not_called()

    def test_internal_sync_zero_does_not_fall_back_to_interactive_mode(self):
        self.engine.sync_naive_inbound.side_effect = ApplyError('Некорректный номер')
        with mock.patch.object(cli, 'run_tui', side_effect=AssertionError('Служба не должна открывать TUI')):
            self.assertEqual(self.invoke(['--sync-naive-inbound', '0']), 2)

    def test_internal_sync_is_hidden_and_mutually_exclusive(self):
        self.assertNotIn('--sync-naive-inbound', cli._parser().format_help())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli._parser().parse_args(['--sync-naive-inbound', '7', '--apply'])


if __name__ == '__main__':
    unittest.main()
