from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_staging_eligibility import candidate_manifest

from lucx_post_configurator import cli
from lucx_post_configurator.engine import Engine
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import FAILED_STATE_PATH


class CLIManifestSourceTests(unittest.TestCase):
    def test_resume_passes_guard_and_rejects_replaced_input_after_confirmation(self):
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                fs = TargetFS(Path(temporary))
                raw = json.dumps({'status': 'failed', 'run_id': 'synthetic-run',
                                  'manifest': candidate_manifest()}, indent=3) + '\n\n'
                fs.atomic_write_text(FAILED_STATE_PATH, raw)
                path = fs.path(FAILED_STATE_PATH)
                before = path.stat().st_mtime_ns
                engine = mock.Mock(fs=fs)
                engine.plan.return_value = {'warnings': []}
                engine.prepare_manifest_source.side_effect = lambda m, source, audit=None: (m, source)
                applied = []

                def confirm(*_, changed=changed, fs=fs, raw=raw):
                    if changed:
                        fs.atomic_write_text(FAILED_STATE_PATH, raw.replace('synthetic-run', 'synthetic-new'))
                    return True

                def apply(manifest, *, audit=None, manifest_source=None, applied=applied):
                    self.assertIsNotNone(manifest_source, 'Resume потерял привязку к исходному state')
                    Engine._verify_manifest_source(manifest_source, manifest)
                    applied.append(True)
                    return {'status': 'fixture'}

                engine.apply.side_effect = apply
                with mock.patch.object(cli, 'Engine', return_value=engine), \
                        mock.patch.object(cli, '_confirm', side_effect=confirm), \
                        mock.patch.object(cli, 'format_plan', return_value='fixture plan'), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(cli.main(['--resume', '--yes']), 2 if changed else 0)
                self.assertEqual(applied, [] if changed else [True])
                self.assertEqual(path.read_text(encoding='utf-8'),
                                 raw.replace('synthetic-run', 'synthetic-new') if changed else raw)
                if not changed:
                    self.assertEqual(path.stat().st_mtime_ns, before)

    def test_apply_preserves_file_bytes_and_passes_guard_for_exact_confirmed_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'manifest.json'
            raw = json.dumps(candidate_manifest(), indent=3) + '\n\n'
            path.write_text(raw, encoding='utf-8')
            before = path.stat().st_mtime_ns
            engine = mock.Mock()
            engine.plan.return_value = {'warnings': []}
            engine.prepare_manifest_source.side_effect = lambda m, source, audit=None: (m, source)

            def apply(manifest, *, audit=None, manifest_source=None):
                self.assertIsNotNone(manifest_source)
                manifest_source.verify(manifest=manifest)
                self.assertEqual(path.read_text(encoding='utf-8'), raw)
                return {'status': 'fixture'}

            engine.apply.side_effect = apply
            with mock.patch.object(cli, 'Engine', return_value=engine), \
                    mock.patch.object(cli, 'format_plan', return_value='fixture plan'), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(['--apply', '--manifest', str(path), '--yes']), 0)
            engine.apply.assert_called_once()
            self.assertEqual(path.read_text(encoding='utf-8'), raw)
            self.assertEqual(path.stat().st_mtime_ns, before)


if __name__ == '__main__':
    unittest.main()
