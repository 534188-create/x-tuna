from __future__ import annotations

import json
import re
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from lucx_post_configurator.engine import Engine, ApplyError
from lucx_post_configurator.models import default_manifest
from lucx_post_configurator.renderers import render_tls_hook
from lucx_post_configurator.targetfs import TargetFS


class ReloadDispatchTests(unittest.TestCase):
    def manifest(self):
        manifest = default_manifest()
        manifest['components']['naive_frontend'] = True
        manifest['decoys']['extended_routes'] = [
            {'inbound_id': 7, 'strategy': 'naive_managed', 'status': 'ready'},
            {'inbound_id': 8, 'strategy': 'naive_managed', 'status': 'blocked'},
        ]
        return manifest

    def test_each_reload_queues_unique_transaction_without_waiting_for_parent_lock(self):
        hook = render_tls_hook(self.manifest())
        self.assertIn("<<'LUCX_NAIVE_SYNC'", hook)
        block = hook.split("<<'LUCX_NAIVE_SYNC'\n", 1)[1].split('\nLUCX_NAIVE_SYNC', 1)[0]
        self.assertGreater(hook.index("<<'LUCX_NAIVE_SYNC'"), hook.index('systemctl try-reload-or-restart'))
        with patch('subprocess.run') as run:
            exec(compile(block, 'reload-dispatch', 'exec'), {})
            exec(compile(block, 'reload-dispatch', 'exec'), {})
        self.assertEqual(run.call_count, 2)
        units = []
        for call in run.call_args_list:
            args = call.args[0]
            self.assertEqual(args[0], 'systemd-run')
            self.assertIn('--no-block', args)
            # Через transient D-Bus значение 0 означает немедленный timeout.
            # Здесь нужно явное infinity, в отличие от legacy unit-file parser.
            self.assertIn('--property=TimeoutStartSec=infinity', args)
            self.assertNotIn('--property=TimeoutStartSec=0', args)
            self.assertIn('--property=UMask=0077', args)
            self.assertEqual(args[-3:], ['--', '/usr/local/libexec/lucx-naive-sync.py', '7'])
            self.assertTrue(call.kwargs['check'])
            unit = next(a for a in args if a.startswith('--unit='))
            self.assertRegex(unit, r'^--unit=lucx-naive-reload-7-[a-f0-9]{32}$')
            units.append(unit)
        self.assertNotEqual(*units)

    def test_no_managed_route_does_not_schedule_worker(self):
        self.assertNotIn('LUCX_NAIVE_SYNC', render_tls_hook(default_manifest()))

    def test_untrusted_identifier_cannot_enter_dispatch_command(self):
        manifest = self.manifest()
        manifest['decoys']['extended_routes'][0]['inbound_id'] = '7;id'
        with self.assertRaises(ValueError):
            render_tls_hook(manifest)


class LiveTestFS(TargetFS):
    @property
    def is_live(self):
        return True


class SyncLockWaitTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.engine = Engine(temp.name)
        self.engine.fs = LiveTestFS(temp.name)
        self.fcntl = types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, LOCK_UN=8, flock=Mock())

    def test_background_waits_before_entering_then_never_interrupts_commit(self):
        self.fcntl.flock.side_effect = [BlockingIOError(), None, None]
        with patch.dict('sys.modules', {'fcntl': self.fcntl}), patch(
            'lucx_post_configurator.engine.time.monotonic', side_effect=[0, 0.1]
        ), patch('lucx_post_configurator.engine.time.sleep') as sleep:
            with self.engine._exclusive_lock(wait_timeout=180):
                self.assertEqual(self.fcntl.flock.call_count, 2)
            self.assertEqual(self.fcntl.flock.call_args.args[1], self.fcntl.LOCK_UN)
            sleep.assert_called_once()

    def test_timeout_does_not_mutate_owner_metadata_or_enter_operation(self):
        path = self.engine.fs.path('/run/lock/lucx-post-configurator.lock.json')
        path.parent.mkdir(parents=True)
        original = json.dumps({'pid': 1, 'operation': 'existing'})
        path.write_text(original)
        self.fcntl.flock.side_effect = BlockingIOError()
        with patch.dict('sys.modules', {'fcntl': self.fcntl}), patch(
            'lucx_post_configurator.engine.time.monotonic', side_effect=[0, 181]
        ), patch('lucx_post_configurator.engine.os.kill'):
            with self.assertRaises(ApplyError):
                with self.engine._exclusive_lock(wait_timeout=180):
                    self.fail('lock was not acquired')
        self.assertEqual(path.read_text(), original)

    def test_interactive_lock_still_fails_immediately(self):
        self.fcntl.flock.side_effect = BlockingIOError()
        with patch.dict('sys.modules', {'fcntl': self.fcntl}), patch(
            'lucx_post_configurator.engine.time.sleep'
        ) as sleep:
            with self.assertRaises(ApplyError):
                with self.engine._exclusive_lock():
                    self.fail('lock was not acquired')
            sleep.assert_not_called()
