from __future__ import annotations

import contextlib
import io
import stat
import subprocess
import types
import unittest
from unittest.mock import patch

from lucx_post_configurator.naive_frontend import (
    render_naive_sync_script,
    render_naive_sync_unit,
    render_naive_frontend_unit,
)


class NaiveSyncWorkerBoundaryTests(unittest.TestCase):
    def worker(self):
        namespace = {"__name__": "naive_sync_worker_test"}
        exec(compile(render_naive_sync_script(), "naive-sync.py", "exec"), namespace)
        return namespace

    @staticmethod
    def executable(*, mode=stat.S_IFREG | 0o755, uid=0):
        return types.SimpleNamespace(st_mode=mode, st_uid=uid)

    def test_worker_dispatches_only_internal_engine_operation(self):
        worker = self.worker()
        with patch.object(worker["os"], "lstat", return_value=self.executable()), patch.object(
            worker["subprocess"], "run", return_value=types.SimpleNamespace(returncode=0)
        ) as run:
            self.assertEqual(worker["main"](["7"]), 0)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/usr/local/sbin/lucx-post-configure", "--sync-naive-inbound", "7"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn("PYTHONPATH", kwargs["env"])
        self.assertNotIn("LD_PRELOAD", kwargs["env"])
        self.assertNotIn("timeout", kwargs)

    def test_invalid_identifier_never_executes_or_reads_target(self):
        worker = self.worker()
        for args in [[], ["0"], ["-1"], ["01"], ["../7"], ["7;id"], ["7", "8"], ["2147483648"]]:
            with self.subTest(args=args), patch.object(worker["os"], "lstat") as inspect, patch.object(
                worker["subprocess"], "run"
            ) as run, contextlib.redirect_stderr(io.StringIO()):
                self.assertNotEqual(worker["main"](args), 0)
                inspect.assert_not_called()
                run.assert_not_called()

    def test_untrusted_installed_payload_never_executes(self):
        worker = self.worker()
        for metadata in [self.executable(mode=stat.S_IFLNK | 0o777), self.executable(uid=1000),
                         self.executable(mode=stat.S_IFREG | 0o775), self.executable(mode=stat.S_IFREG | 0o644)]:
            with self.subTest(metadata=metadata), patch.object(worker["os"], "lstat", return_value=metadata), patch.object(
                worker["subprocess"], "run"
            ) as run, contextlib.redirect_stderr(io.StringIO()):
                self.assertNotEqual(worker["main"](["7"]), 0)
                run.assert_not_called()

    def test_child_failure_is_nonzero_and_output_is_not_logged(self):
        worker = self.worker()
        secret = "secret-marker-do-not-log"
        captured = io.StringIO()
        with patch.object(worker["os"], "lstat", return_value=self.executable()), patch.object(
            worker["subprocess"], "run", return_value=types.SimpleNamespace(returncode=17, stdout=secret, stderr=secret)
        ), contextlib.redirect_stderr(captured):
            self.assertNotEqual(worker["main"](["7"]), 0)
        self.assertNotIn(secret, captured.getvalue())
        self.assertIn("[lucx-naive-sync]", captured.getvalue())

    def test_os_failure_never_prints_exception_or_secrets(self):
        worker = self.worker()
        captured = io.StringIO()
        with patch.object(worker["os"], "lstat", side_effect=OSError("secret-marker-do-not-log")), contextlib.redirect_stderr(captured):
            self.assertNotEqual(worker["main"](["7"]), 0)
        self.assertNotIn("secret-marker-do-not-log", captured.getvalue())

    def test_worker_cannot_copy_source_or_restart_services_directly(self):
        script = render_naive_sync_script()
        for forbidden in ["os.replace", "basic_auth", "socks5://", "try-restart", "systemctl", "open("]:
            self.assertNotIn(forbidden, script)

    def test_unit_runs_private_root_transaction_without_killing_commit(self):
        unit = render_naive_sync_unit(7)
        self.assertIn("User=root", unit)
        self.assertIn("Group=root", unit)
        self.assertIn("UMask=0077", unit)
        self.assertIn("TimeoutStartSec=0", unit)
        self.assertIn("ExecStart=/usr/local/libexec/lucx-naive-sync.py 7", unit)

    def test_frontend_restart_never_recursively_takes_engine_lock(self):
        unit = render_naive_frontend_unit(inbound_id=7, binary_path="/usr/local/bin/caddy")
        self.assertNotIn("ExecStartPre=", unit)
        self.assertNotIn("lucx-naive-sync", unit)
        self.assertIn("PartOf=x-ui.service", unit)


if __name__ == "__main__":
    unittest.main()
