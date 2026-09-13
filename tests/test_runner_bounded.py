import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from lucx_post_configurator import runner as module


class BoundedRunnerTests(unittest.TestCase):
    def run_child(self, code, **kwargs):
        return module.Runner().run_bounded([sys.executable,'-c',code],timeout=3,
                                           max_output_bytes=128,**kwargs)

    def test_stdout_and_stderr_floods_are_stopped_without_raw_error_output(self):
        for stream in ('stdout','stderr'):
            with self.subTest(stream=stream):
                with self.assertRaises(module.OutputLimitExceeded) as caught:
                    self.run_child("import sys; sys."+stream+".write('sensitive-sentinel'*100000)")
                self.assertNotIn('sensitive-sentinel',str(caught.exception))

    def test_stdout_and_stderr_share_one_limit(self):
        with self.assertRaises(module.OutputLimitExceeded):
            self.run_child("import sys; sys.stdout.write('a'*80); sys.stderr.write('b'*80)")

    def test_exact_limit_is_successful(self):
        result=self.run_child("import sys; sys.stdout.write('a'*128)")
        self.assertEqual(result.stdout,'a'*128)

    def test_stdin_nonzero_and_utf8_are_preserved(self):
        result=self.run_child("import sys; sys.stdout.write(sys.stdin.read()); sys.exit(4)",
                              input_text='Пример',check=False)
        self.assertEqual(result.returncode,4)
        self.assertEqual(result.stdout,'Пример')

    def test_isolated_environment_does_not_forward_parent_variables(self):
        with mock.patch.dict(os.environ, {'XTUNA_PARENT_SENTINEL': 'private-context'}):
            try:
                result = self.run_child(
                    "import os; print(os.environ.get('XTUNA_PARENT_SENTINEL','absent'))",
                    inherit_env=False)
            except TypeError:
                self.fail('Runner должен уметь запускать worker без наследования окружения')
        self.assertEqual(result.stdout.strip(), 'absent')

    def test_timeout_reaps_sleeping_child(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            module.Runner().run_bounded([sys.executable,'-c','import time; time.sleep(10)'],
                                        timeout=0.1,max_output_bytes=128)

    def test_dry_run_and_invalid_limit_do_not_spawn(self):
        self.assertEqual(module.Runner(dry_run=True).run_bounded(['not-a-command'],max_output_bytes=1).returncode,0)
        with self.assertRaises(ValueError):
            module.Runner().run_bounded(['not-a-command'],max_output_bytes=0)

    def test_process_group_argument_is_explicit(self):
        import inspect
        self.assertIn('isolate_process_group', inspect.signature(module.Runner.run_bounded).parameters)

    @unittest.skipUnless(sys.platform == 'linux', 'Проверка Linux process group')
    def test_process_group_reaps_descendant_after_parent_exit_and_timeout(self):
        for parent_exits in (True, False):
            with self.subTest(parent_exits=parent_exits), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'child.pid'
                code = ("import pathlib,subprocess,sys,time; "
                    "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(20)']); "
                    "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); "
                    + ("print('done')" if parent_exits else "time.sleep(20)"))
                call = lambda code=code, path=path: module.Runner().run_bounded([sys.executable, '-c', code, str(path)],
                    timeout=.6, max_output_bytes=128, isolate_process_group=True)
                if parent_exits:
                    self.assertEqual(call().stdout.strip(), 'done')
                else:
                    with self.assertRaises(subprocess.TimeoutExpired): call()
                child = int(path.read_text())
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    status = Path(f'/proc/{child}/stat')
                    if not status.exists() or status.read_text().split()[2] == 'Z': break
                    time.sleep(.01)
                else:
                    os.kill(child, 9)
                    self.fail('Дочерний процесс пережил ограниченный lifecycle')


if __name__=='__main__': unittest.main()
