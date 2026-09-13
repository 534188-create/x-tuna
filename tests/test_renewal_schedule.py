from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import Mock, PropertyMock, patch

from lucx_post_configurator.renewal_schedule import schedule_status
from lucx_post_configurator.runner import CommandResult
from lucx_post_configurator.targetfs import TargetFS

COMMAND = '"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null'


class ScheduleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fs = TargetFS(self.temp.name)

    def put(self, path, text):
        self.fs.atomic_write_text(path, text, mode=0o600)

    def test_root_cron_exact_command_and_known_timezone(self):
        self.put('/var/spool/cron/crontabs/root', '17 3 * * * ' + COMMAND + '\n')
        self.put('/etc/timezone', 'Etc/UTC\n')
        result = schedule_status(self.fs)
        self.assertTrue(result['schedule_found'])
        self.assertEqual(result['schedules'], [{'expression': '17 3 * * *', 'timezone': 'Etc/UTC'}])
        self.assertIsNone(result['cron_active'])
        self.assertFalse(result['schedule_verified'])
        self.assertNotIn('/root/', repr(result))

    def test_cron_d_root_user_and_redirect(self):
        self.put('/etc/cron.d/acme', '*/15 * * * * root ' + COMMAND + ' 2>&1\n')
        self.assertTrue(schedule_status(self.fs)['schedule_found'])

    def test_four_daily_runs_and_compact_redirect(self):
        self.put('/var/spool/cron/crontabs/root',
                 '57 0,6,12,18 * * * /root/.acme.sh/acme.sh --cron --home /root/.acme.sh >/dev/null 2>&1\n')
        self.assertEqual(schedule_status(self.fs)['schedules'][0]['expression'], '57 0,6,12,18 * * *')

    def test_shell_wrapper_is_unknown_not_absent(self):
        self.put('/var/spool/cron/crontabs/root', '0 0 * * * /bin/sh ' + COMMAND + '\n')
        self.assertEqual(schedule_status(self.fs)['schedule_state'], 'unsupported')

    def test_comments_echo_other_user_and_disabled_file_are_ignored(self):
        self.put('/var/spool/cron/crontabs/root', '# 0 0 * * * ' + COMMAND + '\n0 0 * * * echo ' + COMMAND + '\n')
        self.put('/etc/cron.d/acme', '0 0 * * * nobody ' + COMMAND + '\n')
        self.put('/etc/cron.d/acme.disabled', '0 0 * * * root ' + COMMAND + '\n')
        result = schedule_status(self.fs)
        self.assertFalse(result['schedule_found'])
        self.assertEqual(result['schedule_state'], 'absent')

    def test_unsupported_commands_and_invalid_expression_are_unknown(self):
        for line in ['0 0 * * * ' + COMMAND + ' && echo secret',
                     '99 0 * * * ' + COMMAND, '0 0 * * * ' + COMMAND + ' %secret',
                     '0 0 * * * /root/.acme.sh/acme.sh --cron --home /other']:
            with self.subTest(line=line):
                self.put('/var/spool/cron/crontabs/root', line + '\n')
                result = schedule_status(self.fs)
                self.assertIsNone(result['schedule_found'])
                self.assertEqual(result['schedule_state'], 'unsupported')
                self.assertNotIn('secret', repr(result))

    def test_unreadable_is_not_absent(self):
        with patch('lucx_post_configurator.renewal_schedule._read', side_effect=PermissionError):
            self.assertEqual(schedule_status(self.fs)['schedule_state'], 'unreadable')

    @unittest.skipIf(os.name == 'nt', 'POSIX metadata')
    def test_writable_cron_is_not_trusted(self):
        self.put('/etc/cron.d/acme', '0 0 * * * root ' + COMMAND + '\n')
        self.fs.path('/etc/cron.d/acme').chmod(0o666)
        self.assertIsNone(schedule_status(self.fs)['schedule_found'])

    def test_service_is_checked_without_running_cron_job(self):
        self.put('/var/spool/cron/crontabs/root', '0 0 * * * ' + COMMAND + '\n')
        runner = Mock(dry_run=False)
        runner.run_bounded.return_value = CommandResult([], 0, 'active\n', '')
        with patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True):
            result = schedule_status(self.fs, runner)
        self.assertTrue(result['schedule_verified'])
        self.assertEqual(runner.run_bounded.call_args.args[0], ['systemctl', 'is-active', 'cron.service'])
        runner.run.assert_not_called()

    def test_inactive_and_unreadable_service_are_distinct(self):
        self.put('/var/spool/cron/crontabs/root', '0 0 * * * ' + COMMAND + '\n')
        runner = Mock(dry_run=False)
        with patch.object(TargetFS, 'is_live', new_callable=PropertyMock, return_value=True):
            runner.run_bounded.return_value = CommandResult([], 3, 'inactive\n', '')
            self.assertFalse(schedule_status(self.fs, runner)['cron_active'])
            runner.run_bounded.side_effect = OSError('secret')
            self.assertIsNone(schedule_status(self.fs, runner)['cron_active'])


if __name__ == '__main__':
    unittest.main()
