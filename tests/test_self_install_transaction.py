from __future__ import annotations

import contextlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lucx_post_configurator.engine import Engine
from lucx_post_configurator.runner import CommandError, CommandResult, Runner
from lucx_post_configurator.self_install import (
    INSTALLED_COMMAND,
    POST_UPDATE_UNIT,
    REPAIR_COMMAND,
    UPDATE_WORKER_UNIT_PATH,
    X_TUNA_COMMAND,
    install_self,
)
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import STATE_PATH, managed_target_state

COMMANDS = (INSTALLED_COMMAND, REPAIR_COMMAND, X_TUNA_COMMAND)
TARGETS = (*COMMANDS, POST_UPDATE_UNIT, UPDATE_WORKER_UNIT_PATH)
ENABLE_LINK = "/etc/systemd/system/multi-user.target.wants/lucx-post-update-repair.service"


class LiveTestFS(TargetFS):
    @property
    def is_live(self):
        return True


class ServiceRunner(Runner):
    """Моделирует только внешние процессы; backup/commit/rollback работают на FS."""

    def __init__(self, fs):
        super().__init__()
        self.fs = fs
        self.failure = None
        self.before_command = None

    def run(self, args, *, check=True, **kwargs):
        command = [str(value) for value in args]
        self.history.append(command)
        if self.before_command:
            self.before_command(command)
        code, stdout = 0, ""
        if command[:2] == ["systemctl", "is-enabled"]:
            enabled = self.fs.path(ENABLE_LINK).is_symlink()
            code, stdout = (0, "enabled\n") if enabled else (1, "disabled\n")
        if self.failure and self.failure(command):
            self.failure = None
            code = 17
        result = CommandResult(command, code, stdout, "проверочный отказ" if code == 17 else "")
        if check and code:
            raise CommandError(result)
        return result


class SelfInstallTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fs = LiveTestFS(self.root)
        self.runner = ServiceRunner(self.fs)
        self.source = self.root / "installer.sh"
        self.source.write_bytes(b"#!/bin/sh\nexit 0\n__LUCX_POST_CONFIGURATOR_PAYLOAD__\n")
        self.original = {}
        for target in TARGETS:
            self.fs.atomic_write(target, b"previous-command\n", mode=0o755)
            self.original[target] = managed_target_state(self.fs, target)
        if os.name == "nt":
            patcher = mock.patch.object(Engine, "_exclusive_lock", lambda _engine: contextlib.nullcontext())
            patcher.start()
            self.addCleanup(patcher.stop)

    def install(self):
        return install_self(self.fs, self.runner, source=str(self.source))

    def assert_original_files(self, *, except_target=None):
        for target in TARGETS:
            if target == except_target:
                continue
            actual = managed_target_state(self.fs, target)
            for field in ("kind", "mode", "uid", "gid", "sha256"):
                self.assertEqual(actual.get(field), self.original[target].get(field), (target, field))

    def require_symlinks(self):
        candidate = self.root / "symlink-capability"
        try:
            os.symlink(self.source, candidate)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        candidate.unlink()

    def test_invalid_staging_prevents_any_command_replacement(self):
        self.runner.failure = lambda command: command[:2] == ["sh", "-n"]
        with self.assertRaisesRegex(RuntimeError, "проверочный отказ"):
            self.install()
        self.assert_original_files()
        self.assertFalse(any(command[:2] == ["systemctl", "daemon-reload"] for command in self.runner.history))

    @unittest.skipIf(os.name == "nt", "проверка использует настоящий POSIX sh")
    def test_staging_executes_candidate_help_and_rejects_broken_payload(self):
        class ShellRunner(ServiceRunner):
            def run(self, args, **kwargs):
                if str(args[0]) == "sh":
                    return Runner.run(self, args, **kwargs)
                return super().run(args, **kwargs)

        self.runner = ShellRunner(self.fs)
        self.source.write_bytes(b"#!/bin/sh\nexit 17\n__LUCX_POST_CONFIGURATOR_PAYLOAD__\n")
        with self.assertRaisesRegex(RuntimeError, "17"):
            self.install()
        self.assert_original_files()

    def test_changed_staged_payload_cannot_be_committed(self):
        def change_on_validation(command):
            if command[0] == "systemd-analyze":
                staged_root = self.fs.path("/var/lib/lucx-post-configurator/staging")
                for path in staged_root.rglob("lucx-post-configure"):
                    path.write_bytes(b"changed-staging\n")

        self.runner.before_command = change_on_validation
        with self.assertRaisesRegex(RuntimeError, "staging"):
            self.install()
        self.assert_original_files()

    def test_dry_run_cannot_bypass_real_installation_validation(self):
        self.runner.dry_run = True
        with self.assertRaisesRegex(RuntimeError, "dry.run"):
            self.install()
        self.assert_original_files()

    def test_each_partial_file_commit_restores_previously_written_files(self):
        for index, failed_target in enumerate(TARGETS):
            with self.subTest(target=failed_target):
                original_write = self.fs.atomic_write
                armed = True

                def fail_once(target, data, mode=0o644, *,
                              _failed_target=failed_target, _original_write=original_write, **kwargs):
                    nonlocal armed
                    if str(target) == _failed_target and armed:
                        armed = False
                        raise OSError("проверочный отказ записи")
                    return _original_write(target, data, mode, **kwargs)

                with (mock.patch.object(self.fs, "atomic_write", side_effect=fail_once),
                      mock.patch("lucx_post_configurator.self_install.new_run_id", return_value=f"write-{index}"),
                      self.assertRaisesRegex((OSError, RuntimeError), "проверочный отказ")):
                    self.install()
                self.assert_original_files()

    def test_changed_target_after_staging_is_preserved_without_commit(self):
        def change_on_validation(command):
            if command[0] == "systemd-analyze":
                self.fs.atomic_write(REPAIR_COMMAND, b"external-change\n")

        self.runner.before_command = change_on_validation
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertEqual(self.fs.read_bytes(REPAIR_COMMAND), b"external-change\n")
        self.assert_original_files(except_target=REPAIR_COMMAND)

    def test_newer_saved_manifest_is_rejected_before_writes(self):
        self.fs.atomic_write_text(STATE_PATH, json.dumps({"manifest": {"schema_version": 999}}))
        with self.assertRaises(ValueError):
            self.install()
        self.assert_original_files()

    def test_saved_state_changed_during_staging_blocks_commit(self):
        self.fs.atomic_write_text(STATE_PATH, json.dumps({"manifest": {"schema_version": 3}}))

        def change_on_validation(command):
            if command[0] == "systemd-analyze":
                self.fs.atomic_write_text(STATE_PATH, json.dumps({"manifest": {"schema_version": 999}}))

        self.runner.before_command = change_on_validation
        with self.assertRaises(RuntimeError):
            self.install()
        self.assert_original_files()
        self.assertEqual(json.loads(self.fs.read_text(STATE_PATH))["manifest"]["schema_version"], 999)

    def test_busy_common_lock_prevents_backup_or_install(self):
        @contextlib.contextmanager
        def busy_lock(_engine):
            raise RuntimeError("операция уже выполняется")
            yield

        with (mock.patch.object(Engine, "_exclusive_lock", busy_lock),
              self.assertRaisesRegex(RuntimeError, "уже выполняется")):
            self.install()
        self.assert_original_files()
        self.assertFalse(self.fs.path("/var/backups/lucx-post-configurator").exists())

    def test_daemon_reload_and_health_failures_restore_files_and_enablement(self):
        self.require_symlinks()
        for failure in (lambda c: c[:2] == ["systemctl", "daemon-reload"],
                        lambda c: c[:2] == ["systemctl", "is-enabled"],
                        lambda c: c == [str(self.fs.path(X_TUNA_COMMAND)), "--help"]):
            with self.subTest(failure=failure):
                self.runner.failure = failure
                with self.assertRaisesRegex(RuntimeError, "проверочный отказ|Автозапуск"):
                    self.install()
                self.assert_original_files()
                self.assertFalse(self.fs.path(ENABLE_LINK).is_symlink())

    def test_external_replacement_after_commit_survives_failed_health(self):
        self.require_symlinks()

        def change_at_health(command):
            if command == [str(self.fs.path(INSTALLED_COMMAND)), "--help"]:
                self.fs.atomic_write(REPAIR_COMMAND, b"external-change\n")

        self.runner.before_command = change_at_health
        self.runner.failure = lambda command: command == [str(self.fs.path(X_TUNA_COMMAND)), "--help"]
        with self.assertRaisesRegex(RuntimeError, "конфликт"):
            self.install()
        self.assertEqual(self.fs.read_bytes(REPAIR_COMMAND), b"external-change\n")
        self.assert_original_files(except_target=REPAIR_COMMAND)

    def test_repeated_installation_has_one_enable_link_and_unique_backups(self):
        self.require_symlinks()
        first = self.install()
        second = self.install()
        self.assertNotEqual(first["backup"], second["backup"])
        self.assertEqual(self.fs.read_bytes(INSTALLED_COMMAND), self.source.read_bytes())
        self.assertEqual(os.readlink(self.fs.path(ENABLE_LINK)), POST_UPDATE_UNIT)
        self.assertEqual(len(list(self.fs.path(ENABLE_LINK).parent.iterdir())), 1)
        self.assertEqual(first["status"], "complete")
        self.assertEqual(second["status"], "complete")

    @unittest.skipUnless(shutil.which("systemctl"), "проверка использует настоящий offline systemctl")
    def test_offline_systemctl_dropin_cannot_expand_transaction_write_set(self):
        self.require_symlinks()

        class OfflineSystemctlRunner(ServiceRunner):
            def run(self, args, **kwargs):
                command = [str(value) for value in args]
                if command[:2] in (["systemctl", "enable"], ["systemctl", "is-enabled"]):
                    return Runner.run(self, ["systemctl", f"--root={self.fs.root}", *command[1:]], **kwargs)
                return super().run(command, **kwargs)

        dropin = "/etc/systemd/system/lucx-post-update-repair.service.d/local.conf"
        content = "[Install]\nWantedBy=graphical.target\n"
        self.fs.atomic_write_text(dropin, content)
        self.runner = OfflineSystemctlRunner(self.fs)
        result = self.install()
        self.assertEqual(result["status"], "complete")
        extra_link = "/etc/systemd/system/graphical.target.wants/lucx-post-update-repair.service"
        self.assertFalse(managed_target_state(self.fs, extra_link)["existed"],
                         "Установка не должна создавать ссылки из чужого Install drop-in")
        self.assertTrue(self.fs.path(ENABLE_LINK).is_symlink())
        self.assertEqual(self.fs.read_text(dropin), content)

    def test_clean_installation_and_failed_upgrade_preserve_enabled_state(self):
        self.require_symlinks()
        for target in TARGETS:
            self.fs.path(target).unlink()
        self.install()
        self.original = {target: managed_target_state(self.fs, target) for target in TARGETS}
        original_link = managed_target_state(self.fs, ENABLE_LINK)
        self.runner.failure = lambda command: command[:2] == ["systemctl", "is-enabled"]
        with self.assertRaisesRegex(RuntimeError, "Автозапуск"):
            self.install()
        self.assert_original_files()
        self.assertEqual(managed_target_state(self.fs, ENABLE_LINK), original_link)

    def test_failed_clean_installation_removes_only_its_commands(self):
        self.require_symlinks()
        for target in TARGETS:
            self.fs.path(target).unlink()
        untouched = self.fs.path("/etc/systemd/system/existing.service")
        untouched.write_bytes(b"existing-service\n")
        self.runner.failure = lambda command: command[:2] == ["systemctl", "is-enabled"]
        with self.assertRaisesRegex(RuntimeError, "Автозапуск"):
            self.install()
        for target in (*TARGETS, ENABLE_LINK):
            self.assertFalse(managed_target_state(self.fs, target)["existed"])
        self.assertEqual(untouched.read_bytes(), b"existing-service\n")

    def test_failed_rollback_reload_is_reported_as_incomplete_restore(self):
        self.require_symlinks()
        reached_health = False

        def fail_rollback(command):
            nonlocal reached_health
            if command[:2] == ["systemctl", "is-enabled"]:
                reached_health = True
                raise RuntimeError("проверочный отказ health-check")
            if reached_health and command[:2] == ["systemctl", "daemon-reload"]:
                raise RuntimeError("проверочный отказ reload")

        self.runner.before_command = fail_rollback
        with self.assertRaisesRegex(RuntimeError, "daemon-reload после отката"):
            self.install()
        self.assert_original_files()


if __name__ == "__main__":
    unittest.main()
