from __future__ import annotations

import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

from lucx_post_configurator import updates
from lucx_post_configurator.engine import Engine
from lucx_post_configurator.repair import PENDING_POST_UPDATE_REPAIR
from lucx_post_configurator.runner import CommandResult, Runner
from lucx_post_configurator.targetfs import TargetFS


class LiveTestFS(TargetFS):
    @property
    def is_live(self) -> bool:
        return True


class UpdateRebootGuardTests(unittest.TestCase):
    def test_tui_blocked_update_does_not_ask_for_source_or_confirmation(self) -> None:
        from lucx_post_configurator import tui
        with tempfile.TemporaryDirectory() as temporary:
            engine = Engine(temporary, runner=Runner(dry_run=True))
            output = []
            answer = mock.Mock(side_effect=AssertionError('Заблокированное обновление не требует ввода'))
            with mock.patch.object(tui, 'repair_check') as repair, mock.patch.object(tui, 'update_lucx') as update:
                tui._update(engine, answer, output.append)
            answer.assert_not_called()
            repair.assert_not_called()
            update.assert_not_called()
            self.assertIn(updates.AUTOMATIC_UPDATE_BLOCKED_REASON, '\n'.join(output))

    def test_cli_blocked_update_fails_before_repair_or_confirmation(self) -> None:
        from lucx_post_configurator import cli
        with tempfile.TemporaryDirectory() as temporary:
            engine = Engine(temporary, runner=Runner(dry_run=True))
            output = io.StringIO()
            with mock.patch.object(cli, 'Engine', return_value=engine), \
                    mock.patch.object(cli, '_require_live_root'), mock.patch.object(cli, 'repair_check') as repair, \
                    mock.patch.object(cli, '_confirm') as confirm, mock.patch.object(cli, 'update_lucx') as update, \
                    redirect_stdout(output), redirect_stderr(output):
                result = cli.main(['--update-lucx', '--yes'])
            self.assertEqual(result, 2)
            repair.assert_not_called()
            confirm.assert_not_called()
            update.assert_not_called()
            self.assertIn(updates.AUTOMATIC_UPDATE_BLOCKED_REASON, output.getvalue())

    def test_update_lucx_refuses_before_install_download_or_queue_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            engine = Engine(root, runner=Runner(dry_run=True))
            engine.fs = LiveTestFS(root)
            install_marker = root / "install-self-ran"

            def mutating_install(*_args: object, **_kwargs: object) -> dict[str, list]:
                install_marker.write_text("changed", encoding="utf-8")
                return {"installed": []}

            with (
                mock.patch(
                    "lucx_post_configurator.updates.repair_check",
                    return_value={"repair_required": False},
                ) as repair_check,
                mock.patch(
                    "lucx_post_configurator.updates.install_self",
                    side_effect=mutating_install,
                ) as install_self,
                mock.patch(
                    "lucx_post_configurator.updates.load_state",
                    return_value={
                        "manifest": {"lucx": {"db_path": "/etc/x-ui/x-ui.db"}}
                    },
                ),
                mock.patch(
                    "lucx_post_configurator.updates._download_archive",
                    side_effect=RuntimeError("контролируемая попытка загрузки"),
                ) as download,
            ):
                try:
                    updates.update_lucx(engine, source="sourcecraft")
                except RuntimeError as exc:
                    error = str(exc)
                else:
                    error = ""

            self.assertIn("автоматическое обновление LucX недоступно", error)
            self.assertIn("перезагруз", error)
            repair_check.assert_not_called()
            install_self.assert_not_called()
            download.assert_not_called()
            self.assertFalse(install_marker.exists())
            self.assertFalse(engine.fs.path(updates.UPDATE_JOB_ROOT).exists())
            self.assertEqual(engine.runner.history, [])

    def test_old_worker_job_refuses_without_execution_or_payload_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = Runner(dry_run=True)
            engine = Engine(root, runner=runner)
            job_id = "20260901T091114Z-629799"
            job_dir = engine.fs.path(f"{updates.UPDATE_JOB_ROOT}/{job_id}")
            script = job_dir / "source/update.sh"
            script.parent.mkdir(parents=True)
            script.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            descriptor_path = job_dir / "job.json"
            descriptor_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "job_id": job_id,
                        "update_script": "source/update.sh",
                        "install_source": "github",
                        "source": "github",
                        "safe_mode": True,
                        "allow_reboot": False,
                    }
                ),
                encoding="utf-8",
            )
            engine.fs.atomic_write_text(
                PENDING_POST_UPDATE_REPAIR,
                job_id + "\n",
                mode=0o600,
            )
            engine.fs.atomic_write_text(
                updates.UPDATE_JOB_STATUS,
                json.dumps(
                    {
                        "schema_version": 1,
                        "job_id": job_id,
                        "state": "queued",
                    }
                ),
                mode=0o600,
            )
            execution_marker = root / "updater-ran"

            def controlled_updater(*_args: object, **_kwargs: object) -> CommandResult:
                execution_marker.write_text("executed", encoding="utf-8")
                return CommandResult(["bash", str(script)], 0, "", "")

            protected = {
                path: path.read_bytes()
                for path in (
                    descriptor_path,
                    script,
                    engine.fs.path(PENDING_POST_UPDATE_REPAIR),
                    engine.fs.path(updates.UPDATE_JOB_STATUS),
                )
            }
            runner.run = mock.Mock(side_effect=controlled_updater)

            with mock.patch(
                "lucx_post_configurator.updates.repair_apply",
                return_value={"run_id": "must-not-run"},
            ) as repair_apply:
                try:
                    updates.run_update_worker(engine, job_id)
                except RuntimeError as exc:
                    error = str(exc)
                else:
                    error = ""

            self.assertIn("автоматическое обновление LucX недоступно", error)
            self.assertIn("перезагруз", error)
            runner.run.assert_not_called()
            repair_apply.assert_not_called()
            self.assertFalse(execution_marker.exists())
            for path, expected in protected.items():
                self.assertTrue(path.is_file())
                self.assertEqual(path.read_bytes(), expected)

    def test_update_source_status_explains_fail_closed_guard_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            engine = Engine(temporary, runner=Runner(dry_run=True))
            engine.fs.atomic_write_text(
                updates.UPDATE_SOURCE_STATE,
                json.dumps({"source": "github"}),
                mode=0o600,
            )
            source_path = engine.fs.path(updates.UPDATE_SOURCE_STATE)
            before = source_path.read_bytes()

            status = updates.update_source_status(engine)

            self.assertFalse(status["automatic_update_available"])
            self.assertIn(
                "автоматическое обновление LucX недоступно",
                status["automatic_update_reason"],
            )
            self.assertIn("перезагруз", status["automatic_update_reason"])
            self.assertEqual(source_path.read_bytes(), before)
            self.assertEqual(engine.runner.history, [])


if __name__ == "__main__":
    unittest.main()
