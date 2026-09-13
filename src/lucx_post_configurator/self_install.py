from __future__ import annotations

import hashlib
import json
import os
import posixpath
import uuid
from pathlib import Path
from typing import Any

from .migrations import migrate_manifest
from .renderers import GeneratedFile
from .runner import Runner
from .targetfs import TargetFS
from .transaction import (
    FAILED_STATE_PATH,
    STATE_PATH,
    commit_managed_transition,
    create_backup,
    managed_target_state,
    new_run_id,
    remove_staging,
    restore_backup,
    stage_files,
)

INSTALLED_COMMAND = "/usr/local/sbin/lucx-post-configure"
REPAIR_COMMAND = "/usr/local/sbin/lucx-sub-repair"
X_TUNA_COMMAND = "/usr/local/sbin/x-tuna"
POST_UPDATE_UNIT = "/etc/systemd/system/lucx-post-update-repair.service"
UPDATE_WORKER_UNIT_PATH = "/etc/systemd/system/lucx-post-update@.service"
POST_UPDATE_ENABLE_LINK = "/etc/systemd/system/multi-user.target.wants/lucx-post-update-repair.service"


REPAIR_WRAPPER = b"""#!/bin/sh
set -eu
case "${1:-}" in
  --check) shift; exec /usr/local/sbin/lucx-post-configure --repair-check "$@" ;;
  --apply) shift; exec /usr/local/sbin/lucx-post-configure --repair-apply "$@" ;;
  "") exec /usr/local/sbin/lucx-post-configure ;;
  *) exec /usr/local/sbin/lucx-post-configure "$@" ;;
esac
"""


X_TUNA_WRAPPER = b"""#!/bin/sh
set -eu
exec /usr/local/sbin/lucx-post-configure --tui "$@"
"""


POST_UPDATE_SERVICE = b"""[Unit]
Description=Repair LucX external routing after a panel update or reboot
After=network-online.target x-ui.service
Wants=network-online.target x-ui.service
ConditionPathExists=/var/lib/lucx-post-configurator/pending-post-update-repair
StartLimitIntervalSec=600
StartLimitBurst=10

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lucx-post-configure --repair-apply --yes
TimeoutStartSec=900
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=multi-user.target
"""


UPDATE_WORKER_UNIT = b"""[Unit]
Description=LucX detached update job %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lucx-post-configure --update-worker --update-job-id %i
TimeoutStartSec=2700
"""


def _source_path(explicit: str | None = None) -> Path:
    raw = explicit or os.environ.get("LUCX_PC_SELF", "")
    if not raw:
        raise RuntimeError(
            "не найден исходный автономный скрипт; запустите установку TUI из lucx-post-configure.sh"
        )
    path = Path(raw).absolute()
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("исходный автономный скрипт должен быть обычным файлом")
    payload = path.read_bytes()
    if not payload.startswith(b"#!/bin/sh\n") or b"__LUCX_POST_CONFIGURATOR_PAYLOAD__\n" not in payload:
        raise RuntimeError("исходный файл не является автономным lucx-post-configure.sh")
    return path


def _validate_saved_states(fs: TargetFS) -> None:
    for target in (STATE_PATH, FAILED_STATE_PATH):
        state = managed_target_state(fs, target)
        if not state["existed"]:
            continue
        if state["kind"] != "file":
            raise RuntimeError("Сохранённое состояние должно быть обычным файлом")
        value = json.loads(fs.read_text(target))
        if not isinstance(value, dict) or not isinstance(value.get("manifest"), dict):
            raise RuntimeError("Сохранённое состояние не содержит совместимый manifest")  # noqa: TRY004 — ошибка входного state, обрабатываемая CLI.
        migrate_manifest(value["manifest"])


def _validate_staged_commands(staged: dict[str, Path], runner: Runner) -> None:
    for target in (INSTALLED_COMMAND, REPAIR_COMMAND, X_TUNA_COMMAND):
        runner.run(["sh", "-n", staged[target]])
    # --help распаковывает payload и импортирует CLI, не запуская изменяющие действия.
    runner.run(["sh", staged[INSTALLED_COMMAND], "--help"])
    validation_dir = staged[POST_UPDATE_UNIT].parent / "unit-validation"
    validation_dir.mkdir()
    units = []
    for target in (POST_UPDATE_UNIT, UPDATE_WORKER_UNIT_PATH):
        unit = validation_dir / Path(target).name
        unit.write_text(staged[target].read_text(encoding="utf-8").replace(
            INSTALLED_COMMAND, str(staged[INSTALLED_COMMAND])
        ), encoding="utf-8")
        units.append(unit)
    runner.run(["systemd-analyze", "verify", "--man=no", *units])


def install_self(
    fs: TargetFS,
    runner: Runner,
    *,
    source: str | None = None,
) -> dict[str, Any]:
    if not fs.is_live:
        raise RuntimeError("установка TUI разрешена только в живую систему")
    if runner.dry_run:
        raise RuntimeError("dry-run не разрешает установку без реальных проверок")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("установка TUI требует root")
    # Общая блокировка сериализует установку с apply, repair и rollback.
    from .engine import Engine

    engine = Engine(fs.root, runner=runner)
    engine.fs = fs
    with engine._exclusive_lock():
        return _install_locked(fs, runner, source=source)


def _install_locked(fs: TargetFS, runner: Runner, *, source: str | None) -> dict[str, Any]:
    _validate_saved_states(fs)
    source_path = _source_path(source)
    source_payload = source_path.read_bytes()
    source_metadata = source_path.lstat()
    generated = {
        INSTALLED_COMMAND: GeneratedFile(
            source_payload, mode=0o755, component="self-install"
        ),
        REPAIR_COMMAND: GeneratedFile(
            REPAIR_WRAPPER, mode=0o755, component="self-install"
        ),
        X_TUNA_COMMAND: GeneratedFile(
            X_TUNA_WRAPPER, mode=0o755, component="self-install"
        ),
        POST_UPDATE_UNIT: GeneratedFile(
            POST_UPDATE_SERVICE, mode=0o644, component="self-install"
        ),
        UPDATE_WORKER_UNIT_PATH: GeneratedFile(
            UPDATE_WORKER_UNIT, mode=0o644, component="self-install"
        ),
    }
    baseline = {target: managed_target_state(fs, target)
                for target in (*generated, POST_UPDATE_ENABLE_LINK, STATE_PATH, FAILED_STATE_PATH)}
    for target in generated:
        if baseline[target]["existed"] and baseline[target]["kind"] != "file":
            raise RuntimeError(f"Устанавливаемая команда или unit имеет небезопасный тип: {target}")
    link_state = baseline[POST_UPDATE_ENABLE_LINK]
    if link_state["existed"] and (link_state["kind"] != "symlink" or posixpath.normpath(
        posixpath.join(posixpath.dirname(POST_UPDATE_ENABLE_LINK), str(link_state.get("link_target", "")))
    ) != POST_UPDATE_UNIT):
        raise RuntimeError("Ссылка автозапуска принадлежит другой конфигурации")
    # Ссылка создаётся нашей атомарной записью; systemctl enable мог бы применить
    # чужие Install drop-ins и создать дополнительные ссылки вне нашего backup.
    files = dict(generated)
    if not link_state["existed"]:
        generated[POST_UPDATE_ENABLE_LINK] = GeneratedFile(
            symlink_target=POST_UPDATE_UNIT, component="self-install"
        )
    run_id = new_run_id() + "-self-install-" + uuid.uuid4().hex[:12]
    backup = create_backup(fs, generated, run_id)
    journal: dict[str, dict[str, Any]] = {}
    systemd_touched = False
    try:
        staged = stage_files(fs, files, run_id)
        _validate_staged_commands(staged, runner)
        for target, artifact in files.items():
            if staged[target].is_symlink() or staged[target].read_bytes() != artifact.content:
                raise RuntimeError(f"Файл staging изменился во время проверки: {target}")
        if source_path.lstat() != source_metadata or source_path.read_bytes() != source_payload:
            raise RuntimeError("Исходный installer изменился после staging")
        for target, expected in baseline.items():
            if managed_target_state(fs, target) != expected:
                raise RuntimeError(f"Состояние изменилось после staging: {target}")
        _validate_saved_states(fs)
        commit_managed_transition(fs, generated, [], {}, baseline=backup, mutation_journal=journal)
        systemd_touched = True
        runner.run(["systemctl", "daemon-reload"])
        for target in (INSTALLED_COMMAND, REPAIR_COMMAND, X_TUNA_COMMAND):
            runner.run([fs.path(target), "--help"])
        enabled = runner.run(["systemctl", "is-enabled", "lucx-post-update-repair.service"], check=False)
        if enabled.returncode or enabled.stdout.strip() != "enabled":
            raise RuntimeError("Автозапуск post-update repair не подтверждён")
        for target, receipt in journal.items():
            if managed_target_state(fs, target) != receipt:
                raise RuntimeError(f"Установленный файл изменился во время health-check: {target}")
    except Exception as error:
        failures = []
        try:
            conflicts = restore_backup(fs, backup, expected_current=journal)
            failures.extend(f"конфликт внешнего изменения: {target}" for target in conflicts)
        except Exception as rollback_error:  # noqa: BLE001 — исходная ошибка и ошибка отката должны сохраниться вместе.
            failures.append(f"ошибка возврата файлов: {rollback_error}")
        if systemd_touched:
            try:
                runner.run(["systemctl", "daemon-reload"])
            except Exception as reload_error:  # noqa: BLE001 — откат не объявляется успешным при любом отказе reload.
                failures.append(f"ошибка daemon-reload после отката: {reload_error}")
        if failures:
            raise RuntimeError(f"Установка не завершена: {error}; откат: " + "; ".join(failures)) from error
        raise
    finally:
        remove_staging(fs, run_id)
    return {
        "status": "complete",
        "run_id": run_id,
        "installed": sorted(files),
        "backup": str(backup.directory),
        "sha256": hashlib.sha256(source_payload).hexdigest(),
        "command": INSTALLED_COMMAND,
        "tui_command": X_TUNA_COMMAND,
        "repair_command": REPAIR_COMMAND,
    }
