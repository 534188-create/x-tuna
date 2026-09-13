"""Транзакция только управляемых Naive Caddyfile под внешним Engine lock.

Source/state не принадлежат этому модулю. commit_state обязан быть атомарным:
при исключении он самостоятельно откатывает собственную state receipt через CAS.
"""
from __future__ import annotations

import hashlib
import json
import os
import re

from .naive_probe_source import _capture
from .naive_runtime import _metadata, _target, _trusted
from .renderers import GeneratedFile
from .transaction import managed_target_state

_ERROR = 'Синхронизация Naive не выполнена'
_MANAGED = re.compile(r'/etc/lucx-post-configurator/naive/naive-([1-9][0-9]{0,9})\.caddyfile')


class NaiveSyncError(RuntimeError):
    def __init__(self, *, rollback_failed=False):
        self.rollback_failed = rollback_failed
        super().__init__(_ERROR + ('; откат требует проверки' if rollback_failed else ''))


def _read(fs, target):
    path = _target(fs, target)
    _trusted(path.lstat(), fs)
    data, snapshot, metadata = _capture(path)
    if os.name == 'posix' and (metadata['uid'] != (0 if fs.is_live else os.geteuid()) or metadata['mode'] & 0o022):
        raise NaiveSyncError()
    receipt = managed_target_state(fs, target)
    if (receipt.get('sha256') != hashlib.sha256(data).hexdigest()
            or any(receipt.get(k) != metadata[k] for k in ('uid', 'gid', 'mode'))):
        raise NaiveSyncError()
    return data, snapshot, receipt


def _fence(source_fence):
    if source_fence() is False:
        raise NaiveSyncError()


def _run(runner, args, timeout=30):
    result = runner.run_bounded(args, max_output_bytes=65536, check=False,
        timeout=timeout, inherit_env=False,
        env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
             'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
    if result.returncode:
        raise NaiveSyncError()


def _directory(fs, target):
    path = _target(fs, target)
    if path.exists():
        raise NaiveSyncError()
    path.mkdir(parents=True, mode=0o700)
    return path


def synchronize_managed_naive(fs, runner, desired: dict[str, GeneratedFile], *,
        bindings: dict, installed_hashes: dict, source_fence, run_id: str,
        commit_state=None, mutation_journal=None) -> dict:
    """Проверяет/stage/commit/health/rollback existing active managed targets.

    Пустой набор также проходит source fence и commit_state: native route может
    обновить только подтверждённые source generation metadata. Перезапуска x-ui нет.
    """
    baseline, binaries, writes, changed_content, receipts = {}, {}, {}, set(), {}
    stage_dir = None
    stage_receipts = {}
    service_touched = set()
    try:
        if (type(desired) is not dict or type(bindings) is not dict or set(bindings) != set(desired)
                or len(desired) > 128 or not callable(source_fence)
                or not isinstance(run_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9T_-]{0,127}', run_id)
                or fs.is_live and os.name != 'posix'):
            raise NaiveSyncError()
        _fence(source_fence)
        for target, file in sorted(desired.items()):
            match = _MANAGED.fullmatch(target)
            binding = bindings[target]
            if (match is None or not isinstance(file, GeneratedFile) or file.symlink_target
                    or not isinstance(file.content, bytes) or not 0 < len(file.content) <= 1024 * 1024
                    or not isinstance(binding, dict) or set(binding) != {'binary_path', 'service'}
                    or binding['service'] != f'lucx-naive-decoy-{int(match[1])}.service'):
                raise NaiveSyncError()
            captured = _read(fs, target)
            baseline[target] = captured
            if installed_hashes.get(target) != captured[2]['sha256'] and captured[0] != file.content:
                raise NaiveSyncError()
            executable = _target(fs, binding['binary_path'])
            metadata = executable.lstat()
            _trusted(metadata, fs, executable=True)
            binaries[target] = (executable, _metadata(metadata))
            private_mode = captured[2]['mode'] == 0o600 or os.name != 'posix' and not fs.is_live
            if captured[0] != file.content or not private_mode:
                writes[target] = file
            if captured[0] != file.content:
                changed_content.add(target)
        # Не запускаем намеренно остановленную службу в фоне.
        for target in sorted(changed_content):
            _run(runner, ['systemctl', 'is-active', '--quiet', bindings[target]['service']])
        if writes:
            backup_target = f'/var/backups/lucx-post-configurator/{run_id}-naive-sync'
            _directory(fs, backup_target)
            for target in sorted(writes):
                fs.atomic_write(backup_target + '/' + fs.path(target).name, baseline[target][0], 0o600)
            fs.atomic_write_text(backup_target + '/backup.json', json.dumps({
                'targets': {target: baseline[target][2] for target in sorted(writes)},
                'receipts': {}}, sort_keys=True), mode=0o600)
            stage_target = f'/var/lib/lucx-post-configurator/staging/{run_id}-naive-sync'
            stage_dir = _directory(fs, stage_target)
            for target, file in sorted(writes.items()):
                staged = stage_target + '/' + fs.path(target).name
                stage_receipts[staged] = fs.atomic_write(staged, file.content, 0o600)
                if _metadata(binaries[target][0].lstat()) != binaries[target][1]:
                    raise NaiveSyncError()
                _run(runner, [str(binaries[target][0]), 'validate', '--config', str(fs.path(staged)), '--adapter', 'caddyfile'])
                if managed_target_state(fs, staged) != stage_receipts[staged]:
                    raise NaiveSyncError()
        _fence(source_fence)
        for target in sorted(desired):
            if _read(fs, target) != baseline[target] or _metadata(binaries[target][0].lstat()) != binaries[target][1]:
                raise NaiveSyncError()
        for target, file in sorted(writes.items()):
            _fence(source_fence)
            if _read(fs, target) != baseline[target]:
                raise NaiveSyncError()
            before = baseline[target][2]
            receipt = fs.atomic_write(target, file.content, 0o600, owner=(before['uid'], before['gid']))
            receipts[target] = receipt
            if mutation_journal is not None:
                mutation_journal[target] = receipt
            if managed_target_state(fs, target) != receipt:
                raise NaiveSyncError()
            fs.atomic_write_text(backup_target + '/backup.json', json.dumps({
                'targets': {name: baseline[name][2] for name in sorted(writes)},
                'receipts': receipts}, sort_keys=True), mode=0o600)
        for target in sorted(changed_content):
            service = bindings[target]['service']
            service_touched.add(target)
            _run(runner, ['systemctl', 'restart', service], timeout=60)
            _run(runner, ['systemctl', 'is-active', '--quiet', service])
        _fence(source_fence)
        for target in sorted(desired):
            expected = receipts.get(target, baseline[target][2])
            if (managed_target_state(fs, target) != expected
                    or _metadata(binaries[target][0].lstat()) != binaries[target][1]):
                raise NaiveSyncError()
        hashes = {target: hashlib.sha256(file.content).hexdigest() for target, file in sorted(desired.items())}
        result = {'changed': bool(writes), 'hashes': hashes, 'receipts': receipts}
        # Последний fallible этап. Callback сам отвечает за state receipt rollback.
        if commit_state is not None:
            commit_state(dict(hashes), {name: dict(receipt) for name, receipt in receipts.items()})
        return result
    except Exception:  # noqa: BLE001 — любой отказ запускает own-receipt rollback без утечки вывода.
        rollback_failed = False
        restored = set()
        # При исключении без receipt нельзя присваивать себе новый target даже
        # при совпавших байтах. Отмечаем неопределённый результат без перезаписи.
        for target in baseline.keys() - receipts.keys():
            try:
                if managed_target_state(fs, target) != baseline[target][2]:
                    rollback_failed = True
            except Exception:  # noqa: BLE001 — неопределённый target не перезаписывается.
                rollback_failed = True
        for target, receipt in reversed(list(receipts.items())):
            try:
                if managed_target_state(fs, target) != receipt:
                    rollback_failed = True
                    continue
                before = baseline[target][2]
                restored_receipt = fs.atomic_write(target, baseline[target][0], before['mode'],
                    owner=(before['uid'], before['gid']))
                if mutation_journal is not None:
                    mutation_journal[target] = restored_receipt
                if managed_target_state(fs, target) != restored_receipt:
                    rollback_failed = True
                else:
                    restored.add(target)
            except Exception:  # noqa: BLE001 — продолжаем безопасный rollback остальных own targets.
                rollback_failed = True
        for target in sorted(restored & service_touched):
            try:
                _run(runner, ['systemctl', 'restart', bindings[target]['service']], timeout=60)
                _run(runner, ['systemctl', 'is-active', '--quiet', bindings[target]['service']])
            except Exception:  # noqa: BLE001 — служебный вывод не должен попасть в ошибку.
                rollback_failed = True
        raise NaiveSyncError(rollback_failed=rollback_failed) from None
    finally:
        # Удаляются только наши неизменённые staged files и затем пустой каталог.
        for staged, receipt in stage_receipts.items():
            try:
                if managed_target_state(fs, staged) == receipt:
                    fs.path(staged).unlink()
            except Exception:  # noqa: BLE001, S110 — cleanup не отменяет успешный state commit.
                pass
        if stage_dir is not None:
            try:
                stage_dir.rmdir()
            except Exception:  # noqa: BLE001, S110 — закрытый непустой staging сохраняется без утечки.
                pass
