"""Чтение ACME и узкая регистрация hook под внешней блокировкой Engine.

Callback commit_state вызывается последним. Его собственный CAS/rollback state
обеспечивает Engine; изменения внешнего процесса не считаются отменёнными.
"""
from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from .renderers import GeneratedFile
from .runner import Runner
from .targetfs import TargetFS
from .transaction import create_backup, managed_target_state, restore_backup

HOOK_PATH = '/usr/local/sbin/lucx-tls-reload'
_START = '__ACME_BASE64__START_'
_END = '__ACME_BASE64__END_'
_LIMIT = 1024 * 1024


class RenewalError(RuntimeError):
    """Безопасная ошибка: содержимое записей и вывод ACME сюда не включаются."""


@dataclass
class _Record:
    path: str = field(repr=False)
    values: dict[str, str] = field(repr=False)
    snapshot: dict[str, Any] = field(repr=False)
    domain: str = field(repr=False)
    ecc: bool = False


def decode_reload_command(value: str) -> str:
    """Декодирует только известную обёртку; никогда не исполняет shell."""
    if value.startswith(_START) or value.endswith(_END):
        if not value.startswith(_START) or not value.endswith(_END):
            raise RenewalError('Некорректная кодировка reload hook ACME')
        try:
            value = base64.b64decode(value[len(_START):-len(_END)], validate=True).decode('utf-8')
        except (ValueError, UnicodeError, binascii.Error):
            raise RenewalError('Некорректная кодировка reload hook ACME') from None
    if '\x00' in value or '\n' in value or '\r' in value:
        raise RenewalError('Недопустимое содержимое reload hook ACME')
    return value


def _parse_record(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)=(.*)', line)
        if not match or match[1] in values:
            raise RenewalError('Неоднозначная или неподдерживаемая запись ACME')
        raw = match[2]
        single_quoted = len(raw) >= 2 and raw[0] == raw[-1] == "'" and "'" not in raw[1:-1]
        double_quoted = (len(raw) >= 2 and raw[0] == raw[-1] == '"'
                         and not any(c in raw[1:-1] for c in '$`\\"'))
        if single_quoted or double_quoted:
            value = raw[1:-1]
        elif re.fullmatch(r'[A-Za-z0-9_./:@*+%=,-]*', raw):
            value = raw
        else:
            raise RenewalError('Неподдерживаемое shell-выражение в записи ACME')
        if '\x00' in value:
            raise RenewalError('Недопустимое содержимое записи ACME')
        values[match[1]] = value
    return values


def _safe_file(fs: TargetFS, target: str, *, optional: bool = False) -> dict[str, Any]:
    path = fs.path(target)
    if path.absolute() != path.resolve(strict=False):
        raise RenewalError('Символическая ссылка в пути операции ACME запрещена')
    state = managed_target_state(fs, target)
    if not state.get('existed') and optional:
        return state
    if state.get('kind') != 'file':
        raise RenewalError('Ожидался обычный файл операции ACME')
    if fs.is_live and (state.get('uid') != 0 or int(state.get('mode', 0)) & 0o022):
        raise RenewalError('Небезопасный владелец или режим файла операции ACME')
    return state


def _read_record(fs: TargetFS, target: str) -> tuple[dict[str, str], dict[str, Any]]:
    before = _safe_file(fs, target)
    with fs.path(target).open('rb') as stream:
        payload = stream.read(_LIMIT + 1)
    if len(payload) > _LIMIT or managed_target_state(fs, target) != before:
        raise RenewalError('Запись ACME изменилась при чтении либо превышает лимит')
    try:
        return _parse_record(payload.decode('utf-8')), before
    except UnicodeError:
        raise RenewalError('Некорректная кодировка записи ACME') from None


def _find_record(fs: TargetFS, cert_path: str, key_path: str) -> _Record | None:
    matches = []
    root = fs.path('/root/.acme.sh')
    for path in sorted(root.glob('*/*.conf')):
        # В том же каталоге acme.sh хранит OpenSSL *.csr.conf. Это не
        # shell-записи продления; принадлежность проверяем до разбора файла.
        directory = path.parent.name
        expected_domain = directory[:-4] if directory.endswith('_ecc') else directory
        if (not re.fullmatch(r'(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', expected_domain)
                or path.name != expected_domain + '.conf'):
            continue
        target = '/' + path.relative_to(fs.root).as_posix()
        values, snapshot = _read_record(fs, target)
        domain = values.get('Le_Domain', '')
        if domain != expected_domain:
            raise RenewalError('Запись ACME не соответствует собственному домену')
        parent = PurePosixPath(target).parent
        expected_cert = values.get('Le_RealFullChainPath') or str(parent / 'fullchain.cer')
        expected_key = values.get('Le_RealKeyPath') or str(parent / (domain + '.key'))
        if cert_path != expected_cert or key_path != expected_key:
            continue
        if parent.name not in {domain, domain + '_ecc'} or path.name != domain + '.conf':
            raise RenewalError('Запись ACME не соответствует собственному домену')
        matches.append(_Record(target, values, snapshot, domain, parent.name.endswith('_ecc')))
    if len(matches) > 1:
        raise RenewalError('Несколько записей ACME соответствуют выбранной паре')
    return matches[0] if matches else None


def renewal_status(fs: TargetFS, cert_path: str, key_path: str, *, runner=None) -> dict[str, Any]:
    """Факты без доменов, путей, команд и прочей приватной metadata."""
    record = _find_record(fs, cert_path, key_path)
    registered = bool(record and decode_reload_command(record.values.get('Le_ReloadCmd', '')) == HOOK_PATH)
    from .renewal_schedule import schedule_status
    return {'provider': 'acme.sh' if record else 'unknown', 'record_found': record is not None,
            'registered': registered, 'hook_present': fs.exists(HOOK_PATH),
            **schedule_status(fs, runner), 'reload_verified': False}


def _candidate_record(record: _Record, original: str) -> str:
    """Меняет ровно одно поле в формате acme.sh, сохраняя остальные байты."""
    encoded = _START + base64.b64encode(HOOK_PATH.encode()).decode('ascii') + _END
    replacement = "Le_ReloadCmd='" + encoded + "'"
    if 'Le_ReloadCmd' in record.values:
        return re.sub(r'^Le_ReloadCmd=[^\r\n]*', lambda _: replacement, original, flags=re.MULTILINE)
    return original + ('' if not original or original.endswith('\n') else '\n') + replacement + '\n'


def register_existing_renewal(
    fs: TargetFS, runner: Runner, manifest: dict[str, Any], selected: dict[str, Any], *,
    hook: GeneratedFile, validate_candidate: Callable[[], Any],
    post_reload: Callable[[], Any], commit_state: Callable[[], Any], run_id: str,
    before_reload: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Hook/metadata без полного apply; caller держит lock и source fence.

    selected требует только cert_path/key_path. Callback validate_candidate
    обязан проверить пару и кандидат hook, post_reload — поколение и health.
    Сам acme.sh не запускается: --install-cert обнуляет не переданные Le_Real*.
    После записи metadata запускается только проверенный hook. Повторный вызов
    с тем же hook не запускает reload повторно. before_reload фиксирует эпоху
    только перед фактическим запуском hook, после CAS и readback metadata.
    """
    configured = manifest.get('certificates') or {}
    cert_path, key_path = str(selected.get('cert_path') or ''), str(selected.get('key_path') or '')
    if not cert_path or not key_path or any(selected.get(k) != configured.get(k) for k in ('cert_path', 'key_path')):
        raise RenewalError('Смена путей сертификата требует отдельного плана')
    record = _find_record(fs, cert_path, key_path)
    if record is None:
        raise RenewalError('Точная запись ACME для выбранной пары не найдена')
    if getattr(runner, 'dry_run', False):
        raise RenewalError('Регистрация ACME не допускает dry-run подтверждение успеха')
    before = {p: _safe_file(fs, p) for p in (record.path, cert_path, key_path)}
    original = fs.read_bytes(record.path).decode('utf-8')
    if before[record.path] != record.snapshot or managed_target_state(fs, record.path) != record.snapshot:
        raise RenewalError('Запись ACME изменилась после выбора')
    before[HOOK_PATH] = _safe_file(fs, HOOK_PATH, optional=True)
    if hook.symlink_target or not hook.content.startswith(b'#!/bin/sh\n') or hook.mode != 0o750:
        raise RenewalError('Небезопасный кандидат reload hook')
    validate_candidate()
    if any(managed_target_state(fs, p) != value for p, value in before.items()):
        raise RenewalError('Исходные файлы ACME изменились до регистрации')
    already = decode_reload_command(record.values.get('Le_ReloadCmd', '')) == HOOK_PATH
    hook_same = (before[HOOK_PATH].get('existed') and fs.read_bytes(HOOK_PATH) == hook.content
                 and (not fs.is_live or before[HOOK_PATH].get('mode') == hook.mode))
    if already and hook_same:
        post_reload()
        if any(managed_target_state(fs, p) != value for p, value in before.items()):
            raise RenewalError('Конкурентное изменение ACME перед сохранением состояния')
        status = {**renewal_status(fs, cert_path, key_path), 'reload_verified': True, 'changed': False}
        commit_state()
        return status
    backup = create_backup(fs, {HOOK_PATH: hook}, run_id, extra_targets=[record.path])
    if any(managed_target_state(fs, p) != value for p, value in before.items()):
        raise RenewalError('Исходные файлы ACME изменились при backup')
    journal: dict[str, dict[str, Any]] = {}
    try:
        if not hook_same:
            journal[HOOK_PATH] = fs.atomic_write(HOOK_PATH, hook.content, mode=hook.mode)
        candidate_record = _candidate_record(record, original)
        expected = {**before, **journal}
        if any(managed_target_state(fs, p) != value for p, value in expected.items()):
            raise RenewalError('Конкурентное изменение ACME во время регистрации')
        owner = (record.snapshot['uid'], record.snapshot['gid'])
        journal[record.path] = fs.atomic_write(record.path, candidate_record.encode(),
                                              mode=record.snapshot['mode'], owner=owner)
        expected.update(journal)
        if any(managed_target_state(fs, p) != value for p, value in expected.items()):
            raise RenewalError('Конкурентное изменение ACME после записи metadata')
        values, readback = _read_record(fs, record.path)
        if values != _parse_record(candidate_record) or readback != journal[record.path]:
            raise RenewalError('Запись ACME не прошла проверку после изменения')
        if before_reload is not None:
            before_reload()
        if any(managed_target_state(fs, p) != value for p, value in expected.items()):
            raise RenewalError('Конкурентное изменение ACME перед запуском reload hook')
        if hasattr(runner, 'run_bounded'):
            result = runner.run_bounded([HOOK_PATH], check=False, timeout=120,
                                        max_output_bytes=65536)
        else:
            result = runner.run([HOOK_PATH], check=False, timeout=120)
        if result.returncode:
            raise RenewalError('Reload hook завершился неуспешно; вывод процесса скрыт')
        post_reload()
        if any(managed_target_state(fs, p) != value for p, value in expected.items()):
            raise RenewalError('Конкурентное изменение ACME перед сохранением состояния')
        status = {**renewal_status(fs, cert_path, key_path), 'reload_verified': True, 'changed': True}
        commit_state()
        return status
    except Exception as exc:
        conflicts = restore_backup(fs, backup, expected_current=journal)
        if conflicts:
            raise RenewalError('Откат ACME ограничен: конкурентное изменение сохранено; внешний reload не отменён') from None
        if isinstance(exc, RenewalError):
            raise
        raise RenewalError('Операция ACME не завершена; собственная metadata восстановлена, внешний reload не отменён') from None
