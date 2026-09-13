"""Наблюдение Debian cron без исполнения записанных команд и без изменений."""
from __future__ import annotations

import os
import re
import shlex
import stat
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .targetfs import TargetFS

_SCRIPT = '/root/.acme.sh/acme.sh'
_HOME = '/root/.acme.sh'
_LIMIT = 256 * 1024


def _seal(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns if os.name == 'posix' else 0)


def _check_path(fs, path):
    owner = 0 if fs.is_live else (os.geteuid() if os.name == 'posix' else 0)
    for parent in (path.parent, *path.parents):
        if parent == fs.root:
            break
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or os.name == 'posix'
                and (info.st_uid != owner or info.st_mode & 0o002)):
            raise ValueError('Недостоверный источник cron')
    return owner


def _read(fs, target):
    path = fs.path(target)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    owner = _check_path(fs, path)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _LIMIT
            or os.name == 'posix' and (before.st_uid != owner or before.st_mode & 0o022)):
        raise ValueError('Недостоверный источник cron')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(fd, 'rb') as stream:
        if _seal(os.fstat(stream.fileno())) != _seal(before):
            raise ValueError('Источник cron изменился')
        payload = stream.read(_LIMIT + 1)
        if (len(payload) > _LIMIT or _seal(os.fstat(stream.fileno())) != _seal(before)
                or _seal(path.lstat()) != _seal(before)):
            raise ValueError('Источник cron изменился')
    return payload.decode('utf-8')


def _expression(fields):
    if len(fields) == 1:
        return fields[0] in {'@yearly', '@annually', '@monthly', '@weekly', '@daily', '@midnight', '@hourly'}
    if len(fields) != 5:
        return False
    for field, (low, high) in zip(fields, [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]):
        if len(field) > 80:
            return False
        for part in field.split(','):
            match = re.fullmatch(r'(\*|[0-9]{1,2}(?:-[0-9]{1,2})?)(?:/([0-9]{1,2}))?', part)
            if not match or match[2] is not None and not 1 <= int(match[2]) <= high + 1:
                return False
            if match[1] != '*':
                numbers = [int(n) for n in match[1].split('-')]
                if not all(low <= n <= high for n in numbers) or numbers != sorted(numbers):
                    return False
    return True


def _parse(text, system):
    expressions, unsupported = [], False
    supported_shell = True
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        env = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)', line)
        if env:
            if env[1] == 'SHELL':
                supported_shell = env[2].strip('\"\'') == '/bin/sh'
            continue
        count = (1 if line.startswith('@') else 5) + int(system)
        parts = line.split(None, count)
        if len(parts) != count + 1:
            continue
        if system and parts[-2] != 'root':
            continue
        command = parts[-1]
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            lexer.commenters = ''
            tokens = list(lexer)
        except ValueError:
            unsupported |= _SCRIPT in command
            continue
        if tokens and tokens[0] in {'sh', 'bash', '/bin/sh', '/bin/bash', 'env', '/usr/bin/env'}:
            unsupported |= any(_SCRIPT in value for value in tokens[1:])
        if not tokens or tokens[0] != _SCRIPT:
            continue
        fields = parts[:count - int(system)]
        tail = tokens[4:]
        if (tokens[:4] != [_SCRIPT, '--cron', '--home', _HOME] or '%' in command
                or tail not in ([], ['>', '/dev/null'], ['>', '/dev/null', '2', '>&', '1'])
                or not supported_shell or not _expression(fields)):
            unsupported = True
            continue
        expressions.append(' '.join(fields))
    return expressions, unsupported


def _timezone(fs):
    try:
        name = (_read(fs, '/etc/timezone') or '').strip()
        if not re.fullmatch(r'[A-Za-z0-9_+/-]{1,80}', name) or '..' in name or name.startswith('/'):
            return None
        if name not in {'UTC', 'Etc/UTC', 'GMT', 'Etc/GMT'}:
            ZoneInfo(name)
        return name
    except (OSError, ValueError, ZoneInfoNotFoundError):
        return None


def schedule_status(fs: TargetFS, runner=None) -> dict:
    """Только факты cron; отсутствие здесь не исключает иной планировщик."""
    expressions, unreadable, unsupported = [], False, False
    targets = [('/var/spool/cron/crontabs/root', False), ('/etc/crontab', True)]
    try:
        directory = fs.path('/etc/cron.d')
        if directory.exists() or directory.is_symlink():
            _check_path(fs, directory / 'placeholder')
            paths = list(directory.iterdir())
            if len(paths) > 4096:
                raise ValueError('Слишком много записей cron')
            targets.extend(('/etc/cron.d/' + p.name, True) for p in sorted(paths)
                           if re.fullmatch(r'[A-Za-z0-9_-]+', p.name))
    except (OSError, ValueError):
        unreadable = True
    for target, system in targets:
        try:
            payload = _read(fs, target)
            if payload is not None:
                found, unknown = _parse(payload, system)
                expressions.extend(found)
                unsupported |= unknown
        except (OSError, ValueError):
            unreadable = True
    active = None
    if runner is not None and fs.is_live and not getattr(runner, 'dry_run', False):
        try:
            result = runner.run_bounded(['systemctl', 'is-active', 'cron.service'], check=False,
                                        timeout=10, max_output_bytes=4096)
            if result.returncode == 0 and result.stdout.strip() == 'active':
                active = True
            elif result.returncode == 3 and result.stdout.strip() in {'inactive', 'failed'}:
                active = False
        except Exception:  # noqa: BLE001 — вывод Runner не включается в статус.
            active = None
    state = 'unreadable' if unreadable else 'unsupported' if unsupported else 'found' if expressions else 'absent'
    found = True if expressions else None if unreadable or unsupported else False
    timezone = _timezone(fs)
    return {'schedule_found': found, 'schedule_state': state,
            'schedule_verified': found is True and active is True and state == 'found',
            'schedules': [{'expression': value, 'timezone': timezone} for value in sorted(set(expressions))],
            'cron_active': active}
