"""Foreground frontend в отдельном coordinator, созданном внешним Runner.

Модуль не создаёт session/process group и не является crash-recovery для Engine.
Все specs и временные конфиги передаёт доверенный код coordinator, не manifest.
"""
from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import math
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Self

from .render_runtime import SocketAddress

_ROLES = frozenset({'haproxy', 'nginx'})
_MAX_PROCESSES = 16384
_MAX_MEMBERS = 128
_MAX_FDS = 4096
_MAX_LISTENERS = 256
_MAX_TABLE_BYTES = 8 * 1024 * 1024
_MAX_TABLE_ROWS = 32768
_MAX_BINARY_BYTES = 256 * 1024 * 1024
_CLEANUP_SECONDS = 2.0
_TERM_SECONDS = .35
_ACTIVE_SESSION: int | None = None


class StagingProcessError(ValueError):
    """Только фиксированная причина; argv, paths и daemon output не публикуются."""


@dataclass(frozen=True, slots=True)
class ServiceIdentity:
    uid: int
    gid: int

    def __post_init__(self) -> None:
        if any(type(value) is not int or not 0 < value < 2**31 for value in (self.uid, self.gid)):
            raise StagingProcessError('Требуется непривилегированная service identity')


@dataclass(frozen=True, slots=True)
class FrontendSpec:
    role: Literal['haproxy', 'nginx']
    binary_path: Path = field(repr=False)
    expected_sha256: str = field(repr=False)
    config_path: Path = field(repr=False)
    working_root: Path = field(repr=False)
    identity: ServiceIdentity = field(repr=False)

    def __post_init__(self) -> None:
        if (self.role not in _ROLES or not isinstance(self.identity, ServiceIdentity)
                or not isinstance(self.expected_sha256, str)
                or not re.fullmatch(r'[0-9a-f]{64}', self.expected_sha256)
                or any(not isinstance(path, Path) or not path.is_absolute()
                       for path in (self.binary_path, self.config_path, self.working_root))):
            raise StagingProcessError('Некорректная спецификация staging frontend')


@dataclass(frozen=True, slots=True)
class TCPListener:
    host: str
    port: int
    inode: int


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    ppid: int
    pgrp: int
    session: int
    starttime: int
    state: str

    def same_process(self, other: ProcessIdentity) -> bool:
        return (self.pid, self.starttime, self.pgrp, self.session) == (
            other.pid, other.starttime, other.pgrp, other.session)


def _budget(value: float, cap: float) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or not 0 < value <= cap:
        raise StagingProcessError('Некорректный бюджет staging процессов')
    return float(value)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise StagingProcessError('Исчерпан бюджет staging процессов')
    return remaining


def parse_tcp_listeners(data: str, *, ipv6: bool, byteorder: Literal['little', 'big'] = sys.byteorder,
                        max_rows: int = _MAX_TABLE_ROWS,
                        max_bytes: int = _MAX_TABLE_BYTES) -> tuple[TCPListener, ...]:
    """Читает literal /proc/net/tcp{,6}; адрес состоит из native-endian u32 слов."""
    try:
        if (type(data) is not str or len(data) > max_bytes or not data.isascii()
                or type(max_rows) is not int or max_rows <= 0 or byteorder not in {'little', 'big'}):
            raise ValueError
        lines = data.splitlines()
        if not lines or 'local_address' not in lines[0].split():
            raise ValueError
        if len(lines) - 1 > max_rows:
            raise ValueError
        listeners: list[TCPListener] = []
        inodes: set[int] = set()
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 10 or not re.fullmatch(r'[0-9]+:', fields[0]):
                raise ValueError
            length = 32 if ipv6 else 8
            if (not re.fullmatch(r'[0-9A-Fa-f]{' + str(length) + r'}:[0-9A-Fa-f]{4}', fields[1])
                    or not re.fullmatch(r'[0-9A-Fa-f]{2}', fields[3])):
                raise ValueError
            if fields[3].upper() != '0A':
                continue
            host, port = fields[1].split(':')
            raw = b''.join(int(host[index:index + 8], 16).to_bytes(4, byteorder)
                           for index in range(0, length, 8))
            inode = int(fields[9])
            if inode <= 0 or inode in inodes or not 0 < int(port, 16) <= 65535:
                raise ValueError
            inodes.add(inode)
            listeners.append(TCPListener(str(ipaddress.ip_address(raw)), int(port, 16), inode))
        return tuple(listeners)
    except (ValueError, TypeError, OverflowError, IndexError):
        raise StagingProcessError('Некорректная таблица TCP listeners') from None


def parse_process_stat(data: str) -> ProcessIdentity:
    """Не разделяет comm по пробелам: поле 22 starttime привязано к последней скобке."""
    try:
        if type(data) is not str or len(data) > 8192:
            raise ValueError
        prefix, suffix = data.rsplit(')', 1)
        pid_text, _comm = prefix.split(' (', 1)
        fields = suffix.split()
        pid, ppid, pgrp, session, started = (int(pid_text), int(fields[1]), int(fields[2]),
                                             int(fields[3]), int(fields[19]))
        if (pid <= 0 or min(ppid, pgrp, session) < 0 or started <= 0
                or len(fields[0]) != 1 or fields[0] not in 'RSDZTWtXxKWPIN'):
            raise ValueError
        return ProcessIdentity(pid, ppid, pgrp, session, started, fields[0])
    except (ValueError, TypeError, IndexError):
        raise StagingProcessError('Некорректная identity процесса') from None


def normalize_expected(expected: Mapping[str, Sequence[SocketAddress]],
                       roles: set[str]) -> dict[str, frozenset[SocketAddress]]:
    if not isinstance(expected, Mapping) or set(expected) != roles or not roles or not roles <= _ROLES:
        raise StagingProcessError('Неполный набор ролей frontend')
    seen: set[SocketAddress] = set()
    result: dict[str, frozenset[SocketAddress]] = {}
    for role, values in expected.items():
        if not isinstance(values, Sequence) or not 0 < len(values) <= _MAX_LISTENERS:
            raise StagingProcessError('Некорректный набор listeners')
        for address in values:
            if not isinstance(address, SocketAddress) or address in seen:
                raise StagingProcessError('Коллизия либо некорректный listener')
            seen.add(address)
        result[role] = frozenset(values)
    if len(seen) > _MAX_LISTENERS:
        raise StagingProcessError('Превышен предел listeners')
    return result


def _read(path: Path, limit: int, deadline: float, *, encoding: str = 'ascii') -> str:
    _remaining(deadline)
    data = bytearray()
    with path.open('rb', buffering=0) as stream:
        # proc seq_file может вернуть только одну страницу без EOF. Иначе
        # listeners после первой страницы незаметно выпадают из проверки.
        while len(data) <= limit:
            _remaining(deadline)
            chunk = stream.read(min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    _remaining(deadline)
    if len(data) > limit:
        raise StagingProcessError('Превышен предел чтения proc')
    return data.decode(encoding, 'strict')


def _process(pid: int, deadline: float) -> ProcessIdentity:
    # comm допускает произвольные bytes, включая не-ASCII; его содержимое не используется.
    result = parse_process_stat(_read(Path('/proc') / str(pid) / 'stat', 8192, deadline, encoding='latin1'))
    if result.pid != pid:
        raise StagingProcessError('Identity процесса изменилась')
    return result


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_gid)


def _open_regular(path: Path) -> int:
    # O_NONBLOCK исключает ожидание на FIFO до проверки типа. Все компоненты без symlink.
    if not path.is_absolute() or '..' in path.parts:
        raise StagingProcessError('Небезопасный путь staging файла')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise StagingProcessError('Staging файл должен быть regular')
        return fd
    finally:
        os.close(parent)


def _verified_binary(path: Path, expected: str, deadline: float) -> int:
    fd = _open_regular(path)
    try:
        before = os.fstat(fd)
        if (not 0 < before.st_size <= _MAX_BINARY_BYTES or before.st_mode & 0o6022
                or not before.st_mode & 0o111 or before.st_uid not in {0, os.geteuid()}):
            raise StagingProcessError('Небезопасный staging binary')
        digest = hashlib.sha256()
        total = 0
        while True:
            _remaining(deadline)
            chunk = os.read(fd, min(1024 * 1024, _MAX_BINARY_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_BINARY_BYTES:
                raise StagingProcessError('Превышен размер staging binary')
            digest.update(chunk)
        if digest.hexdigest() != expected or _file_identity(before) != _file_identity(os.fstat(fd)):
            raise StagingProcessError('Staging binary изменился')
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _checked_config(spec: FrontendSpec) -> int:
    # Здесь проверяются лишь принадлежащие coordinator копии; исходники не открываются.
    try:
        relative = spec.config_path.relative_to(spec.working_root)
    except ValueError:
        raise StagingProcessError('Config вне собственного staging root') from None
    if '..' in relative.parts:
        raise StagingProcessError('Config вне собственного staging root')
    for directory in (spec.working_root, *spec.config_path.parents):
        if directory != spec.working_root and spec.working_root not in directory.parents:
            continue
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o027 or info.st_gid != spec.identity.gid):
            raise StagingProcessError('Небезопасный staging config root')
    fd = _open_regular(spec.config_path)
    info = os.fstat(fd)
    if (info.st_uid != os.geteuid() or info.st_gid != spec.identity.gid
            or info.st_mode & 0o6027 or not 0 < info.st_size <= 4 * 1024 * 1024):
        os.close(fd)
        raise StagingProcessError('Небезопасная staging config copy')
    return fd


def _subreaper(value: int | None = None) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    # Linux prctl: PR_GET_CHILD_SUBREAPER=37, PR_SET_CHILD_SUBREAPER=36.
    old = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(old), 0, 0, 0) != 0:
        raise StagingProcessError('Недоступен Linux subreaper')
    if value is not None and libc.prctl(36, ctypes.c_ulong(value), 0, 0, 0) != 0:
        raise StagingProcessError('Невозможно настроить Linux subreaper')
    return old.value


@dataclass(repr=False)
class _Frontend:
    role: str
    process: subprocess.Popen
    identity: ProcessIdentity


class ForegroundSession:
    """Только main thread отдельного root coordinator; внешний Runner держит hard cap.

    Перед выходом вызывающий код проверяет cleanup_complete. Ошибка очистки блокирует
    receipt. Trusted foreground binaries не должны делать setsid/setpgid.
    """

    def __init__(self, *, timeout: float = 60) -> None:
        self._timeout = _budget(timeout, 300)
        if self._timeout < 3:
            raise StagingProcessError('Недостаточен общий бюджет staging процессов')
        self._deadline = 0.0
        self._lifecycle_deadline = 0.0
        self._pid = 0
        self._entered = False
        self._used = False
        self._old_subreaper = 0
        self._old_handlers: dict[int, Any] = {}
        self._frontends: list[_Frontend] = []
        self._children: list[subprocess.Popen] = []
        self._seen_inodes: set[int] = set()
        self._cleanup_complete = False

    @property
    def cleanup_complete(self) -> bool:
        return self._cleanup_complete

    def _guard(self) -> None:
        if (sys.platform != 'linux' or os.geteuid() != 0 or os.getpid() != os.getpgrp()
                or os.getpid() != os.getsid(0) or threading.current_thread() is not threading.main_thread()):
            raise StagingProcessError('Нужен отдельный root Linux coordinator')
        if self._pid and os.getpid() != self._pid:
            raise StagingProcessError('Coordinator identity изменилась')

    def _members(self, deadline: float) -> dict[int, ProcessIdentity]:
        self._guard()
        result: dict[int, ProcessIdentity] = {}
        count = 0
        with os.scandir('/proc') as entries:
            for entry in entries:
                _remaining(deadline)
                if not entry.name.isdigit():
                    continue
                count += 1
                if count > _MAX_PROCESSES:
                    raise StagingProcessError('Превышен предел proc процессов')
                try:
                    info = _process(int(entry.name), deadline)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if info.pgrp == self._pid:
                    if info.session != self._pid:
                        raise StagingProcessError('Группа покинула session coordinator')
                    result[info.pid] = info
                    if len(result) > _MAX_MEMBERS:
                        raise StagingProcessError('Превышен предел группы staging')
        if self._pid not in result:
            raise StagingProcessError('Coordinator не найден в proc')
        return result

    def __enter__(self) -> Self:
        global _ACTIVE_SESSION
        self._guard()
        if self._used or _ACTIVE_SESSION is not None:
            raise StagingProcessError('Session staging нельзя использовать повторно')
        self._pid = os.getpid()
        self._lifecycle_deadline = time.monotonic() + self._timeout
        self._deadline = self._lifecycle_deadline - _CLEANUP_SECONDS
        try:
            if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
                raise StagingProcessError('Недоступно безопасное управление PID')
            fd = os.pidfd_open(self._pid)
            os.close(fd)
            if set(self._members(self._deadline)) != {self._pid}:
                raise StagingProcessError('Группа coordinator уже содержит процессы')
            self._old_subreaper = _subreaper()
            self._used = self._entered = True
            _ACTIVE_SESSION = self._pid
            _subreaper(1)
            for kind in (signal.SIGTERM, signal.SIGINT):
                self._old_handlers[kind] = signal.getsignal(kind)
                signal.signal(kind, self._abort)
            return self
        except BaseException as exc:  # Даже прерывание enter восстанавливает session.
            if self._entered:
                self._restore()
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise StagingProcessError('Не удалось подготовить staging coordinator') from None

    @staticmethod
    def _abort(kind: int, frame: object) -> None:
        if kind == signal.SIGINT:
            raise KeyboardInterrupt
        raise StagingProcessError('Staging прерван сигналом')

    def _restore(self) -> None:
        global _ACTIVE_SESSION
        for kind, old in self._old_handlers.items():
            signal.signal(kind, old)
        self._old_handlers.clear()
        _subreaper(self._old_subreaper)
        self._entered = False
        _ACTIVE_SESSION = None

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> Literal[False]:
        self.cleanup()
        return False

    def start(self, spec: FrontendSpec) -> None:
        binary_fd = config_fd = -1
        try:
            self._guard()
            if not self._entered or not isinstance(spec, FrontendSpec):
                raise StagingProcessError('Нет активной staging session')
            _remaining(self._deadline)
            if any(item.role == spec.role for item in self._frontends):
                raise StagingProcessError('Роль frontend уже запущена')
            import grp
            import pwd
            pwd.getpwuid(spec.identity.uid)
            grp.getgrgid(spec.identity.gid)
            binary_fd = _verified_binary(spec.binary_path, spec.expected_sha256, self._deadline)
            config_fd = _checked_config(spec)
            executable = f'/proc/self/fd/{binary_fd}'
            config = f'/proc/self/fd/{config_fd}'
            args = ([executable, '-db', '-f', config] if spec.role == 'haproxy' else
                    [executable, '-c', config, '-p', str(spec.working_root) + '/',
                     '-g', 'daemon off; master_process off;'])
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                user=spec.identity.uid, group=spec.identity.gid, extra_groups=[],
                cwd=spec.working_root, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'},
                pass_fds=(binary_fd, config_fd), close_fds=True)
            self._children.append(process)
            identity = _process(process.pid, self._deadline)
            self._frontends.append(_Frontend(spec.role, process, identity))
            if identity.pgrp != self._pid or identity.session != self._pid:
                raise StagingProcessError('Frontend вышел из группы coordinator')
            if process.poll() is not None:
                raise StagingProcessError('Frontend завершился до старта')
        except Exception:  # noqa: BLE001 — argv и исключение Popen не публикуются.
            raise StagingProcessError('Не удалось запустить staging frontend') from None
        finally:
            for fd in (config_fd, binary_fd):
                if fd >= 0:
                    os.close(fd)

    def _socket_inodes(self, info: ProcessIdentity, deadline: float) -> set[int]:
        before = _process(info.pid, deadline)
        if not info.same_process(before):
            raise StagingProcessError('Владелец listener изменился')
        result: set[int] = set()
        with os.scandir(f'/proc/{info.pid}/fd') as entries:
            for count, entry in enumerate(entries, 1):
                _remaining(deadline)
                if count > _MAX_FDS:
                    raise StagingProcessError('Превышен предел FD процесса')
                try:
                    value = os.readlink(entry.path)
                except FileNotFoundError:
                    continue
                match = re.fullmatch(r'socket:\[([0-9]+)\]', value)
                if match:
                    result.add(int(match[1]))
        if not info.same_process(_process(info.pid, deadline)):
            raise StagingProcessError('Владелец listener изменился')
        return result

    @staticmethod
    def _listeners(deadline: float) -> tuple[TCPListener, ...]:
        values: list[TCPListener] = []
        for name, ipv6 in (('tcp', False), ('tcp6', True)):
            values.extend(parse_tcp_listeners(_read(Path('/proc/net') / name, _MAX_TABLE_BYTES, deadline),
                                               ipv6=ipv6))
        return tuple(values)

    def wait_for_listeners(self, expected: Mapping[str, Sequence[SocketAddress]], *, timeout: float = 10) -> None:
        try:
            if not self._entered:
                raise StagingProcessError('Нет активной staging session')
            deadline = min(self._deadline, time.monotonic() + _budget(timeout, 10))
            normalized = normalize_expected(expected, {item.role for item in self._frontends})
            while True:
                _remaining(deadline)
                # TCP snapshot должен предшествовать FD snapshot: иначе только что
                # созданный owned socket ошибочно выглядит чужим из-за старого FD списка.
                listeners = self._listeners(deadline)
                members = self._members(deadline)
                roles: dict[int, str] = {}
                for frontend in self._frontends:
                    live = members.get(frontend.identity.pid)
                    if (frontend.process.poll() is not None or live is None
                            or not frontend.identity.same_process(live) or live.state in {'Z', 'X', 'x'}):
                        raise StagingProcessError('Frontend завершился до проверки listeners')
                    roles[live.pid] = frontend.role
                # Только подтверждённая ancestry; усыновлённый неизвестный listener не угадывается.
                for _ in range(len(members)):
                    additions = {pid: roles[info.ppid] for pid, info in members.items()
                                 if pid not in roles and info.ppid in roles}
                    if not additions:
                        break
                    roles.update(additions)
                sockets: dict[int, set[str | None]] = {}
                for pid, info in members.items():
                    if info.state in {'Z', 'X', 'x'}:
                        continue
                    for inode in self._socket_inodes(info, deadline):
                        sockets.setdefault(inode, set()).add(roles.get(pid))
                observed: dict[str, set[SocketAddress]] = {role: set() for role in normalized}
                expected_addresses = {address for values in normalized.values() for address in values}
                for listener in listeners:
                    owners = sockets.get(listener.inode)
                    host = ipaddress.ip_address(listener.host)
                    address = SocketAddress(listener.host, listener.port) if host.is_loopback else None
                    if owners is not None:
                        self._seen_inodes.add(listener.inode)
                        if (len(owners) != 1 or None in owners or address is None):
                            raise StagingProcessError('Лишний либо неоднозначный owned listener')
                        role = next(iter(owners))
                        if role is None or address not in normalized[role] or address in observed[role]:
                            raise StagingProcessError('Лишний owned listener')
                        observed[role].add(address)
                    elif address in expected_addresses or (host.is_unspecified and any(
                            item.port == listener.port and ipaddress.ip_address(item.host).version == host.version
                            for item in expected_addresses)):
                        raise StagingProcessError('Ожидаемый listener принадлежит другому процессу')
                if all(observed[role] == normalized[role] for role in normalized):
                    # Новое bind/закрытие во время чтения требует полного свежего
                    # inventory и ownership, а не выдачи ready по разным снимкам.
                    if set(listeners) != set(self._listeners(deadline)):
                        time.sleep(min(.02, _remaining(deadline)))
                        continue
                    # Повторная identity/alive проверка закрывает exit во время чтения /proc.
                    for frontend in self._frontends:
                        if (frontend.process.poll() is not None or not frontend.identity.same_process(
                                _process(frontend.identity.pid, deadline))):
                            raise StagingProcessError('Frontend завершился при проверке listeners')
                    return
                time.sleep(min(.02, _remaining(deadline)))
        except Exception:  # noqa: BLE001 — raw proc/paths не входят в причины отказа.
            raise StagingProcessError('Staging listeners не подтверждены') from None

    def _signal(self, info: ProcessIdentity, kind: int, deadline: float) -> None:
        self._guard()
        if info.pid == self._pid or info.pgrp != self._pid or info.session != self._pid:
            raise StagingProcessError('Запрещён сигнал вне owned группы')
        fd = -1
        try:
            if not info.same_process(_process(info.pid, deadline)):
                raise StagingProcessError('PID изменился перед сигналом')
            fd = os.pidfd_open(info.pid)
            if not info.same_process(_process(info.pid, deadline)):
                raise StagingProcessError('PID изменился перед сигналом')
            signal.pidfd_send_signal(fd, kind)
        except (FileNotFoundError, ProcessLookupError):
            pass
        finally:
            if fd >= 0:
                os.close(fd)

    def _reap(self) -> None:
        for process in self._children:
            process.poll()
        # waitpid(-pgrp) не захватывает детей, ушедших из owned группы.
        for _ in range(_MAX_MEMBERS):
            try:
                pid, _status = os.waitpid(-self._pid, os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                break

    def cleanup(self) -> None:
        if not self._entered:
            return
        deadline = min(self._lifecycle_deadline, time.monotonic() + _CLEANUP_SECONDS)
        failure = False
        try:
            self._guard()
            # Повторный SIGINT/SIGTERM не прерывает ограниченную очистку.
            for kind in self._old_handlers:
                signal.signal(kind, signal.SIG_IGN)
            grace = time.monotonic() + _TERM_SECONDS
            first = True
            while True:
                self._reap()
                members = self._members(deadline)
                members.pop(self._pid)
                if not members:
                    if any(row.inode in self._seen_inodes for row in self._listeners(deadline)):
                        raise StagingProcessError('Owned listener пережил очистку')
                    self._cleanup_complete = True
                    break
                if first or time.monotonic() >= grace:
                    kind = signal.SIGTERM if first else signal.SIGKILL
                    # Корневые frontend в обратном порядке, затем их прочие потомки.
                    ordered = [item.identity.pid for item in reversed(self._frontends)]
                    ordered.extend(pid for pid in members if pid not in ordered)
                    for pid in ordered:
                        if pid in members and members[pid].state not in {'Z', 'X', 'x'}:
                            self._signal(members[pid], kind, deadline)
                    first = False
                time.sleep(min(.02, _remaining(deadline)))
        except Exception:  # noqa: BLE001 — любая ошибка cleanup блокирует receipt.
            failure = True
        finally:
            try:
                self._restore()
            except Exception:  # noqa: BLE001 — восстановление тоже часть cleanup.
                failure = True
        if failure:
            self._cleanup_complete = False
            raise StagingProcessError('Очистка staging процессов не подтверждена') from None
