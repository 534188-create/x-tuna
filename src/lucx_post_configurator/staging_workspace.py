"""Владелец только своего tmpfs workspace после остановки staging worker.

Материалы и persistent transaction staging имеют отдельных владельцев. Здесь
нет запуска процессов, рекурсивного rmtree и восстановления после crash/SIGKILL.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
import sys
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .staging_materials import _confirmed_tmpfs, _parent
from .staging_processes import ServiceIdentity

_ERROR = 'Рабочий каталог staging недоступен или изменён'
_CLEANUP_ERROR = 'Очистка рабочего каталога staging не подтверждена'
_ROLES = ('haproxy', 'nginx')
_TEMPS = ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi')
_LIMIT = 16 * 1024 * 1024
_MAX_ENTRIES = 256
_MAX_DEPTH = 8
_SECONDS = 10.0


def _guard() -> None:
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError(_ERROR)


def _check_time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ValueError(_ERROR)


def _basic(info: os.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (*_basic(info), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _entries(fd: int, deadline: float) -> set[str]:
    names = set()
    with os.scandir(fd) as entries:
        for entry in entries:
            _check_time(deadline)
            names.add(entry.name)
            if len(names) > _MAX_ENTRIES:
                raise ValueError(_ERROR)
    return names


@dataclass(frozen=True, slots=True, repr=False)
class StagingWorkspace:
    """Публичные пути неизменяемы; cleanup caller вызывает после worker death."""
    _root: Path
    _service: ServiceIdentity
    _ancestors: tuple[Any, ...]
    _created: dict[str, tuple[int, ...]] = field(default_factory=dict)
    _directory_snapshots: dict[str, tuple[int, ...]] = field(default_factory=dict)
    _files: dict[str, tuple[tuple[int, ...], str]] = field(default_factory=dict)
    _remaining: dict[str, tuple[int, ...]] = field(default_factory=dict)
    _written: bool = False
    _attempted: bool = False
    _deleting: bool = False
    _closed: bool = False

    @property
    def root(self) -> Path:
        return self._root

    @property
    def config_root(self) -> Path:
        return self._root / 'configs'

    @property
    def runtime_root(self) -> Path:
        return self._root / 'runtime'

    @property
    def config_paths(self) -> Mapping[str, Path]:
        return MappingProxyType({role: self.config_root / (role + '.conf') for role in _ROLES})

    @property
    def cleanup_complete(self) -> bool:
        return self._closed

    @contextmanager
    def _open(self):
        _guard()
        if self._closed:
            raise ValueError(_ERROR)
        with _parent(self._root) as (parent, ancestors, missing):
            if parent is None or missing or ancestors != self._ancestors:
                raise ValueError(_ERROR)
            fd = os.open(self._root.name, _flags(), dir_fd=parent)
            try:
                if _basic(os.fstat(fd)) != self._created.get(''):
                    raise ValueError(_ERROR)
                yield parent, fd
                if _basic(os.stat(self._root.name, dir_fd=parent, follow_symlinks=False)) != self._created.get(''):
                    raise ValueError(_ERROR)
            finally:
                os.close(fd)

    @contextmanager
    def _directory(self, root_fd: int, relative: str):
        fd = os.dup(root_fd)
        try:
            current = ''
            for part in relative.split('/') if relative else ():
                current = part if not current else current + '/' + part
                child = os.open(part, _flags(), dir_fd=fd)
                os.close(fd)
                fd = child
                expected = self._created.get(current) or self._remaining.get(current, ())[:5]
                if not expected or _basic(os.fstat(fd)) != expected:
                    raise ValueError(_ERROR)
            yield fd
        finally:
            os.close(fd)

    def _named_stat(self, root_fd: int, relative: str) -> os.stat_result:
        if not relative:
            return os.fstat(root_fd)
        parent, _, name = relative.rpartition('/')
        with self._directory(root_fd, parent) as fd:
            return os.stat(name, dir_fd=fd, follow_symlinks=False)

    def _file_snapshot(self, root_fd: int, relative: str, deadline: float) -> tuple[tuple[int, ...], str]:
        parent, _, name = relative.rpartition('/')
        with self._directory(root_fd, parent) as directory:
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != 0 or before.st_gid != self._service.gid
                    or stat.S_IMODE(before.st_mode) != 0o640 or not 0 < before.st_size <= _LIMIT):
                raise ValueError(_ERROR)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            try:
                identity = _snapshot(before)
                if _snapshot(os.fstat(fd)) != identity:
                    raise ValueError(_ERROR)
                digest = hashlib.sha256()
                size = 0
                while True:
                    _check_time(deadline)
                    data = os.read(fd, min(65536, _LIMIT + 1 - size))
                    if not data:
                        break
                    size += len(data)
                    if size > _LIMIT:
                        raise ValueError(_ERROR)
                    digest.update(data)
                if (size != before.st_size or _snapshot(os.fstat(fd)) != identity
                        or _snapshot(os.stat(name, dir_fd=directory, follow_symlinks=False)) != identity):
                    raise ValueError(_ERROR)
                return identity, digest.hexdigest()
            finally:
                os.close(fd)

    def _verify(self, root_fd: int, deadline: float, *, allow_empty: bool = False) -> None:
        if self._deleting or not self._written and not allow_empty:
            raise ValueError(_ERROR)
        for relative, expected in self._directory_snapshots.items():
            info = self._named_stat(root_fd, relative)
            if _basic(info) != self._created[relative]:
                raise ValueError(_ERROR)
            if relative in {'', 'configs'} and _snapshot(info) != expected:
                raise ValueError(_ERROR)
        if _entries(root_fd, deadline) != {'configs', 'runtime'}:
            raise ValueError(_ERROR)
        with self._directory(root_fd, 'configs') as config_fd:
            expected = {role + '.conf' for role in _ROLES} if self._written else set()
            if _entries(config_fd, deadline) != expected:
                raise ValueError(_ERROR)
        if self._written:
            for relative, expected in self._files.items():
                if self._file_snapshot(root_fd, relative, deadline) != expected:
                    raise ValueError(_ERROR)

    def verify_configs(self) -> None:
        try:
            with self._open() as (_, fd):
                self._verify(fd, time.monotonic() + _SECONDS)
        except (OSError, TypeError, ValueError, KeyError, OverflowError):
            raise ValueError(_ERROR) from None

    def write_configs(self, values: Mapping[str, bytes]) -> None:
        try:
            _guard()
            if (self._attempted or self._closed or not isinstance(values, Mapping)
                    or set(values) != set(_ROLES)
                    or any(type(value) is not bytes or not 0 < len(value) <= _LIMIT for value in values.values())):
                raise ValueError(_ERROR)
            payloads = dict(values)
            with self._open() as (_, fd):
                deadline = time.monotonic() + _SECONDS
                self._verify(fd, deadline, allow_empty=True)
                # До write/start допускается только точное пустое созданное дерево.
                self._check_known_tree(fd, self._created, deadline, full=False)
                object.__setattr__(self, '_attempted', True)
                try:
                    with self._directory(fd, 'configs') as config_fd:
                        for role in _ROLES:
                            name, relative = role + '.conf', 'configs/' + role + '.conf'
                            file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                              0o600, dir_fd=config_fd)
                            self._created[relative] = _basic(os.fstat(file_fd))
                            try:
                                os.fchown(file_fd, 0, self._service.gid)
                                os.fchmod(file_fd, 0o640)
                                view = memoryview(payloads[role])
                                while view:
                                    _check_time(deadline)
                                    count = os.write(file_fd, view[:65536])
                                    if count <= 0:
                                        raise ValueError(_ERROR)
                                    view = view[count:]
                            finally:
                                self._created[relative] = _basic(os.fstat(file_fd))
                                os.close(file_fd)
                    for role in _ROLES:
                        relative = 'configs/' + role + '.conf'
                        actual = self._file_snapshot(fd, relative, deadline)
                        if actual[1] != hashlib.sha256(payloads[role]).hexdigest():
                            raise ValueError(_ERROR)
                        self._files[relative] = actual
                    self._directory_snapshots['configs'] = _snapshot(self._named_stat(fd, 'configs'))
                    object.__setattr__(self, '_written', True)
                    self._verify(fd, deadline)
                except (OSError, TypeError, ValueError, KeyError, OverflowError):
                    self._cleanup_partial()
                    raise ValueError(_ERROR) from None
        except (OSError, TypeError, ValueError, KeyError, OverflowError):
            raise ValueError(_ERROR) from None

    def _walk_runtime(self, root_fd: int, deadline: float) -> dict[str, tuple[int, ...]]:
        result: dict[str, tuple[int, ...]] = {}
        count = size = 0
        device = self._created[''][0]

        def visit(fd: int, relative: str, depth: int) -> None:
            nonlocal count, size
            _check_time(deadline)
            if depth > _MAX_DEPTH:
                raise ValueError(_ERROR)
            before = _snapshot(os.fstat(fd))
            for name in _entries(fd, deadline):
                count += 1
                if count > _MAX_ENTRIES or depth + 1 > _MAX_DEPTH:
                    raise ValueError(_ERROR)
                path = relative + '/' + name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if (info.st_dev != device or (info.st_uid, info.st_gid) != (self._service.uid, self._service.gid)
                        or info.st_mode & 0o7022):
                    raise ValueError(_ERROR)
                snapshot = _snapshot(info)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, _flags(), dir_fd=fd)
                    try:
                        if _snapshot(os.fstat(child)) != snapshot:
                            raise ValueError(_ERROR)
                        visit(child, path, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    size += info.st_size
                    if size > _LIMIT:
                        raise ValueError(_ERROR)
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        if _snapshot(os.fstat(child)) != snapshot:
                            raise ValueError(_ERROR)
                    finally:
                        os.close(child)
                else:
                    raise ValueError(_ERROR)
                if _snapshot(os.stat(name, dir_fd=fd, follow_symlinks=False)) != snapshot:
                    raise ValueError(_ERROR)
                if path in self._created and _basic(info) != self._created[path]:
                    raise ValueError(_ERROR)
                result[path] = snapshot
            if _snapshot(os.fstat(fd)) != before:
                raise ValueError(_ERROR)
            result[relative] = before

        with self._directory(root_fd, 'runtime') as runtime_fd:
            visit(runtime_fd, 'runtime', 0)
        return result

    def _check_known_tree(self, root_fd: int, records: Mapping[str, tuple[int, ...]], deadline: float, *, full: bool) -> None:
        for relative, expected in records.items():
            _check_time(deadline)
            actual = self._named_stat(root_fd, relative)
            if _basic(actual) != expected[:5]:
                raise ValueError(_CLEANUP_ERROR)
            if stat.S_ISDIR(actual.st_mode):
                with self._directory(root_fd, relative) as directory:
                    prefix = relative + '/' if relative else ''
                    children = {name[len(prefix):] for name in records
                                if name.startswith(prefix) and name != relative and '/' not in name[len(prefix):]}
                    if _entries(directory, deadline) != children:
                        raise ValueError(_CLEANUP_ERROR)
            elif not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1 or full and _snapshot(actual) != expected:
                raise ValueError(_CLEANUP_ERROR)

    def _delete(self, parent_fd: int, root_fd: int, records: dict[str, tuple[int, ...]], deadline: float) -> None:
        for relative in sorted(records, key=lambda path: (path.count('/'), len(path)), reverse=True):
            if not relative:
                continue
            _check_time(deadline)
            # Путь root должен по-прежнему обозначать созданный inode перед каждой записью.
            if _basic(os.stat(self._root.name, dir_fd=parent_fd, follow_symlinks=False)) != self._created['']:
                raise ValueError(_CLEANUP_ERROR)
            parent, _, name = relative.rpartition('/')
            with self._directory(root_fd, parent) as directory:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                expected = records[relative]
                if _basic(info) != expected[:5]:
                    raise ValueError(_CLEANUP_ERROR)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, _flags(), dir_fd=directory)
                    try:
                        if _basic(os.fstat(child)) != expected[:5] or _entries(child, deadline):
                            raise ValueError(_CLEANUP_ERROR)
                    finally:
                        os.close(child)
                    os.rmdir(name, dir_fd=directory)
                else:
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or len(expected) > 5 and _snapshot(info) != expected:
                        raise ValueError(_CLEANUP_ERROR)
                    os.unlink(name, dir_fd=directory)
                del records[relative]
        if _entries(root_fd, deadline):
            raise ValueError(_CLEANUP_ERROR)
        if _basic(os.stat(self._root.name, dir_fd=parent_fd, follow_symlinks=False)) != self._created['']:
            raise ValueError(_CLEANUP_ERROR)
        os.rmdir(self._root.name, dir_fd=parent_fd)
        records.clear()
        object.__setattr__(self, '_closed', True)

    def _cleanup_partial(self) -> None:
        """До запуска сервиса известен каждый созданный inode, даже при failed chmod."""
        try:
            with self._open() as (parent, fd):
                deadline = time.monotonic() + _SECONDS
                records = dict(self._created)
                self._check_known_tree(fd, records, deadline, full=False)
                self._remaining.update(records)
                object.__setattr__(self, '_deleting', True)
                self._delete(parent, fd, self._remaining, deadline)
        except (OSError, TypeError, ValueError, KeyError, OverflowError):
            if not self._closed:
                raise ValueError(_CLEANUP_ERROR) from None

    def cleanup(self) -> None:
        if self._closed:
            return
        try:
            with self._open() as (parent, fd):
                deadline = time.monotonic() + _SECONDS
                if not self._deleting:
                    self._verify(fd, deadline, allow_empty=True)
                    records = {relative: _snapshot(self._named_stat(fd, relative)) for relative in self._created}
                    records.update(self._walk_runtime(fd, deadline))
                    self._remaining.clear()
                    self._remaining.update(records)
                self._check_known_tree(fd, self._remaining, deadline, full=True)
                # Перед destructive phase повторяем полную проверку known inventory.
                self._check_known_tree(fd, self._remaining, deadline, full=True)
                object.__setattr__(self, '_deleting', True)
                self._delete(parent, fd, self._remaining, deadline)
        except (OSError, TypeError, ValueError, KeyError, OverflowError):
            if not self._closed:
                raise ValueError(_CLEANUP_ERROR) from None


def _mkdir(owner: StagingWorkspace, parent_fd: int, name: str, relative: str, uid: int, gid: int, mode: int) -> None:
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    owner._created[relative] = _basic(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
    fd = os.open(name, _flags(), dir_fd=parent_fd)
    try:
        if _basic(os.fstat(fd)) != owner._created[relative]:
            raise ValueError(_ERROR)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
    finally:
        owner._created[relative] = _basic(os.fstat(fd))
        os.close(fd)


def create_staging_workspace(identity: ServiceIdentity, *, temporary_parent: Path | None = None) -> StagingWorkspace:
    """Только Linux root и tmpfs конкретного FD; нет disk fallback и chmod предков."""
    owner = None
    try:
        _guard()
        if type(identity) is not ServiceIdentity:
            raise ValueError(_ERROR)
        import grp
        import pwd
        pwd.getpwuid(identity.uid)
        grp.getgrgid(identity.gid)
        parent_path = Path('/dev/shm') if temporary_parent is None else temporary_parent
        if (not isinstance(parent_path, Path) or not parent_path.is_absolute()
                or any(part in {'.', '..'} for part in parent_path.parts)):
            raise ValueError(_ERROR)
        root = parent_path / ('x-tuna-workspace-' + secrets.token_hex(12))
        with _parent(root) as (parent_fd, ancestors, missing):
            if parent_fd is None or missing or not _confirmed_tmpfs(parent_fd):
                raise ValueError(_ERROR)
            owner = StagingWorkspace(root, identity, ancestors)
            _mkdir(owner, parent_fd, root.name, '', 0, identity.gid, 0o710)
            with owner._open() as (_, fd):
                _mkdir(owner, fd, 'configs', 'configs', 0, identity.gid, 0o710)
                _mkdir(owner, fd, 'runtime', 'runtime', identity.uid, identity.gid, 0o700)
                with owner._directory(fd, 'runtime') as runtime_fd:
                    for name in _TEMPS:
                        _mkdir(owner, runtime_fd, name, 'runtime/' + name, identity.uid, identity.gid, 0o700)
                for relative in owner._created:
                    owner._directory_snapshots[relative] = _snapshot(owner._named_stat(fd, relative))
                owner._verify(fd, time.monotonic() + _SECONDS, allow_empty=True)
        return owner
    except (OSError, TypeError, ValueError, KeyError, OverflowError):
        if owner is not None and '' in owner._created:
            owner._cleanup_partial()
        raise ValueError(_ERROR) from None
