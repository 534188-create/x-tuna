"""Приватные read-only снимки материалов frontend, без запуска процессов.

Повторное чтение обнаруживает наблюдаемый дрейф; это не атомарный filesystem
snapshot и не защита от произвольного ABA доверенным root writer. Live-копии
разрешены только на подтверждённом tmpfs (он может использовать swap).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import posixpath
import re
import secrets
import stat
import sys
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Self

from .renderers import GeneratedFile, frontend_material_inventory
from .targetfs import TargetFS

_ERROR = 'Материалы staging неполны, изменены или не поддерживаются'
_CLEANUP_ERROR = 'Очистка материалов staging не завершена: владение не подтверждено'
_MIME = '/etc/nginx/mime.types'
_ALIAS = '/etc/lucx-post-configurator/tls/certificate.pem'
_ACL = '/etc/haproxy/cloudflare-ips.lst'


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                    separators=(',', ':'), allow_nan=False).encode('ascii')).hexdigest()


def _identity(info: os.stat_result, *, directory: bool = False) -> tuple[int, ...]:
    basic = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    return basic if directory else (*basic, info.st_nlink, info.st_size, info.st_mtime_ns,
                                    info.st_ctime_ns if os.name == 'posix' else 0)


def _safe(path: str) -> bool:
    return (type(path) is str and re.fullmatch(r'/[A-Za-z0-9_./-]+', path) is not None
            and all(part not in {'', '.', '..'} for part in path.split('/')[1:]))


def _ordinary(info: os.stat_result) -> bool:
    return not (getattr(info, 'st_file_attributes', 0)
                & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0))


def _check_time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class MaterialLimits:
    max_file_bytes: int = 16 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_entries: int = 2048
    max_depth: int = 16
    max_symlink_hops: int = 16

    def __post_init__(self) -> None:
        for value, maximum in ((self.max_file_bytes, 16 * 1024 * 1024),
                               (self.max_total_bytes, 64 * 1024 * 1024),
                               (self.max_entries, 2048), (self.max_depth, 16),
                               (self.max_symlink_hops, 16)):
            if type(value) is not int or not 0 < value <= maximum:
                raise ValueError(_ERROR)


_DEFAULT_LIMITS = MaterialLimits()


@dataclass(slots=True)
class _Budget:
    limits: MaterialLimits
    deadline: float
    entries: int = 0
    total: int = 0

    def add(self, size: int = 0, depth: int = 0) -> None:
        _check_time(self.deadline)
        self.entries += 1
        self.total += size
        if (size > self.limits.max_file_bytes or self.total > self.limits.max_total_bytes
                or self.entries > self.limits.max_entries or depth > self.limits.max_depth):
            raise ValueError(_ERROR)


@contextmanager
def _parent(path: Path) -> Iterator[tuple[int | None, tuple[Any, ...], str | None]]:
    """Закрепляет каждый предок; отсутствующий предок фиксирует как absence."""
    ancestors: list[tuple[str, tuple[int, ...]]] = []
    missing = None
    with ExitStack() as stack:
        fd = None
        if os.name == 'posix':
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(path.anchor, flags)
            stack.callback(os.close, fd)
            current = Path(path.anchor)
            ancestors.append((str(current), _identity(os.fstat(fd), directory=True)))
            for part in path.parent.parts[1:]:
                current /= part
                try:
                    next_fd = os.open(part, flags, dir_fd=fd)
                except FileNotFoundError:
                    missing = str(current)
                    break
                fd = next_fd
                stack.callback(os.close, fd)
                ancestors.append((str(current), _identity(os.fstat(fd), directory=True)))
        else:
            for current in reversed(path.parents):
                try:
                    info = current.lstat()
                except FileNotFoundError:
                    missing = str(current)
                    break
                if not stat.S_ISDIR(info.st_mode) or not _ordinary(info):
                    raise ValueError(_ERROR)
                ancestors.append((str(current), _identity(info, directory=True)))
        yield fd, tuple(ancestors), missing
        for name, expected in ancestors:
            if _identity(Path(name).lstat(), directory=True) != expected:
                raise ValueError(_ERROR)
        if missing is not None and os.path.lexists(missing):
            raise ValueError(_ERROR)


def _stat(path: Path, fd: int | None) -> os.stat_result | None:
    try:
        return os.stat(path.name if fd is not None else path, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _read_regular(path: Path, parent: int | None, info: os.stat_result, budget: _Budget) -> bytes:
    if not stat.S_ISREG(info.st_mode) or not _ordinary(info):
        raise ValueError(_ERROR)
    budget.add(info.st_size)
    flags = (os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
             | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0))
    fd = os.open(path.name if parent is not None else path, flags, dir_fd=parent)
    try:
        before = _identity(info)
        if _identity(os.fstat(fd)) != before:
            raise ValueError(_ERROR)
        data = bytearray()
        while len(data) < info.st_size:
            _check_time(budget.deadline)
            chunk = os.read(fd, min(65536, info.st_size - len(data)))
            if not chunk:
                raise ValueError(_ERROR)
            data.extend(chunk)
        if os.read(fd, 1) or _identity(os.fstat(fd)) != before:
            raise ValueError(_ERROR)
        after = _stat(path, parent)
        if after is None or _identity(after) != before:
            raise ValueError(_ERROR)
        return bytes(data)
    finally:
        os.close(fd)


def _source_file(fs: TargetFS, target: str, budget: _Budget, *, links: bool,
                 missing_ok: bool = False, hops: int = 0) -> tuple[bytes | None, tuple[Any, ...]]:
    if not _safe(target) or hops > budget.limits.max_symlink_hops:
        raise ValueError(_ERROR)
    path = fs.path(target)
    with _parent(path) as (parent, ancestors, missing):
        info = None if missing else _stat(path, parent)
        if info is None:
            if not missing_ok:
                raise ValueError(_ERROR)
            return None, (target, 'absent', ancestors, missing)
        before = _identity(info)
        if stat.S_ISLNK(info.st_mode) and links and os.name == 'posix':
            budget.add()
            link = os.readlink(path.name, dir_fd=parent)
            if '\\' in link or '\x00' in link:
                raise ValueError(_ERROR)
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(target), link))
            data, referent = _source_file(fs, resolved, budget, links=True, hops=hops + 1)
            after = _stat(path, parent)
            if (after is None or _identity(after) != before
                    or os.readlink(path.name, dir_fd=parent) != link):
                raise ValueError(_ERROR)
            return data, (target, 'symlink', before, _digest(link), ancestors, referent)
        data = _read_regular(path, parent, info, budget)
        return data, (target, 'file', before, hashlib.sha256(data).hexdigest(), ancestors)


def _source_tree(fs: TargetFS, target: str, budget: _Budget, *, depth: int = 0
                 ) -> tuple[dict[str, bytes], set[str], tuple[Any, ...]]:
    path = fs.path(target)
    with _parent(path) as (parent, ancestors, missing):
        info = None if missing else _stat(path, parent)
        if info is None:
            return {}, set(), (target, 'absent', ancestors, missing)
        if not stat.S_ISDIR(info.st_mode) or not _ordinary(info):
            raise ValueError(_ERROR)
        budget.add(depth=depth)
        before = _identity(info)
        with ExitStack() as stack:
            directory = None
            if os.name == 'posix':
                directory = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                    | os.O_CLOEXEC, dir_fd=parent)
                stack.callback(os.close, directory)
                if _identity(os.fstat(directory)) != before:
                    raise ValueError(_ERROR)
            # scandir итеративный: не строим неограниченный listdir до count gate.
            names = []
            with os.scandir(directory if directory is not None else path) as iterator:
                for entry in iterator:
                    _check_time(budget.deadline)
                    names.append(entry.name)
                    if len(names) + budget.entries > budget.limits.max_entries:
                        raise ValueError(_ERROR)
            files, directories, children = {}, {target}, []
            for name in sorted(names):
                if name in {'.', '..'} or '/' in name or '\\' in name or '\x00' in name:
                    raise ValueError(_ERROR)
                child = target + '/' + name
                child_path = fs.path(child)
                child_info = _stat(child_path, directory)
                if child_info is None:
                    raise ValueError(_ERROR)
                if stat.S_ISDIR(child_info.st_mode):
                    nested_files, nested_dirs, snapshot = _source_tree(fs, child, budget, depth=depth + 1)
                    files.update(nested_files)
                    directories.update(nested_dirs)
                else:
                    if depth + 1 > budget.limits.max_depth:
                        raise ValueError(_ERROR)
                    data = _read_regular(child_path, directory, child_info, budget)
                    files[child] = data
                    snapshot = (child, 'file', _identity(child_info), hashlib.sha256(data).hexdigest())
                children.append(snapshot)
            after = _stat(path, parent)
            if (after is None or _identity(after) != before
                    or directory is not None and _identity(os.fstat(directory)) != before):
                raise ValueError(_ERROR)
            return files, directories, (target, 'directory', before, ancestors, tuple(children))


def _plan_digest(manifest: dict, generated: dict[str, GeneratedFile], routing_material: Any) -> str:
    rows = []
    if type(generated) is not dict or len(generated) > 2048:
        raise ValueError(_ERROR)
    total = 0
    for path, artifact in sorted(generated.items()):
        if (not _safe(path) or type(artifact) is not GeneratedFile or type(artifact.content) is not bytes
                or type(artifact.symlink_target) is not str
                or artifact.symlink_target and (artifact.content or not _safe(artifact.symlink_target))):
            raise ValueError(_ERROR)
        total += len(artifact.content)
        if len(artifact.content) > 16 * 1024 * 1024 or total > 64 * 1024 * 1024:
            raise ValueError(_ERROR)
        rows.append((path, artifact.mode, artifact.component, artifact.symlink_target,
                     hashlib.sha256(artifact.content).hexdigest()))
    return _digest((manifest, rows, routing_material))


def _capture(fs: TargetFS, manifest: dict, generated: dict[str, GeneratedFile], routing_material: Any,
             limits: MaterialLimits, deadline: float) -> tuple[dict[str, bytes], set[str], tuple[Any, ...]]:
    _check_time(deadline)
    plan = _plan_digest(manifest, generated, routing_material)
    inventory = frontend_material_inventory(manifest, routing_material=routing_material)
    if _MIME in inventory:
        raise ValueError(_ERROR)
    budget = _Budget(limits, deadline)
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    records = []
    aliases = {_ALIAS: manifest['certificates']['cert_path'],
               _ALIAS + '.key': manifest['certificates']['key_path']}
    for target, kind in (*sorted(inventory.items()), (_MIME, 'file')):
        artifact = generated.get(target)
        if kind == 'directory':
            tree, dirs, snapshot = _source_tree(fs, target, budget)
            overrides = {path: item for path, item in generated.items() if path.startswith(target + '/')}
            if snapshot[1] == 'absent' and (target + '/index.html' not in overrides
                                           or not overrides[target + '/index.html'].content):
                raise ValueError(_ERROR)
            if artifact is not None:
                raise ValueError(_ERROR)
            directories.add(target)
            directories.update(dirs)
            files.update(tree)
            records.append(('original', snapshot))
            for path, item in sorted(overrides.items()):
                if item.symlink_target or path in directories:
                    raise ValueError(_ERROR)
                relative = path[len(target) + 1:]
                budget.add(len(item.content), depth=len(relative.split('/')))
                parent = posixpath.dirname(path)
                while parent != target:
                    if parent in files:
                        raise ValueError(_ERROR)
                    directories.add(parent)
                    parent = posixpath.dirname(parent)
                files[path] = item.content
                records.append(('generated', path, hashlib.sha256(item.content).hexdigest()))
            if target + '/index.html' not in files:
                raise ValueError(_ERROR)
        elif target in aliases:
            if artifact is None or artifact.symlink_target != aliases[target] or artifact.content:
                raise ValueError(_ERROR)
            data, snapshot = _source_file(fs, aliases[target], budget, links=True)
            if data is None:
                raise ValueError(_ERROR)
            files[target] = data
            records.append(('generated-alias', target, snapshot))
        else:
            if artifact is not None and (target != _ACL or artifact.symlink_target):
                raise ValueError(_ERROR)
            data, snapshot = _source_file(fs, target, budget, links=target not in {_ACL, _MIME},
                                          missing_ok=artifact is not None)
            records.append(('original', snapshot))
            if artifact is not None:
                budget.add(len(artifact.content))
                data = artifact.content
                records.append(('generated', target, hashlib.sha256(data).hexdigest()))
            if data is None:
                raise ValueError(_ERROR)
            files[target] = data
    if _plan_digest(manifest, generated, routing_material) != plan:
        raise ValueError(_ERROR)
    return files, directories, (plan, tuple(records))


def _confirmed_tmpfs(fd: int) -> bool:
    """Проверка filesystem конкретного FD через Linux mnt_id, без догадок по пути."""
    try:
        with Path(f'/proc/self/fdinfo/{fd}').open(encoding='ascii') as stream:
            descriptor = stream.read(65537)
        if len(descriptor) > 65536:
            return False
        ids = [line.split(':', 1)[1].strip() for line in descriptor.splitlines() if line.startswith('mnt_id:')]
        with Path('/proc/self/mountinfo').open(encoding='ascii') as stream:
            mounts = stream.read(1024 * 1024 + 1)
        if len(mounts) > 1024 * 1024:
            return False
        matches = [line.split(' - ', 1)[1].split()[0] for line in mounts.splitlines()
                   if len(ids) == 1 and line.split(' ', 1)[0] == ids[0] and ' - ' in line]
        return matches == ['tmpfs']
    except (OSError, ValueError, IndexError):
        return False


@dataclass(frozen=True, slots=True, repr=False)
class StagingSourceFence:
    """Повторное чтение источников после удаления секретных временных копий.

    Создаётся владельцем материалов; не является загружаемым отчётом или
    доказательством функциональной приёмки. Не удерживает payload сертификатов.
    """
    _fs: TargetFS
    _sources: tuple[Any, ...]
    _limits: MaterialLimits
    _timeout: float

    def verify(self, manifest: dict, generated: dict[str, GeneratedFile], *,
               routing_material: Any = None) -> None:
        try:
            _, _, current = _capture(self._fs, manifest, generated, routing_material,
                                     self._limits, time.monotonic() + self._timeout)
            if current != self._sources:
                raise ValueError(_ERROR)
        except (OSError, TypeError, ValueError, KeyError, OverflowError, RecursionError):
            raise ValueError(_ERROR) from None


@dataclass(slots=True, repr=False)
class StagingMaterials:
    """Владелец только своих копий; методы проверки никогда не пишут источники."""
    root: Path
    paths: Mapping[str, str]
    mime_path: Path
    _fs: TargetFS
    _manifest: dict
    _generated: dict[str, GeneratedFile]
    _routing_material: Any
    _limits: MaterialLimits
    _timeout: float
    _sources: tuple[Any, ...]
    _root_identity: tuple[int, ...]
    _parent_identity: tuple[int, ...]
    _copies: tuple[Any, ...] = ()
    _path_snapshot: tuple[Any, ...] = ()
    _owned: dict[Path, tuple[int, ...]] = field(default_factory=dict)
    _closed: bool = False

    def __post_init__(self) -> None:
        self._path_snapshot = (tuple(sorted(self.paths.items())), str(self.mime_path))

    def __repr__(self) -> str:
        return f'StagingMaterials(snapshot_digest={self.snapshot_digest!r}, closed={self._closed!r})'

    @property
    def snapshot_digest(self) -> str:
        return _digest((self._sources, self._copies, self._path_snapshot))

    def __enter__(self) -> Self:
        self.verify_copies()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.cleanup()

    def _check_root(self) -> None:
        if (self._closed or _identity(self.root.lstat(), directory=True) != self._root_identity
                or _identity(self.root.parent.lstat(), directory=True) != self._parent_identity
                or (tuple(sorted(self.paths.items())), str(self.mime_path)) != self._path_snapshot):
            raise ValueError(_ERROR)

    def verify_sources(self) -> None:
        try:
            self._check_root()
            _, _, current = _capture(self._fs, self._manifest, self._generated, self._routing_material,
                                     self._limits, time.monotonic() + self._timeout)
            if current != self._sources:
                raise ValueError(_ERROR)
        except (OSError, TypeError, ValueError, KeyError, OverflowError, RecursionError):
            raise ValueError(_ERROR) from None

    def source_fence(self) -> StagingSourceFence:
        """Копии ещё принадлежат нам и проверены; последующие чтения независимы."""
        self.verify_sources()
        self.verify_copies()
        return StagingSourceFence(self._fs, self._sources, self._limits, self._timeout)

    def _copy_snapshot(self, expected_files: dict[Path, bytes] | None = None) -> tuple[Any, ...]:
        self._check_root()
        # Root копии вне TargetFS источников: отдельная фиктивная FS для точного tree walk.
        copied_fs = TargetFS(self.root.parent)
        files, directories, snapshot = _source_tree(copied_fs, '/' + self.root.name,
                                                    _Budget(self._limits, time.monotonic() + self._timeout))
        if {copied_fs.path(path) for path in set(files) | directories} != set(self._owned):
            raise ValueError(_ERROR)
        for path, expected in self._owned.items():
            actual = path.lstat()
            if (_identity(actual, directory=True) != expected
                    or stat.S_ISREG(actual.st_mode) and actual.st_nlink != 1):
                raise ValueError(_ERROR)
        if expected_files is not None and {copied_fs.path(path): data for path, data in files.items()} != expected_files:
            raise ValueError(_ERROR)
        return snapshot

    def verify_copies(self) -> None:
        try:
            if self._copy_snapshot() != self._copies:
                raise ValueError(_ERROR)
        except (OSError, TypeError, ValueError, KeyError, OverflowError, RecursionError):
            raise ValueError(_ERROR) from None

    def prepare_read_access(self, uid: int, gid: int) -> None:
        """Root-owned копии: service group читает 0640 и проходит каталоги 0710.

        UID/GID выбирает будущий code-owned coordinator. Метод не создаёт users,
        не меняет предков вне root и не выдаёт writable runtime-каталогов.
        """
        if (os.name != 'posix' or not sys.platform.startswith('linux') or os.geteuid() != 0
                or any(type(value) is not int or not 0 < value < 2**32 - 1 for value in (uid, gid))):
            raise ValueError(_ERROR)
        self.verify_copies()
        try:
            for path, expected in tuple(self._owned.items()):
                with _parent(path) as (parent, _, missing):
                    if missing:
                        raise ValueError(_ERROR)
                    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                    if stat.S_ISDIR(expected[2]):
                        flags |= os.O_DIRECTORY
                    fd = os.open(path.name, flags, dir_fd=parent)
                    owned = False
                    try:
                        if _identity(os.fstat(fd), directory=True) != expected:
                            raise ValueError(_ERROR)
                        owned = True
                        os.fchown(fd, 0, gid)
                        mode = 0o710 if stat.S_ISDIR(expected[2]) else 0o640
                        os.fchmod(fd, mode)
                        actual = os.fstat(fd)
                        if (actual.st_uid, actual.st_gid, stat.S_IMODE(actual.st_mode)) != (0, gid, mode):
                            raise ValueError(_ERROR)
                    finally:
                        if owned:
                            # Даже после ошибки chmod это наш проверенный FD;
                            # cleanup знает результат только наших частичных правок.
                            self._owned[path] = _identity(os.fstat(fd), directory=True)
                            if path == self.root:
                                self._root_identity = self._owned[path]
                        os.close(fd)
            # Сверяем payloads отдельно: permission transition не узаконивает изменение bytes.
            updated = self._copy_snapshot()
            if _content_rows(updated) != _content_rows(self._copies):
                raise ValueError(_ERROR)
            self._copies = updated
            self.verify_sources()
            self.verify_copies()
        except (OSError, TypeError, ValueError, KeyError, OverflowError, RecursionError):
            try:
                self.cleanup()
            except ValueError:
                raise ValueError(_CLEANUP_ERROR) from None
            raise ValueError(_ERROR) from None

    def cleanup(self) -> None:
        if self._closed:
            return
        try:
            self._check_root()
            # Только известные inode; никакого rmtree и удаления неожиданного соседа.
            for path, expected in self._owned.items():
                if _identity(path.lstat(), directory=True) != expected:
                    raise ValueError(_CLEANUP_ERROR)
                if stat.S_ISDIR(expected[2]):
                    children = {child.name for child in self._owned if child.parent == path}
                    with _parent(path / 'ownership-check') as (directory, _, missing):
                        if missing:
                            raise ValueError(_CLEANUP_ERROR)
                        with os.scandir(directory if directory is not None else path) as entries:
                            for entry in entries:
                                if entry.name not in children:
                                    raise ValueError(_CLEANUP_ERROR)
                                children.remove(entry.name)
                        if children:
                            raise ValueError(_CLEANUP_ERROR)
            for path in sorted(self._owned, key=lambda item: len(item.parts), reverse=True):
                expected = self._owned[path]
                with _parent(path) as (parent, _, missing):
                    info = None if missing else _stat(path, parent)
                    if info is None or _identity(info, directory=True) != expected:
                        raise ValueError(_CLEANUP_ERROR)
                    name = path.name if parent is not None else path
                    if stat.S_ISDIR(info.st_mode):
                        os.rmdir(name, dir_fd=parent)
                    else:
                        os.unlink(name, dir_fd=parent)
            self._closed = True
        except (OSError, TypeError, ValueError):
            raise ValueError(_CLEANUP_ERROR) from None


def _content_rows(snapshot: tuple[Any, ...]) -> tuple[Any, ...]:
    if snapshot[1] == 'file':
        return snapshot[0], snapshot[1], snapshot[3]
    if snapshot[1] != 'directory':
        raise ValueError(_ERROR)
    return snapshot[0], snapshot[1], tuple(_content_rows(child) for child in snapshot[4])


def _write_copies(owner: StagingMaterials, files: dict[str, bytes], directories: set[str],
                  targets: dict[str, Path], deadline: float) -> None:
    all_dirs = {targets[path] for path in directories}
    all_dirs.update(path.parent for path in targets.values())
    for path in sorted(all_dirs, key=lambda item: len(item.parts)):
        if path == owner.root:
            continue
        _check_time(deadline)
        with _parent(path) as (parent, _, missing):
            if missing:
                raise ValueError(_ERROR)
            os.mkdir(path.name if parent is not None else path, 0o700, dir_fd=parent)
            owner._owned[path] = _identity(path.lstat(), directory=True)
    for target, payload in sorted(files.items()):
        _check_time(deadline)
        path = targets[target]
        with _parent(path) as (parent, _, missing):
            if missing:
                raise ValueError(_ERROR)
            flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
                     | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0))
            fd = os.open(path.name if parent is not None else path, flags, 0o600, dir_fd=parent)
            owner._owned[path] = _identity(os.fstat(fd), directory=True)
            try:
                view = memoryview(payload)
                while view:
                    _check_time(deadline)
                    count = os.write(fd, view[:65536])
                    if count <= 0:
                        raise ValueError(_ERROR)
                    view = view[count:]
            finally:
                os.close(fd)


def create_staging_materials(
    fs: TargetFS, manifest: dict, generated: dict[str, GeneratedFile], *,
    routing_material: Any = None, temporary_parent: Path | None = None,
    limits: MaterialLimits = _DEFAULT_LIMITS, timeout: float = 10.0,
) -> StagingMaterials:
    """Создать private copies и дважды сверить originals до возврата владельца."""
    owner = None
    try:
        if (type(limits) is not MaterialLimits or type(timeout) not in {int, float}
                or not math.isfinite(timeout) or not 0 < timeout <= 60
                or fs.is_live and (os.name != 'posix' or not sys.platform.startswith('linux'))):
            raise ValueError(_ERROR)
        deadline = time.monotonic() + timeout
        files, directories, sources = _capture(fs, manifest, generated, routing_material, limits, deadline)
        inventory = frontend_material_inventory(manifest, routing_material=routing_material)
        parent_path = Path(temporary_parent if temporary_parent is not None
                           else '/dev/shm' if fs.is_live else tempfile.gettempdir()).absolute()
        root = parent_path / ('x-tuna-materials-' + secrets.token_hex(12))
        with _parent(root) as (parent_fd, _, missing):
            if missing or fs.is_live and (parent_fd is None or not _confirmed_tmpfs(parent_fd)):
                raise ValueError(_ERROR)
            os.mkdir(root.name if parent_fd is not None else root, 0o700, dir_fd=parent_fd)
            root_identity = _identity(root.lstat(), directory=True)
            paths = {target: str(root / f'm{index:04d}') for index, target in enumerate(sorted(inventory))}
            paths[_ALIAS + '.key'] = paths[_ALIAS] + '.key'
            owner = StagingMaterials(root, MappingProxyType(paths), root / 'mime.types', fs, manifest,
                                     generated, routing_material, limits, timeout, sources, root_identity,
                                     _identity(parent_path.lstat(), directory=True))
            owner._owned[root] = root_identity
            if os.name == 'posix' and (root_identity[3] != os.geteuid()
                                      or stat.S_IMODE(root_identity[2]) != 0o700):
                raise ValueError(_ERROR)
            targets = {_MIME: owner.mime_path, **{name: Path(path) for name, path in paths.items()}}
            for target in set(files) | directories:
                if target not in targets:
                    bases = [base for base, kind in inventory.items()
                             if kind == 'directory' and target.startswith(base + '/')]
                    if len(bases) != 1:
                        raise ValueError(_ERROR)
                    targets[target] = Path(paths[bases[0]]) / target[len(bases[0]) + 1:]
            _write_copies(owner, files, directories, targets, deadline)
            owner._copies = owner._copy_snapshot({targets[target]: data for target, data in files.items()})
            # Первое чтение уже завершено; повторное не заменяет исходный снимок.
            _, _, fresh = _capture(fs, manifest, generated, routing_material, limits, deadline)
            if fresh != sources:
                raise ValueError(_ERROR)
            owner.verify_copies()
            _check_time(deadline)
        return owner
    except (OSError, TypeError, ValueError, KeyError, OverflowError, RecursionError):
        if owner is not None:
            try:
                owner.cleanup()
            except ValueError:
                raise ValueError(_CLEANUP_ERROR) from None
        raise ValueError(_ERROR) from None
