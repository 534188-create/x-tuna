"""Связывает исходный план, буферы commit и фактические файлы staging.

Это проверка целостности кандидата, а не функциональная VPN-приёмка. Symlink
проверяется как ссылка; сертификат или иной referent проверяется отдельно.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .renderers import GeneratedFile
from .targetfs import TargetFS
from .transaction import RUN_ID_RE, STAGING_ROOT

_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 32 * 1024 * 1024
_MAX_FILES = 512
_ERROR = "Кандидат staging изменён или не соответствует исходному плану"


def _path_valid(value: Any) -> bool:
    return (type(value) is str and re.fullmatch(r"/[A-Za-z0-9_./-]+", value) is not None
            and all(part not in {"", ".", ".."} for part in value.split("/")[1:]))


def _digest(value: Any) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError(_ERROR) from None
    return hashlib.sha256(encoded).hexdigest()


def _identity(info: os.stat_result, *, directory: bool = False) -> tuple[int, ...]:
    result = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    # Валидатор может создавать соседние wrapper-файлы. Это меняет mtime
    # каталога, но не позволяет подменить сам каталог или его владельца.
    # На Windows ctime — устаревающее поле времени создания; после replace
    # path/FD могут сообщать разные значения. Linux change-time сохраняем.
    change_time = info.st_ctime_ns if os.name == "posix" else 0
    return result if directory else (*result, info.st_size, info.st_mtime_ns, change_time)


def _directory(info: os.stat_result) -> bool:
    return (stat.S_ISDIR(info.st_mode)
            and not getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _file_snapshot(path: Path, artifact: GeneratedFile) -> tuple[Any, ...]:
    """В POSIX открывает компоненты через dir_fd; ни один FD не пишущий."""
    with ExitStack() as stack:
        ancestors: list[tuple[Path, tuple[int, ...]]] = []
        parent_fd = None
        if os.name == "posix":
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            parent_fd = os.open(path.anchor, flags)
            stack.callback(os.close, parent_fd)
            current = Path(path.anchor)
            ancestors.append((current, _identity(os.fstat(parent_fd), directory=True)))
            for part in path.parent.parts[1:]:
                parent_fd = os.open(part, flags, dir_fd=parent_fd)
                stack.callback(os.close, parent_fd)
                current /= part
                ancestors.append((current, _identity(os.fstat(parent_fd), directory=True)))
            info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        else:
            for current in reversed(path.parents):
                info = current.lstat()
                if not _directory(info):
                    raise ValueError(_ERROR)
                ancestors.append((current, _identity(info, directory=True)))
            info = path.lstat()
        before = _identity(info)
        if artifact.symlink_target:
            if not stat.S_ISLNK(info.st_mode):
                raise ValueError(_ERROR)
            link = (os.readlink(path.name, dir_fd=parent_fd) if parent_fd is not None
                    else os.readlink(path))
            if link != artifact.symlink_target:
                raise ValueError(_ERROR)
            payload_digest = hashlib.sha256(link.encode("utf-8")).hexdigest()
        else:
            if (not stat.S_ISREG(info.st_mode) or info.st_size != len(artifact.content)
                    or (os.name == "posix" and stat.S_IMODE(info.st_mode) != artifact.mode)
                    or getattr(info, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
                raise ValueError(_ERROR)
            flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0))
            fd = (os.open(path.name, flags, dir_fd=parent_fd) if parent_fd is not None
                  else os.open(path, flags))
            stack.callback(os.close, fd)
            if _identity(os.fstat(fd)) != before:
                raise ValueError(_ERROR)
            digest, size = hashlib.sha256(), 0
            while chunk := os.read(fd, min(65536, len(artifact.content) + 1 - size)):
                size += len(chunk)
                if size > len(artifact.content):
                    raise ValueError(_ERROR)
                digest.update(chunk)
            payload_digest = digest.hexdigest()
            if (size != len(artifact.content)
                    or payload_digest != hashlib.sha256(artifact.content).hexdigest()
                    or _identity(os.fstat(fd)) != before):
                raise ValueError(_ERROR)
        after = (os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                 if parent_fd is not None else path.lstat())
        if _identity(after) != before:
            raise ValueError(_ERROR)
        for directory, expected in ancestors:
            actual = directory.lstat()
            if not _directory(actual) or _identity(actual, directory=True) != expected:
                raise ValueError(_ERROR)
        return before, payload_digest, tuple((str(name), value) for name, value in ancestors)


def _capture(fs: TargetFS, manifest: dict[str, Any], generated: dict[str, GeneratedFile],
             staged: dict[str, Path], run_id: str) -> tuple[str, tuple[Any, ...]]:
    if (type(run_id) is not str or RUN_ID_RE.fullmatch(run_id) is None
            or type(manifest) is not dict or type(generated) is not dict or type(staged) is not dict
            or len(generated) > _MAX_FILES or set(generated) != set(staged)):
        raise ValueError(_ERROR)
    plan, paths, total = [], [], 0
    for target, artifact in sorted(generated.items()):
        if (not _path_valid(target) or type(artifact) is not GeneratedFile
                or type(artifact.content) is not bytes or type(artifact.mode) is not int
                or not 0 <= artifact.mode <= 0o7777 or type(artifact.component) is not str
                or type(artifact.symlink_target) is not str
                or (artifact.symlink_target and (artifact.content or not _path_valid(artifact.symlink_target)))):
            raise ValueError(_ERROR)
        total += len(artifact.content)
        if len(artifact.content) > _MAX_FILE_BYTES or total > _MAX_TOTAL_BYTES:
            raise ValueError(_ERROR)
        expected = fs.path(f"{STAGING_ROOT}/{run_id}{target}")
        path = staged[target]
        if not isinstance(path, Path) or path != expected or any(part in {".", ".."} for part in path.parts):
            raise ValueError(_ERROR)
        paths.append((target, path, artifact))
        plan.append((target, artifact.mode, artifact.component, artifact.symlink_target,
                     hashlib.sha256(artifact.content).hexdigest()))
    # Сначала проверяется весь inventory, затем начинаются read-only открытия.
    plan_digest = _digest({"manifest": manifest, "generated": plan, "run_id": run_id})
    files = tuple((target, str(path), _file_snapshot(path, artifact)) for target, path, artifact in paths)
    return plan_digest, files


@dataclass(frozen=True, slots=True)
class StagedCandidateSeal:
    """В памяти только digest и метаданные, без конфигов и manifest secrets."""
    digest: str
    _snapshot: tuple[Any, ...] = field(repr=False)

    def verify(self, fs: TargetFS, manifest: dict[str, Any], generated: dict[str, GeneratedFile],
               staged: dict[str, Path], run_id: str) -> None:
        current = capture_staged_candidate(fs, manifest, generated, staged, run_id)
        if self != current:
            raise ValueError(_ERROR)


def capture_staged_candidate(fs: TargetFS, manifest: dict[str, Any], generated: dict[str, GeneratedFile],
                             staged: dict[str, Path], run_id: str) -> StagedCandidateSeal:
    try:
        plan_digest, files = _capture(fs, manifest, generated, staged, run_id)
    except (OSError, TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError(_ERROR) from None
    return StagedCandidateSeal(_digest({"plan": plan_digest, "files": files}), (plan_digest, files))
