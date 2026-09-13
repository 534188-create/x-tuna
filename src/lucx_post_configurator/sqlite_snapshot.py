"""Ограниченный SQLite snapshot без SQLite VFS-доступа к оригиналам.

Двойное чтение и проверки поколения обнаруживают наблюдаемый дрейф. Они не
являются атомарным filesystem snapshot и не доказывают отсутствие произвольной
ABA-подмены доверенным writer. Неизвестные и нестабильные состояния отклоняются.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .targetfs import TargetFS

_MAX_INPUT = 16 * 1024 * 1024
_MAX_IMAGE = 16 * 1024 * 1024
_CHUNK = 64 * 1024
_SUFFIXES = ('', '-wal', '-shm', '-journal')


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ValueError('Время получения снимка исчерпано')


@contextmanager
def _parent(path: Path, live: bool) -> Iterator[int | None]:
    """Linux: каждый предок закреплён O_DIRECTORY/O_NOFOLLOW дескриптором."""
    if os.name != 'posix':
        if live:
            raise ValueError('Live snapshot требует Linux')
        for ancestor in (path.parent, *path.parent.parents):
            if ancestor.is_symlink():
                raise ValueError('Ссылка в пути источника')
        yield None  # Только синтетические Windows fixtures.
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        fd = os.open(path.anchor, flags)
        stack.callback(os.close, fd)
        for part in path.parent.parts[1:]:
            fd = os.open(part, flags, dir_fd=fd)
            stack.callback(os.close, fd)
        yield fd


def _stat(path: Path, parent: int | None) -> os.stat_result | None:
    try:
        return os.stat(path.name if parent is not None else path,
                       dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _regular(info: os.stat_result, *, database: bool = False) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_INPUT
            or info.st_size < (100 if database else 0)):
        raise ValueError('Неподтверждённый тип или размер источника')
    if os.name == 'posix' and (info.st_mode & 0o022 or info.st_uid not in {0, os.geteuid()}):
        raise ValueError('Неподтверждённые права источника')


def _read(fd: int, size: int, deadline: float) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = bytearray()
    while len(chunks) < size:
        _deadline(deadline)
        chunk = os.read(fd, min(_CHUNK, size - len(chunks)))
        if not chunk:
            raise ValueError('Неполное чтение источника')
        chunks.extend(chunk)
    if os.read(fd, 1):
        raise ValueError('Источник вырос во время чтения')
    return bytes(chunks)


def _digest(fd: int, size: int, deadline: float) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    left = size
    while left:
        _deadline(deadline)
        chunk = os.read(fd, min(_CHUNK, left))
        if not chunk:
            raise ValueError('Неполное повторное чтение')
        digest.update(chunk)
        left -= len(chunk)
    if os.read(fd, 1):
        raise ValueError('Источник вырос при повторном чтении')
    return digest.digest()


def _read_index(fd: int, deadline: float) -> bytes:
    """Только две 48-байтовые копии WalIndexHdr, без read marks и hash tables."""
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) < 96:
        _deadline(deadline)
        chunk = os.read(fd, 48 if not data else min(48, 96 - len(data)))
        if not chunk:
            raise ValueError('Неполный заголовок WAL-index')
        data.extend(chunk)
    return bytes(data)


def _source_bytes(fs: TargetFS, target: str, deadline: float) -> tuple[bytes, bytes, bytes | None]:
    if (not isinstance(target, str) or not target.startswith('/') or '\\' in target
            or any(part in {'.', '..'} for part in target.split('/'))):
        raise ValueError('Неподтверждённый путь источника')
    path = fs.path(target)
    with _parent(path, fs.is_live) as parent, ExitStack() as handles:
        directory = os.fstat(parent) if parent is not None else path.parent.lstat()
        entries: dict[str, tuple[Path, os.stat_result | None, int | None]] = {}
        fd_states = {}
        fd: int | None
        # Весь набор FD и отсутствий фиксируется до первого чтения содержимого.
        for suffix in _SUFFIXES:
            name = path.with_name(path.name + suffix)
            info = _stat(name, parent)
            if info is None:
                if not suffix:
                    raise ValueError('Источник отсутствует')
                entries[suffix] = (name, None, None)
                continue
            _regular(info, database=not suffix)
            if suffix == '-shm' and (info.st_size < 32768 or info.st_size % 32768):
                raise ValueError('Размер WAL-index не подтверждён')
            if suffix == '-journal':
                raise ValueError('Rollback journal требует отдельного согласованного снимка')
            flags = (os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
                     | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0))
            fd = os.open(name.name if parent is not None else name, flags, dir_fd=parent)
            handles.callback(os.close, fd)
            opened = os.fstat(fd)
            # Windows fixture: lstat и CRT fstat имеют разную семантику ctime.
            # Каждая шкала сверяется сама с собой, inode/тип/размер — между ними.
            if _identity(info)[:6] != _identity(opened)[:6]:
                raise ValueError('Источник заменён при открытии')
            if os.name == 'posix' and _identity(info) != _identity(opened):
                raise ValueError('Источник изменён при открытии')
            fd_states[fd] = opened
            entries[suffix] = (name, info, fd)
        wal_fd = entries['-wal'][2]
        wal_header = os.read(wal_fd, 32) if wal_fd is not None else b''
        shm_fd = entries['-shm'][2]
        index_header = _read_index(shm_fd, deadline) if shm_fd is not None else None
        data = {}
        for suffix in ('', '-wal'):
            _, info, fd = entries[suffix]
            data[suffix] = _read(fd, info.st_size, deadline) if fd is not None and info is not None else b''
        if data['-wal'][:32] != wal_header:
            raise ValueError('Поколение WAL изменилось до чтения')
        for suffix in ('', '-wal'):
            _, info, fd = entries[suffix]
            if (fd is not None and info is not None
                    and _digest(fd, info.st_size, deadline) != hashlib.sha256(data[suffix]).digest()):
                raise ValueError('Содержимое источника изменилось')
        if wal_fd is not None:
            os.lseek(wal_fd, 0, os.SEEK_SET)
            if os.read(wal_fd, 32) != wal_header:
                raise ValueError('Поколение WAL изменилось после чтения')
        if shm_fd is not None and _read_index(shm_fd, deadline) != index_header:
            raise ValueError('Граница commit в WAL-index изменилась')
        for name, info, fd in entries.values():
            current = _stat(name, parent)
            if ((info is None) != (current is None) or
                    info is not None and (current is None or _identity(info) != _identity(current)
                    or fd is None or _identity(fd_states[fd]) != _identity(os.fstat(fd)))):
                raise ValueError('Состав или свойства источника изменились')
        # mtime/ctime каталога фиксируют в том числе появление и удаление sidecars.
        current_dir = os.fstat(parent) if parent is not None else path.parent.lstat()
        if _identity(directory) != _identity(current_dir):
            raise ValueError('Состав каталога изменился')
        # Повторный проход от корня обнаруживает смену закреплённых предков.
        with _parent(path, fs.is_live) as again:
            named_dir = os.fstat(again) if again is not None else path.parent.lstat()
            if _identity(current_dir) != _identity(named_dir):
                raise ValueError('Каталог источника заменён')
        return data[''], data['-wal'], index_header


def _confirmed_tmpfs(fd: int) -> bool:
    """mnt_id открытого каталога сверяется с ядром, а не с префиксом пути."""
    if not sys.platform.startswith('linux'):
        return False
    with open(f'/proc/self/fdinfo/{fd}', 'r', encoding='ascii') as source:
        info = source.read(65537)
    if len(info) > 65536:
        return False
    ids = [line.split()[1] for line in info.splitlines() if line.startswith('mnt_id:')]
    if len(ids) != 1 or not ids[0].isdigit():
        return False
    with open('/proc/self/mountinfo', 'r', encoding='ascii') as source:
        mounts = source.read(1024 * 1024 + 1)
    if len(mounts) > 1024 * 1024:
        return False
    matches = [line.split(' - ', 1)[1].split()[0] for line in mounts.splitlines()
               if line.split(' ', 1)[0] == ids[0] and ' - ' in line]
    return matches == ['tmpfs']


@contextmanager
def _private_directory(live: bool) -> Iterator[Path]:
    if live and (os.name != 'posix' or not sys.platform.startswith('linux')):
        raise ValueError('Приватный live tmpfs недоступен')
    # Только fixture может использовать системный TemporaryDirectory.
    with tempfile.TemporaryDirectory(prefix='x-tuna-snapshot-', dir='/dev/shm' if live else None) as temporary:
        path = Path(temporary)
        if os.name == 'posix':
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise ValueError('Неподтверждённые права приватного каталога')
                if live and not _confirmed_tmpfs(fd):
                    raise ValueError('Файловая система приватной копии не подтверждена как tmpfs')
            finally:
                os.close(fd)
        yield path


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
                 | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_CLOEXEC', 0), 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)


def _configure(db: sqlite3.Connection, deadline: float) -> None:
    db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _MAX_IMAGE)
    db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16384)
    db.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 256)
    steps = 0
    def budget() -> int:
        nonlocal steps
        steps += 1000
        return int(steps > 500000 or time.monotonic() >= deadline)
    db.set_progress_handler(budget, 1000)
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA temp_store=MEMORY')
    db.execute('PRAGMA mmap_size=0')
    db.execute('PRAGMA cache_size=-2048')


def _wal_geometry(raw: bytes, wal: bytes) -> int:
    # Только заголовок/геометрия: frame checksums, commits и replay проверяет SQLite.
    if len(raw) < 100 or raw[:16] != b'SQLite format 3\x00' or raw[18:20] not in {b'\x01\x01', b'\x02\x02'}:
        raise ValueError('Заголовок SQLite не подтверждён')
    size = int.from_bytes(raw[16:18], 'big')
    size = 65536 if size == 1 else size
    if size < 512 or size > 65536 or size & (size - 1) or len(raw) % size:
        raise ValueError('Размер страниц SQLite не подтверждён')
    if not wal:
        return 0
    if (raw[18:20] != b'\x02\x02' or len(wal) < 32
            or int.from_bytes(wal[:4], 'big') not in {0x377F0682, 0x377F0683}
            or int.from_bytes(wal[4:8], 'big') != 3007000
            or int.from_bytes(wal[8:12], 'big') != size
            or (len(wal) - 32) % (size + 24)):
        raise ValueError('Заголовок или длина WAL не подтверждены')
    return (len(wal) - 32) // (size + 24)


def _checked_index(headers: bytes) -> bytes:
    """Unix/Windows WalIndexHdr: sqlite.org/walformat.html и wal.c.

    Это проверка фиксированного WAL-index header. Frame parser/checksums/replay
    остаются внутри SQLite. Index checksum использует native endian всегда.
    """
    if len(headers) != 96 or headers[:48] != headers[48:]:
        raise ValueError('Копии WAL-index header не согласованы')
    header = headers[:48]
    number = lambda start, end: int.from_bytes(header[start:end], sys.byteorder)
    if number(0, 4) != 3007000 or number(4, 8) or header[12] != 1 or header[13] not in {0, 1}:
        raise ValueError('Формат WAL-index header не подтверждён')
    first = second = 0
    for offset in range(0, 40, 8):
        first = (first + number(offset, offset + 4) + second) & 0xFFFFFFFF
        second = (second + number(offset + 4, offset + 8) + first) & 0xFFFFFFFF
    if (first, second) != (number(40, 44), number(44, 48)):
        raise ValueError('Checksum WAL-index header не подтверждена')
    return header


def _wal_horizon(wal: bytes, headers: bytes | None, frames: int) -> bytes | None:
    header = _checked_index(headers) if headers is not None else None
    if header is None:
        if wal:
            raise ValueError('WAL без подтверждённой границы commit')
        return None
    mx_frame = int.from_bytes(header[16:20], sys.byteorder)
    if mx_frame > frames:
        raise ValueError('WAL не соответствует committed horizon источника')
    if not wal:
        # Существующий SHM.mxFrame>0 запрещает fallback к DB при потерянном WAL.
        return header
    page_size = int.from_bytes(header[14:16], sys.byteorder)
    page_size = 65536 if page_size == 1 else page_size
    pages = int.from_bytes(header[20:24], sys.byteorder)
    if (page_size != int.from_bytes(wal[8:12], 'big')
            or header[13] != (wal[3] & 1) or header[32:40] != wal[16:24]
            or frames and not 0 < pages * page_size <= _MAX_IMAGE):
        raise ValueError('Поколение или размер committed WAL-index не подтверждены')
    if mx_frame < frames:
        # RESTART checkpoint переиспользует начало WAL без усечения файла.
        # Старый хвост допускается только вне текущего поколения. Полный WAL
        # далее читает SQLite: recovered mxFrame/checksum обязаны совпасть с SHM.
        if not mx_frame or any(wal[offset + 8:offset + 16] == wal[16:24]
                for offset in range(32 + mx_frame * (page_size + 24), len(wal), page_size + 24)):
            raise ValueError('WAL содержит неподтверждённый хвост текущего поколения')
    return header


def _serialize_private(raw: bytes, wal: bytes, headers: bytes | None, live: bool, deadline: float) -> bytes:
    frames = _wal_geometry(raw, wal)
    horizon = _wal_horizon(wal, headers, frames)
    committed_frames = int.from_bytes(horizon[16:20], sys.byteorder) if horizon is not None else 0
    with _private_directory(live) as private:
        path = private / 'snapshot.db'
        _write_private(path, raw)
        if wal:
            _write_private(path.with_name(path.name + '-wal'), wal)
        db = sqlite3.connect(path, timeout=0)
        try:
            _configure(db, deadline)
            db.execute('BEGIN')
            pages = db.execute('PRAGMA page_count').fetchone()[0]
            page_size = db.execute('PRAGMA page_size').fetchone()[0]
            if not 0 < pages * page_size <= _MAX_IMAGE:
                raise ValueError('Логический снимок превышает лимит')
            if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise ValueError('Целостность снимка не подтверждена')
            if wal:
                # SQLite самостоятельно восстановил index только приватной копии.
                # Его horizon/checksum последнего frame сверяется с captured SHM,
                # а не выводится лишь из усечённого физического WAL prefix.
                with path.with_name(path.name + '-shm').open('rb') as native_index:
                    recovered = _checked_index(_read_index(native_index.fileno(), deadline))
                if horizon is None or recovered[12:40] != horizon[12:40]:
                    raise ValueError('Native recovery не подтвердил последний commit источника')
            _deadline(deadline)
            image = db.serialize()
            if len(image) != pages * page_size:
                raise ValueError('Размер сериализации не подтверждён')
            db.rollback()
            if wal:
                # Native recovery может молча отбросить invalid/uncommitted хвост.
                # Сравнение его числа committed frames с геометрией исключает это.
                checkpoint = db.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone()
                if checkpoint != (0, committed_frames, committed_frames):
                    raise ValueError('WAL содержит неподтверждённый хвост')
            return image
        finally:
            db.close()


def open_snapshot(fs: TargetFS, target: str) -> sqlite3.Connection:
    """Возвращает один query-only :memory: connection; копии уже удалены.

    При SIGKILL cleanup невозможен: остатки защищены 0700/0600 в tmpfs.
    tmpfs допускает swap; физическое отсутствие копий в swap не обещается.
    """
    if not callable(getattr(sqlite3.Connection, 'serialize', None)) or not callable(getattr(sqlite3.Connection, 'deserialize', None)):
        raise TypeError('SQLite serialize/deserialize недоступны')
    deadline = time.monotonic() + 3
    raw, wal, headers = _source_bytes(fs, target, deadline)
    image = _serialize_private(raw, wal, headers, fs.is_live, deadline)
    del raw, wal, headers
    # Меняются только байты уже восстановленного сериализованного снимка.
    normalized = bytearray(image)
    normalized[18:20] = b'\x01\x01'
    del image
    db = sqlite3.connect(':memory:', timeout=0)
    try:
        _configure(db, deadline)
        db.deserialize(normalized)
        del normalized
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise ValueError('Целостность memory snapshot не подтверждена')
        return db
    except BaseException:
        db.close()
        raise
