"""Read-only привязка внешнего файла manifest к подтверждённому плану."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .migrations import migrate_manifest
from .models import ConfigurationError, validate_manifest
from .staging_materials import (
    MaterialLimits,
    _Budget,
    _identity,
    _parent,
    _read_regular,
    _stat,
)

_ERROR = 'Исходный файл манифеста изменён или не прошёл безопасное чтение'
_LIMIT = 4 * 1024 * 1024


def _read(path: Path) -> tuple[bytes, tuple[Any, ...]]:
    with _parent(path) as (parent, ancestors, missing):
        info = None if missing else _stat(path, parent)
        if info is None or info.st_size == 0 or info.st_nlink != 1:
            raise ConfigurationError(_ERROR)
        budget = _Budget(MaterialLimits(max_file_bytes=_LIMIT, max_total_bytes=_LIMIT,
                                        max_entries=1), time.monotonic() + 5)
        data = _read_regular(path, parent, info, budget)
        snapshot = (ancestors, _identity(info), hashlib.sha256(data).hexdigest())
    return data, snapshot


def _digest(manifest: dict) -> str:
    def check(value):
        if type(value) is dict:
            if any(type(key) is not str for key in value):
                raise ValueError(_ERROR)
            for item in value.values():
                check(item)
        elif type(value) is list:
            for item in value:
                check(item)
        elif value is not None and type(value) not in {str, bool, int, float}:
            raise ValueError(_ERROR)
    if type(manifest) is not dict:
        raise ValueError(_ERROR)
    check(manifest)
    encoded = json.dumps(manifest, sort_keys=True, ensure_ascii=True,
                         separators=(',', ':'), allow_nan=False).encode('ascii')
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class ManifestSourceFence:
    _path: Path = field(repr=False)
    _snapshot: tuple[Any, ...] = field(repr=False)
    _manifest_digest: str = field(repr=False)

    def guards(self, path: str | Path) -> bool:
        """Сравнивает кодовую цель с исходником, не открывая её и не раскрывая путь."""
        return Path(path).absolute() == self._path

    def verify(self, *, manifest: dict | None = None) -> None:
        try:
            if manifest is not None and _digest(manifest) != self._manifest_digest:
                raise ValueError(_ERROR)
            _, snapshot = _read(self._path)
            if snapshot != self._snapshot:
                raise ValueError(_ERROR)
        except (OSError, TypeError, ValueError, OverflowError, RecursionError):
            raise ConfigurationError(_ERROR) from None


def read_manifest_source(path: str | Path, *, envelope: str = 'manifest') -> tuple[dict, ManifestSourceFence]:
    """Читает manifest либо явный state envelope без записи или hydration.

    State связывается целиком; нормализуется только вложенный manifest.
    Форма выбирается вызывающим кодом, не содержимым исходного JSON.
    """
    try:
        if type(envelope) is not str or envelope not in {'manifest', 'state'}:
            raise ValueError(_ERROR)
        source = Path(path).absolute()
        if '..' in source.parts:
            raise ValueError(_ERROR)
        data, snapshot = _read(source)

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(_ERROR)
                result[key] = value
            return result

        raw = json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError(_ERROR)))
        if envelope == 'state':
            if type(raw) is not dict or type(raw.get('manifest')) is not dict:
                raise ValueError(_ERROR)
            raw = raw['manifest']
        manifest = migrate_manifest(raw)
        validate_manifest(manifest)
        fence = ManifestSourceFence(source, snapshot, _digest(manifest))
        fence.verify(manifest=manifest)
        return manifest, fence
    except (OSError, TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        raise ConfigurationError(_ERROR) from None
