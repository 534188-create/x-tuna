"""Связь внутренних результатов staging с одним кандидатом и запуском.

Это чистый валидатор: он не запускает frontend и не подтверждает истинность
переданных code-owned свидетельств. Координатор обязан получить их проверками
ОС, повторить source/seal fences и передать собственный expected_binding.
Объекты не загружаются из manifest либо прежнего transaction state.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields
from types import MappingProxyType
from typing import Any

from .decoy_health import decoy_acceptance_summary, vpn_acceptance_summary
from .models import Audit
from .render_runtime import RenderRuntime, runtime_layout
from .staging_integrity import StagedCandidateSeal
from .transaction import RUN_ID_RE

_ERROR = 'Некорректная привязка результатов staging к кандидату'
_SHA256 = re.compile(r'[0-9a-f]{64}\Z')
_MAX_JSON_BYTES = 8 * 1024 * 1024
_MAX_ROWS = 4096


def _canonical(value: Any) -> bytes:
    """JSON без потери типов ключей; ошибки не содержат исходных значений."""
    def plain(item: Any, depth: int = 0) -> Any:
        if depth > 64:
            raise ValueError(_ERROR)
        if isinstance(item, Mapping):
            if len(item) > 16384 or any(type(key) is not str for key in item):
                raise ValueError(_ERROR)
            return {key: plain(value, depth + 1) for key, value in item.items()}
        if type(item) in {list, tuple}:
            if len(item) > 16384:
                raise ValueError(_ERROR)
            return [plain(value, depth + 1) for value in item]
        if item is None or type(item) in {str, int, bool, float}:
            if isinstance(item, str) and len(item) > _MAX_JSON_BYTES:
                raise ValueError(_ERROR)
            return item
        raise ValueError(_ERROR)
    try:
        encoded = json.dumps(plain(value), sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True, allow_nan=False).encode('ascii')
        if len(encoded) > _MAX_JSON_BYTES:
            raise ValueError(_ERROR)
        return encoded
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ValueError(_ERROR) from None


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class CandidateBinding:
    run_id: str
    nonce: str = field(repr=False)
    manifest_sha256: str
    routing_snapshot_sha256: str
    staged_candidate_sha256: str
    runtime_config_sha256: str
    layout_sha256: str
    material_snapshot_sha256: str
    toolchain_sha256: str
    native_sources_sha256: str = field(default_factory=lambda: _digest(None))
    routing_material_sha256: str = field(default_factory=lambda: _digest(None))
    echo_address_sha256: str = field(default_factory=lambda: _digest('127.0.0.1'))
    phase: str = field(default='staging', init=False)
    schema_version: int = field(default=1, init=False)

    def __post_init__(self) -> None:
        if type(self.run_id) is not str or RUN_ID_RE.fullmatch(self.run_id) is None:
            raise ValueError(_ERROR)
        for name in ('nonce', *(item.name for item in fields(self) if item.name.endswith('_sha256'))):
            value = getattr(self, name)
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ValueError(_ERROR)

    @property
    def fingerprint(self) -> str:
        return 'sha256:' + _digest({item.name: getattr(self, item.name) for item in fields(self)})


def create_candidate_binding(manifest: dict[str, Any], *, run_id: str,
                             staged_seal: StagedCandidateSeal, routing_snapshot: Mapping[str, Any],
                             runtime_configs: Mapping[str, bytes], runtime: RenderRuntime,
                             material_snapshot_digest: str,
                             toolchain: Mapping[str, Any], native_sources: Any = None,
                             routing_material: Any = None, echo_address: str = '127.0.0.1') -> CandidateBinding:
    """Хеширует переданные bytes; актуальность файлов проверяется координатором.

    staged_seal уже охватывает production write-set и фактические staging files.
    runtime_configs должны содержать полный реально запускаемый Nginx wrapper.
    """
    if (type(manifest) is not dict or type(staged_seal) is not StagedCandidateSeal
            or type(runtime) is not RenderRuntime or not isinstance(routing_snapshot, Mapping)
            or not isinstance(toolchain, Mapping) or not toolchain
            or not isinstance(runtime_configs, Mapping) or set(runtime_configs) != {'haproxy', 'nginx'}
            or any(type(value) is not bytes or not value or len(value) > 16 * 1024 * 1024
                   for value in runtime_configs.values())):
        raise ValueError(_ERROR)
    layout = runtime_layout(runtime)
    return CandidateBinding(run_id=run_id, nonce=secrets.token_hex(32),
        manifest_sha256=_digest(manifest), routing_snapshot_sha256=_digest(routing_snapshot),
        staged_candidate_sha256=staged_seal.digest,
        runtime_config_sha256=_digest({role: hashlib.sha256(data).hexdigest()
                                      for role, data in runtime_configs.items()}),
        layout_sha256=_digest(layout), material_snapshot_sha256=material_snapshot_digest,
        toolchain_sha256=_digest(toolchain), native_sources_sha256=_digest(native_sources),
        routing_material_sha256=_digest(routing_material), echo_address_sha256=_digest(echo_address))


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _rows(value: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    if (type(value) not in {list, tuple} or len(value) > _MAX_ROWS
            or any(not isinstance(item, Mapping) for item in value)):
        raise ValueError(_ERROR)
    # Копируем и замораживаем также вложенные значения, не только внешний tuple.
    return _freeze(json.loads(_canonical(value)))


@dataclass(frozen=True, slots=True)
class StagingReceipt:
    binding: CandidateBinding
    browser_rows: Sequence[Mapping[str, Any]] = field(repr=False)
    vpn_rows: Sequence[Mapping[str, Any]] = field(repr=False)
    cleanup_complete: bool
    sources_verified: bool
    listeners_verified: bool
    runtime_verified: bool

    def __post_init__(self) -> None:
        if type(self.binding) is not CandidateBinding or any(type(value) is not bool for value in (
                self.cleanup_complete, self.sources_verified, self.listeners_verified, self.runtime_verified)):
            raise ValueError(_ERROR)
        object.__setattr__(self, 'browser_rows', _rows(self.browser_rows))
        object.__setattr__(self, 'vpn_rows', _rows(self.vpn_rows))


def staging_acceptance_summary(manifest: dict[str, Any], receipt: StagingReceipt, *,
                               expected_binding: CandidateBinding, audit: Audit | None = None) -> dict[str, Any]:
    """Не публикует исходные строки, домены и сведения client/material/toolchain."""
    result = {'phase': 'staging', 'public': False, 'complete': False, 'candidate_verified': False,
              'verified_sites': 0, 'verified_endpoints': 0, 'reason': 'candidate_unverified'}
    if type(receipt) is not StagingReceipt or type(expected_binding) is not CandidateBinding:
        return result
    result.update(run_id=expected_binding.run_id, candidate=expected_binding.fingerprint[7:19])
    try:
        decoys = manifest.get('decoys') or {}
        if (decoys.get('enabled') is not True or decoys.get('require_full_acceptance') is not True
                or receipt.binding != expected_binding or _digest(manifest) != expected_binding.manifest_sha256
                or not all((receipt.cleanup_complete, receipt.sources_verified,
                            receipt.listeners_verified, receipt.runtime_verified))
                or any(row.get('candidate_fingerprint') != expected_binding.fingerprint
                       for row in (*receipt.browser_rows, *receipt.vpn_rows))):
            return result
        browser = decoy_acceptance_summary(manifest, receipt.browser_rows, audit=audit, phase='staging')
        vpn = vpn_acceptance_summary(manifest, receipt.vpn_rows, phase='staging')
        result.update(verified_sites=browser['verified_sites'], verified_endpoints=vpn['verified_endpoints'])
        # Пустой или отключённый набор не подтверждает функциональный кандидат.
        complete = (browser.get('matrix_complete') is True and browser['requested_sites'] > 0
                    and vpn.get('complete') is True and vpn['required_endpoints'] > 0)
        result.update(complete=complete, candidate_verified=complete,
                      reason='verified' if complete else 'matrix_incomplete')
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return {**result, 'complete': False, 'candidate_verified': False, 'reason': 'candidate_unverified'}
    return result
