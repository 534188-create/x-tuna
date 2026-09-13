"""Поколения read-only источника Naive; пользовательское намерение не меняется."""
from __future__ import annotations

import copy
import os
from pathlib import PurePosixPath

from .extended_decoys import classify_extended_decoy_routes
from .naive_probe_source import _capture
from .routing_profiles import source_routing_fingerprint
from .validation import routing_audit_snapshot


def prepare_naive_manifest(fs, manifest, audit):
    """До подтверждения обновляет доказательства допустимой регенерации.

    Нельзя вызывать для молчаливой замены уже подтверждённого плана. Все
    изменения ограничены производными Naive полями; прежний объект сохраняется.
    """
    candidate = copy.deepcopy(manifest)
    decoys = candidate.get('decoys') or {}
    naive_ids = {p['inbound_id'] for p in candidate.get('protocols', []) if p.get('protocol') == 'naive'}
    if decoys.get('routing_mode') != 'extended' or not naive_ids:
        return candidate
    old_routes = decoys.get('extended_routes') or []
    fresh_routes = classify_extended_decoy_routes(candidate, audit)
    targets = [r for r in fresh_routes if r.get('inbound_id') in naive_ids and
               r.get('strategy') in {'naive_managed', 'naive_native', 'naive_connect_h2'} and
               r.get('status') == 'ready']
    if not targets:
        return candidate
    records = copy.deepcopy(candidate.get('naive_generations') or {})
    adoption = list(candidate.get('naive_generation_adoption') or [])
    by_id = {p['inbound_id']: p for p in candidate['protocols']}
    actual = {p.id: p for p in audit.inbounds}
    old_by_id = {r.get('inbound_id'): r for r in old_routes}
    if len(old_by_id) != len(old_routes):
        raise ValueError('Naive: повторяющиеся маршруты; требуется новый план')
    metadata_by_path = {r.get('path'): r for r in (audit.naive_caddyfile or {}).get('files', [])}
    for route in targets:
        number = route['inbound_id']
        protocol = by_id[number]
        observed = actual.get(number)
        expected = protocol.get('source_routing_fingerprint')
        if observed is None or (expected and expected != source_routing_fingerprint(observed)):
            raise ValueError('Naive: настройки подключения изменились; требуется новый план')
        saved = old_by_id.get(number, {})
        identity = route.get('source_identity') or {}
        path = route.get('source_caddyfile') or identity.get('path')
        if (not isinstance(path, str) or not path.startswith('/') or
                PurePosixPath(path).name != f'naive-{number}.caddyfile' or
                '..' in PurePosixPath(path).parts):
            raise ValueError('Naive: источник не имеет подтверждённого пути')
        metadata = metadata_by_path.get(path)
        if not metadata:
            raise ValueError('Naive: источник отсутствует в свежем аудите')
        payload, seal, captured = _capture(fs.path(path))
        if (any(metadata.get(key) != value for key, value in captured.items()) or
                captured['uid'] != 0 or captured['gid'] != 0 or
                (os.name != 'nt' and captured['mode'] != 0o600)):
            raise ValueError('Naive: источник или его права изменились после аудита')
        old = records.get(str(number))
        if old is None and number not in adoption:
            adoption.append(number)
        try:
            from .naive_runtime import NaivePolicyError, validate_source_binding
            binding = validate_source_binding(fs, candidate['lucx']['db_path'], number, payload.decode('utf-8'))
        except NaivePolicyError:
            raise
        except (OSError, UnicodeError, ValueError):
            raise ValueError('Naive: источник, клиенты или внутренний мост не подтверждены') from None
        if old and any(old.get(key) != binding.get(key) for key in ('database_sha256', 'semantic_sha256')):
            raise ValueError('Naive: изменились защищённые настройки; требуется новый план')
        if saved and any(saved.get(key) != route.get(key) for key in
                         ('strategy', 'status', 'domain', 'public_port', 'managed_listen_port', 'source_caddyfile')):
            raise ValueError('Naive: изменился маршрут; требуется новый план')
        if _capture(fs.path(path))[1] != seal:
            raise ValueError('Naive: источник изменился во время подготовки')
        records[str(number)] = dict(binding, path=path, source_sha256=captured['sha256'],
                                    metadata={k: v for k, v in captured.items() if k != 'sha256'})
    # Обновляются только выбранные Naive routes. Остальные сохранённые маршруты
    # по-прежнему проверяет renderer; здесь они не получают новое разрешение.
    refreshed = {r['inbound_id']: r for r in targets}
    candidate['decoys']['extended_routes'] = [copy.deepcopy(refreshed.get(r.get('inbound_id'), r))
                                              for r in old_routes] if old_routes else fresh_routes
    candidate['naive_generations'] = records
    if adoption:
        candidate['naive_generation_adoption'] = sorted(adoption)
    if 'routing_snapshot' in candidate:
        old_snapshot = candidate['routing_snapshot']
        fresh_snapshot = routing_audit_snapshot(audit)
        # Топология не переносится из аудита поверх выбранной пользователем.
        if {k: v for k, v in old_snapshot.items() if k != 'naive_files'} != {
                k: v for k, v in fresh_snapshot.items() if k != 'naive_files'}:
            raise ValueError('Naive: топология сохранённого плана изменилась')
        candidate['routing_snapshot']['naive_files'] = fresh_snapshot['naive_files']
    return candidate
