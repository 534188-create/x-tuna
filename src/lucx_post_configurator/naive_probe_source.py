"""Read-only auth из точного Caddyfile; не подтверждает политику клиентов в БД LucX."""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .extended_decoys import classify_naive_connect_candidate
from .discovery import read_lucx_connection
from .models import Audit
from .naive_frontend import parse_naive_connect_source
from .routing_profiles import routing_fingerprint
from .staging_materials import (
    MaterialLimits,
    _Budget,
    _identity,
    _parent,
    _read_regular,
    _stat,
)
from .targetfs import TargetFS
from .sqlite_snapshot import open_snapshot
from .vpn_probe_source import _MAX_FIELD, _bounded_schema, _json_object, _same_profile, _zero

_ERROR = 'Источник Naive не подтверждён'
_LIMIT = 1024 * 1024
# Совместимость внутреннего API существующих focused-тестов.
_parse_source = parse_naive_connect_source


def _capture(path: Path):
    with _parent(path) as (parent, ancestors, missing):
        info = None if missing else _stat(path, parent)
        if info is None or info.st_nlink != 1 or info.st_size == 0:
            raise ValueError(_ERROR)
        data = _read_regular(path, parent, info,
            _Budget(MaterialLimits(max_file_bytes=_LIMIT, max_total_bytes=_LIMIT, max_entries=1),
                    time.monotonic() + 5))
        digest = hashlib.sha256(data).hexdigest()
        snapshot = (ancestors, _identity(info), digest)
        metadata = {'kind': 'file', 'mode': info.st_mode & 0o7777, 'uid': info.st_uid,
                    'gid': info.st_gid, 'sha256': digest}
    return data, snapshot, metadata


@dataclass(frozen=True, slots=True, repr=False)
class _Entry:
    path: Path = field(repr=False)
    snapshot: tuple[Any, ...] = field(repr=False)
    username: str = field(repr=False)
    password: str = field(repr=False)
    profile_fingerprint: str = field(repr=False)
    policy_fingerprint: str = field(repr=False)


class NaiveCaddyCredentialSource:
    """Фиксирует auth на время пробы: новый файл требует нового audit/provider.

    Вызывающий Engine обязан отдельно проверить актуальную LucX topology.
    Здесь проверяется только исходная auth Caddyfile, включая весь набор
    пользователей и директив. Источник не открывает SQLite, ключи или CA.
    """

    __slots__ = ('_entries', '_shared_port')

    def __init__(self, fs: TargetFS, manifest: dict, audit: Audit):
        try:
            shared = manifest['network']['public_tcp_port']
            if type(shared) is not int or not 1 <= shared <= 65535:
                raise ValueError(_ERROR)
            entries = {}
            for protocol in manifest['protocols']:
                if protocol.get('protocol') != 'naive' or protocol.get('enable') is False:
                    continue
                inbound_id = protocol.get('inbound_id')
                if inbound_id in entries or len(entries) >= 128:
                    raise ValueError(_ERROR)
                candidate = classify_naive_connect_candidate(manifest, audit, inbound_id)
                expected = candidate['source_identity']
                path = fs.path(expected['path'])
                data, snapshot, metadata = _capture(path)
                if any(metadata[key] != expected[key] for key in metadata):
                    raise ValueError(_ERROR)
                source = parse_naive_connect_source(data.decode('utf-8'))
                pairs = source.auth_pairs
                if (source.probe_resistance or source.upstream or not 1 <= len(pairs) <= 128
                        or len({user for user, _ in pairs}) != len(pairs)
                        or any(not user or not password for user, password in pairs)):
                    raise ValueError(_ERROR)
                fingerprint = routing_fingerprint(protocol, shared)
                policy = 'sha256:' + hashlib.sha256(json.dumps((snapshot, fingerprint),
                    sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
                entries[inbound_id] = _Entry(path, snapshot, pairs[0][0], pairs[0][1], fingerprint, policy)
                if _capture(path)[1] != snapshot:
                    raise ValueError(_ERROR)
            if not entries:
                raise ValueError(_ERROR)
            self._entries, self._shared_port = MappingProxyType(entries), shared
        except Exception:  # noqa: BLE001 — parser может содержать исходную строку.
            raise ValueError(_ERROR) from None

    def __call__(self, protocol: dict):
        try:
            from .naive_probes import NaiveProbeCredential
            if type(protocol) is not dict or protocol.get('enable') is False:
                return None
            entry = self._entries.get(protocol.get('inbound_id'))
            if (entry is None or routing_fingerprint(protocol, self._shared_port) != entry.profile_fingerprint
                    or _capture(entry.path)[1] != entry.snapshot):
                return None
            return NaiveProbeCredential(entry.username, entry.password, entry.profile_fingerprint,
                                        policy_fingerprint=entry.policy_fingerprint)
        except Exception:  # noqa: BLE001 — источник не публикует данные и ошибки parser.
            return None


# Unicode White_Space, используемый Go strings.TrimSpace. str.strip() Python
# дополнительно удаляет U+001C..U+001F и меняет HMAC identity таких строк.
_GO_SPACE = '\t\n\v\f\r \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000'
_NAIVE_SETTINGS = {'remark', 'listen', 'domain', 'useAcme', 'acmeEmail', 'certFile', 'keyFile',
    'authUser', 'authPass', 'authSeed', 'enableH3', 'probeResistance', 'logLevel', 'extraArgs',
    'routeThroughXray', 'routeXrayPort', 'outboundTag', 'useRawConfig', 'rawConfig', 'behindCover', 'clients'}
_NAIVE_CLIENT_FIELDS = {'id', 'email', 'enable', 'totalGB', 'expiryTime', 'limitIp', 'reset',
    'resetDay', 'resetMax', 'trafficReset', 'trafficResetDay', 'security', 'password', 'flow',
    'reverse', 'auth', 'privateKey', 'publicKey', 'allowedIPs', 'allowedIPsByInbound',
    'preSharedKey', 'keepAlive', 'forwardedPorts', 'secret', 'adTag', 'tgId', 'subId', 'group',
    'comment', 'created_at', 'updated_at'}
_INERT_CLIENT = {'comment', 'created_at', 'updated_at', 'tg_id', 'sub_id'}
_INERT_TRAFFIC = {'up', 'down', 'last_online', 'last_sub_fetch', 'inbound_id'}
_INERT_INBOUND = {'up', 'down', 'remark', 'sub_sort_index', 'last_traffic_reset_time'}
_COHORT_MAX_BYTES = 8 * 1024 * 1024
_SOURCE_MAX_BYTES = 8 * 1024 * 1024


class _CohortBudget:
    __slots__ = ('deadline', 'policy_bytes', 'source_bytes')

    def __init__(self):
        self.deadline = time.monotonic() + 3
        self.policy_bytes = _COHORT_MAX_BYTES
        self.source_bytes = _SOURCE_MAX_BYTES

    def check(self):
        if time.monotonic() >= self.deadline:
            raise ValueError(_ERROR)

    def capture(self, path):
        self.check()
        result = _capture(path)
        self.source_bytes -= len(result[0])
        if self.source_bytes < 0:
            raise ValueError(_ERROR)
        self.check()
        return result

    def fingerprint(self, value):
        """Потоковое хеширование: общий лимит до накопления JSON всего cohort."""
        self.check()
        digest = hashlib.sha256()
        encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
        for part in encoder.iterencode(value):
            self.check()
            data = part.encode('ascii')
            self.policy_bytes -= len(data)
            if self.policy_bytes < 0:
                raise ValueError(_ERROR)
            digest.update(data)
        self.check()
        return 'sha256:' + digest.hexdigest()


def _go_trim(value: Any) -> str:
    if type(value) is not str or len(value.encode('utf-8')) > _MAX_FIELD:
        raise ValueError(_ERROR)
    return value.strip(_GO_SPACE)


def _email_key(value: Any) -> str:
    if type(value) is not str or len(value.encode('utf-8')) > 256:
        raise ValueError(_ERROR)
    result = _go_trim(value).casefold()
    if not result:
        raise ValueError(_ERROR)
    return result


def _naive_auth(key: str, inbound_id: int, email: str) -> tuple[str, str]:
    """Контракт LucX dad034…: UTF-8 HMAC scope, без генерации/записи секретов."""
    identity = f'{inbound_id}:{_go_trim(email)}'.encode('utf-8')
    user = hmac.new(key.encode('utf-8'), b'lucx-naive-user:' + identity, hashlib.sha256)
    password = hmac.new(key.encode('utf-8'), b'lucx-naive-pass:' + identity, hashlib.sha256)
    return 'nx' + user.hexdigest()[:10], base64.urlsafe_b64encode(password.digest()).decode('ascii')[:27]


def _naive_policy(client: dict, row: dict, traffic: dict) -> None:
    if (set(client) - _NAIVE_CLIENT_FIELDS or type(client.get('enable')) is not bool
            or type(row.get('enable')) is not int or row['enable'] not in (0, 1)
            or type(traffic.get('enable')) is not int or traffic['enable'] not in (0, 1)
            or client['enable'] != bool(row['enable']) or row['enable'] != traffic['enable']):
        raise ValueError(_ERROR)
    for item, keys in ((client, ('totalGB', 'expiryTime', 'limitIp', 'reset')),
                       (row, ('total_gb', 'expiry_time', 'limit_ip', 'limit_hwid', 'reset', 'reset_day', 'reset_max')),
                       (traffic, ('total', 'expiry_time', 'reset', 'reset_day', 'reset_max', 'reset_count'))):
        if any(not _zero(item.get(key)) for key in keys):
            raise ValueError(_ERROR)
    if not _zero(row.get('sync_orphaned_at', 0)):
        raise ValueError(_ERROR)
    # LucX 0fcf5d…: ParseInboundSettingsClients даёт Go zero только отсутствующим
    # resetDay/resetMax. client_link сохраняет DB cycle/day при legacy пустом
    # cycle/нулевом дне. Поэтому разрешение зависит от явного relational never.
    if any(not _zero(client.get(key, 0)) for key in ('resetDay', 'resetMax')):
        raise ValueError(_ERROR)
    cycle, day = client.get('trafficReset', ''), client.get('trafficResetDay', 0)
    if (type(cycle) is not str or cycle not in {'', 'never'} or type(day) is not int
            or not 0 <= day <= 31 or row.get('traffic_reset') != 'never'
            or type(row.get('traffic_reset_day')) is not int or not 0 <= row['traffic_reset_day'] <= 31):
        raise ValueError(_ERROR)
    if 'id' in client and client['id'] != row.get('uuid'):
        raise ValueError(_ERROR)


def _naive_source_modes(settings: dict, raw: dict, source) -> None:
    """Согласованность исходника; активный bridge/egress доказывается отдельно.

    LucX 0fcf5d… создаёт отдельный process-scoped SOCKS пароль из 18 random
    bytes. Он не становится клиентской auth; аварийный фиксированный fallback
    не входит в этот адаптер. Исходный URL не разбирается с нормализацией.
    """
    resistance = settings.get('probeResistance', False)
    routed = settings.get('routeThroughXray', False)
    if (type(resistance) is not bool or resistance != source.probe_resistance
            or type(routed) is not bool):
        raise ValueError(_ERROR)
    if not routed:
        if source.upstream:
            raise ValueError(_ERROR)
        return
    port, tag = settings.get('routeXrayPort'), raw.get('tag')
    outbound = settings.get('outboundTag', '')
    if (type(port) is not int or not 1 <= port <= 65535
            or type(tag) is not str or not 1 <= len(tag) <= 256
            or type(outbound) is not str or len(outbound) > 256
            or any(ord(c) < 32 or ord(c) == 127 for c in tag + outbound)
            or re.fullmatch(r'socks5://lucx:[A-Za-z0-9_-]{24}@127\.0\.0\.1:' + str(port),
                            source.upstream) is None):
        raise ValueError(_ERROR)


class LucXNaiveCredentialSource:
    """Полный read-only cohort Naive; пока не зарегистрирован в Engine.

    Консервативная форма: локальные бессрочные/безлимитные клиенты с явно
    согласованными relational, embedded и traffic policy. Даже невыбранный
    клиент входит в baseline; старый provider не выбирает другого после drift.
    """

    __slots__ = ('_fs', '_db_path', '_manifest', '_audit', '_protocols', '_baseline', '_entries')

    def __init__(self, fs: TargetFS, db_path: str, manifest: dict, audit: Audit):
        try:
            self._fs, self._db_path = fs, db_path
            self._manifest, self._audit = copy.deepcopy(manifest), copy.deepcopy(audit)
            shared = self._manifest['network']['public_tcp_port']
            if type(shared) is not int or not 1 <= shared <= 65535:
                raise ValueError(_ERROR)
            protocols = {}
            for item in self._manifest['protocols']:
                if item.get('protocol') != 'naive' or item.get('enable', True) is False:
                    continue
                number = item.get('inbound_id')
                if (type(number) is not int or number <= 0 or number in protocols
                        or item.get('enable', True) is not True or len(protocols) >= 128):
                    raise ValueError(_ERROR)
                protocols[number] = item
            if not protocols:
                raise ValueError(_ERROR)
            self._protocols = protocols
            entries, baseline = self._collect()
            if self._collect()[1] != baseline:
                raise ValueError(_ERROR)
            self._entries, self._baseline = MappingProxyType(entries), baseline
        except Exception:  # noqa: BLE001 — SQLite/parser/HMAC не раскрывают исходные поля.
            raise ValueError(_ERROR) from None

    def _collect(self):
        limits = _CohortBudget()
        captured, snapshots = {}, {}
        for number in self._protocols:
            limits.check()
            route = classify_naive_connect_candidate(self._manifest, self._audit, number)
            expected = route['source_identity']
            path = self._fs.path(expected['path'])
            data, snapshot, metadata = limits.capture(path)
            source = parse_naive_connect_source(data.decode('utf-8'))
            if (any(expected[key] != value for key, value in metadata.items())
                    or not 1 <= len(source.auth_pairs) <= 128
                    or len({user for user, _ in source.auth_pairs}) != len(source.auth_pairs)
                    or any(not user or not password for user, password in source.auth_pairs)):
                raise ValueError(_ERROR)
            captured[number] = source
            snapshots[number] = (path, snapshot)
        database = open_snapshot(self._fs, self._db_path)
        try:
            limits.check()
            database.row_factory = sqlite3.Row
            database.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _MAX_FIELD)
            database.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16384)
            database.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 256)
            steps = 0
            def budget():
                nonlocal steps
                steps += 1000
                return int(steps > 500000 or time.monotonic() >= limits.deadline)
            database.set_progress_handler(budget, 1000)
            database.execute('PRAGMA query_only=ON')
            database.execute('PRAGMA trusted_schema=OFF')
            schema = _bounded_schema(database)
            if not {'clients', 'client_inbounds'} <= schema.keys():
                raise ValueError(_ERROR)
            _, inbounds, supported, warnings = read_lucx_connection(database)
            if not supported or warnings:
                raise ValueError(_ERROR)
            secret_rows = database.execute("SELECT value FROM settings WHERE key='secret'").fetchall()
            if len(secret_rows) != 1 or type(secret_rows[0][0]) is not str or not secret_rows[0][0]:
                raise ValueError(_ERROR)
            secret = secret_rows[0][0]
            clients = [dict(row) for row in database.execute('SELECT * FROM clients ORDER BY id')]
            attachments = [dict(row) for row in database.execute('SELECT * FROM client_inbounds')]
            traffic_rows = [dict(row) for row in database.execute('SELECT * FROM client_traffics')]
            emails, client_index, traffic_index = set(), {}, {}
            for row in clients:
                limits.check()
                email = _email_key(row.get('email'))
                number = row.get('id')
                if (email in emails or type(number) is not int or number <= 0 or number in client_index):
                    raise ValueError(_ERROR)
                emails.add(email)
                client_index[number] = row
            for row in traffic_rows:
                limits.check()
                email = _email_key(row.get('email'))
                if email in traffic_index:
                    raise ValueError(_ERROR)
                traffic_index[email] = row
            links_by_inbound, links_by_client = {}, {}
            for row in attachments:
                limits.check()
                if any(type(row.get(key)) is not int or row[key] <= 0 for key in ('client_id', 'inbound_id')):
                    raise ValueError(_ERROR)
                links_by_inbound.setdefault(row['inbound_id'], []).append(row)
                links_by_client.setdefault(row['client_id'], []).append(row)
            inbound_ids = {item.id for item in inbounds}
            client_policies = {}
            selected, cohort = {}, {}
            for number, protocol in self._protocols.items():
                limits.check()
                matches = [item for item in inbounds if item.id == number]
                if len(matches) != 1 or not _same_profile(matches[0], protocol):
                    raise ValueError(_ERROR)
                raw = dict(database.execute('SELECT * FROM inbounds WHERE id=?', (number,)).fetchone())
                if (type(raw['enable']) is not int or raw['enable'] != 1
                        or not _zero(raw['total']) or not _zero(raw['expiry_time'])
                        or raw.get('node_id') is not None or raw.get('origin_node_guid', '') != ''
                        or raw.get('traffic_reset') != 'never'
                        or type(raw.get('traffic_reset_day')) is not int
                        or not 0 <= raw['traffic_reset_day'] <= 31):
                    raise ValueError(_ERROR)
                settings = _json_object(raw['settings'])
                if (set(settings) - _NAIVE_SETTINGS
                        or settings.get('useRawConfig', False) is not False
                        or settings.get('rawConfig', '') or settings.get('extraArgs', '')):
                    raise ValueError(_ERROR)
                _naive_source_modes(settings, raw, captured[number])
                embedded = settings.get('clients')
                if not isinstance(embedded, list) or not 1 <= len(embedded) <= 128:
                    raise ValueError(_ERROR)
                declared = {}
                for client in embedded:
                    limits.check()
                    if (type(client) is not dict or type(client.get('email')) is not str
                            or not _email_key(client['email']) or client['email'] in declared):
                        raise ValueError(_ERROR)
                    declared[client['email']] = client
                links = links_by_inbound.get(number, [])
                ids = [row['client_id'] for row in links]
                if (any(type(value) is not int for value in ids) or len(set(ids)) != len(ids)
                        or any(row.get('flow_override') != '' for row in links)):
                    raise ValueError(_ERROR)
                records = [client_index[value] for value in sorted(ids)]
                if len(records) != len(ids) or {row['email'] for row in records} != set(declared):
                    raise ValueError(_ERROR)
                seed = _go_trim(settings.get('authSeed', ''))
                key, scope = (seed, 0) if seed else (secret, number)
                expected_pairs, policies, enabled = [], [], []
                service_user = _go_trim(settings.get('authUser', ''))
                service_password = _go_trim(settings.get('authPass', ''))
                if bool(service_user) != bool(service_password):
                    raise ValueError(_ERROR)
                if service_user:
                    expected_pairs.append((service_user, service_password))
                for row in records:
                    limits.check()
                    traffic = traffic_index.get(_email_key(row['email']))
                    if traffic is None or traffic['email'] != row['email']:
                        raise ValueError(_ERROR)
                    client = declared[row['email']]
                    _naive_policy(client, row, traffic)
                    if row['id'] not in client_policies:
                        client_policies[row['id']] = limits.fingerprint({
                            'client': {k: v for k, v in row.items() if k not in _INERT_CLIENT},
                            'traffic': {k: v for k, v in traffic.items() if k not in _INERT_TRAFFIC}})
                    policies.append((row['id'], client_policies[row['id']]))
                    if client['enable']:
                        pair = _naive_auth(key, scope, row['email'])
                        limits.check()
                        enabled.append(pair)
                        expected_pairs.append(pair)
                if (not enabled or len({user for user, _ in expected_pairs}) != len(expected_pairs)
                        or set(expected_pairs) != set(captured[number].auth_pairs)):
                    raise ValueError(_ERROR)
                selected[number] = enabled[0]
                related = [row for value in ids for row in links_by_client[value]]
                if any(row['inbound_id'] not in inbound_ids for row in related):
                    raise ValueError(_ERROR)
                canonical_links = sorted((row['client_id'], row['inbound_id'], row['flow_override']) for row in related)
                if len(set(canonical_links)) != len(canonical_links):
                    raise ValueError(_ERROR)
                cohort[number] = {'inbound': {k: v for k, v in raw.items() if k not in _INERT_INBOUND},
                    'clients': policies, 'attachments': canonical_links,
                    'source': snapshots[number][1], 'profile': routing_fingerprint(protocol,
                        self._manifest['network']['public_tcp_port'])}
            for path, snapshot in snapshots.values():
                if limits.capture(path)[1] != snapshot:
                    raise ValueError(_ERROR)
            digest = limits.fingerprint({'cohort': cohort, 'secret': secret})
            return selected, digest
        finally:
            database.close()

    def __call__(self, protocol: dict):
        try:
            from .naive_probes import NaiveProbeCredential
            if (type(protocol) is not dict or type(protocol.get('inbound_id')) is not int
                    or protocol.get('protocol') != 'naive' or protocol.get('enable', True) is not True):
                return None
            number = protocol['inbound_id']
            expected = self._protocols.get(number)
            shared = self._manifest['network']['public_tcp_port']
            if (expected is None or routing_fingerprint(protocol, shared) != routing_fingerprint(expected, shared)
                    or protocol.get('source_routing_fingerprint') != expected.get('source_routing_fingerprint')):
                return None
            if self._collect()[1] != self._baseline or self._collect()[1] != self._baseline:
                return None
            username, password = self._entries[number]
            return NaiveProbeCredential(username, password, routing_fingerprint(protocol, shared),
                                        policy_fingerprint=self._baseline)
        except Exception:  # noqa: BLE001 — никаких секретных payload и raw ошибок наружу.
            return None
