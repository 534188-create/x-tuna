"""Read-only привязка Naive к политике LucX и объявленному runtime Xray.

Не заменяет функциональную VPN-пробу и не доказывает историческую загрузку
конфига процессом. Наружу выходят только отпечатки, ошибки не содержат source.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import stat
import urllib.parse
from pathlib import Path, PurePosixPath

from .naive_frontend import (
    _line_tokens,
    parse_naive_connect_source,
    parse_naive_native_source,
)
from .naive_probe_source import (
    _NAIVE_CLIENT_FIELDS,
    _NAIVE_SETTINGS,
    _capture,
    _go_trim,
    _naive_auth,
)
from .sqlite_snapshot import open_snapshot
from .targetfs import TargetFS
from .vpn_probe_source import _CLIENT_COLUMNS, _INBOUND_COLUMNS, _json_object

_ERROR = 'Источник Naive не подтверждён'
_TRAFFIC = {'up', 'down', 'last_traffic_reset_time'}


class NaivePolicyError(ValueError):
    """Фиксированная безопасная причина отказа без данных источника."""


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()


def _target(fs: TargetFS, name: str) -> Path:
    if (type(name) is not str or not name.startswith('/') or '\\' in name or '\x00' in name
            or str(PurePosixPath(name)) != name or '..' in PurePosixPath(name).parts):
        raise ValueError(_ERROR)
    path = fs.path(name)
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError(_ERROR)
        if ancestor == fs.root:
            break
    return path


def _trusted(info, fs, *, executable=False):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError(_ERROR)
    if os.name == 'posix' and (info.st_uid != (0 if fs.is_live else os.geteuid()) or info.st_mode & 0o022):
        if executable:
            raise NaivePolicyError('Naive: исполняемый файл Xray имеет небезопасные права; '
                'требуется владелец root и режим 0755. Сначала проверьте происхождение бинарника.')
        raise ValueError(_ERROR)
    if executable and os.name == 'posix' and not info.st_mode & stat.S_IXUSR:
        raise ValueError(_ERROR)


def _metadata(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_file(fs, target):
    path = _target(fs, target)
    _trusted(path.lstat(), fs)
    data, snapshot, metadata = _capture(path)
    if os.name == 'posix' and (metadata['uid'] != (0 if fs.is_live else os.geteuid())
                              or metadata['mode'] & 0o022):
        raise ValueError(_ERROR)
    return data, snapshot


def _proc_bytes(fs, target):
    # /proc regular files имеют st_size=0: bounded read вместо size-based capture.
    path = _target(fs, target)
    before = path.lstat()
    _trusted(before, fs)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if _metadata(before)[:6] != _metadata(opened)[:6]:
            raise ValueError(_ERROR)
        chunks = bytearray()
        while len(chunks) <= 16384:
            block = os.read(fd, min(4096, 16385 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > 16384 or _metadata(opened) != _metadata(os.fstat(fd)):
            raise ValueError(_ERROR)
    finally:
        os.close(fd)
    if _metadata(before) != _metadata(path.lstat()):
        raise ValueError(_ERROR)
    return bytes(chunks), _metadata(before)


def _schema(db, table, required, allowed, maximum):
    row = db.execute('SELECT type FROM sqlite_master WHERE name=?', (table,)).fetchall()
    columns = {r[1] for r in db.execute(f'PRAGMA table_info("{table}")')}
    if (row != [('table',)] or not required <= columns or columns - allowed
            or db.execute('SELECT 1 FROM sqlite_master WHERE type=? AND tbl_name=?', ('trigger', table)).fetchone()
            or db.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0] > maximum):
        raise ValueError(_ERROR)


def _database(fs, db_path, number):
    _trusted(_target(fs, db_path).lstat(), fs)
    db = open_snapshot(fs, db_path)
    try:
        _schema(db, 'inbounds', {'id', 'protocol', 'enable', 'listen', 'port', 'settings'}, _INBOUND_COLUMNS, 4096)
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        relational = bool({'clients', 'client_inbounds'} & tables)
        if relational:
            _schema(db, 'clients', {'id', 'email', 'enable'}, _CLIENT_COLUMNS, 4096)
            _schema(db, 'client_inbounds', {'client_id', 'inbound_id'},
                    {'client_id', 'inbound_id', 'flow_override', 'created_at'}, 8192)
        db.row_factory = sqlite3.Row
        matches = db.execute('SELECT * FROM inbounds WHERE id=?', (number,)).fetchall()
        if len(matches) != 1:
            raise ValueError(_ERROR)
        row = dict(matches[0])
        if row['protocol'] != 'naive' or type(row['enable']) is not int or row['enable'] != 1:
            raise ValueError(_ERROR)
        settings = _json_object(row['settings'])
        if (set(settings) - _NAIVE_SETTINGS or settings.get('useRawConfig', False) is not False
                or settings.get('useAcme', False) is not False or settings.get('rawConfig', '')
                or settings.get('extraArgs', '')):
            raise ValueError(_ERROR)
        embedded = settings.get('clients', [])
        if type(embedded) is not list or len(embedded) > 128:
            raise ValueError(_ERROR)
        declared = {}
        for client in embedded:
            if (type(client) is not dict or set(client) - _NAIVE_CLIENT_FIELDS
                    or type(client.get('enable')) is not bool):
                raise ValueError(_ERROR)
            email = _go_trim(client.get('email'))
            if not email or email in declared:
                raise ValueError(_ERROR)
            declared[email] = client
        links, clients = [], []
        if relational:
            links = [dict(r) for r in db.execute('SELECT * FROM client_inbounds WHERE inbound_id=? ORDER BY client_id', (number,))]
            ids = [r['client_id'] for r in links]
            if (len(ids) > 128 or len(set(ids)) != len(ids)
                    or any(type(v) is not int or v <= 0 for v in ids)
                    or any(r.get('flow_override', '') not in ('', None) for r in links)):
                raise ValueError(_ERROR)
            for identity in ids:
                rows = db.execute('SELECT * FROM clients WHERE id=?', (identity,)).fetchall()
                if len(rows) != 1:
                    raise ValueError(_ERROR)
                client = dict(rows[0])
                if type(client['enable']) is not int or client['enable'] not in (0, 1):
                    raise ValueError(_ERROR)
                clients.append(client)
            current = {_go_trim(c['email']): bool(c['enable']) for c in clients}
            if len(current) != len(clients) or (embedded and current != {e: c['enable'] for e, c in declared.items()}):
                raise ValueError(_ERROR)
        else:
            current = {e: c['enable'] for e, c in declared.items()}
        active = sorted(e for e, enabled in current.items() if enabled)
        key, scope = _go_trim(settings.get('authSeed', '')), 0
        if active and not key:
            db.row_factory = None
            _schema(db, 'settings', {'key', 'value'}, {'id', 'key', 'value'}, 4096)
            secrets = db.execute("SELECT value FROM settings WHERE key='secret'").fetchall()
            if len(secrets) != 1 or type(secrets[0][0]) is not str or not secrets[0][0]:
                raise ValueError(_ERROR)
            key, scope = secrets[0][0], number
        user, password = _go_trim(settings.get('authUser', '')), _go_trim(settings.get('authPass', ''))
        if bool(user) != bool(password):
            raise ValueError(_ERROR)
        pairs = ([(user, password)] if user else []) + [_naive_auth(key, scope, email) for email in active]
        if not pairs or len({u for u, _ in pairs}) != len(pairs):
            raise ValueError(_ERROR)
        proof = {'inbound': {k: v for k, v in row.items() if k not in _TRAFFIC},
                 'clients': clients, 'links': links, 'derivation_key_sha256': _digest(key) if active else ''}
        return row, settings, pairs, _digest(proof)
    finally:
        db.close()


def _upstream(value):
    if re.search(r'%(?![0-9A-Fa-f]{2})', value):
        raise ValueError(_ERROR)
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != 'socks5' or parsed.hostname != '127.0.0.1' or parsed.path or parsed.query
            or parsed.fragment or not parsed.username or not parsed.password or parsed.port is None
            or not 1 <= parsed.port <= 65535 or value.count('@') != 1):
        raise ValueError(_ERROR)
    user = urllib.parse.unquote(parsed.username, errors='strict')
    password = urllib.parse.unquote(parsed.password, errors='strict')
    if any(ord(c) < 33 for c in user + password) or not user or not password:
        raise ValueError(_ERROR)
    return user, password, parsed.port


def _process_start(fs, prefix):
    if not fs.is_live and not fs.path(prefix + '/stat').exists():
        return None  # Минимальный синтетический /proc fixture.
    value = _proc_bytes(fs, prefix + '/stat')[0]
    closing = value.rfind(b') ')
    fields = value[closing + 2:].split() if closing >= 0 else []
    if len(fields) < 20 or not fields[19].isdigit() or int(fields[19]) <= 0:
        raise ValueError(_ERROR)
    return int(fields[19])


def _runtime(fs, upstream):
    matches = []
    processes = list(fs.path('/proc').iterdir())
    if len(processes) > 8192:
        raise ValueError(_ERROR)
    for proc in processes:
        if not proc.name.isdigit():
            continue
        prefix = '/proc/' + proc.name
        try:
            # LucX Xray должен принадлежать root; nginx/www-data и другие
            # пользователи не являются кандидатами и не блокируют discovery.
            owner = 0 if fs.is_live or os.name == 'nt' else os.geteuid()
            directory = proc.lstat()
            if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != owner:
                continue
            comm = _proc_bytes(fs, prefix + '/comm')
        except FileNotFoundError:
            continue
        if not re.fullmatch(rb'xray[A-Za-z0-9_.-]*\n?', comm[0]):
            continue
        process_start = _process_start(fs, prefix)
        command = _proc_bytes(fs, prefix + '/cmdline')
        argv = command[0].rstrip(b'\0').decode('utf-8').split('\0')
        options = [i for i, a in enumerate(argv) if a in ('-c', '-config', '--config')]
        if (len(options) != 1 or options[0] + 1 >= len(argv)
                or any(a.startswith(('-confdir', '--confdir')) for a in argv)):
            raise ValueError(_ERROR)
        config_name = argv[options[0] + 1]
        exe_name = argv[0]
        exe_link = cwd_link = ''
        if fs.is_live:
            exe_link = os.readlink(proc / 'exe')
            exe_name = exe_link
            if not config_name.startswith('/'):
                cwd_link = os.readlink(proc / 'cwd')
                config_name = str(PurePosixPath(cwd_link) / config_name)
        executable = _target(fs, exe_name)
        if not re.fullmatch(r'xray[A-Za-z0-9_.-]*', executable.name):
            raise ValueError(_ERROR)
        executable_before = executable.lstat()
        _trusted(executable_before, fs, executable=True)
        if fs.is_live and _metadata((proc / 'exe').stat())[:2] != _metadata(executable_before)[:2]:
            raise ValueError(_ERROR)
        config = _read_file(fs, config_name)
        document = _json_object(config[0].decode('utf-8'))
        inbounds = document.get('inbounds')
        if type(inbounds) is not list or len(inbounds) > 4096:
            raise ValueError(_ERROR)
        candidates = [r for r in inbounds if isinstance(r, dict) and r.get('port') == upstream[2]]
        if len(candidates) != 1:
            continue
        candidate = candidates[0]
        config_settings = candidate.get('settings', {})
        accounts = config_settings.get('accounts')
        if (candidate.get('protocol') != 'socks' or candidate.get('listen') != '127.0.0.1'
                or config_settings.get('auth') != 'password' or type(accounts) is not list
                or len(accounts) != 1 or not isinstance(accounts[0], dict)
                or (accounts[0].get('user'), accounts[0].get('pass')) != upstream[:2]):
            raise ValueError(_ERROR)
        if (_read_file(fs, config_name) != config or _proc_bytes(fs, prefix + '/comm') != comm
                or _proc_bytes(fs, prefix + '/cmdline') != command
                or _process_start(fs, prefix) != process_start
                or _metadata(executable.lstat()) != _metadata(executable_before)
                or fs.is_live and (os.readlink(proc / 'exe') != exe_link
                    or cwd_link and os.readlink(proc / 'cwd') != cwd_link)):
            raise ValueError(_ERROR)
        epoch = _digest({'pid': proc.name, 'process_start': process_start,
                         'executable': _metadata(executable_before)})
        matches.append((_digest({'config_sha256': hashlib.sha256(config[0]).hexdigest(),
            'pid': proc.name, 'process_start': process_start,
            'command_sha256': hashlib.sha256(command[0]).hexdigest(),
            'executable': _metadata(executable_before)}), epoch))
    if len(matches) != 1:
        raise ValueError(_ERROR)
    return matches[0]


def validate_source_binding(fs: TargetFS, db_path: str, inbound_id: int, text: str) -> dict:
    """Проверяет весь auth набор и endpoint; оригиналы и публичная сеть не пишутся."""
    try:
        if type(inbound_id) is not int or inbound_id <= 0 or (fs.is_live and os.name != 'posix'):
            raise ValueError(_ERROR)
        row, settings, pairs, database_sha = _database(fs, db_path, inbound_id)
        source = parse_naive_connect_source(text)
        if len(source.auth_pairs) != len(pairs) or set(source.auth_pairs) != set(pairs):
            raise ValueError(_ERROR)
        routed = settings.get('routeThroughXray', False)
        resistance = settings.get('probeResistance', False)
        if type(routed) is not bool or type(resistance) is not bool or resistance != source.probe_resistance:
            raise ValueError(_ERROR)
        bridge = _upstream(source.upstream) if source.upstream else None
        port = settings.get('routeXrayPort', 0)
        if (bool(bridge) != routed or routed and (type(port) is not int or port <= 0 or bridge[2] != port)):
            raise ValueError(_ERROR)
        rows = [_line_tokens(line.rstrip('\r')) for line in text.split('\n')]
        structural = []
        semantic = []
        auth_added = False
        for tokens in rows:
            if tokens and tokens[0] == 'upstream':
                structural.append('upstream socks5://lucx:' + 'A' * 24 + '@127.0.0.1:' + str(bridge[2]))
                semantic.append(['upstream', bridge[0], '127.0.0.1', bridge[2]])
            elif tokens == ['output', 'file', f'bin/tunnel/naive-{inbound_id}-data/access.json']:
                # LucX AccessLogPath: относительный bin/tunnel/<key>-data/access.json.
                # Только для проверки структуры: этот лог не открываем и не
                # переносим в managed copy. Исходное значение остаётся в proof.
                structural.append(f'output file /var/log/lucx-naive-source-{inbound_id}.json')
                semantic.append(tokens)
            else:
                # Строки исходника сохраняются для строгого Caddy lexer ниже.
                structural.append(None)
                if tokens and tokens[0] == 'basic_auth':
                    if not auth_added:
                        semantic.append(['basic_auth_digest', _digest(sorted(pairs))])
                        auth_added = True
                elif tokens:
                    semantic.append(tokens)
        actual_lines = text.split('\n')
        normalized = '\n'.join(replacement if replacement is not None else original
                               for replacement, original in zip(structural, actual_lines))
        native = parse_naive_native_source(normalized)
        listen = _go_trim(settings.get('listen', '')) or _go_trim(row['listen'] or '')
        expected_bind = '' if listen in ('', '0.0.0.0', '::') else str(ipaddress.ip_address(listen))
        domain = _go_trim(settings.get('domain', ''))
        if (type(row['port']) is not int or native.port != (row['port'] or 443)
                or native.bind_host != expected_bind or native.server_names != ((domain,) if domain else ())
                or native.cert_path != _go_trim(settings.get('certFile', ''))
                or native.key_path != _go_trim(settings.get('keyFile', ''))):
            raise ValueError(_ERROR)
        runtime_sha, process_epoch_sha = _runtime(fs, bridge) if bridge else ('', '')
        if _database(fs, db_path, inbound_id)[3] != database_sha:
            raise ValueError(_ERROR)
        return {'database_sha256': database_sha, 'semantic_sha256': _digest(semantic),
                'runtime_sha256': runtime_sha, 'process_epoch_sha256': process_epoch_sha}
    except NaivePolicyError:
        raise
    except Exception:  # noqa: BLE001 — ошибки parser/SQLite могут содержать секреты.
        raise ValueError(_ERROR) from None
