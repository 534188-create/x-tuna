"""Привязка текущих исходников Naive к TLS endpoint и владельцам sockets.

Не доказывает историческую загрузку Caddyfile либо выбранный outboundTag.
Функциональный CONNECT и участие bridge проверяются отдельным observer.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import ssl
import sys
import time
from contextlib import ExitStack

from .extended_decoys import classify_naive_connect_candidate
from .naive_bridge import _actor, _owned, _pin_actor, _same_actor, _tcp_inode
from .naive_frontend import parse_naive_connect_source, parse_naive_native_source
from .naive_probe_source import LucXNaiveCredentialSource, _capture
from .routing_profiles import routing_fingerprint
from .sqlite_snapshot import open_snapshot
from .staging_materials import _identity, _parent
from .vpn_probe_backend import _executable_hash, _listener_owner, _owner
from .vpn_probe_source import _MAX_FIELD, _json_object

_ERROR = 'Исходный backend Naive не подтверждён'
_CADDY_SHA256 = '9a8a4d2cf9dd14040086cf5f1762eb8b4304f1dbc0c85784d8bdf27c2587956b'


def _check(deadline):
    if time.monotonic() >= deadline:
        raise ValueError(_ERROR)


def _stable(actor):
    """R/S меняются при работе; starttime, netns и exe остаются обязательными."""
    info, namespace, executable = actor
    return (info.pid, info.starttime, info.pgrp, info.session, namespace, executable)


def _bridge_owner(port: int, deadline: float) -> int:
    return _listener_owner('127.0.0.1', port, deadline, bridge=True)


def _pair(cert_path, key_path, captures):
    """OpenSSL проверяет пару через удерживаемые O_NOFOLLOW fd, без записи."""
    with ExitStack() as stack:
        descriptors = []
        for path, capture in zip((cert_path, key_path), captures):
            parent, _, missing = stack.enter_context(_parent(path))
            if missing or parent is None:
                raise ValueError(_ERROR)
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                 dir_fd=parent)
            stack.callback(os.close, descriptor)
            if _identity(os.fstat(descriptor)) != capture[1][1]:
                raise ValueError(_ERROR)
            descriptors.append(descriptor)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*(f'/proc/self/fd/{fd}' for fd in descriptors), password=lambda: '')
        if any(_identity(os.fstat(fd)) != capture[1][1]
               for fd, capture in zip(descriptors, captures)):
            raise ValueError(_ERROR)


def _tls(host, port, name, pem, leaf, deadline, expected=None):
    before = _pin_actor(_listener_owner(host, port, deadline), _CADDY_SHA256, deadline)
    if expected is not None and not _same_actor(expected, before):
        raise ValueError(_ERROR)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=pem)
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    context.set_alpn_protocols(['h2'])
    _check(deadline)
    with (socket.create_connection((host, port), timeout=min(3, deadline - time.monotonic())) as raw,
          context.wrap_socket(raw, server_hostname=name) as stream):
        if stream.selected_alpn_protocol() != 'h2' or stream.getpeercert(binary_form=True) != leaf:
            raise ValueError(_ERROR)
        local, remote = stream.getsockname(), stream.getpeername()
        inode = _tcp_inode(remote, local, deadline)
        pid = _owner(inode, deadline)
        if expected is not None and expected[0].pid != pid:
            raise ValueError(_ERROR)
        actor = _pin_actor(pid, _CADDY_SHA256, deadline)
        if not _same_actor(before, actor):
            raise ValueError(_ERROR)
        _owned(actor, inode, deadline)
        if _tcp_inode(remote, local, deadline) != inode or _owner(inode, deadline) != pid:
            raise ValueError(_ERROR)
        _owned(actor, inode, deadline)
        return actor


class NativeNaiveSource:
    """Один provider хранит baseline; ошибка либо drift необратимо его закрывают."""

    def __init__(self, fs, manifest, audit, auth_source: LucXNaiveCredentialSource):
        try:
            if (sys.platform != 'linux' or not fs.is_live
                    or type(auth_source) is not LucXNaiveCredentialSource
                    or not auth_source._fs.is_live):
                raise ValueError(_ERROR)
            self._fs, self._auth = fs, auth_source
            self._manifest, self._audit = copy.deepcopy(manifest), copy.deepcopy(audit)
            self._failed = False
            self._entries = {}
            self._protocols = {p['inbound_id']: p for p in self._manifest['protocols']
                               if p.get('protocol') == 'naive' and p.get('enable', True) is True}
            if not 1 <= len(self._protocols) <= 128:
                raise ValueError(_ERROR)
            deadline = time.monotonic() + 30
            for number in self._protocols:
                entry = self._collect(number, deadline)
                if self._collect(number, deadline, entry)[0] != entry[0]:
                    raise ValueError(_ERROR)
                self._entries[number] = entry
        except Exception:  # noqa: BLE001 — TLS, SQLite и proc ошибки не раскрывают исходные данные.
            raise ValueError(_ERROR) from None

    def _settings(self, number, deadline):
        database = open_snapshot(self._fs, self._auth._db_path)
        try:
            database.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _MAX_FIELD)
            database.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 4096)
            database.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 256)
            steps = 0
            def progress():
                nonlocal steps
                steps += 1000
                return int(steps > 500000 or time.monotonic() >= deadline)
            database.set_progress_handler(progress, 1000)
            database.execute('PRAGMA query_only=ON')
            database.execute('PRAGMA trusted_schema=OFF')
            rows = database.execute('SELECT settings, listen, port FROM inbounds WHERE id=? LIMIT 2',
                                    (number,)).fetchall()
            if len(rows) != 1:
                raise ValueError(_ERROR)
            return _json_object(rows[0][0]), rows[0][1], rows[0][2]
        finally:
            database.close()

    def _collect(self, number, deadline, expected=None):
        from .naive_probes import NATIVE_XRAY_HASHES, NativeBackendBinding
        _check(deadline)
        protocol = self._protocols[number]
        credential = self._auth(protocol)
        if (credential is None or credential.profile_fingerprint != routing_fingerprint(
                protocol, self._manifest['network']['public_tcp_port'])):
            raise ValueError(_ERROR)
        route = classify_naive_connect_candidate(self._manifest, self._audit, number)
        source_path = self._fs.path(route['source_identity']['path'])
        source_capture = _capture(source_path)
        if any(route['source_identity'][key] != value for key, value in source_capture[2].items()):
            raise ValueError(_ERROR)
        native = parse_naive_native_source(source_capture[0].decode('utf-8'))
        source = parse_naive_connect_source(source_capture[0].decode('utf-8'))
        database_fields = self._settings(number, deadline)
        settings, listen, source_port = database_fields
        if type(listen) is not str:
            raise ValueError(_ERROR)
        source_host = '127.0.0.1' if listen == 'localhost' else listen.strip('[]')
        host = protocol.get('internal_host') or '127.0.0.1'
        if host == 'localhost':
            host = '127.0.0.1'
        host = host.strip('[]')
        if (native.port != protocol['internal_port'] or native.port != source_port
                or native.bind_host and native.bind_host != source_host
                or not native.bind_host and source_host not in {'', '0.0.0.0', '::'}
                or native.server_names and native.server_names != (route['backend_sni'],)):
            raise ValueError(_ERROR)
        backend = '127.0.0.1' if host in {'0.0.0.0', '::'} else host
        # IPv6 loopback без IPv4 mapping пока не входит в socket witness.
        if ipaddress.ip_address(backend).version != 4:
            raise ValueError(_ERROR)
        if (settings.get('useAcme', False) is not False
                or settings.get('certFile') != native.cert_path or settings.get('keyFile') != native.key_path
                or settings.get('domain') != route['backend_sni']):
            raise ValueError(_ERROR)
        paths = (source_path, self._fs.path(native.cert_path), self._fs.path(native.key_path))
        captures = (source_capture, _capture(paths[1]), _capture(paths[2]))
        if any(capture[2]['uid'] != 0 or capture[2]['mode'] & 0o022 for capture in captures):
            raise ValueError(_ERROR)
        if captures[2][2]['mode'] & 0o077 or any(len(c[0]) > 65536 for c in captures[1:]):
            raise ValueError(_ERROR)
        pem = captures[1][0].decode('ascii')
        certificates = re.findall(r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----', pem)
        if not certificates or re.sub(r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----', '', pem).strip():
            raise ValueError(_ERROR)
        leaf = ssl.PEM_cert_to_DER_cert(certificates[0])
        _pair(paths[1], paths[2], captures[1:])
        caddy = _tls(backend, native.port, route['backend_sni'], pem, leaf, deadline,
                     None if expected is None else expected[1])
        bridge, xray, xray_hash = 0, None, ''
        if source.upstream:
            bridge = int(source.upstream.rsplit(':', 1)[1])
            pid = _bridge_owner(bridge, deadline)
            if pid == caddy[0].pid:
                raise ValueError(_ERROR)
            xray_hash = _executable_hash(pid, deadline) if expected is None else expected[0].xray_sha256
            if xray_hash not in NATIVE_XRAY_HASHES:
                raise ValueError(_ERROR)
            xray = _pin_actor(pid, xray_hash, deadline)
            if expected is not None and (expected[2] is None or not _same_actor(expected[2], xray)):
                raise ValueError(_ERROR)
        if (any(_capture(path)[1] != capture[1] for path, capture in zip(paths, captures))
                or self._settings(number, deadline) != database_fields
                or self._auth(protocol) != credential
                or not _same_actor(caddy, _actor(caddy[0].pid, deadline))
                or xray is not None and (not _same_actor(xray, _actor(xray[0].pid, deadline))
                                        or _bridge_owner(bridge, deadline) != xray[0].pid)):
            raise ValueError(_ERROR)
        material = (credential.profile_fingerprint, credential.policy_fingerprint,
                    tuple(c[1] for c in captures), _stable(caddy), None if xray is None else _stable(xray),
                    xray_hash, bridge, backend, native.port, route['backend_sni'], native.probe_resistance)
        fingerprint = 'sha256:' + hashlib.sha256(json.dumps(material, sort_keys=True,
            separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()
        binding = NativeBackendBinding(profile_fingerprint=credential.profile_fingerprint,
            auth_policy_fingerprint=credential.policy_fingerprint, binding_fingerprint=fingerprint,
            caddy_pid=caddy[0].pid, caddy_sha256=_CADDY_SHA256,
            xray_pid=0 if xray is None else xray[0].pid, xray_sha256=xray_hash, bridge_port=bridge,
            probe_resistance=native.probe_resistance, backend_address=backend, backend_port=native.port,
            backend_sni=route['backend_sni'], backend_ca_pem=pem)
        _check(deadline)
        return binding, caddy, xray

    def __call__(self, protocol):
        try:
            if self._failed or type(protocol) is not dict:
                return None
            number = protocol.get('inbound_id')
            if type(number) is not int or number not in self._protocols:
                return None
            shared = self._manifest['network']['public_tcp_port']
            if routing_fingerprint(protocol, shared) != routing_fingerprint(self._protocols[number], shared):
                return None
            if self._auth(protocol) is None:
                raise ValueError(_ERROR)
            expected = self._entries[number]
            observed = self._collect(number, time.monotonic() + 20, expected)
            if observed[0] != expected[0]:
                raise ValueError(_ERROR)
            return expected[0]
        except Exception:  # noqa: BLE001 — отсутствие proof, без исходных путей и секретов.
            self._failed = True
            return None
