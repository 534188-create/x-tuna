"""Функциональный кандидат на временных loopback frontend до commit.

Родитель владеет файлами, секретным источником и expected binding; отдельный
worker владеет процессной группой. Ни один результат не загружается из state.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import socket
import sys
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .decoy_health import (
    BrowserDialAddress,
    _probe_protocol,
    _vpn_targets,
    observe_decoy_capabilities,
    observe_vpn_capabilities,
    vpn_acceptance_summary,
)
from .naive_probes import NAIVE_SHA256, NaiveProbeContext, NaiveProbeCredential, NaiveVPNObserver, _secret
from .models import Audit
from .discovery import audit_system
from .naive_probe_source import LucXNaiveCredentialSource
from .naive_frontend import supports_native_decoy
from .render_runtime import ListenerKey, RenderRuntime, SocketAddress, runtime_layout
from .renderers import frontend_listener_inventory, render_haproxy, render_nginx_decoys
from .routing_profiles import routing_fingerprint
from .runner import Runner
from .staging_binding import (
    CandidateBinding,
    StagingReceipt,
    _canonical,
    _digest,
    create_candidate_binding,
    staging_acceptance_summary,
)
from .staging_eligibility import staging_eligibility_errors
from .staging_integrity import StagedCandidateSeal
from .staging_materials import StagingSourceFence, create_staging_materials
from .staging_native import NativeStagingSet, decode_native_payload
from .staging_processes import (
    ForegroundSession,
    FrontendSpec,
    ServiceIdentity,
    _file_identity,
    _open_regular,
    _verified_binary,
)
from .staging_workspace import create_staging_workspace
from .targetfs import TargetFS
from .vpn_probe_registry import NAIVE_PROBE_PATH, XRAY_PROBE_PATH
from .vpn_probe_source import LucXXrayCredentialSource
from .vpn_probes import (
    XRAY_SHA256,
    XrayProbeContext,
    XrayProbeCredential,
    XrayVPNObserver,
)

_ERROR = 'Функциональный staging не подтвердил полный неизменный кандидат'
_CLEANUP_ERROR = 'Очистка собственного staging workspace не подтверждена'
_FINGERPRINT = re.compile(r'sha256:[0-9a-f]{64}\Z')
_MAX_IPC = 8 * 1024 * 1024
_WORKER_TIMEOUT = 240
_ROLES = frozenset({'haproxy', 'nginx', 'xray', 'curl'})


def _decode_material(payload: Any) -> dict | None:
    if payload is None:
        return None
    if type(payload) is not list or len(payload) > 128:
        raise ValueError(_ERROR)
    result = {}
    for row in payload:
        if (type(row) is not dict or set(row) != {'inbound_id', 'material'}
                or type(row['inbound_id']) is not int or row['inbound_id'] <= 0
                or row['inbound_id'] in result or type(row['material']) is not dict):
            raise ValueError(_ERROR)
        result[row['inbound_id']] = json.loads(_canonical(row['material']))
    return result


def _material_payload(material: Any) -> list | None:
    if material is None:
        return None
    if type(material) is not dict or len(material) > 128:
        raise ValueError(_ERROR)
    rows = []
    for key, value in material.items():
        if type(key) is str and re.fullmatch('[1-9][0-9]{0,9}', key):
            key = int(key)
        rows.append({'inbound_id': key, 'material': value})
    decoded = _decode_material(rows)
    return [{'inbound_id': key, 'material': decoded[key]} for key in sorted(decoded)]


def _has_naive(manifest: dict) -> bool:
    return any(p.get('protocol') == 'naive' and p.get('enable') is not False
               and p.get('exposure') != 'none' for p in manifest['protocols'])


def _material_audit(material: dict | None) -> Audit:
    files = []
    for value in (material or {}).values():
        if 'naive_caddyfile_text' not in value:
            continue
        metadata = value['naive_source_metadata']
        files.append({**{key: metadata[key] for key in ('path', 'kind', 'mode', 'uid', 'gid', 'sha256')},
                      'capabilities': {'forward_proxy': True,
                                       'native_decoy': supports_native_decoy(value['naive_caddyfile_text'])}})
    return Audit(naive_caddyfile={'files': files})


def _target_key(target: dict) -> str:
    return _digest(target['identity'])


def _valid_credential(value: Any, protocol: dict, port: int) -> bool:
    try:
        if type(protocol) is not dict or type(port) is not int or not 1 <= port <= 65535:
            return False
        if protocol.get('protocol') in {'vless', 'vmess'}:
            auth_valid = (type(value) is XrayProbeCredential and type(value.user_id) is str
                          and str(uuid.UUID(value.user_id)) == value.user_id)
        elif protocol.get('protocol') == 'naive':
            auth_valid = (type(value) is NaiveProbeCredential
                          and _secret(value.username) and _secret(value.password))
        else:
            return False
        return (auth_valid and type(value.profile_fingerprint) is str
            and _FINGERPRINT.fullmatch(value.profile_fingerprint) is not None
            and value.profile_fingerprint == routing_fingerprint(protocol, port)
            and type(value.ca_pem) is str and len(value.ca_pem.encode('utf-8')) <= 65536
            and type(value.policy_fingerprint) is str and _FINGERPRINT.fullmatch(value.policy_fingerprint) is not None)
    except (ValueError, TypeError, AttributeError):
        return False


def _credential_protocols(manifest: dict) -> dict[str, dict]:
    """Полный текущий набор endpoints, без выбора family из приватного payload."""
    targets, errors = _vpn_targets(manifest)
    port = manifest['network']['public_tcp_port']
    if errors or not targets or len(targets) > 128 or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError(_ERROR)
    protocols = {}
    for target in targets:
        key = _target_key(target)
        protocol = _probe_protocol(target, 'staging')
        if key in protocols or protocol.get('protocol') not in {'vless', 'vmess', 'naive'}:
            raise ValueError(_ERROR)
        protocols[key] = protocol
    return protocols


def _decode_credentials(payload: list[dict], manifest: dict) -> dict[str, XrayProbeCredential | NaiveProbeCredential]:
    """Строгий приватный IPC; тип определяется protocol текущего endpoint."""
    try:
        protocols = _credential_protocols(manifest)
        if type(payload) is not list or len(payload) != len(protocols):
            raise ValueError(_ERROR)
        credentials = {}
        for row in payload:
            if (type(row) is not dict or type(row.get('key')) is not str
                    or row['key'] not in protocols or row['key'] in credentials):
                raise ValueError(_ERROR)
            protocol = protocols[row['key']]
            naive = protocol['protocol'] == 'naive'
            schema = {'key', 'type', 'credential'} if naive else {'key', 'credential'}
            if set(row) != schema or (naive and row['type'] != 'naive'):
                raise ValueError(_ERROR)
            credential_type = NaiveProbeCredential if naive else XrayProbeCredential
            data = row['credential']
            if type(data) is not dict or set(data) != {item.name for item in fields(credential_type)}:
                raise ValueError(_ERROR)
            value = credential_type(**data)
            if not _valid_credential(value, protocol, manifest['network']['public_tcp_port']):
                raise ValueError(_ERROR)
            credentials[row['key']] = value
        if set(credentials) != set(protocols):
            raise ValueError(_ERROR)
        return credentials
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ValueError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class StagingCredentialSet:
    """Выбранные credentials всех endpoints; callable сам не доказывает DB policy."""
    entries: Mapping[str, XrayProbeCredential | NaiveProbeCredential]
    _source: Callable = field(repr=False)

    @classmethod
    def capture(cls, manifest: dict, source: Callable) -> StagingCredentialSet:
        try:
            protocols = _credential_protocols(manifest)
            if not callable(source):
                raise TypeError(_ERROR)
            port = manifest['network']['public_tcp_port']
            selected = {}
            for key, protocol in protocols.items():
                credential = source(copy.deepcopy(protocol))
                if not _valid_credential(credential, protocol, port):
                    raise ValueError(_ERROR)
                selected[key] = credential
            return cls(MappingProxyType(selected), source)
        except Exception:  # noqa: BLE001 — источник может содержать секрет в исключении.
            raise ValueError(_ERROR) from None

    def verify(self, manifest: dict) -> None:
        fresh = type(self).capture(manifest, self._source)
        if dict(fresh.entries) != dict(self.entries):
            raise ValueError(_ERROR)

    def private_payload(self) -> list[dict]:
        """Только stdin изолированного worker; запрещено помещать в отчёты."""
        result = []
        for key, value in self.entries.items():
            if type(value) not in {XrayProbeCredential, NaiveProbeCredential}:
                raise ValueError(_ERROR)
            row = {'key': key}
            if type(value) is NaiveProbeCredential:
                row['type'] = 'naive'
            row['credential'] = {item.name: getattr(value, item.name) for item in fields(value)}
            result.append(row)
        return result


def capture_lucx_staging_credentials(fs: TargetFS, manifest: dict, *,
                                     audit: Audit | None = None) -> StagingCredentialSet:
    """Полный набор источников из БД; не разрешает запуск или применение Naive.

    Источник Naive фиксируется один раз по свежему audit. Повторная сверка
    всего набора выявляет drift первого семейства при чтении следующего.
    """
    try:
        current = copy.deepcopy(manifest)
        protocols = _credential_protocols(current)
        families = {item['protocol'] for item in protocols.values()}
        if 'naive' in families and type(audit) is not Audit:
            raise ValueError(_ERROR)
        db_path, port = current['lucx']['db_path'], current['network']['public_tcp_port']
        naive = LucXNaiveCredentialSource(fs, db_path, current, audit) if 'naive' in families else None
        xray = LucXXrayCredentialSource(fs, db_path, port) if families & {'vless', 'vmess'} else None

        def source(protocol):
            if protocol.get('protocol') == 'naive' and naive is not None:
                return naive(protocol)
            if protocol.get('protocol') in {'vless', 'vmess'} and xray is not None:
                return xray(protocol)
            return None

        selected = StagingCredentialSet.capture(current, source)
        selected.verify(current)
        return selected
    except Exception:  # noqa: BLE001 — не раскрываем причины из БД и исходного Caddyfile.
        raise ValueError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class StagingTools:
    """Пути задаёт только код; hash фиксирует установленный инструмент на этот run."""
    binaries: Mapping[str, tuple[Path, str]]
    identity: ServiceIdentity

    def __post_init__(self) -> None:
        if (not isinstance(self.binaries, Mapping) or not _ROLES <= set(self.binaries) <= _ROLES | {'naive'}
                or type(self.identity) is not ServiceIdentity):
            raise ValueError(_ERROR)
        copied = dict(self.binaries)
        if any(type(value) is not tuple or len(value) != 2 or not isinstance(value[0], Path)
               or not value[0].is_absolute() or type(value[1]) is not str
               or re.fullmatch(r'[0-9a-f]{64}', value[1]) is None for value in copied.values()):
            raise ValueError(_ERROR)
        if copied['xray'][1] != XRAY_SHA256 or 'naive' in copied and copied['naive'][1] != NAIVE_SHA256:
            raise ValueError(_ERROR)
        object.__setattr__(self, 'binaries', MappingProxyType(copied))

    def verify(self) -> None:
        for path, digest in self.binaries.values():
            descriptor = _verified_binary(path, digest, time.monotonic() + 10)
            os.close(descriptor)

    def payload(self) -> dict:
        return {role: {'path': str(path), 'sha256': digest} for role, (path, digest) in self.binaries.items()}


def _snapshot_binary(path: Path) -> str:
    descriptor = _open_regular(path)
    try:
        info = os.fstat(descriptor)
        if (info.st_uid != 0 or info.st_mode & 0o6022 or not info.st_mode & 0o111
                or not 0 < info.st_size <= 256 * 1024 * 1024):
            raise ValueError(_ERROR)
        digest, total, deadline = hashlib.sha256(), 0, time.monotonic() + 10
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > 256 * 1024 * 1024 or time.monotonic() >= deadline:
                raise ValueError(_ERROR)
            digest.update(chunk)
        if _file_identity(info) != _file_identity(os.fstat(descriptor)):
            raise ValueError(_ERROR)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _installed_haproxy_path(runner: Runner) -> Path:
    """Использует effective ExecStart, включая согласованный systemd drop-in.

    Наличие сохранённого пакетного бинарника не разрешает проверять им новый
    runtime. Неизвестные wrappers и неоднозначные команды требуют отдельного adapter.
    """
    try:
        result = runner.run_bounded(['/usr/bin/systemctl', 'show', 'haproxy.service',
            '--property=ExecStart', '--value'], timeout=5, max_output_bytes=8192,
            check=False, inherit_env=False)
        value = result.stdout.strip()
        match = re.fullmatch(r'\{ path=(/usr/(?:local/)?sbin/haproxy) ; argv\[\]=[^\r\n]* \}', value)
        if result.returncode or match is None or value.count('{ path=') != 1:
            raise ValueError(_ERROR)
        return Path(match[1])
    except Exception:
        raise ValueError(_ERROR) from None


def installed_staging_tools(*, include_naive: bool = False) -> StagingTools:
    import pwd
    account = pwd.getpwnam('haproxy')
    paths = {'haproxy': _installed_haproxy_path(Runner()), 'nginx': Path('/usr/sbin/nginx'),
             'xray': Path(XRAY_PROBE_PATH), 'curl': Path('/usr/bin/curl')}
    if include_naive:
        paths['naive'] = Path(NAIVE_PROBE_PATH)
    tools = StagingTools({role: (path, _snapshot_binary(path)) for role, path in paths.items()},
                         ServiceIdentity(account.pw_uid, account.pw_gid))
    tools.verify()
    return tools


@dataclass(frozen=True, slots=True, repr=False)
class StagingPreflight:
    tools: StagingTools
    credentials: StagingCredentialSet
    packages_ready: bool = False
    native_sources: NativeStagingSet | None = field(default=None, repr=False)
    routing_material_sha256: str = field(default_factory=lambda: _digest(None))
    echo_address: str = field(default='127.0.0.1', repr=False)

    def verify(self, manifest: dict, *, routing_material: Any = None) -> None:
        from .vpn_probe_backend import valid_echo_address
        if (staging_eligibility_errors(manifest, packages_ready=self.packages_ready, routing_material=routing_material)
                or _digest(_material_payload(routing_material)) != self.routing_material_sha256
                or _has_naive(manifest) != (self.native_sources is not None)
                or self.echo_address != '127.0.0.1' and not valid_echo_address(self.echo_address)):
            raise ValueError(_ERROR)
        if self.native_sources is not None:
            if type(self.native_sources) is not NativeStagingSet or 'naive' not in self.tools.binaries:
                raise ValueError(_ERROR)
            if self.echo_address != self.native_sources.echo_address:
                raise ValueError(_ERROR)
            self.native_sources.verify(manifest)
        self.credentials.verify(manifest)
        self.tools.verify()


def prepare_functional_staging(fs: TargetFS, runner: Runner, manifest: dict, *,
                               packages_ready: bool = False, audit: Audit | None = None,
                               routing_material: Any = None) -> StagingPreflight:
    """Только чтение до backup: запрещено устанавливать инструменты ради пробы."""
    try:
        if (sys.platform != 'linux' or os.geteuid() != 0 or runner.dry_run
                or staging_eligibility_errors(manifest, packages_ready=packages_ready, routing_material=routing_material)):
            raise ValueError(_ERROR)
        native = None
        from .vpn_probe_backend import valid_echo_address
        audit = audit if audit is not None else audit_system(fs.root, manifest['lucx']['db_path'])
        if type(audit) is not Audit or type(audit.public_addresses) is not list:
            raise ValueError(_ERROR)
        echo_address = next((address for address in audit.public_addresses if valid_echo_address(address)), None)
        if echo_address is None:
            raise ValueError(_ERROR)
        if _has_naive(manifest):
            native = NativeStagingSet.capture(fs, manifest, audit)
        tools = installed_staging_tools(include_naive=True) if native is not None else installed_staging_tools()
        source = LucXXrayCredentialSource(fs, manifest['lucx']['db_path'], manifest['network']['public_tcp_port'])
        def selected(protocol):
            return native.credential(protocol) if native is not None and protocol['protocol'] == 'naive' else source(protocol)
        result = StagingPreflight(tools, StagingCredentialSet.capture(manifest, selected), packages_ready,
                                  native, _digest(_material_payload(routing_material)), echo_address)
        result.verify(manifest, routing_material=routing_material)
        return result
    except Exception:  # noqa: BLE001 — только безопасная причина, без source payload.
        raise ValueError(_ERROR) from None


def _layout(runtime: RenderRuntime) -> dict:
    return runtime_layout(runtime)


def _decode_runtime(data: dict, expected_keys) -> RenderRuntime:
    """Строгий приватный IPC: повторные роли не схлопываются в dict."""
    if (type(data) is not dict
            or set(data) != {'listeners', 'paths', 'foreground', 'suppress_system_log'}
            or type(data['listeners']) not in {list, tuple}
            or data['foreground'] is not True or data['suppress_system_log'] is not True):
        raise ValueError(_ERROR)
    listeners = {}
    for row in data['listeners']:
        if type(row) not in {list, tuple} or len(row) not in {4, 5}:
            raise ValueError(_ERROR)
        role, identity, host, port = row[:4]
        ingress_port = row[4] if len(row) == 5 else 0
        # Пятое поле имеет единственное представление: ненулевой split ingress.
        if len(row) == 5 and (type(ingress_port) is not int or ingress_port == 0):
            raise ValueError(_ERROR)
        key = ListenerKey(role, identity, ingress_port)
        if key in listeners:
            raise ValueError(_ERROR)
        listeners[key] = SocketAddress(host, port)
    runtime = RenderRuntime(listeners, data['paths'], foreground=True, suppress_system_log=True)
    if set(runtime.listeners) != set(expected_keys):
        raise ValueError(_ERROR)
    return runtime


def _nginx_wrapper(fragment: str, mime: Path, runtime_root: Path) -> bytes:
    lines = ['error_log stderr warn;', f'pid {runtime_root}/nginx.pid;', 'events {}', 'http {',
             f'include {mime};', 'access_log off;']
    for directive in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'):
        lines.append(f'{directive}_temp_path {runtime_root}/{directive};')
    return ('\n'.join(lines) + '\n' + fragment + '\n}\n').encode('utf-8')


def _json(value: str) -> Any:
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(_ERROR)
            result[key] = item
        return result
    if type(value) is not str or len(value.encode('utf-8')) > _MAX_IPC:
        raise ValueError(_ERROR)
    return json.loads(value, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError(_ERROR)))


def _decode_worker_result(payload: str, expected: CandidateBinding, manifest: dict | None = None) -> StagingReceipt:
    try:
        result = _json(payload)
        direct_required = type(expected) is CandidateBinding and (expected.native_sources_sha256 != _digest(None)
                          or expected.echo_address_sha256 != _digest('127.0.0.1'))
        if (type(expected) is not CandidateBinding or type(result) is not dict
                or set(result) != {'ok', 'binding', 'browser_rows', 'vpn_rows', 'cleanup_complete',
                                   'listeners_verified', 'runtime_verified'} | ({'direct_rows'} if direct_required else set())
                or result['ok'] is not True or result['binding'] != expected.fingerprint):
            raise ValueError(_ERROR)
        if direct_required:
            rows = result['direct_rows']
            if (type(manifest) is not dict or _digest(manifest) != expected.manifest_sha256
                    or type(rows) is not list or not rows or len(rows) > 4096
                    or any(type(row) is not dict or row.get('candidate_fingerprint') != expected.fingerprint for row in rows)):
                raise ValueError(_ERROR)
            summary = vpn_acceptance_summary(manifest, rows, phase='direct')
            if summary.get('complete') is not True or summary.get('required_endpoints', 0) <= 0:
                raise ValueError(_ERROR)
        return StagingReceipt(expected, result['browser_rows'], result['vpn_rows'],
                              result['cleanup_complete'], False, result['listeners_verified'], result['runtime_verified'])
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ValueError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedStaging:
    binding: CandidateBinding
    summary: Mapping[str, Any]
    _sources: StagingSourceFence
    _credentials: StagingCredentialSet
    _tools: StagingTools
    _native: NativeStagingSet | None = field(default=None, repr=False)

    def verify(self, fs: TargetFS, manifest: dict, generated: dict, staged: dict, *,
               staged_seal: StagedCandidateSeal, routing_snapshot: dict, routing_material: Any = None) -> None:
        if (_digest(manifest) != self.binding.manifest_sha256
                or _digest(routing_snapshot) != self.binding.routing_snapshot_sha256
                or staged_seal.digest != self.binding.staged_candidate_sha256):
            raise ValueError(_ERROR)
        staged_seal.verify(fs, manifest, generated, staged, self.binding.run_id)
        self._sources.verify(manifest, generated, routing_material=routing_material)
        self._credentials.verify(manifest)
        native_payload = None
        if self._native is not None:
            self._native.verify(manifest)
            native_payload = self._native.private_payload()
        if (_digest(native_payload) != self.binding.native_sources_sha256
                or _digest(_material_payload(routing_material)) != self.binding.routing_material_sha256):
            raise ValueError(_ERROR)
        self._tools.verify()


def run_functional_staging(fs: TargetFS, runner: Runner, manifest: dict, generated: dict,
                           staged: dict, run_id: str, *, staged_seal: StagedCandidateSeal,
                           routing_snapshot: dict, routing_material: Any = None,
                           tools: StagingTools | None = None, credential_source: Callable | None = None,
                           temporary_parent: Path | None = None, browser_ca_source: str | None = None,
                           preflight: StagingPreflight | None = None,
                           native_sources: NativeStagingSet | None = None,
                           echo_address: str | None = None) -> VerifiedStaging:
    """Code-owned overrides нужны Linux fixture; CLI/manifest их не предоставляют."""
    workspace = materials = None
    try:
        if preflight is not None and type(preflight) is not StagingPreflight:
            raise ValueError(_ERROR)
        packages_ready = preflight.packages_ready if preflight is not None else False
        if (sys.platform != 'linux' or os.geteuid() != 0 or runner.dry_run
                or staging_eligibility_errors(manifest, packages_ready=packages_ready, routing_material=routing_material)
                or type(staged_seal) is not StagedCandidateSeal):
            raise ValueError(_ERROR)
        staged_seal.verify(fs, manifest, generated, staged, run_id)
        if preflight is not None:
            if tools is not None or credential_source is not None or native_sources is not None or echo_address is not None:
                raise ValueError(_ERROR)
            preflight.verify(manifest, routing_material=routing_material)
            selected_tools, credentials = preflight.tools, preflight.credentials
            native_sources = preflight.native_sources
            echo_address = preflight.echo_address
        else:
            selected_tools = tools if tools is not None else installed_staging_tools()
            selected_tools.verify()
            source = credential_source if credential_source is not None else LucXXrayCredentialSource(
                fs, manifest['lucx']['db_path'], manifest['network']['public_tcp_port'])
            credentials = StagingCredentialSet.capture(manifest, source)
        if _has_naive(manifest) != (native_sources is not None):
            raise ValueError(_ERROR)
        native_payload = None
        if native_sources is not None:
            if type(native_sources) is not NativeStagingSet or 'naive' not in selected_tools.binaries:
                raise ValueError(_ERROR)
            native_sources.verify(manifest)
            native_payload = native_sources.private_payload()
            if echo_address is not None and echo_address != native_sources.echo_address:
                raise ValueError(_ERROR)
            echo_address = native_sources.echo_address
        echo_address = echo_address if echo_address is not None else '127.0.0.1'
        from .vpn_probe_backend import valid_echo_address
        if echo_address != '127.0.0.1' and not valid_echo_address(echo_address):
            raise ValueError(_ERROR)
        materials = create_staging_materials(fs, manifest, generated, routing_material=routing_material,
                                            temporary_parent=temporary_parent)
        materials.prepare_read_access(selected_tools.identity.uid, selected_tools.identity.gid)
        workspace = create_staging_workspace(selected_tools.identity, temporary_parent=temporary_parent)
        reservations = []
        try:
            listeners = {}
            for key in frontend_listener_inventory(manifest, routing_material=routing_material):
                stream = socket.socket()
                reservations.append(stream)
                stream.bind(('127.0.0.1', 0))
                listeners[key] = SocketAddress('127.0.0.1', stream.getsockname()[1])
            runtime = RenderRuntime(listeners, materials.paths, foreground=True, suppress_system_log=True)
            configs = {'haproxy': render_haproxy(manifest, routing_material=routing_material, runtime=runtime).encode('utf-8'),
                       'nginx': _nginx_wrapper(render_nginx_decoys(manifest, runtime=runtime,
                           routing_material=routing_material), materials.mime_path, workspace.runtime_root)}
            workspace.write_configs(configs)
            material_payload = _material_payload(routing_material)
            binding = create_candidate_binding(manifest, run_id=run_id, staged_seal=staged_seal,
                routing_snapshot=routing_snapshot, runtime_configs=configs, runtime=runtime,
                material_snapshot_digest=materials.snapshot_digest, toolchain=selected_tools.payload(),
                native_sources=native_payload, routing_material=material_payload, echo_address=echo_address)
            request = {'manifest': manifest, 'packages_ready': packages_ready, 'runtime': _layout(runtime), 'binding': {
                item.name: getattr(binding, item.name) for item in fields(binding)},
                'toolchain': selected_tools.payload(), 'identity': {'uid': selected_tools.identity.uid, 'gid': selected_tools.identity.gid},
                'configs': {role: str(path) for role, path in workspace.config_paths.items()},
                'config_root': str(workspace.config_root), 'credentials': credentials.private_payload(),
                'native_sources': native_payload, 'routing_material': material_payload, 'echo_address': echo_address,
                'browser_ca': materials.paths[browser_ca_source] if browser_ca_source is not None else None}
            encoded = _canonical(request).decode('ascii')
            workspace.verify_configs()
            materials.verify_copies()
        finally:
            for stream in reservations:
                stream.close()
        bootstrap = ('import sys,runpy;sys.path.insert(0,sys.argv[1]);'
            'sys.argv=["x-tuna-staging","--worker"];'
            'runpy.run_module("lucx_post_configurator.staging_probes",run_name="__main__")')
        completed = runner.run_bounded([sys.executable, '-I', '-S', '-c', bootstrap,
            str(Path(__file__).absolute().parent.parent)], input_text=encoded, timeout=_WORKER_TIMEOUT,
            max_output_bytes=_MAX_IPC, isolate_process_group=True, inherit_env=False, check=False)
        if completed.returncode:
            raise ValueError(_ERROR)
        receipt = _decode_worker_result(completed.stdout, binding, manifest)
        workspace.verify_configs()
        materials.verify_copies()
        source_fence = materials.source_fence()
        credentials.verify(manifest)
        if native_sources is not None:
            native_sources.verify(manifest)
            if _digest(native_sources.private_payload()) != binding.native_sources_sha256:
                raise ValueError(_ERROR)
        selected_tools.verify()
        staged_seal.verify(fs, manifest, generated, staged, run_id)
        workspace.cleanup()
        if not workspace.cleanup_complete:
            raise ValueError(_CLEANUP_ERROR)
        materials.cleanup()
        verified_receipt = StagingReceipt(binding, receipt.browser_rows, receipt.vpn_rows,
            receipt.cleanup_complete, True, receipt.listeners_verified, receipt.runtime_verified)
        summary = staging_acceptance_summary(manifest, verified_receipt, expected_binding=binding,
                                              audit=_material_audit(routing_material))
        if summary.get('candidate_verified') is not True:
            raise ValueError(_ERROR)
        if native_sources is not None or echo_address != '127.0.0.1':
            summary['direct_verified'] = True
        result = VerifiedStaging(binding, MappingProxyType(summary), source_fence, credentials, selected_tools, native_sources)
        result.verify(fs, manifest, generated, staged, staged_seal=staged_seal,
                      routing_snapshot=routing_snapshot, routing_material=routing_material)
        return result
    except Exception:  # noqa: BLE001 — ни source payload, ни daemon output не публикуются.
        raise ValueError(_ERROR) from None
    finally:
        failed = False
        for owner in (workspace, materials):
            if owner is not None:
                try:
                    owner.cleanup()
                except Exception:  # noqa: BLE001 — попытаться очистить также второго владельца.
                    failed = True
        if failed:
            raise ValueError(_CLEANUP_ERROR) from None


class _ProbeRunner(Runner):
    def __init__(self, curl: Path):
        super().__init__()
        self._curl = curl

    def run_bounded(self, args, **kwargs):
        args = list(args)
        if args and args[0] == 'curl':
            args[0] = str(self._curl)
        kwargs['inherit_env'] = False
        return super().run_bounded(args, **kwargs)


def _config_hash(path: Path) -> str:
    descriptor = _open_regular(path)
    try:
        before = os.fstat(descriptor)
        if before.st_size > 4 * 1024 * 1024 or before.st_nlink != 1:
            raise ValueError(_ERROR)
        data = os.read(descriptor, 4 * 1024 * 1024 + 1)
        if len(data) != before.st_size or _file_identity(before) != _file_identity(os.fstat(descriptor)):
            raise ValueError(_ERROR)
        return hashlib.sha256(data).hexdigest()
    finally:
        os.close(descriptor)


def _worker(request: dict) -> dict:
    try:
        if (sys.platform != 'linux' or os.geteuid() != 0 or os.getpid() != os.getpgrp()
                or os.getpid() != os.getsid(0) or type(request) is not dict):
            raise ValueError(_ERROR)
        manifest = request['manifest']
        material_payload = request.get('routing_material')
        material = _decode_material(material_payload)
        native_payload = request.get('native_sources')
        echo_address = request.get('echo_address', '127.0.0.1')
        from .vpn_probe_backend import valid_echo_address
        if echo_address != '127.0.0.1' and not valid_echo_address(echo_address):
            raise ValueError(_ERROR)
        if (staging_eligibility_errors(manifest, packages_ready=request['packages_ready'], routing_material=material)
                or _has_naive(manifest) != (native_payload is not None)):
            raise ValueError(_ERROR)
        runtime = _decode_runtime(request['runtime'], frontend_listener_inventory(manifest, routing_material=material))
        binding_data = request['binding']
        binding = CandidateBinding(**{item.name: binding_data[item.name] for item in fields(CandidateBinding) if item.init})
        if binding_data != {item.name: getattr(binding, item.name) for item in fields(binding)}:
            raise ValueError(_ERROR)
        tools = StagingTools({role: (Path(value['path']), value['sha256']) for role, value in request['toolchain'].items()},
                             ServiceIdentity(**request['identity']))
        configs = {role: Path(path) for role, path in request['configs'].items()}
        hashes = {role: _config_hash(path) for role, path in configs.items()}
        if (set(configs) != {'haproxy', 'nginx'} or _digest(hashes) != binding.runtime_config_sha256
                or _digest(manifest) != binding.manifest_sha256 or _digest(_layout(runtime)) != binding.layout_sha256
                or _digest(tools.payload()) != binding.toolchain_sha256
                or _digest(material_payload) != binding.routing_material_sha256
                or _digest(native_payload) != binding.native_sources_sha256
                or _digest(echo_address) != binding.echo_address_sha256):
            raise ValueError(_ERROR)
        tools.verify()
        credentials = _decode_credentials(request['credentials'], manifest)
        native_bindings, native_echo = ({}, '') if native_payload is None else decode_native_payload(native_payload, manifest)
        if native_bindings and echo_address != native_echo:
            raise ValueError(_ERROR)
        if native_bindings and 'naive' not in tools.binaries:
            raise ValueError(_ERROR)

        def source(protocol):
            value = credentials[_digest(protocol['acceptance_target'])]
            if not _valid_credential(value, protocol, manifest['network']['public_tcp_port']):
                raise ValueError(_ERROR)
            return value

        def browser_dial(target, phase):
            if phase != 'staging':
                raise ValueError(_ERROR)
            key = (ListenerKey('public', target['port']) if target['path'] == 'public_tls' else
                   ListenerKey('decoy_tls' if target['path'] == 'internal_tls' else 'decoy_h2c'))
            address = runtime.listeners[key]
            return BrowserDialAddress(address.host, address.port)

        def vpn_dial(protocol, phase):
            if phase == 'direct':
                host = protocol['internal_host']
                return ('127.0.0.1' if host in {'0.0.0.0', 'localhost', ''} else host), protocol['internal_port']
            if phase != 'staging':
                raise ValueError(_ERROR)
            address = runtime.listeners[ListenerKey('public', protocol['acceptance_endpoint']['port'])]
            return address.host, address.port

        runner = _ProbeRunner(tools.binaries['curl'][0])
        observer = XrayVPNObserver(XrayProbeContext(tools.binaries['xray'][0], XRAY_SHA256,
            source, echo_address, 0, shared_tcp_port=manifest['network']['public_tcp_port'], timeout=20,
            dial_target_provider=vpn_dial, coordinator_pid=os.getpid()))
        observers = {'vless': observer, 'vmess': observer}
        direct = []
        if native_bindings:
            observers['naive'] = NaiveVPNObserver(NaiveProbeContext(tools.binaries['naive'][0], NAIVE_SHA256,
                source, echo_address, 0, shared_tcp_port=manifest['network']['public_tcp_port'], timeout=30,
                dial_target_provider=vpn_dial, coordinator_pid=os.getpid(),
                native_binding_provider=lambda protocol: native_bindings.get(protocol['inbound_id'])))
        if native_bindings or echo_address != '127.0.0.1':
            direct = observe_vpn_capabilities(manifest, runner, phase='direct', observers=observers)
            direct_summary = vpn_acceptance_summary(manifest, direct, phase='direct')
            if direct_summary.get('complete') is not True or direct_summary.get('required_endpoints', 0) <= 0:
                raise ValueError(_ERROR)
        expected = {'haproxy': [address for key, address in runtime.listeners.items() if key.role in {'public', 'split'}],
                    'nginx': [address for key, address in runtime.listeners.items() if key.role.startswith('decoy_')]}
        session = ForegroundSession(timeout=_WORKER_TIMEOUT - 5)
        with session:
            for role in ('haproxy', 'nginx'):
                path, digest = tools.binaries[role]
                session.start(FrontendSpec(role, path, digest, configs[role], Path(request['config_root']), tools.identity))
            session.wait_for_listeners(expected, timeout=10)
            browser = observe_decoy_capabilities(manifest, '127.0.0.1', timeout=5, runner=runner,
                phase='staging', dial_target_provider=browser_dial, ca_file=request['browser_ca'],
                audit=_material_audit(material))
            vpn = observe_vpn_capabilities(manifest, runner, phase='staging', observers=observers)
            session.wait_for_listeners(expected, timeout=3)
            if {role: _config_hash(path) for role, path in configs.items()} != hashes:
                raise ValueError(_ERROR)
            tools.verify()
        for row in (*browser, *vpn, *direct):
            row['candidate_fingerprint'] = binding.fingerprint
        result = {'ok': True, 'binding': binding.fingerprint, 'browser_rows': browser, 'vpn_rows': vpn,
                  'cleanup_complete': session.cleanup_complete, 'listeners_verified': True, 'runtime_verified': True}
        if native_bindings or echo_address != '127.0.0.1':
            result['direct_rows'] = direct
        return result
    except Exception:  # noqa: BLE001 — stdin и daemon output не отражаются в IPC error.
        return {'ok': False, 'reason': 'staging_failed'}


if __name__ == '__main__':
    if sys.argv[1:] != ['--worker']:
        raise SystemExit(2)
    try:
        response = _worker(_json(sys.stdin.read(_MAX_IPC + 1)))
    except Exception:  # noqa: BLE001 — единственный безопасный ответ на невалидный stdin.
        response = {'ok': False, 'reason': 'staging_failed'}
    print(json.dumps(response, separators=(',', ':'), ensure_ascii=True))
