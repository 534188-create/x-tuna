"""Ограниченная функциональная проба настоящего Naive без изменений backend."""
from __future__ import annotations

import copy
import ipaddress
import json
import math
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .models import valid_domain
from .routing_profiles import routing_fingerprint
from .runner import Runner
from .vpn_probes import (
    XRAY_SHA256,
    _binary_identity,
    _endpoint_fingerprint,
    _endpoint_valid,
    _open_binary,
    _port,
    _receive,
    _remaining,
    _roundtrip,
)

NAIVE_SHA256 = "baea1e9b9f8dd879a6374110bd7bdca80c2ecbdca8debc4f84f784a8739eaea7"
# Официальные Linux-amd64 binaries v26.3.27 и v26.7.28; только SOCKS bridge.
# https://github.com/XTLS/Xray-core/releases/tag/v26.7.28
NATIVE_XRAY_HASHES = frozenset({XRAY_SHA256,
    '64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d'})
_PHASES = frozenset({"direct", "staging", "public", "rollback"})
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_INPUT = 128 * 1024
_MAX_STDERR = 64 * 1024
_MAX_NETLOG = 2 * 1024 * 1024
_TRANSFER_BYTES = 16384
_ERROR = "Naive не подтвердил текущий профиль и аутентифицированный обмен"


@dataclass(frozen=True, slots=True, repr=False)
class NativeBackendBinding:
    profile_fingerprint: str
    auth_policy_fingerprint: str
    binding_fingerprint: str
    caddy_pid: int
    caddy_sha256: str
    xray_pid: int
    xray_sha256: str
    bridge_port: int
    probe_resistance: bool
    backend_address: str
    backend_port: int
    backend_sni: str
    backend_ca_pem: str


@dataclass(frozen=True, slots=True)
class NaiveProbeCredential:
    username: str = field(repr=False)
    password: str = field(repr=False)
    profile_fingerprint: str
    ca_pem: str = field(default="", repr=False)
    policy_fingerprint: str = field(default="", repr=False)


@dataclass(frozen=True, slots=True)
class NaiveProbeContext:
    binary_path: Path
    binary_sha256: str
    credential_provider: Callable[[dict[str, Any]], NaiveProbeCredential | None] = field(repr=False)
    echo_address: str = field(repr=False)
    echo_port: int
    shared_tcp_port: int = 443
    timeout: float = 20.0
    dial_target_provider: Callable[[dict[str, Any], str], tuple[str, int]] | None = field(default=None, repr=False)
    coordinator_pid: int | None = field(default=None, repr=False)
    native_binding_provider: Callable[[dict[str, Any]], NativeBackendBinding | None] | None = field(default=None, repr=False)


def _native_valid(binding: NativeBackendBinding) -> bool:
    if type(binding) is not NativeBackendBinding:
        return False
    return (all(type(value) is str and _FINGERPRINT.fullmatch(value) for value in (
            binding.profile_fingerprint, binding.auth_policy_fingerprint, binding.binding_fingerprint))
        and type(binding.caddy_pid) is int and binding.caddy_pid > 1
        and binding.caddy_sha256 == '9a8a4d2cf9dd14040086cf5f1762eb8b4304f1dbc0c85784d8bdf27c2587956b'
        and type(binding.probe_resistance) is bool
        and binding.backend_address == '127.0.0.1' and _port(binding.backend_port)
        and valid_domain(binding.backend_sni) and '*' not in binding.backend_sni
        and type(binding.backend_ca_pem) is str and 0 < len(binding.backend_ca_pem.encode()) <= 65536
        and type(binding.xray_pid) is int and type(binding.bridge_port) is int
        and ((binding.xray_pid == 0 and binding.bridge_port == 0 and binding.xray_sha256 == '')
            or (binding.xray_pid > 1 and binding.xray_pid != binding.caddy_pid
                and _port(binding.bridge_port) and type(binding.xray_sha256) is str
                and binding.xray_sha256 in NATIVE_XRAY_HASHES)))


def _native_echo_address(address: str) -> bool:
    value = ipaddress.ip_address(address)
    return (value.version == 4 and not value.is_unspecified and not value.is_multicast
            and not value.is_loopback and not value.is_link_local and str(value) == address
            and address != '255.255.255.255')


def _simple_profile(protocol: dict[str, Any]) -> bool:
    if (protocol.get("protocol") != "naive" or protocol.get("transport") != "tcp"
            or protocol.get("network") != "tcp" or protocol.get("security") != "tls"
            or protocol.get("exposure") != "tcp_sni" or protocol.get("enable") is False
            or any(protocol.get(key) for key in ("flow", "udp_over_tcp", "transport_path", "transport_mode"))
            or protocol.get("transport_hosts", []) != []
            or protocol.get("alpn") not in (["h2"], ["h2", "http/1.1"], ["http/1.1", "h2"])):
        return False
    details = protocol.get("transport_details", {})
    fingerprints = {"settings_fingerprint", "stream_fingerprint", "inbound_settings_fingerprint"}
    flags = {"unsupported_settings", "unknown_stream_fields", "conflicting_settings_alias", "requires_adapter_review"}
    allowed = fingerprints | flags | {"support_status", "settings_keys", "extra", "masks"}
    if (not isinstance(details, dict) or set(details) - allowed
            or details.get("support_status", "") not in {"", "supported"}
            or details.get("settings_keys", []) != [] or any(details.get(key) for key in flags)):
        return False
    if any(key in details and (not isinstance(details[key], str)
            or not _FINGERPRINT.fullmatch(details[key])) for key in fingerprints):
        return False
    for name, keys in (("extra", {"present", "keys", "fingerprint"}),
                       ("masks", {"present", "tcp_types", "udp_types", "fingerprint"})):
        item = details.get(name, {})
        if not isinstance(item, dict) or set(item) - keys or any(item.get(key) for key in keys - {"fingerprint"}):
            return False
        if "fingerprint" in item and (not isinstance(item["fingerprint"], str)
                or not _FINGERPRINT.fullmatch(item["fingerprint"])):
            return False
    endpoints = protocol.get("public_endpoints")
    return (type(protocol.get("inbound_id")) is int and protocol["inbound_id"] > 0
        and isinstance(endpoints, list) and bool(endpoints) and all(
            _endpoint_valid(endpoint) and endpoint["address"] == endpoint["sni"]
            and endpoint.get("http_host", "") == "" for endpoint in endpoints))


def _secret(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value.encode("utf-8")) <= 1024 and not any(
        character in value for character in ("\x00", "\r", "\n"))


def _native_profile_shape(protocol: dict[str, Any]) -> bool:
    """Только форма профиля; разрешение обмена отдельно требует native binding."""
    checked = copy.deepcopy(protocol)
    if checked.get('security') == '':
        checked['security'] = 'tls'
    if checked.get('alpn') == []:
        checked['alpn'] = ['h2']
    details = checked.get('transport_details')
    if isinstance(details, dict) and details.get('support_status') == 'unverified':
        details['support_status'] = 'supported'
    return _simple_profile(checked)


def _binary(path: Path, digest: str) -> int:
    if digest != NAIVE_SHA256:
        raise ValueError(_ERROR)
    return _open_binary(path, digest)


class NaiveVPNObserver:
    def __init__(self, context: NaiveProbeContext) -> None:
        self.context = context

    def _worker_isolation(self, protocol: dict[str, Any]) -> bool:
        owner = self.context.coordinator_pid
        if owner is None:
            return True
        if (type(owner) is not int or owner <= 1 or sys.platform != "linux"
                or protocol.get("acceptance_phase") not in {"direct", "staging"}
                or owner != os.getpid() or owner != os.getpgrp() or owner != os.getsid(0)):
            raise ValueError(_ERROR)
        return False

    def _prepare(self, protocol: dict[str, Any]) -> tuple[NaiveProbeCredential, NativeBackendBinding | None]:
        self._worker_isolation(protocol)
        context = self.context
        native = context.native_binding_provider is not None
        if (sys.platform != "linux" or not _port(context.shared_tcp_port)
                or type(context.timeout) not in {float, int} or not math.isfinite(context.timeout)
                or not 4 <= context.timeout <= 60 or not (_port(context.echo_port)
                    or type(context.echo_port) is int and context.echo_port == 0 and (
                        context.echo_address == "127.0.0.1" or native and _native_echo_address(context.echo_address)))):
            raise ValueError(_ERROR)
        ipaddress.ip_address(context.echo_address)
        descriptor = _binary(Path(context.binary_path), context.binary_sha256)
        os.close(descriptor)
        credential = context.credential_provider(copy.deepcopy(protocol))
        if (type(credential) is not NaiveProbeCredential or not _secret(credential.username)
                or not _secret(credential.password)
                or credential.profile_fingerprint != routing_fingerprint(protocol, context.shared_tcp_port)
                or type(credential.ca_pem) is not str or len(credential.ca_pem.encode("utf-8")) > 65536
                or type(credential.policy_fingerprint) is not str
                or credential.policy_fingerprint and not _FINGERPRINT.fullmatch(credential.policy_fingerprint)):
            raise ValueError(_ERROR)
        binding = None
        if native:
            binding = context.native_binding_provider(copy.deepcopy(protocol))
            if (not _native_valid(binding) or binding.profile_fingerprint != credential.profile_fingerprint
                    or binding.auth_policy_fingerprint != credential.policy_fingerprint
                    or binding.backend_port != protocol.get('internal_port')
                    or context.echo_port != 0 or not _native_echo_address(context.echo_address)):
                raise ValueError(_ERROR)
        if not (_native_profile_shape(protocol) if native else _simple_profile(protocol)):
            raise ValueError(_ERROR)
        return credential, binding

    def _credential(self, protocol: dict[str, Any]) -> NaiveProbeCredential:
        return self._prepare(protocol)[0]

    def _identity_valid(self, protocol: dict[str, Any], credential: NaiveProbeCredential) -> bool:
        endpoint, identity = protocol.get("acceptance_endpoint"), protocol.get("acceptance_target")
        return (protocol.get("acceptance_phase") in _PHASES and isinstance(identity, dict)
            and _endpoint_valid(endpoint) and endpoint in protocol["public_endpoints"]
            and identity.get("inbound_id") == protocol["inbound_id"]
            and identity.get("profile_fingerprint") == credential.profile_fingerprint
            and identity.get("endpoint_fingerprint") == _endpoint_fingerprint(endpoint))

    def _dial_target(self, protocol: dict[str, Any], binding: NativeBackendBinding | None = None) -> tuple[str, int]:
        phase = protocol["acceptance_phase"]
        if phase == 'direct' and binding is not None:
            return binding.backend_address, binding.backend_port
        if phase in {"direct", "staging"}:
            if self.context.dial_target_provider is None:
                raise ValueError(_ERROR)
            dial = self.context.dial_target_provider(copy.deepcopy(protocol), phase)
            if not isinstance(dial, tuple) or len(dial) != 2 or not _port(dial[1]):
                raise ValueError(_ERROR)
            ipaddress.ip_address(dial[0])
            return dial
        endpoint = protocol["acceptance_endpoint"]
        return endpoint["address"], endpoint["port"]

    def supports(self, protocol: dict[str, Any]) -> bool:
        try:
            self._credential(protocol)
            return True
        except Exception:  # noqa: BLE001 — данные источника не отражаются в сообщении.
            return False

    def preflight(self, protocol: dict[str, Any], runner: Runner) -> bool:
        """Только profile/source/hash; без запуска клиента или echo."""
        try:
            credential, binding = self._prepare(protocol)
            if not self._identity_valid(protocol, credential):
                return False
            self._dial_target(protocol, binding)
            return True
        except Exception:  # noqa: BLE001
            return False

    def __call__(self, protocol: dict[str, Any], runner: Runner) -> dict[str, Any]:
        phase = protocol.get("acceptance_phase")
        phase = phase if isinstance(phase, str) and phase in _PHASES else ""
        result: dict[str, Any] = {"state": "not_tested", "phase": phase, "functional": False,
            "public": phase in {"public", "rollback"}, "authenticated": False,
            "bytes_sent": 0, "bytes_received": 0}
        identity = protocol.get("acceptance_target")
        if isinstance(identity, dict):
            if type(identity.get("inbound_id")) is int:
                result["inbound_id"] = identity["inbound_id"]
            for key in ("profile_fingerprint", "endpoint_fingerprint"):
                if isinstance(identity.get(key), str) and _FINGERPRINT.fullmatch(identity[key]):
                    result[key] = identity[key]
        if runner.dry_run or not phase:
            return result
        try:
            credential, binding = self._prepare(protocol)
            if not self._identity_valid(protocol, credential):
                return result
            dial = self._dial_target(protocol, binding)
            request = {"binary": str(self.context.binary_path), "sha256": self.context.binary_sha256,
                "username": credential.username, "password": credential.password, "ca_pem": credential.ca_pem,
                "sni": protocol["acceptance_endpoint"]["sni"], "address": dial[0], "port": dial[1],
                "echo_address": self.context.echo_address, "echo_port": self.context.echo_port,
                "timeout": self.context.timeout - 1}
            if binding is not None:
                request['native'] = asdict(binding)
                if phase == 'direct':
                    request.update(sni=binding.backend_sni, ca_pem=binding.backend_ca_pem)
                else:
                    request['proxy_port'] = protocol['acceptance_endpoint']['port']
            encoded = json.dumps(request, separators=(",", ":"), allow_nan=False)
            if len(encoded.encode("utf-8")) > _MAX_INPUT:
                return result
            bootstrap = ("import sys,runpy;sys.path.insert(0,sys.argv[1]);"
                "sys.argv=['x-tuna-naive-probe','--worker'];"
                "runpy.run_module('lucx_post_configurator.naive_probes',run_name='__main__')")
            completed = runner.run_bounded([sys.executable, "-I", "-S", "-c", bootstrap,
                str(Path(__file__).absolute().parent.parent)], input_text=encoded, timeout=self.context.timeout,
                max_output_bytes=1024, isolate_process_group=self._worker_isolation(protocol),
                inherit_env=False, check=False)
            result["state"] = "failed"
            observed = json.loads(completed.stdout) if completed.returncode == 0 else {}
            if (isinstance(observed, dict) and observed.get("authenticated") is True
                    and observed.get("negative_auth") is True and observed.get("reconnect") is True
                    and all(type(observed.get(key)) is int and observed[key] == _TRANSFER_BYTES
                            for key in ("bytes_sent", "bytes_received"))):
                # Успех worker относится к исходным auth, policy, CA и адресу;
                # новый снимок после обмена не может подменить эту привязку.
                if (self._prepare(protocol) != (credential, binding)
                        or not self._identity_valid(protocol, credential)
                        or self._dial_target(protocol, binding) != dial):
                    return result
                result.update(state="healthy", functional=True, authenticated=True,
                    bytes_sent=_TRANSFER_BYTES, bytes_received=_TRANSFER_BYTES)
        except Exception:  # noqa: BLE001 — ни stderr, ни исключения source не публикуются.
            result["state"] = "failed"
        return result


def _auth_denied(stderr: bytes) -> bool:
    return bool(re.search(rb"\bERR_PROXY_AUTH_(?:UNSUPPORTED|REQUESTED)\b", stderr))


def _netlog_h2(data: bytes, request: dict[str, Any]) -> bool:
    """Только полные event records; незавершённый JSON trailer не восстанавливается.

    Закреплённый FileNetLogObserver пишет constants, затем один event на строку.
    HTTP2_SESSION DATA связывается с двумя CONNECT к цели именно этой пробы.
    """
    try:
        if len(data) > _MAX_NETLOG:
            return False
        lines = data.split(b"\n")[:-1]  # Частичная последняя запись не доказательство.
        prefix = b'{"constants":'
        if (len(lines) < 3 or not lines[0].startswith(prefix) or not lines[0].endswith(b",")
                or lines[1].strip() != b'"events": ['):
            return False
        constants = json.loads(lines[0][len(prefix):-1])
        names = ("HTTP2_SESSION_SEND_HEADERS", "HTTP2_SESSION_RECV_HEADERS",
            "HTTP2_SESSION_SEND_DATA", "HTTP2_SESSION_RECV_DATA")
        types = {constants["logEventTypes"][name]: name for name in names}
        source_type = constants["logSourceType"]["HTTP2_SESSION"]
        echo = ipaddress.ip_address(request["echo_address"])
        authority = f"[{echo}]:{request['echo_port']}" if echo.version == 6 else f"{echo}:{request['echo_port']}"
        streams: dict[tuple[int, int], dict[str, Any]] = {}
        for line in lines[2:]:
            line = line.strip()
            if line in {b"]", b"}", b"]}"}:
                continue
            event = json.loads(line[:-1] if line.endswith(b",") else line)
            if not isinstance(event, dict) or not isinstance(event.get("source"), dict):
                return False
            name = types.get(event.get("type"))
            source = event["source"]
            if name is None or source.get("type") != source_type:
                continue
            params = event.get("params")
            if (not isinstance(params, dict) or type(source.get("id")) is not int or source["id"] <= 0
                    or type(params.get("stream_id")) is not int or params["stream_id"] <= 0):
                return False
            state = streams.setdefault((source["id"], params["stream_id"]),
                {"connect": False, "ok": False, "sent": 0, "received": 0})
            if name.endswith("HEADERS"):
                headers = params.get("headers")
                if not isinstance(headers, list) or any(type(header) is not str for header in headers):
                    return False
                if name == "HTTP2_SESSION_SEND_HEADERS":
                    state["connect"] = (headers.count(":method: CONNECT") == 1
                        and [item for item in headers if item.startswith(":authority:")] == [":authority: " + authority])
                else:
                    state["ok"] = [item for item in headers if item.startswith(":status:")] == [":status: 200"]
            else:
                size = params.get("size")
                if type(size) is not int or not 0 <= size <= _MAX_NETLOG:
                    return False
                state["sent" if name == "HTTP2_SESSION_SEND_DATA" else "received"] += size
        return sum(state["connect"] and state["ok"] and state["sent"] >= 8192
            and state["received"] >= 8192 for state in streams.values()) >= 2
    except (ValueError, TypeError, KeyError, RecursionError):
        return False


def _netlog_bytes(descriptor: int) -> bytes:
    size = os.fstat(descriptor).st_size
    if not 0 <= size <= _MAX_NETLOG:
        raise OSError(_ERROR)
    return os.pread(descriptor, size, 0)


def _netlog_hidden_auth_denial(data: bytes, request: dict[str, Any], *, minimum_roots: int | None = None) -> bool:
    """Только форма отказа canonical Caddy; не разрешение режима observer.

    Caller обязан отдельно подтвердить source/fork, завершение попытки и flush
    всего NetLog. Успешная auth этого fork добавляет Padding до ACL/dial, поэтому
    200 с Padding даже без DATA не доказывает отказ аутентификации.
    """
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(_ERROR)
            result[key] = value
        return result

    try:
        if (type(data) is not bytes or not data.endswith(b'\n') or len(data) > _MAX_NETLOG
                or type(request) is not dict or not _port(request.get('echo_port'))
                or not _port(request.get('port')) or type(request.get('sni')) is not str
                or not valid_domain(request['sni']) or '*' in request['sni']):
            return False
        echo = ipaddress.ip_address(request['echo_address'])
        authority = f'[{echo}]:{request["echo_port"]}' if echo.version == 6 else f'{echo}:{request["echo_port"]}'
        proxy_port = request.get('proxy_port', request['port'])
        if not _port(proxy_port):
            return False
        proxy_authorities = {request['sni'] + ':' + str(proxy_port)}
        if proxy_port == 443:
            proxy_authorities.add(request['sni'])
        lines = data.split(b'\n')[:-1]
        prefix = b'{"constants":'
        if (len(lines) < 4 or not lines[0].startswith(prefix) or not lines[0].endswith(b',')
                or lines[1].strip() != b'"events": ['):
            return False
        constants = json.loads(lines[0][len(prefix):-1], object_pairs_hook=unique)
        names = ('HTTP2_SESSION_SEND_HEADERS', 'HTTP2_SESSION_RECV_HEADERS',
                 'HTTP2_SESSION_SEND_DATA', 'HTTP2_SESSION_RECV_DATA',
                 'HTTP2_SESSION_SEND_RST_STREAM', 'HTTP2_SESSION_RECV_RST_STREAM')
        codes = [constants['logEventTypes'][name] for name in names]
        source_type = constants['logSourceType']['HTTP2_SESSION']
        if (any(type(code) is not int or code < 0 for code in codes)
                or len(set(codes)) != len(codes) or type(source_type) is not int):
            return False
        types = dict(zip(codes, names))
        streams = {}
        counts = {'setup': 0, 'resource': 0, 'connect': 0}
        kinds, reset_streams = {}, set()
        bodies = {}
        setup_bytes = 0
        root_started, head_streams = set(), set()
        closing = False
        for line in lines[2:]:
            line = line.strip()
            if line in {b']', b'}', b']}'}:
                closing = True
                continue
            if closing:
                return False
            event = json.loads(line[:-1] if line.endswith(b',') else line, object_pairs_hook=unique)
            if (type(event) is not dict or type(event.get('type')) is not int
                    or type(event.get('source')) is not dict):
                return False
            name = types.get(event['type'])
            if name is None:
                continue
            source, params = event['source'], event.get('params')
            if (type(source.get('type')) is not int or source['type'] != source_type
                    or type(source.get('id')) is not int or source['id'] <= 0
                    or type(params) is not dict or type(params.get('stream_id')) is not int
                    or params['stream_id'] <= 0 or params['stream_id'] % 2 != 1):
                return False
            key = (source['id'], params['stream_id'])
            if name == 'HTTP2_SESSION_RECV_RST_STREAM':
                # RFC 9113 §8.1: NO_ERROR после END_STREAM завершает оставшуюся
                # request-половину и не отменяет уже полный response.
                if (streams.get(key) is not True or kinds.get(key) != 'connect'
                        or key in reset_streams or params.get('error_code') != '0 (NO_ERROR)'):
                    return False
                reset_streams.add(key)
                continue
            if name == 'HTTP2_SESSION_RECV_DATA':
                # GET preamble может получить сайт frontend. Только полный
                # ограниченный ответ. CONNECT допускает только пустой END_STREAM,
                # который frontend может перенести из HEADERS в DATA.
                if (streams.get(key) is not False
                        or key not in bodies or type(params.get('size')) is not int
                        or params['size'] < 0 or type(params.get('fin')) is not bool):
                    return False
                if (kinds.get(key) == 'connect' or key in head_streams) and (params['size'] != 0 or not params['fin']):
                    return False
                if kinds.get(key) == 'setup' and params['size'] > 0:
                    root_started.add(key)
                bodies[key] -= params['size']
                if bodies[key] < 0 or params['fin'] and bodies[key] != 0:
                    return False
                streams[key] = params['fin']
                continue
            if not name.endswith('HEADERS'):
                return False
            headers = params.get('headers')
            if (type(headers) is not list or not 1 <= len(headers) <= 128
                    or any(type(h) is not str or len(h) > 8192
                           or re.fullmatch(r"[:a-z0-9!#$%&'*+.^_`|~-]+: [^\r\n\x00]*", h) is None
                           for h in headers)):
                return False
            if name == 'HTTP2_SESSION_SEND_HEADERS':
                if key in streams:
                    return False
                pseudo = sorted(h for h in headers if h.startswith(':'))
                auth = [h for h in headers if h.startswith('proxy-authorization:')]
                if pseudo == sorted([':method: CONNECT', ':authority: ' + authority]):
                    if params.get('fin') is not False or len(auth) != 1:
                        return False
                    kind, maximum = 'connect', 3
                elif any(pseudo == sorted([':method: GET', ':scheme: https', ':path: /',
                                           ':authority: ' + target]) for target in proxy_authorities):
                    if params.get('fin') is not True or auth:
                        return False
                    kind, maximum = 'setup', 2
                else:
                    paths = [h for h in pseudo if h.startswith(':path: ')]
                    methods = [h for h in pseudo if h.startswith(':method: ')]
                    if (len(paths) != 1 or len(paths[0]) > 2048
                            or methods not in ([':method: GET'], [':method: HEAD'])
                            or re.fullmatch(r":path: /(?!/)[A-Za-z0-9._~!$&'()*+,;=:@%/?-]+", paths[0]) is None
                            or not any(pseudo == sorted([methods[0], ':scheme: https', paths[0],
                                                         ':authority: ' + target]) for target in proxy_authorities)
                            or params.get('fin') is not True or auth
                            or not any(sid == key[0] and kinds.get((sid, stream)) == 'setup'
                                       and (done or (sid, stream) in root_started)
                                       for (sid, stream), done in streams.items())):
                        return False
                    if methods == [':method: HEAD']:
                        head_streams.add(key)
                    # Naive загружает ресурсы сайта после GET /. Это не auth
                    # evidence; требуем тот же origin/session и полное тело.
                    kind, maximum = 'resource', 64
                counts[kind] += 1
                if counts[kind] > maximum:
                    return False
                streams[key] = False
                kinds[key] = kind
            else:
                if (key not in streams or streams[key] or key in bodies
                        or type(params.get('fin')) is not bool
                        or [h for h in headers if h.startswith(':')] != [':status: 200']
                        or any(h.startswith('padding:') for h in headers)):
                    return False
                lengths = [h for h in headers if h.startswith('content-length:')]
                if (len(lengths) != 1
                        or re.fullmatch(r'content-length: (0|[1-9][0-9]{0,6})', lengths[0]) is None):
                    return False
                length = int(lengths[0].split(': ', 1)[1])
                if (length > 1048576 or params['fin'] and length != 0 and key not in head_streams
                        or kinds[key] == 'connect' and length != 0):
                    return False
                if key in head_streams:
                    length = 0
                if kinds[key] != 'connect':
                    setup_bytes += length
                    if setup_bytes > _MAX_NETLOG:
                        return False
                bodies[key] = length
                streams[key] = params['fin']
        return (counts['connect'] > 0 and all(streams.values())
                and (minimum_roots is None or type(minimum_roots) is int and 1 <= minimum_roots <= 2 and counts['setup'] >= minimum_roots))
    except (ValueError, TypeError, KeyError, RecursionError, AttributeError):
        return False


def _netlog_terminal(data: bytes, control_peers: tuple[int, ...], primary_peers: tuple[int, ...],
                     *, require_preambles: bool = False) -> bool:
    """Полный FIFO-префикс после окончания accepted sockets основной попытки.

    Проверяется отдельно от HTTP2/auth/source proof. Фоновые preamble требуют
    собственной проверки всех ожидаемых ответов; socket END их не отменяет.
    """
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(_ERROR)
            result[key] = value
        return result

    try:
        if (type(require_preambles) is not bool
                or type(data) is not bytes or len(data) > _MAX_NETLOG or not data.endswith(b'\n')
                or type(control_peers) is not tuple or not 1 <= len(control_peers) <= 96
                or any(not _port(peer) for peer in control_peers)
                or len(set(control_peers)) != len(control_peers)
                or type(primary_peers) is not tuple or len(primary_peers) != 2
                or any(not _port(peer) for peer in primary_peers) or len(set(primary_peers)) != 2):
            return False
        lines = data.splitlines()
        prefix = b'{"constants":'
        if (len(lines) < 4 or not lines[0].startswith(prefix) or not lines[0].endswith(b',')
                or lines[1].strip() != b'"events": ['):
            return False
        constants = json.loads(lines[0][len(prefix):-1], object_pairs_hook=unique)
        codes = constants['logEventTypes']
        phases = constants['logEventPhase']
        begin, end = phases['PHASE_BEGIN'], phases['PHASE_END']
        if (type(begin) is not int or type(end) is not int or begin == end
                or any(type(code) is not int for code in codes.values())
                or len(set(codes.values())) != len(codes)):
            return False
        alive, accept, socks = (codes[name] for name in ('SOCKET_ALIVE', 'TCP_ACCEPT', 'SOCKS5_CONNECT'))
        handshake = {codes[name] for name in ('SOCKS5_HANDSHAKE_READ', 'SOCKS5_HANDSHAKE_WRITE')}
        socket_type = constants['logSourceType']['SOCKET']
        job_code, job_type = codes['CONNECT_JOB'], constants['logSourceType']['HTTP_PROXY_CONNECT_JOB']
        h2_codes = {code for name, code in codes.items() if name.startswith('HTTP2_SESSION_')
                    and any(name.endswith(suffix) for suffix in ('HEADERS', 'DATA', 'RST_STREAM'))}
        pool_code = codes['SOCKET_POOL'] if require_preambles else None
        pool_codes = {code for name, code in codes.items() if 'SOCKET_POOL' in name}
        pool_owner = None
        pool_pending = 0
        pool_begins = []
        last_pool = -1
        rows, source_types = [], {}
        for line in lines[2:]:
            line = line.strip()
            row = json.loads(line[:-1] if line.endswith(b',') else line, object_pairs_hook=unique)
            source = row['source']
            if (type(row.get('type')) is not int or type(row.get('phase')) is not int
                    or type(source.get('id')) is not int or source['id'] <= 0
                    or type(source.get('type')) is not int or type(row.get('params', {})) is not dict):
                return False
            if source_types.setdefault(source['id'], source['type']) != source['type']:
                return False
            rows.append(row)
        parents = {row['source']['id'] for row in rows if row['type'] == accept}
        if len(parents) != 2 or any(source_types[p] != socket_type for p in parents):
            return False
        lives, pending, children, accepted = {}, {}, {}, {p: [] for p in parents}
        handshakes, jobs = set(), {}
        last_h2 = -1
        for index, row in enumerate(rows):
            kind, sid, phase = row['type'], row['source']['id'], row['phase']
            params = row.get('params', {})
            if kind in h2_codes:
                last_h2 = index
            if require_preambles and kind in pool_codes:
                last_pool = index
            if require_preambles and kind == pool_code:
                if (row['source']['type'] != constants['logSourceType']['NONE']
                        or phase not in (begin, end) or type(params.get('net_error', 0)) is not int
                        or params.get('net_error', 0) != 0):
                    return False
                if pool_owner is None:
                    pool_owner = sid
                if sid != pool_owner:
                    return False
                # Owner общий: отмена pending CSS и передача его job повторному
                # request допустимы. FIFO/LIFO pairing здесь неверен.
                if phase == begin:
                    pool_pending += 1
                    pool_begins.append(index)
                else:
                    pool_pending -= 1
                if pool_pending < 0 or len(pool_begins) > 128:
                    return False
            if kind == job_code:
                if row['source']['type'] != job_type:
                    return False
                if phase == begin and sid not in jobs:
                    jobs[sid] = None
                elif phase == end and sid in jobs and jobs[sid] is None:
                    jobs[sid] = index
                else:
                    return False
            if kind in handshake:
                if sid not in children or lives[sid][1] is not None:
                    return False
                handshakes.add(sid)
            if row['source']['type'] != socket_type:
                if kind in (accept, socks):
                    return False
                continue
            if kind == alive:
                if phase == begin:
                    if sid in lives:
                        return False
                    lives[sid] = [index, None]
                    dep = params.get('source_dependency', {})
                    parent = dep.get('id')
                    if parent in parents:
                        if (dep.get('type') != socket_type or parent not in pending
                                or pending[parent] is not None):
                            return False
                        children[sid] = {'parent': parent, 'peer': None, 'start': None, 'result': None}
                        pending[parent] = sid
                elif phase == end:
                    if sid not in lives or lives[sid][1] is not None or sid in parents:
                        return False
                    lives[sid][1] = index
                    if sid in children and children[sid]['result'] is None:
                        return False
                else:
                    return False
            elif kind == accept:
                if sid not in lives or lives[sid][1] is not None:
                    return False
                if phase == begin:
                    if sid in pending:
                        return False
                    pending[sid] = None
                elif phase == end:
                    child = pending.pop(sid, None)
                    address = params.get('address')
                    if child is None or type(address) is not str or 'net_error' in params:
                        return False
                    match = re.fullmatch(r'127\.0\.0\.1:([0-9]{1,5})', address)
                    if match is None or not _port(int(match[1])):
                        return False
                    children[child]['peer'] = int(match[1])
                    children[child]['accept_end'] = index
                    accepted[sid].append(child)
                else:
                    return False
            elif kind == socks:
                if sid not in children or children[sid]['peer'] is None or lives[sid][1] is not None:
                    return False
                child = children[sid]
                if phase == begin and child['start'] is None:
                    child['start'] = index
                elif phase == end and child['start'] is not None and child['result'] is None:
                    error = params.get('net_error', 0)
                    if type(error) is not int or error not in (0, -120):
                        return False
                    child['result'] = error
                else:
                    return False
        # Ephemeral port может совпасть при разных destination listeners.
        # Роль задаётся всей упорядоченной парой основного listener, не одним port.
        mains = [p for p in parents if tuple(children[c]['peer'] for c in accepted[p]) == primary_peers]
        if len(mains) != 1:
            return False
        main = mains[0]
        control = next(p for p in parents if p != main)
        main_children = accepted[main]
        if (len(main_children) != 2 or [children[c]['result'] for c in main_children] != [-120, 0]
                or tuple(children[c]['peer'] for c in main_children) != primary_peers
                or any(lives[c][1] is None for c in main_children)
                or pending.get(main) is not None):
            return False
        if require_preambles:
            first, second = (children[c] for c in main_children)
            if (pool_pending != 0 or len(pool_begins) < 3
                    or not any(first['accept_end'] < index < first['start'] for index in pool_begins)
                    or sum(second['accept_end'] < index < second['start'] for index in pool_begins) != 1):
                return False
        # Недописанный хвост control допустим: выбранный ранее marker уже целиком
        # записан. Любой observed foreign peer или успешный control блокирует proof.
        seen = [children[c]['peer'] for c in accepted[control]]
        if not seen or tuple(seen) != control_peers[:len(seen)]:
            return False
        # ClientSocketHandle Reset может оставить unbound ConnectJob в pool.
        # Требуем уничтожение каждого job, а не только закрытие accepted TCP.
        if not jobs or any(value is None for value in jobs.values()):
            return False
        terminal = max(*(lives[c][1] for c in main_children), *jobs.values(), last_pool)
        markers = []
        for child in accepted[control]:
            # OnIOComplete закреплённого SOCKS пишет END без net_error даже при
            # отказе. Private caller уже получил 05ff; CONNECT handshake запрещён.
            if children[child]['result'] not in (None, 0, -120) or child in handshakes:
                return False
            if lives[child][1] is not None and lives[child][0] > max(terminal, last_h2):
                markers.append(child)
        return bool(markers) and last_h2 >= 0
    except (ValueError, TypeError, KeyError, RecursionError, AttributeError):
        return False


class _NaiveNetLogFlush:
    """Отдельный локальный канал событий; сам по себе не доказывает полноту NetLog.

    Вызывающий код обязан остановить Naive и повторить verify_idle до закрытия
    guard. Основной HTTPS proxy не меняется.
    """

    __slots__ = ('_main_port', '_port', '_guard', '_used', '_failed', '_auth')

    def __init__(self, main_port: int):
        if not _port(main_port):
            raise ValueError(_ERROR)
        self._main_port, self._port = main_port, None
        self._guard = None
        self._used = self._failed = False
        self._auth = (secrets.token_hex(16), secrets.token_hex(24))

    def __enter__(self):
        if self._used:
            raise ValueError(_ERROR)
        self._used = True
        guard = socket.socket()
        try:
            # Резервации не пересекаются: guard bind выполняется до release control.
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
                guard.bind(('127.0.0.1', 0))
                if len({port, guard.getsockname()[1], self._main_port}) != 3:
                    raise ValueError(_ERROR)
                guard.listen(1)
                guard.setblocking(False)
            self._guard, self._port = guard, port
            return self
        except BaseException:
            guard.close()
            raise

    def __exit__(self, *exc):
        if self._guard is not None:
            self._guard.close()
        self._guard, self._port = None, None

    def verify_idle(self):
        if self._guard is None or self._failed:
            raise OSError(_ERROR)
        try:
            connection, _ = self._guard.accept()
        except BlockingIOError:
            return
        except OSError:
            self._failed = True
            raise OSError(_ERROR) from None
        connection.close()
        self._failed = True
        raise OSError(_ERROR)

    def configure(self, config: dict[str, Any]) -> dict[str, Any]:
        try:
            if self._guard is None or type(config) is not dict or type(config.get('listen')) is not str:
                raise ValueError
            listen = urllib.parse.urlsplit(config['listen'])
            if (listen.scheme != 'socks' or listen.hostname != '127.0.0.1' or listen.port != self._main_port
                    or not listen.username or not listen.password or listen.path or listen.query or listen.fragment
                    or type(config.get('proxy')) is not str or not config['proxy'].startswith('https://')):
                raise ValueError
            self.verify_idle()
            control = f'socks://{self._auth[0]}:{self._auth[1]}@127.0.0.1:{self._port}'
            proxy = f'http://127.0.0.1:{self._guard.getsockname()[1]}'
            return dict(config, listen=[config['listen'], control], proxy=[config['proxy'], proxy])
        except (ValueError, TypeError, OSError):
            raise ValueError(_ERROR) from None

    def flush(self, deadline: float) -> tuple[int, ...]:
        """Создаёт ограниченную серию NOAUTH отказов, возвращает private peer ports.

        Это enqueue/flush primitive. Маркер окончания основной попытки и охват
        всех её событий будущий collector должен проверить отдельно.
        """
        self.verify_idle()
        peers = []
        for _ in range(24):
            with socket.create_connection(('127.0.0.1', self._port),
                    timeout=min(.2, _remaining(deadline))) as local:
                peers.append(local.getsockname()[1])
                local.sendall(b'\x05\x01\x00')
                if _receive(local, 2, min(deadline, time.monotonic() + .2)) != b'\x05\xff':
                    self._failed = True
                    raise OSError(_ERROR)
            self.verify_idle()
        return tuple(peers)


def _collect_hidden_denial(descriptor: int, control: _NaiveNetLogFlush,
        primary_peers: tuple[int, ...], request: dict[str, Any], deadline: float) -> tuple[bytes, tuple[int, ...]]:
    peers: tuple[int, ...] = ()
    for _ in range(4):
        peers += control.flush(deadline)
        for _ in range(5):
            _remaining(deadline)
            data = _netlog_bytes(descriptor)
            if (_netlog_terminal(data, peers, primary_peers, require_preambles=True)
                    and _netlog_hidden_auth_denial(data, request, minimum_roots=1)):
                control.verify_idle()
                return data, peers
            time.sleep(min(.02, _remaining(deadline)))
    raise OSError(_ERROR)


def _wait_h2(descriptor: int, port: int, request: dict[str, Any], deadline: float) -> None:
    # FileNetLogObserver flush происходит каждые 15 events. Локальные отказы
    # SOCKS method создают TCP_ACCEPT events без нового VPN CONNECT. Naive также
    # может запускать remote preconnect GET; для hidden-denial этот flush не подходит.
    for _ in range(24):
        _remaining(deadline)
        if _netlog_h2(_netlog_bytes(descriptor), request):
            return
        with socket.create_connection(("127.0.0.1", port), timeout=min(.2, _remaining(deadline))) as local:
            local.sendall(b"\x05\x01\x00")
            if _receive(local, 2, min(deadline, time.monotonic() + .2)) != b"\x05\xff":
                raise OSError(_ERROR)
        time.sleep(min(.03, _remaining(deadline)))
    raise OSError(_ERROR)


def _client_config(request: dict[str, Any], password: str, port: int, auth: tuple[bytes, bytes]) -> dict[str, Any]:
    quote = urllib.parse.quote
    proxy_port = request.get('proxy_port', request['port'])
    config = {"listen": f"socks://{auth[0].decode()}:{auth[1].decode()}@127.0.0.1:{port}",
        "proxy": f"https://{quote(request['username'], safe='')}:{quote(password, safe='')}@{request['sni']}:{proxy_port}",
        "log": ""}
    if request["address"] != request["sni"]:
        address = ipaddress.ip_address(request["address"])
        target = f"[{address}]" if address.version == 6 else str(address)
        if proxy_port != request['port']:
            target += ':' + str(request['port'])
        config["host-resolver-rules"] = f"MAP {request['sni']} {target}"
    return config


def _sealed(data: bytes) -> int:
    import fcntl
    descriptor = os.memfd_create("x-tuna-naive-probe", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(data)
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _attempt(request: dict[str, Any], binary_fd: int, password: str, deadline: float,
             *, negative: bool, hidden_denial: bool = False) -> None:
    # Режим задаёт только private caller с проверенной native source policy.
    # Форма HTTP-ответа сама по себе не разрешает этот режим.
    if type(hidden_denial) is not bool or hidden_denial and not negative:
        raise ValueError(_ERROR)
    descriptors: list[int] = []
    process = reader = None
    captured = bytearray()
    overflow = threading.Event()
    failed = False
    unexpected_exit = False
    netlog_fd = None
    netlog_data = b""
    control = None
    hidden_verified = False
    primary_peers: list[int] = []
    control_peers: tuple[int, ...] = ()

    def drain() -> None:
        try:
            while chunk := process.stderr.read(4096):
                remaining = _MAX_STDERR - len(captured)
                captured.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()
        except (OSError, ValueError):
            overflow.set()

    try:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        auth = (secrets.token_hex(16).encode(), secrets.token_hex(24).encode())
        config = _client_config(request, password, port, auth)
        if not negative or hidden_denial:
            netlog_fd = os.memfd_create("x-tuna-naive-evidence", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            descriptors.append(netlog_fd)
            config["log-net-log"] = f"/proc/self/fd/{netlog_fd}"
        if hidden_denial:
            control = _NaiveNetLogFlush(port)
            control.__enter__()
            config = control.configure(config)
        config_fd = _sealed(json.dumps(config, separators=(",", ":")).encode())
        descriptors.append(config_fd)
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        if request["ca_pem"]:
            ca_fd = _sealed(request["ca_pem"].encode("utf-8"))
            descriptors.append(ca_fd)
            environment["SSL_CERT_FILE"] = f"/proc/self/fd/{ca_fd}"
        process = subprocess.Popen([f"/proc/self/fd/{binary_fd}", f"/proc/self/fd/{config_fd}"],
            pass_fds=(binary_fd, *descriptors), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, env=environment)
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        while True:
            _remaining(deadline)
            if process.poll() is not None:
                raise OSError(_ERROR)
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=min(.1, _remaining(deadline))) as ready:
                    if hidden_denial:
                        primary_peers.append(ready.getsockname()[1])
                    break
            except OSError:
                time.sleep(min(.02, _remaining(deadline)))
        if hidden_denial:
            try:
                _roundtrip(port, auth, request, deadline, local_peers=primary_peers)
            except OSError:
                failed = True
                netlog_data, control_peers = _collect_hidden_denial(
                    netlog_fd, control, tuple(primary_peers), request, deadline)
                hidden_verified = True
        else:
            _roundtrip(port, auth, request, deadline)
        if not negative:
            _roundtrip(port, auth, request, deadline)
            _wait_h2(netlog_fd, port, request, deadline)
    except OSError:
        failed = True
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            else:
                unexpected_exit = True
            expected_exit = -signal.SIGTERM
            try:
                actual_exit = process.wait(timeout=.5)
            except subprocess.TimeoutExpired:
                process.kill()
                expected_exit = -signal.SIGKILL
                actual_exit = process.wait(timeout=.5)
            if actual_exit != expected_exit:
                unexpected_exit = True
        if reader is not None:
            reader.join(timeout=.5)
            if reader.is_alive():
                overflow.set()
        if process is not None and process.stderr is not None:
            process.stderr.close()
        try:
            if netlog_fd is not None:
                import fcntl
                fcntl.fcntl(netlog_fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                sealed_data = _netlog_bytes(netlog_fd)
                if not hidden_denial:
                    netlog_data = sealed_data
                elif hidden_verified:
                    hidden_verified = (sealed_data.startswith(netlog_data)
                        and _netlog_terminal(sealed_data, control_peers, tuple(primary_peers), require_preambles=True)
                        and _netlog_hidden_auth_denial(sealed_data, request, minimum_roots=1))
        finally:
            try:
                if control is not None:
                    try:
                        control.verify_idle()
                    finally:
                        control.__exit__(None, None, None)
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
    if (unexpected_exit or overflow.is_set()
            or (negative and not (failed and (hidden_verified if hidden_denial else _auth_denied(captured))))
            or (not negative and failed)):
        raise OSError(_ERROR)
    if not negative and (not _netlog_h2(netlog_data, request)
            or not re.search(rb"\bnegotiated padding type: Variant1(?:\r?\n|$)", captured)):
        raise OSError(_ERROR)


def _worker_exchange(request: dict[str, Any]) -> dict[str, Any]:
    deadline = time.monotonic() + request["timeout"]
    binary_fd = _binary(Path(request["binary"]), request["sha256"])
    try:
        wrong = secrets.token_urlsafe(32)
        while wrong == request["password"]:
            wrong = secrets.token_urlsafe(32)
        hidden = request.get('native', {}).get('probe_resistance') is True
        _attempt(request, binary_fd, wrong, min(deadline, time.monotonic() + 5),
                 negative=True, hidden_denial=hidden)
        _attempt(request, binary_fd, request["password"], deadline, negative=False)
        checked = _binary(Path(request["binary"]), request["sha256"])
        try:
            if _binary_identity(os.fstat(checked)) != _binary_identity(os.fstat(binary_fd)):
                raise OSError(_ERROR)
        finally:
            os.close(checked)
        return {"authenticated": True, "negative_auth": True, "reconnect": True,
            "bytes_sent": _TRANSFER_BYTES, "bytes_received": _TRANSFER_BYTES}
    finally:
        os.close(binary_fd)


class _NativeWitness:
    """Проверяет удерживаемые echo sockets; конфиги и credentials не читает."""

    def __init__(self, binding: NativeBackendBinding, endpoint: tuple[str, int]) -> None:
        self.binding, self.endpoint = binding, endpoint
        self.capture = None
        self.actor = None
        self.used: set[int] = set()
        self.failed = False

    def __enter__(self):
        from .naive_bridge import BridgeCapture, _pin_actor
        binding = self.binding
        if binding.bridge_port:
            self.capture = BridgeCapture(*self.endpoint, binding.bridge_port,
                caddy_pid=binding.caddy_pid, caddy_sha256=binding.caddy_sha256,
                xray_pid=binding.xray_pid, xray_sha256=binding.xray_sha256)
            self.capture.__enter__()
        else:
            self.actor = _pin_actor(binding.caddy_pid, binding.caddy_sha256, time.monotonic() + 3)
        return self

    def prove(self, peer: socket.socket) -> bool:
        from .naive_bridge import _actor, _owned, _same_actor, _tcp_inode
        if self.failed:
            return False
        try:
            if peer.family != socket.AF_INET or peer.getsockname() != self.endpoint:
                raise ValueError(_ERROR)
            if self.capture is not None:
                if not self.capture.prove(peer):
                    raise ValueError(_ERROR)
            else:
                deadline = time.monotonic() + 2
                inode = _tcp_inode(peer.getpeername(), peer.getsockname(), deadline)
                if inode in self.used or self.actor is None:
                    raise ValueError(_ERROR)
                _owned(self.actor, inode, deadline)
                if (not _same_actor(self.actor, _actor(self.binding.caddy_pid, deadline))
                        or _tcp_inode(peer.getpeername(), peer.getsockname(), deadline) != inode):
                    raise ValueError(_ERROR)
                self.used.add(inode)
            return True
        except Exception:  # noqa: BLE001 — никаких данных процесса в результате.
            self.failed = True
            return False

    def __exit__(self, *args):
        if self.capture is not None:
            self.capture.__exit__(*args)


def _worker(request: dict[str, Any]) -> dict[str, Any]:
    import resource
    if (type(request) is not dict or request.get("sha256") != NAIVE_SHA256
            or not _secret(request.get("username")) or not _secret(request.get("password"))
            or type(request.get("ca_pem")) is not str or len(request["ca_pem"].encode()) > 65536
            or not valid_domain(request.get("sni", "")) or "*" in request["sni"]
            or not _port(request.get("port")) or type(request.get("timeout")) not in {int, float}
            or not _port(request.get('proxy_port', request.get('port')))
            or not math.isfinite(request["timeout"]) or not 3 <= request["timeout"] <= 59):
        raise ValueError(_ERROR)
    if request["address"] != request["sni"]:
        ipaddress.ip_address(request["address"])
    ipaddress.ip_address(request["echo_address"])
    native = None
    if 'native' in request:
        if type(request['native']) is not dict:
            raise ValueError(_ERROR)
        native = NativeBackendBinding(**request['native'])
        if (not _native_valid(native) or type(request['echo_port']) is not int
                or request['echo_port'] != 0 or not _native_echo_address(request['echo_address'])):
            raise ValueError(_ERROR)
    if not (_port(request["echo_port"]) or type(request["echo_port"]) is int
            and request["echo_port"] == 0 and (request["echo_address"] == "127.0.0.1" or native is not None)):
        raise ValueError(_ERROR)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_CPU, (65, 65))
    resource.setrlimit(resource.RLIMIT_FSIZE, (_MAX_NETLOG, _MAX_NETLOG))
    if native is not None:
        from .vpn_probe_echo import LocalProbeEcho
        witness = None
        def verify(peer):
            return witness is not None and witness.prove(peer)
        with LocalProbeEcho(bind_address=request['echo_address'], verify_peer=verify) as echo:
            with _NativeWitness(native, echo.endpoint) as witness:
                result = _worker_exchange(dict(request, echo_port=echo.endpoint[1]))
                if echo.verification_failed or echo.verified_connections != 2 or witness.failed:
                    raise ValueError(_ERROR)
                return result
    if request["echo_port"] == 0:
        from .vpn_probe_echo import LocalProbeEcho
        with LocalProbeEcho() as echo:
            return _worker_exchange(dict(request, echo_address=echo.endpoint[0], echo_port=echo.endpoint[1]))
    return _worker_exchange(request)


def _main() -> int:
    try:
        if sys.platform != "linux" or sys.argv[1:] != ["--worker"]:
            return 2
        data = sys.stdin.buffer.read(_MAX_INPUT + 1)
        if len(data) > _MAX_INPUT:
            return 2
        result = _worker(json.loads(data))
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        return 0
    except BaseException:  # noqa: BLE001 — никакой текст ошибки не выходит из worker.
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
