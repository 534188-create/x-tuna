"""Штатная ограниченная Xray-проба; секретный источник подключается только кодом."""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import valid_domain
from .routing_profiles import routing_fingerprint
from .runner import Runner

XRAY_SHA256 = "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed"
_PHASES = frozenset({"direct", "staging", "public", "rollback"})
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_INPUT = 128 * 1024
_PAYLOAD_BYTES = 8192


@dataclass(frozen=True, slots=True)
class XrayProbeCredential:
    """Источник подтверждает именно простой профиль без flow и auth-расширений."""
    user_id: str = field(repr=False)
    profile_fingerprint: str
    ca_pem: str = field(default="", repr=False)
    policy_fingerprint: str = field(default="", repr=False)


@dataclass(frozen=True, slots=True)
class XrayProbeContext:
    binary_path: Path
    binary_sha256: str
    credential_provider: Callable[[dict[str, Any]], XrayProbeCredential | None] = field(repr=False)
    echo_address: str = field(repr=False)
    echo_port: int
    shared_tcp_port: int = 443
    timeout: float = 15.0
    # Переадресация возможна лишь в direct/staging и никогда не берётся из manifest.
    dial_target_provider: Callable[[dict[str, Any], str], tuple[str, int]] | None = field(default=None, repr=False)
    # Только код уже изолированного coordinator может наследовать его группу.
    coordinator_pid: int | None = field(default=None, repr=False)
    # Только штатный registry передаёт ленивый read-only audit собственного IP.
    echo_address_provider: Callable[[], str] | None = field(default=None, repr=False)


def _port(value: Any) -> bool:
    return type(value) is int and 1 <= value <= 65535


def _address(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 253:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return valid_domain(value) and not value.startswith("*.")


def _endpoint_valid(endpoint: Any) -> bool:
    return (isinstance(endpoint, dict) and _address(endpoint.get("address"))
        and _port(endpoint.get("port")) and endpoint.get("valid", True) is True
        and type(endpoint.get("host_id")) is int and endpoint["host_id"] >= 0
        and isinstance(endpoint.get("sni"), str) and valid_domain(endpoint["sni"])
        and not endpoint["sni"].startswith("*.") and endpoint.get("keep_sni_blank") is False
        and endpoint.get("sni_source") in {"address", "explicit", "inherited"}
        and (endpoint.get("http_host", "") == "" or _address(endpoint.get("http_host"))))


def _endpoint_fingerprint(endpoint: dict[str, Any]) -> str:
    identity = {key: endpoint.get(key) for key in (
        "host_id", "address", "port", "sni", "sni_source", "keep_sni_blank", "http_host")}
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _simple_profile(protocol: dict[str, Any]) -> bool:
    transport = protocol.get("transport")
    if (protocol.get("protocol") not in {"vless", "vmess"}
            or protocol.get("security") != "tls" or protocol.get("network") != "tcp"
            or transport not in {"ws", "httpupgrade", "grpc", "xhttp"}
            or protocol.get("flow") or protocol.get("udp_over_tcp")
            or protocol.get("enable") is False):
        return False
    mode = protocol.get("transport_mode", "")
    if mode not in ({"", "auto", "packet-up", "stream-up", "stream-one"} if transport == "xhttp" else {""}):
        return False
    expected_alpn = ["http/1.1"] if transport in {"ws", "httpupgrade"} else ["h2"]
    if protocol.get("alpn") != expected_alpn:
        return False
    path = protocol.get("transport_path")
    pattern = r"[A-Za-z0-9_.-]+" if transport == "grpc" else r"/[A-Za-z0-9/_.~-]*"
    if not isinstance(path, str) or len(path) > 1024 or not re.fullmatch(pattern, path):
        return False
    if transport == "xhttp" and path == "/":
        return False
    details = protocol.get("transport_details", {})
    allowed = {"support_status", "settings_keys", "settings_fingerprint", "stream_fingerprint",
               "extra", "masks", "unsupported_settings", "unknown_stream_fields",
               "conflicting_settings_alias", "requires_adapter_review", "inbound_settings_fingerprint"}
    if not isinstance(details, dict) or set(details) - allowed:
        return False
    if "inbound_settings_fingerprint" in details and (
            not isinstance(details["inbound_settings_fingerprint"], str)
            or not _FINGERPRINT.fullmatch(details["inbound_settings_fingerprint"])):
        return False
    if any(details.get(key) for key in ("requires_adapter_review", "unsupported_settings",
                                       "unknown_stream_fields", "conflicting_settings_alias")):
        return False
    for key in ("extra", "masks"):
        item = details.get(key, {})
        if not isinstance(item, dict) or item.get("present"):
            return False
    keys = details.get("settings_keys", [])
    allowed_keys = {"ws": {"path"}, "httpupgrade": {"path", "host"},
                    "grpc": {"serviceName", "authority"}, "xhttp": {"path", "host", "mode"}}
    if not isinstance(keys, list) or any(key not in allowed_keys[transport] for key in keys):
        return False
    endpoints = protocol.get("public_endpoints")
    hosts = protocol.get("transport_hosts", [])
    if (not isinstance(hosts, list) or any(not _address(host) for host in hosts)
            or (hosts and isinstance(endpoints, list) and any(
                (endpoint.get("http_host") or endpoint.get("sni")) not in hosts
                for endpoint in endpoints if isinstance(endpoint, dict)))):
        return False
    return (isinstance(endpoints, list) and bool(endpoints) and all(map(_endpoint_valid, endpoints))
        and type(protocol.get("inbound_id")) is int and protocol["inbound_id"] > 0)


def _binary_identity(info: os.stat_result) -> tuple[Any, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_gid)


def _open_binary(path: Path, expected: str) -> int:
    if not path.is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Неверное закрепление клиентского инструмента")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024 * 1024:
            raise ValueError("Неверный тип клиентского инструмента")
        if os.name == "posix" and (info.st_mode & 0o022 or not info.st_mode & 0o111
                                  or info.st_uid not in {0, os.geteuid()}):
            raise ValueError("Небезопасные права клиентского инструмента")
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        if digest.hexdigest() != expected or _binary_identity(os.fstat(fd)) != _binary_identity(info):
            raise ValueError("Клиентский инструмент изменился")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


class XrayVPNObserver:
    def __init__(self, context: XrayProbeContext) -> None:
        self.context = context

    def _worker_isolation(self, protocol: dict[str, Any]) -> bool:
        owner = self.context.coordinator_pid
        if owner is None:
            return True
        if (type(owner) is not int or owner <= 1 or sys.platform != "linux"
                or protocol.get("acceptance_phase") not in {"direct", "staging"}
                or owner != os.getpid() or owner != os.getpgrp() or owner != os.getsid(0)):
            raise ValueError("Нет владельца изолированной группы staging")
        return False

    def _credential(self, protocol: dict[str, Any]) -> XrayProbeCredential:
        # Отказ до чтения секретного источника и запуска вложенных процессов.
        self._worker_isolation(protocol)
        context = self.context
        if (sys.platform != "linux" or not _simple_profile(protocol)
                or not _port(context.shared_tcp_port) or not (_port(context.echo_port)
                    or (type(context.echo_port) is int and context.echo_port == 0))
                or not 4 <= context.timeout <= 60 or not math.isfinite(context.timeout)):
            raise ValueError("Профиль не поддерживается штатной пробой")
        # Назначение пробы выбирается доверенным кодом; DNS для echo не используется.
        self._echo_target(protocol)
        credential = context.credential_provider(copy.deepcopy(protocol))
        if (not isinstance(credential, XrayProbeCredential)
                or credential.profile_fingerprint != routing_fingerprint(protocol, context.shared_tcp_port)
                or str(uuid.UUID(credential.user_id)) != credential.user_id
                or not isinstance(credential.ca_pem, str) or len(credential.ca_pem) > 65536):
            raise ValueError("Источник клиента не подтвердил текущий профиль")
        fd = _open_binary(Path(context.binary_path), context.binary_sha256)
        os.close(fd)
        return credential

    def _echo_target(self, protocol):
        context = self.context
        address = context.echo_address_provider() if context.echo_address_provider else context.echo_address
        ipaddress.ip_address(address)
        if context.echo_port != 0 or address == '127.0.0.1':
            return address, None
        from .vpn_probe_backend import valid_echo_address
        if not valid_echo_address(address):
            raise ValueError('Не подтверждён собственный адрес echo')
        host, port = protocol.get('internal_host'), protocol.get('internal_port')
        if host in {'0.0.0.0', '::', '[::]', 'localhost', ''}:
            host = '127.0.0.1'
        if not _port(port) or not isinstance(host, str):
            raise ValueError('Не подтверждён backend echo')
        ipaddress.ip_address(host)
        return address, (host, port)

    def supports(self, protocol: dict[str, Any]) -> bool:
        """До commit проверяет полный профиль, источник и hash; процессы не запускает."""
        try:
            self._credential(protocol)
            return True
        except Exception:  # noqa: BLE001 — источник может выбросить ошибку с секретом.
            return False

    def _identity_valid(self, protocol: dict[str, Any], credential: XrayProbeCredential) -> bool:
        endpoint, identity = protocol.get("acceptance_endpoint"), protocol.get("acceptance_target")
        return (protocol.get("acceptance_phase") in _PHASES and isinstance(identity, dict)
            and _endpoint_valid(endpoint) and endpoint in protocol["public_endpoints"]
            and identity.get("inbound_id") == protocol["inbound_id"]
            and identity.get("profile_fingerprint") == credential.profile_fingerprint
            and identity.get("endpoint_fingerprint") == _endpoint_fingerprint(endpoint))

    def preflight(self, protocol: dict[str, Any], runner: Runner) -> bool:
        """Только чтение источника/hash/endpoint; без subprocess, проб или записей."""
        try:
            if not self._identity_valid(protocol, self._credential(protocol)):
                return False
            self._dial_target(protocol)
            return True
        except Exception:  # noqa: BLE001 — наружу выходит только результат проверки.
            return False

    def _dial_target(self, protocol: dict[str, Any]) -> tuple[str, int]:
        phase = protocol["acceptance_phase"]
        if phase in {"direct", "staging"}:
            if self.context.dial_target_provider is None:
                raise ValueError("Для этой фазы отсутствует проверенная точка подключения")
            dial = self.context.dial_target_provider(copy.deepcopy(protocol), phase)
            if not isinstance(dial, tuple) or len(dial) != 2 or not _port(dial[1]):
                raise ValueError("Некорректная точка подключения пробы")
            ipaddress.ip_address(dial[0])
            return dial
        endpoint = protocol["acceptance_endpoint"]
        return endpoint["address"], endpoint["port"]

    def __call__(self, protocol: dict[str, Any], runner: Runner) -> dict[str, Any]:
        phase = protocol.get("acceptance_phase")
        phase = phase if isinstance(phase, str) else ""
        identity = protocol.get("acceptance_target", {})
        result: dict[str, Any] = {"state": "not_tested", "phase": phase if phase in _PHASES else "",
            "functional": False, "public": phase in {"public", "rollback"},
            "authenticated": False, "bytes_sent": 0, "bytes_received": 0}
        if isinstance(identity, dict):
            if type(identity.get("inbound_id")) is int:
                result["inbound_id"] = identity["inbound_id"]
            for name in ("profile_fingerprint", "endpoint_fingerprint"):
                if isinstance(identity.get(name), str) and _FINGERPRINT.fullmatch(identity[name]):
                    result[name] = identity[name]
        if runner.dry_run or phase not in _PHASES:
            return result
        try:
            credential = self._credential(protocol)
            endpoint = protocol.get("acceptance_endpoint")
            if not self._identity_valid(protocol, credential):
                return result
            dial = self._dial_target(protocol)
            echo_address, echo_backend = self._echo_target(protocol)
            request = {"binary": str(self.context.binary_path), "sha256": self.context.binary_sha256,
                "protocol": protocol["protocol"], "transport": protocol["transport"],
                "path": protocol["transport_path"], "mode": protocol.get("transport_mode") or "auto",
                "alpn": protocol["alpn"], "sni": endpoint["sni"],
                "host": endpoint.get("http_host") or endpoint["sni"],
                "address": dial[0], "port": dial[1], "user_id": credential.user_id,
                "ca_pem": credential.ca_pem, "echo_address": echo_address,
                "echo_port": self.context.echo_port, "timeout": self.context.timeout - 1}
            if echo_backend is not None:
                request['echo_backend'] = list(echo_backend)
            encoded = json.dumps(request, separators=(",", ":"), allow_nan=False)
            if len(encoded.encode("utf-8")) > _MAX_INPUT:
                return result
            # Изолированный startup исключает CWD, PYTHONPATH и пользовательский site.
            # Путь берётся из загруженного пакета, включая установочный zip payload.
            bootstrap = ("import sys,runpy;sys.path.insert(0,sys.argv[1]);"
                "sys.argv=['x-tuna-vpn-probe','--worker'];"
                "runpy.run_module('lucx_post_configurator.vpn_probes',run_name='__main__')")
            package_root = str(Path(__file__).absolute().parent.parent)
            completed = runner.run_bounded([sys.executable, "-I", "-S", "-c", bootstrap, package_root],
                input_text=encoded, timeout=self.context.timeout, max_output_bytes=1024,
                isolate_process_group=self._worker_isolation(protocol), inherit_env=False, check=False)
            result["state"] = "failed"
            observed = json.loads(completed.stdout) if completed.returncode == 0 else {}
            if (isinstance(observed, dict) and observed.get("authenticated") is True
                    and all(type(observed.get(key)) is int and 0 < observed[key] <= _PAYLOAD_BYTES * 2
                            for key in ("bytes_sent", "bytes_received"))):
                if (self._credential(protocol) != credential or self._dial_target(protocol) != dial
                        or self._echo_target(protocol) != (echo_address, echo_backend)):
                    raise ValueError("Источник или точка подключения изменились во время VPN-пробы")
                result.update(state="healthy", functional=True, authenticated=True,
                    bytes_sent=observed["bytes_sent"], bytes_received=observed["bytes_received"])
        except Exception:  # noqa: BLE001 — исключения источника/процесса не публикуются.
            result["state"] = "failed"
        return result


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("Истекло время VPN-пробы")
    return value


def _receive(sock: socket.socket, count: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < count:
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise OSError("Обмен VPN не завершён")
        result.extend(chunk)
    return bytes(result)


def _roundtrip(port: int, auth: tuple[bytes, bytes], request: dict[str, Any], deadline: float,
               *, local_peers: list[int] | None = None) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=_remaining(deadline)) as sock:
        if local_peers is not None:
            local_peers.append(sock.getsockname()[1])
        sock.sendall(b"\x05\x01\x02")
        if _receive(sock, 2, deadline) != b"\x05\x02":
            raise OSError("SOCKS не подтвердил защищённую сессию")
        username, password = auth
        sock.sendall(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
        if _receive(sock, 2, deadline) != b"\x01\x00":
            raise OSError("SOCKS не принял сессию")
        address = ipaddress.ip_address(request["echo_address"])
        sock.sendall(b"\x05\x01\x00" + bytes([1 if address.version == 4 else 4])
                     + address.packed + struct.pack("!H", request["echo_port"]))
        response = _receive(sock, 4, deadline)
        if response[:3] != b"\x05\x00\x00" or response[3] not in {1, 3, 4}:
            raise OSError("SOCKS не установил VPN-соединение")
        length = 4 if response[3] == 1 else 16 if response[3] == 4 else _receive(sock, 1, deadline)[0]
        _receive(sock, length + 2, deadline)
        payload = secrets.token_bytes(_PAYLOAD_BYTES)
        sock.settimeout(_remaining(deadline))
        sock.sendall(payload)
        if not secrets.compare_digest(_receive(sock, len(payload), deadline), payload):
            raise OSError("VPN вернул неверный ответ на проверочные данные")


def _client_config(request: dict[str, Any], user_id: str, port: int, auth: tuple[bytes, bytes]) -> dict[str, Any]:
    transport = request["transport"]
    tls = {"serverName": request["sni"], "allowInsecure": False, "alpn": request["alpn"]}
    if request["ca_pem"]:
        tls["certificates"] = [{"certificate": request["ca_pem"].splitlines(), "usage": "verify"}]
    stream = {"network": transport, "security": "tls", "tlsSettings": tls}
    if transport == "ws":
        stream["wsSettings"] = {"path": request["path"], "headers": {"Host": request["host"]}}
    elif transport == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": request["path"], "host": request["host"]}
    elif transport == "grpc":
        stream["grpcSettings"] = {"serviceName": request["path"], "authority": request["host"]}
    else:
        stream["xhttpSettings"] = {"path": request["path"], "host": request["host"], "mode": request["mode"]}
    user: dict[str, Any] = {"id": user_id}
    user.update({"encryption": "none"} if request["protocol"] == "vless" else {"alterId": 0, "security": "auto"})
    return {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": port,
        "protocol": "socks", "settings": {"auth": "password", "udp": False,
            "accounts": [{"user": auth[0].decode(), "pass": auth[1].decode()}]}}],
        "outbounds": [{"tag": "vpn", "protocol": request["protocol"], "settings": {
            "vnext": [{"address": request["address"], "port": request["port"], "users": [user]}]},
            "streamSettings": stream}, {"tag": "reject", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field",
            "ip": [request["echo_address"]], "port": str(request["echo_port"]), "outboundTag": "vpn"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "reject"}]}}


class _RejectedExchange(OSError):
    """Клиент запущен, но VPN-передача не принята."""


def _attempt(request: dict[str, Any], binary_fd: int, user_id: str, deadline: float, *, reconnect: bool) -> None:
    import fcntl
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    auth = (secrets.token_hex(16).encode(), secrets.token_hex(24).encode())
    config = _client_config(request, user_id, port, auth)
    fd = os.memfd_create("x-tuna-probe", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    process = None
    try:
        os.write(fd, json.dumps(config, separators=(",", ":")).encode())
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        process = subprocess.Popen([f"/proc/self/fd/{binary_fd}", "run", "-format", "json",
            "-config", f"/proc/self/fd/{fd}"], pass_fds=(fd, binary_fd), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        while True:
            _remaining(deadline)
            if process.poll() is not None:
                raise OSError("Клиент VPN не запустился")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=min(.1, _remaining(deadline))):
                    break
            except OSError:
                time.sleep(min(.02, _remaining(deadline)))
        try:
            _roundtrip(port, auth, request, deadline)
            if reconnect:
                _roundtrip(port, auth, request, deadline)
        except OSError:
            raise _RejectedExchange("VPN не подтвердил обмен") from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=.2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=.2)
        os.close(fd)


def _worker(request: dict[str, Any]) -> dict[str, Any]:
    import resource
    # Резерв Go runtime требует адресного пространства; размер кучи ограничен отдельно.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_DATA, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (65, 65))
    if request.get("echo_port") == 0:
        from .vpn_probe_echo import LocalProbeEcho
        if request.get('echo_address') != '127.0.0.1':
            from .vpn_probe_backend import XrayEchoWitness, valid_echo_address
            backend = request.get('echo_backend')
            if (not valid_echo_address(request.get('echo_address')) or type(backend) is not list
                    or len(backend) != 2 or not _port(backend[1]) or type(backend[0]) is not str):
                raise ValueError('Не подтверждён backend собственного echo')
            witness = None
            def verify(peer):
                return witness is not None and witness.prove(peer)
            with LocalProbeEcho(bind_address=request['echo_address'], verify_peer=verify) as echo:
                with XrayEchoWitness(*backend, echo.endpoint) as witness:
                    result = _worker_exchange(dict(request, echo_port=echo.endpoint[1]))
            if echo.verification_failed or echo.verified_connections != 2:
                raise ValueError('Не подтверждён обмен собственного echo')
            witness.verify()
            return result
        with LocalProbeEcho() as echo:
            local = dict(request, echo_address=echo.endpoint[0], echo_port=echo.endpoint[1])
            return _worker_exchange(local)
    return _worker_exchange(request)


def _worker_exchange(request: dict[str, Any]) -> dict[str, Any]:
    deadline = time.monotonic() + request["timeout"]
    binary_fd = _open_binary(Path(request["binary"]), request["sha256"])
    try:
        # Положительная передача доказывает auth только вместе с отрицательным контролем.
        wrong = str(uuid.uuid4())
        try:
            _attempt(request, binary_fd, wrong, min(deadline, time.monotonic() + 2), reconnect=False)
        except _RejectedExchange:
            pass
        else:
            raise OSError("Endpoint принял неверного VPN-клиента")
        _attempt(request, binary_fd, request["user_id"], deadline, reconnect=True)
        checked = _open_binary(Path(request["binary"]), request["sha256"])
        try:
            if _binary_identity(os.fstat(checked)) != _binary_identity(os.fstat(binary_fd)):
                raise OSError("Клиентский инструмент изменился")
        finally:
            os.close(checked)
        return {"authenticated": True, "bytes_sent": _PAYLOAD_BYTES * 2, "bytes_received": _PAYLOAD_BYTES * 2}
    finally:
        os.close(binary_fd)


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
    except BaseException:  # noqa: BLE001 — stderr worker никогда не содержит секреты.
        # Даже текст исключения Xray/источника не входит в stderr или receipt.
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
