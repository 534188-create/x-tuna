from __future__ import annotations

import dataclasses
import base64
import json
import os
import socket
import ssl
import hashlib
import shlex
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from .runner import CommandResult, Runner


@dataclasses.dataclass(slots=True)
class BackendProbe:
    """Read-only capability result for an isolated TrustTunnel backend."""

    binary: str = ""
    version: str = ""
    metadata_state: str = "not_observed"
    capability_ready: bool = False
    supports_tcp: bool = False
    supports_http2_connect: bool = False
    supports_standard_uri: bool = False
    supports_config_file: bool = False
    loopback_port: int = 0
    loopback_available: bool = False
    staging_port_state: str = "not_checked"
    protocol_handshake: bool = False
    protocol_probe_state: str = "not_checked"
    live_ready: bool = False
    ready: bool = False
    reasons: list[str] = dataclasses.field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


DEFAULT_BINARY_CANDIDATES = (
    "/opt/trusttunnel/trusttunnel_endpoint",
    "/usr/local/bin/trusttunnel_endpoint",
    "/usr/local/libexec/x-tuna/trusttunnel-compatible",
    "/usr/local/bin/trusttunnel-compatible",
    "/opt/x-tuna/bin/trusttunnel-compatible",
)


def _result_text(result: CommandResult) -> str:
    return f"{result.stdout}\n{result.stderr}".lower()


def _probe_port(port: int, host: str = "127.0.0.1") -> bool:
    if not 1 <= port <= 65535:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) != 0


def _hpack_literal(name: str, value: str) -> bytes:
    """Encode a sensitive HTTP/2 header without relying on third-party h2."""
    name_bytes = name.encode("ascii")
    value_bytes = value.encode("utf-8")
    if len(name_bytes) > 127 or len(value_bytes) > 127:
        raise ValueError("HTTP/2 probe header is too long")
    return b"\x00" + bytes([len(name_bytes)]) + name_bytes + bytes([len(value_bytes)]) + value_bytes


def _http2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    if len(payload) > 0xFFFFFF:
        raise ValueError("HTTP/2 probe frame is too large")
    return struct.pack("!I", len(payload))[1:] + bytes([frame_type, flags]) + struct.pack("!I", stream_id & 0x7FFFFFFF) + payload


def _read_http2_frame(conn: ssl.SSLSocket, timeout: float) -> tuple[int, int, int, bytes]:
    conn.settimeout(timeout)
    header = b""
    while len(header) < 9:
        chunk = conn.recv(9 - len(header))
        if not chunk:
            raise OSError("HTTP/2 peer closed before frame header")
        header += chunk
    length = int.from_bytes(header[:3], "big")
    payload = b""
    while len(payload) < length:
        chunk = conn.recv(length - len(payload))
        if not chunk:
            raise OSError("HTTP/2 peer closed before frame payload")
        payload += chunk
    return header[3], header[4], int.from_bytes(header[5:9], "big") & 0x7FFFFFFF, payload


def http2_connect_roundtrip(
    host: str,
    port: int,
    *,
    username: str,
    password: str,
    target_port: int,
    target_host: str = "127.0.0.1",
    server_name: str | None = None,
    timeout: float = 5.0,
) -> bool:
    """Perform a real TLS/HTTP2 CONNECT and verify a byte round-trip.

    This deliberately does not use a User-Agent or SNI heuristic.  The target
    is supplied by the caller and should be a disposable local echo service.
    """
    authority = f"{target_host}:{int(target_port)}"
    auth = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    headers = b"".join(
        (
            _hpack_literal(":method", "CONNECT"),
            _hpack_literal(":authority", authority),
            _hpack_literal("user-agent", "x-tuna-protocol-probe"),
            _hpack_literal("proxy-authorization", f"Basic {auth}"),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    with socket.create_connection((host, int(port)), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=server_name or host) as conn:
            if conn.selected_alpn_protocol() != "h2":
                return False
            conn.settimeout(timeout)
            conn.sendall(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                + _http2_frame(4, 0, 0, b"")
                + _http2_frame(1, 0x4, 1, headers)
            )
            status_ok = False
            response_data = bytearray()
            for _ in range(24):
                frame_type, flags, stream_id, payload = _read_http2_frame(conn, timeout)
                if stream_id != 1:
                    continue
                if frame_type == 4:
                    continue
                if frame_type == 1 and payload:
                    # HPACK static-table index 8 is the exact :status 200.
                    status_ok = b"\x88" in payload or b"\x08\x03\x32\x30\x30" in payload
                    if status_ok:
                        break
            if not status_ok:
                return False
            marker = b"x-tuna-connect-probe"
            conn.sendall(_http2_frame(0, 0, 1, marker))
            for _ in range(24):
                frame_type, flags, stream_id, payload = _read_http2_frame(conn, timeout)
                if frame_type == 0 and stream_id == 1:
                    response_data.extend(payload)
                    if marker in response_data:
                        return True
                if frame_type == 7:
                    return False
            return False


def run_endpoint_roundtrip(
    binary: str | Path,
    vpn_config: str | Path,
    hosts_config: str | Path,
    *,
    username: str,
    password: str,
    listen_port: int,
    server_name: str = "127.0.0.1",
    timeout: float = 15.0,
) -> bool:
    """Start an endpoint in staging and perform a real HTTP/2 CONNECT test.

    The endpoint is given the official positional TOML arguments.  The target
    is a disposable local echo socket, so the probe never reaches the public
    network and cannot alter the live ingress.
    """
    if not username or not password or not 1 <= int(listen_port) <= 65535:
        return False

    ready = threading.Event()
    stop = threading.Event()
    target_port: list[int] = []

    def echo_server() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            target_port.append(server.getsockname()[1])
            server.settimeout(0.25)
            ready.set()
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(1.0)
                    while not stop.is_set():
                        try:
                            data = conn.recv(65536)
                        except socket.timeout:
                            continue
                        if not data:
                            break
                        conn.sendall(data)
                return

    echo = threading.Thread(target=echo_server, name="x-tuna-tt-echo", daemon=True)
    echo.start()
    process: subprocess.Popen[str] | None = None
    try:
        if not ready.wait(2.0):
            return False
        process = subprocess.Popen(
            [
                str(Path(binary)),
                str(Path(vpn_config)),
                str(Path(hosts_config)),
                "--loglvl",
                "info",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            if not _probe_port(int(listen_port)):
                try:
                    return http2_connect_roundtrip(
                        "127.0.0.1",
                        int(listen_port),
                        username=username,
                        password=password,
                        target_port=target_port[0],
                        server_name=server_name,
                        timeout=min(5.0, max(0.5, deadline - time.monotonic())),
                    )
                except (OSError, ValueError, ssl.SSLError):
                    return False
            time.sleep(0.1)
        return False
    finally:
        stop.set()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        echo.join(timeout=1)


def probe_endpoint_from_manifest(
    manifest: dict[str, Any],
    *,
    binary: str,
    listen_port: int,
    timeout: float = 20.0,
) -> bool:
    """Run the pinned endpoint against disposable loopback configuration.

    This is deliberately separate from production rendering.  The probe uses
    temporary credentials and a temporary echo target, and never binds the
    public address or port.
    """
    credentials = (manifest.get("trusttunnel_backend") or {}).get("credentials") or []
    if not credentials:
        return False
    first = credentials[0]
    username = str(first.get("username") or "")
    password = str(first.get("password") or "")
    if not username or not password:
        return False

    backend = dict(manifest.get("trusttunnel_backend") or {})
    backend["listen_host"] = "127.0.0.1"
    backend["listen_port"] = int(listen_port)
    backend["decoy_address"] = "127.0.0.1:9"
    probe_manifest = dict(manifest)
    probe_manifest["trusttunnel_backend"] = backend

    from . import trusttunnel_backend as module

    with tempfile.TemporaryDirectory(prefix="x-tuna-tt-probe-") as directory:
        root = Path(directory)
        vpn = root / "vpn.toml"
        hosts = root / "hosts.toml"
        credentials_file = root / "credentials.toml"
        rules_file = root / "rules.toml"
        vpn_text = module.render_backend_vpn_toml(probe_manifest).decode("utf-8")
        vpn_text = vpn_text.replace(
            'credentials_file = "/etc/x-tuna/trusttunnel/credentials.toml"',
            f'credentials_file = {_toml_string(str(credentials_file))}',
        ).replace(
            'rules_file = "/etc/x-tuna/trusttunnel/rules.toml"',
            f'rules_file = {_toml_string(str(rules_file))}',
        ).replace(
            "allow_private_network_connections = false",
            "allow_private_network_connections = true",
        )
        vpn.write_text(vpn_text, encoding="utf-8")
        hosts.write_bytes(module.render_backend_hosts_toml(probe_manifest))
        credentials_file.write_bytes(module.render_backend_credentials_toml(probe_manifest))
        rules_file.write_bytes(module.render_backend_rules_toml(probe_manifest))
        return run_endpoint_roundtrip(
            binary,
            vpn,
            hosts,
            username=username,
            password=password,
            listen_port=int(listen_port),
            server_name=str(backend.get("public_domain") or "127.0.0.1"),
            timeout=timeout,
        )


def probe_backend(
    runner: Runner,
    *,
    binary: str | Path | None = None,
    loopback_port: int = 0,
    protocol_host: str | None = None,
    protocol_username: str | None = None,
    protocol_password: str | None = None,
    protocol_target_port: int = 0,
) -> BackendProbe:
    """Probe a candidate without installing, starting, or changing anything.

    The backend must explicitly advertise the two properties that matter here.
    A generic TrustTunnel binary is deliberately not accepted as compatible.
    """

    selected = str(binary or os.environ.get("X_TUNA_TRUSTTUNNEL_BACKEND", ""))
    candidates = (selected,) if selected else DEFAULT_BINARY_CANDIDATES
    path = next((item for item in candidates if item and Path(item).is_file()), "")
    result = BackendProbe(binary=path, loopback_port=int(loopback_port or 0))
    if not path:
        result.reasons.append("совместимый backend не найден в разрешённых путях")
        return result

    version = runner.run([path, "--version"], check=False, timeout=10)
    help_result = runner.run([path, "--help"], check=False, timeout=10)
    result.metadata_state = (
        "observed" if version.returncode == 0 and help_result.returncode == 0 else "error"
    )
    result.version = (version.stdout or version.stderr).strip().splitlines()[0][:160] if (version.stdout or version.stderr).strip() else "unknown"
    advertised = _result_text(help_result)
    official_endpoint = Path(path).name == "trusttunnel_endpoint"
    result.supports_tcp = "tcp" in advertised or official_endpoint
    result.supports_http2_connect = (
        "http2-connect" in advertised or "http/2 connect" in advertised or official_endpoint
    )
    result.supports_standard_uri = (
        "standard-uri" in advertised or "throne-uri" in advertised or official_endpoint
    )
    # The official endpoint receives two positional TOML paths.  Do not
    # require a non-existent --config option for that implementation.
    positional_config = (
        Path(path).name == "trusttunnel_endpoint"
        or ("vpn.toml" in advertised and "hosts.toml" in advertised)
        or "positional" in advertised
    )
    result.supports_config_file = (
        "--config" in advertised
        or "config-file" in advertised
        or positional_config
    )
    result.capability_ready = bool(
        result.metadata_state == "observed"
        and result.supports_tcp
        and result.supports_http2_connect
        and result.supports_standard_uri
        and result.supports_config_file
    )
    if result.loopback_port:
        result.loopback_available = _probe_port(result.loopback_port)
        result.staging_port_state = "available" if result.loopback_available else "occupied"
    if protocol_host and protocol_username and protocol_password and protocol_target_port:
        try:
            result.protocol_handshake = http2_connect_roundtrip(
                protocol_host,
                result.loopback_port,
                username=protocol_username,
                password=protocol_password,
                target_port=protocol_target_port,
            )
            result.protocol_probe_state = (
                "observed" if result.protocol_handshake else "error"
            )
        except (OSError, ValueError, ssl.SSLError):
            result.protocol_handshake = False
            result.protocol_probe_state = "error"
    else:
        result.reasons.append(
            "реальный HTTPS/h2 CONNECT не проверен: нужны тестовые credentials и echo-target"
        )

    if not result.supports_tcp:
        result.reasons.append("backend не объявляет поддержку TCP")
    if not result.supports_http2_connect:
        result.reasons.append("backend не объявляет поддержку HTTP/2 CONNECT")
    if not result.supports_standard_uri:
        result.reasons.append("backend не объявляет стандартный URI для Throne")
    if not result.supports_config_file:
        result.reasons.append("backend не объявляет запуск через файл конфигурации")
    if (
        result.staging_port_state == "occupied"
        and result.protocol_probe_state == "not_checked"
    ):
        result.reasons.append(
            f"loopback-порт {result.loopback_port} занят; для staging нужен другой порт"
        )
    if result.protocol_probe_state == "error":
        result.reasons.append("backend не прошёл реальный TLS/HTTP/2 CONNECT round-trip")
    result.live_ready = bool(result.capability_ready and result.protocol_handshake)
    result.ready = result.live_ready
    if not result.ready and not result.reasons:
        result.reasons.append("backend не прошёл capability probe")
    return result


def validate_backend_manifest(manifest: dict[str, Any], probe: BackendProbe) -> None:
    """Reject an unproven backend before it can enter generated configuration."""

    backend = (manifest.get("components") or {}).get("trusttunnel_backend")
    if not backend:
        return
    if not probe.ready or not probe.protocol_handshake:
        detail = "; ".join(probe.reasons) or "capability probe не пройден"
        raise ValueError(f"TrustTunnel backend запрещён: {detail}")


def pin_backend(binary: str | Path, *, source: str = "local") -> dict[str, str]:
    """Return a non-secret immutable reference to a locally supplied binary."""

    path = Path(binary).resolve()
    if not path.is_file() or path.is_symlink():
        raise ValueError("TrustTunnel backend must be a regular local file")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"binary_path": str(path), "sha256": digest, "source": source}


def render_backend_config(manifest: dict[str, Any]) -> bytes:
    backend = manifest["trusttunnel_backend"]
    payload = {
        "listen": f"{backend['listen_host']}:{int(backend['listen_port'])}",
        "public_domain": str(backend["public_domain"]).lower(),
        "public_port": int(backend.get("public_port", 443)),
        "transport": "tcp",
        "http2_connect": True,
        "browser_decoy": True,
    }
    return (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _toml_string(value: str) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def render_backend_vpn_toml(manifest: dict[str, Any]) -> bytes:
    """Render the real TrustTunnel endpoint settings file."""
    backend = manifest["trusttunnel_backend"]
    listen = f"{backend['listen_host']}:{int(backend['listen_port'])}"
    lines = [
        f"listen_address = {_toml_string(listen)}",
        "ipv6_available = false",
        "allow_private_network_connections = false",
        "credentials_file = \"/etc/x-tuna/trusttunnel/credentials.toml\"",
        "rules_file = \"/etc/x-tuna/trusttunnel/rules.toml\"",
        "auth_failure_status_code = 407",
        "[listen_protocols.http1]",
        "[listen_protocols.http2]",
        "initial_connection_window_size = 8388608",
        "initial_stream_window_size = 131072",
        "max_concurrent_streams = 1000",
        "non_connect_auth_failure_status_code = 404",
        "[reverse_proxy]",
        f"server_address = {_toml_string(str(backend.get('decoy_address', '127.0.0.1:8446')))}",
        "path_mask = \"/\"",
        "h3_backward_compatibility = false",
        "[forward_protocol]",
        "direct = {}",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def render_backend_hosts_toml(manifest: dict[str, Any]) -> bytes:
    backend = manifest["trusttunnel_backend"]
    cert = manifest["certificates"]["cert_path"]
    key = manifest["certificates"]["key_path"]
    domain = str(backend["public_domain"]).lower()
    return (
        "[[main_hosts]]\n"
        f"hostname = {_toml_string(domain)}\n"
        f"cert_chain_path = {_toml_string(cert)}\n"
        f"private_key_path = {_toml_string(key)}\n"
    ).encode("utf-8")


def render_backend_credentials_toml(manifest: dict[str, Any]) -> bytes:
    credentials = manifest["trusttunnel_backend"].get("credentials") or []
    lines: list[str] = []
    for item in credentials:
        username = str(item.get("username") or "")
        password = str(item.get("password") or "")
        if not username or not password:
            raise ValueError("TrustTunnel backend credentials require username and password")
        lines.extend([
            "[[client]]",
            f"username = {_toml_string(username)}",
            f"password = {_toml_string(password)}",
            "",
        ])
    return "\n".join(lines).encode("utf-8")


def read_backend_credentials(path: str | Path) -> list[dict[str, str]]:
    """Read only the backend credential file; callers must keep it private."""
    result: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line == "[[client]]":
            current = {}
            result.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() not in {"username", "password"}:
            continue
        current[key.strip()] = json.loads(value.strip())
    return [item for item in result if item.get("username") and item.get("password")]


def discover_existing_backend_credentials(root: str | Path = "/") -> list[dict[str, str]]:
    """Discover existing LucX TrustTunnel credentials without printing them."""
    base = Path(root)
    candidates: list[Path] = []
    for directory in (
        base / "usr/local/x-ui/bin/tunnel",
        base / "etc/x-ui",
        base / "etc/trusttunnel",
    ):
        if directory.is_dir():
            candidates.extend(directory.glob("trusttunnel-*-credentials.toml"))
            candidates.extend(directory.glob("*trust*credentials*.toml"))
    for path in sorted(set(candidates)):
        try:
            values = read_backend_credentials(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if values:
            return values
    return []


def render_backend_rules_toml(manifest: dict[str, Any]) -> bytes:
    """Allow authenticated clients; no client-random-prefix dependency."""
    return b"[[rule]]\naction = \"allow\"\n"


def render_backend_unit(manifest: dict[str, Any]) -> bytes:
    backend = manifest["trusttunnel_backend"]
    binary = shlex.quote(str(backend["binary_path"]))
    return f"""[Unit]
Description=Isolated TrustTunnel compatible TCP backend
After=network.target

[Service]
Type=simple
ExecStart={binary} /etc/x-tuna/trusttunnel/vpn.toml /etc/x-tuna/trusttunnel/hosts.toml --loglvl info
Restart=on-failure
RestartSec=3s
User=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
StateDirectory=x-tuna/trusttunnel
ReadOnlyPaths=/etc/x-tuna/trusttunnel
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
""".encode("utf-8")
