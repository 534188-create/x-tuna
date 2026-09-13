from __future__ import annotations

import ipaddress
import hashlib
import json
import re
import shutil
import sqlite3
import stat
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .models import Audit, Inbound, normalize_protocol, valid_domain
from .naive_frontend import supports_native_decoy
from .extended_decoys import exact_client_random_prefix
from .diagnostics import stable_fingerprint
from .targetfs import TargetFS


ALLOWED_SETTING_KEYS = {
    "webListen",
    "webDomain",
    "webPort",
    "webBasePath",
    "webCertFile",
    "webKeyFile",
    "subEnable",
    "subListen",
    "subPort",
    "subPath",
    "subDomain",
    "subCertFile",
    "subKeyFile",
    "subAwgPath",
    "subClashPath",
    "subJsonPath",
    "subURI",
    "subJsonURI",
    "subClashURI",
    "subAwgURI",
}
REQUIRED_INBOUND_COLUMNS = {"id", "protocol", "port"}
CADDYFILE_CANDIDATES = (
    "/etc/x-ui/naive/Caddyfile",
    "/etc/x-ui/caddy/Caddyfile",
    "/etc/caddy/Caddyfile",
)
LUCX_TUNNEL_DIRECTORY = "/usr/local/x-ui/bin/tunnel"
NAIVE_BINARY_DIRECTORIES = (
    "/usr/local/x-ui/bin",
    "/opt/x-ui/bin",
    "/usr/lib/x-ui/bin",
)
MAX_CADDY_CAPABILITY_BYTES = 1024 * 1024
HOST_ROUTING_COLUMNS = {
    "sni", "override_sni_from_address", "keep_sni_blank", "host", "host_header",
    "path", "security", "alpn", "fingerprint", "pinned_peer_cert_sha256",
    "verify_peer_cert_by_name", "allow_insecure", "ech_config_list", "mux_params",
    "sockopt_params", "final_mask", "vless_route", "mihomo_ip_version",
    "mihomo_x25519", "shuffle_host", "node_guids", "exclude_from_sub_types",
}
HOST_METADATA_COLUMNS = {
    "id", "inbound_id", "address", "port", "group_id", "sort_order", "remark",
    "server_description", "is_disabled", "is_hidden", "tags", "created_at", "updated_at",
}


def _host_override_active(name: str, value: Any) -> bool:
    """Пустые значения панели не меняют профиль; остальные требуют адаптера."""
    if name not in HOST_ROUTING_COLUMNS:
        return value is not None and value != ""
    if value is None or value == "" or value is False or value == 0:
        return False
    if isinstance(value, str):
        value = value.strip()
        if not value or (name == "security" and value == "same"):
            return False
        if name in {"allow_insecure", "mihomo_x25519", "shuffle_host"}:
            return value.lower() not in {"false", "0"}
        if name in {"alpn", "pinned_peer_cert_sha256", "node_guids", "exclude_from_sub_types"}:
            try:
                return json.loads(value) not in (None, [])
            except (ValueError, TypeError):
                return True
    return True


def _host_override_facts(row: sqlite3.Row) -> dict[str, Any]:
    """Значения неизвестных overrides остаются только в отпечатке, вне audit."""
    values = dict(row)
    legacy = str(values.get("host") or "").strip()
    modern = str(values.get("host_header") or "").strip()
    authority = modern or legacy
    normalized = _normalize_host(authority)
    unsupported = []
    if (legacy and modern and legacy.lower() != modern.lower()) or (
        authority and authority.lower().rstrip(".") != normalized.rstrip(".")
    ):
        unsupported.append("host_header")
    represented = {"sni", "override_sni_from_address", "keep_sni_blank", "host", "host_header"}
    remaining = {name: value for name, value in values.items()
                 if name not in HOST_METADATA_COLUMNS | represented}
    for name, value in remaining.items():
        if _host_override_active(name, value):
            safe_name = name if name in HOST_ROUTING_COLUMNS else "unknown_host_fields"
            if safe_name not in unsupported:
                unsupported.append(safe_name)
    facts: dict[str, Any] = {"http_host": normalized}
    if unsupported:
        facts["unsupported_overrides"] = sorted(unsupported)
        # SQLite допускает BLOB даже в TEXT: отпечаток не публикует его байты.
        fingerprint_values = {name: value.hex() if isinstance(value, bytes) else value
                              for name, value in {**remaining, "host": legacy,
                                                  "host_header": modern}.items()}
        facts["host_overrides_fingerprint"] = _metadata_fingerprint(fingerprint_values)
    return facts


def _parse_json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _naive_caddy_paths(fs: TargetFS, inbounds: list[Inbound]) -> list[str]:
    """Return every bounded, known-form Naive Caddyfile path without reading content."""

    candidates: list[str] = []

    def add(value: str) -> None:
        path = fs.path(value)
        if value not in candidates and (path.exists() or path.is_symlink()):
            candidates.append(value)

    for inbound_id in sorted(
        item.id for item in inbounds if item.protocol.lower() == "naive"
    ):
        add(f"{LUCX_TUNNEL_DIRECTORY}/naive-{inbound_id}.caddyfile")
    for value in CADDYFILE_CANDIDATES:
        add(value)
    tunnel = fs.path(LUCX_TUNNEL_DIRECTORY)
    if tunnel.is_dir():
        def sort_key(path: Path) -> tuple[int, str]:
            match = re.fullmatch(r"naive-(\d+)\.caddyfile", path.name)
            return (int(match.group(1)) if match else 2**31, path.name)

        for path in sorted(tunnel.glob("naive-*.caddyfile"), key=sort_key):
            relative = path.relative_to(fs.root).as_posix()
            add("/" + relative)
    return candidates


def _caddy_metadata(fs: TargetFS, candidate: str) -> dict[str, Any]:
    path = fs.path(candidate)
    metadata = path.lstat()
    result: dict[str, Any] = {
        "found": True,
        "path": candidate,
        "kind": "symlink" if path.is_symlink() else "file" if path.is_file() else "other",
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": int(metadata.st_uid),
        "gid": int(metadata.st_gid),
        "modified": False,
        "policy": "read-only; never managed",
    }
    if path.is_file():
        result["sha256"] = fs.sha256(candidate)
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                content = handle.read(MAX_CADDY_CAPABILITY_BYTES + 1)
        except OSError:
            content = ""
        if len(content) <= MAX_CADDY_CAPABILITY_BYTES:
            forward_proxy = bool(re.search(r"(?m)^\s*forward_proxy(?:\s|\{)", content))
            file_server = bool(re.search(r"(?m)^\s*file_server(?:\s|\{|$)", content))
            result["capabilities"] = {
                "forward_proxy": forward_proxy,
                "file_server": file_server,
                "native_decoy": supports_native_decoy(content),
            }
        else:
            result["capabilities"] = {
                "forward_proxy": False,
                "file_server": False,
                "native_decoy": False,
                "scan_limited": True,
            }
    return result


def _naive_binary_path(fs: TargetFS) -> str:
    candidates: list[Path] = []
    for directory in NAIVE_BINARY_DIRECTORIES:
        root = fs.path(directory)
        if not root.is_dir():
            continue
        candidates.extend(
            path
            for path in root.glob("caddy-naive-*")
            if path.is_file()
            and not path.is_symlink()
            and (not fs.is_live or bool(path.stat().st_mode & stat.S_IXUSR))
        )
    if not candidates:
        return ""
    selected = sorted(candidates, key=lambda path: path.as_posix())[0]
    return "/" + selected.relative_to(fs.root).as_posix()


def _normalize_host(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text if "://" in text else "//" + text)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_network(protocol: str, settings: dict[str, Any], stream: dict[str, Any]) -> str:
    settings_value = str(settings.get("network") or "").strip().lower()
    stream_value = _extract_transport(settings, stream) if stream.get("network") or stream.get("method") or settings_value else ""
    if stream_value and stream_value not in {
        "tcp", "raw", "udp", "both", "ws", "httpupgrade", "grpc", "http", "xhttp", "kcp", "quic", "hysteria",
    }:
        return "unknown"
    if protocol in {"awg", "amneziawg", "hysteria", "hysteria2", "tuic", "wireguard"}:
        return "udp"
    if protocol == "qwdtt":
        return "both"
    udp_transport = stream_value in {"udp", "kcp", "quic", "hysteria"} or (
        stream_value == "xhttp" and _extract_security(stream) == "tls" and _extract_alpn(stream) == ["h3"]
    )
    if settings_value in {"tcp", "udp", "tcp,udp", "udp,tcp"}:
        declared = "both" if "," in settings_value else settings_value
        if protocol in {"shadowsocks", "socks"}:
            # Эти протоколы могут сохранять собственный UDP вне stream transport.
            return "udp" if udp_transport else declared
        if stream_value not in {"", "tcp", "raw", "udp", "both"}:
            if declared != ("udp" if udp_transport else "tcp"):
                return "unknown"
        else:
            return declared
    if udp_transport:
        return "udp"
    if stream_value == "both":
        return "both"
    return "tcp"


def _extract_transport(settings: dict[str, Any], stream: dict[str, Any]) -> str:
    aliases = {"websocket": "ws", "mkcp": "kcp", "splithttp": "xhttp"}
    network = str(stream.get("network") or "").strip().lower()
    method = str(stream.get("method") or "").strip().lower()
    network = aliases.get(network, network)
    method = aliases.get(method, method)
    # Разные схемы допустимы, противоречащие поля нельзя угадывать.
    if network and method and network != method and {network, method} != {"tcp", "raw"}:
        return "unknown"
    value = method or network or str(settings.get("network") or "tcp").strip().lower()
    if value in {"tcp,udp", "udp,tcp"}:
        return "both"
    return aliases.get(value, value) or "tcp"


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        raw = value.split(",")
    elif isinstance(value, list):
        raw = value
    else:
        raw = []
    result: list[str] = []
    for item in raw:
        text = str(item or "").strip()
        if text and text not in result:
            result.append(text)
    return result


def _extract_alpn(stream: dict[str, Any]) -> list[str]:
    tls = stream.get("tlsSettings")
    return _string_values(tls.get("alpn")) if isinstance(tls, dict) else []


def _transport_settings(transport: str, stream: dict[str, Any]) -> Any:
    key_by_transport = {
        "ws": "wsSettings",
        "httpupgrade": "httpupgradeSettings",
        "xhttp": "xhttpSettings",
        "grpc": "grpcSettings",
        "http": "httpSettings",
        "kcp": "kcpSettings",
        "quic": "quicSettings",
        "hysteria": "hysteriaSettings",
    }
    metadata = stream.get(key_by_transport.get(transport, ""))
    if transport == "xhttp" and metadata is None:
        metadata = stream.get("splithttpSettings")
    return metadata


def _extract_transport_metadata(
    transport: str, stream: dict[str, Any]
) -> tuple[str, list[str], str]:
    metadata = _transport_settings(transport, stream)
    if not isinstance(metadata, dict):
        return "", [], "auto" if transport == "xhttp" else ""
    path = str(
        (metadata.get("serviceName") if transport == "grpc" else metadata.get("path")) or ""
    ).strip()
    hosts = _string_values(metadata.get("host") or metadata.get("authority"))
    headers = metadata.get("headers")
    if not hosts and isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "host":
                hosts = _string_values(value)
                break
    normalized_hosts: list[str] = []
    for value in hosts:
        host = _normalize_host(value)
        if host and valid_domain(host) and not host.startswith("*.") and host not in normalized_hosts:
            normalized_hosts.append(host)
    mode = str(metadata.get("mode") or ("auto" if transport == "xhttp" else "")).strip().lower()
    return path, normalized_hosts, mode


def _metadata_fingerprint(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _extract_transport_details(transport: str, stream: dict[str, Any]) -> dict[str, Any]:
    """Инвентаризация не доказывает поддержку версии или обёртки ядром."""
    metadata = _transport_settings(transport, stream)
    settings = metadata if isinstance(metadata, dict) else {}
    extra = settings.get("extra")
    masks = {key: value for key, value in stream.items() if "mask" in key.lower()}
    finalmask = stream.get("finalmask")
    finalmask = finalmask if isinstance(finalmask, dict) else {}
    mask_present = any(
        (any(value.values()) if key == "finalmask" and isinstance(value, dict) else bool(value))
        for key, value in masks.items()
    )
    known_stream_fields = {
        "network", "method", "security", "tlsSettings", "realitySettings", "sockopt",
        "tcpSettings", "rawSettings", "wsSettings", "httpupgradeSettings", "grpcSettings",
        "httpSettings", "xhttpSettings", "splithttpSettings", "kcpSettings", "quicSettings",
        "hysteriaSettings", "finalmask", "uot", "udpOverTcp", "udp_over_tcp",
    }
    unknown_stream_fields = sorted(set(stream) - known_stream_fields)
    ordinary = {
        "path", "host", "authority", "serviceName", "mode",
        "multiMode", "user_agent",
        "scMaxBufferedPosts", "scStreamUpServerSecs", "xPaddingBytes", "headers", "xmux", "noSSEHeader",
        "maxEarlyData", "earlyDataHeaderName", "useBrowserForwarding",
        "method", "acceptProxyProtocol", "header",
        "health_check", "idle_timeout", "permit_without_stream", "initial_windows_size",
    }
    unsupported = sorted(set(settings) - ordinary)
    conflicting_alias = (
        transport == "xhttp" and "xhttpSettings" in stream and "splithttpSettings" in stream
        and stream["xhttpSettings"] != stream["splithttpSettings"]
    )
    details: dict[str, Any] = {
        "support_status": "unverified",
        "settings_keys": sorted(settings),
        "settings_fingerprint": _metadata_fingerprint(metadata),
        "stream_fingerprint": _metadata_fingerprint(stream),
        "extra": {
            "present": "extra" in settings,
            "keys": sorted(extra) if isinstance(extra, dict) else [],
            "fingerprint": _metadata_fingerprint(extra),
        },
        "masks": {
            "present": mask_present,
            "fingerprint": _metadata_fingerprint(masks),
            "tcp_types": [str(item.get("type") or "unknown") for item in finalmask.get("tcp", []) if isinstance(item, dict)] if isinstance(finalmask.get("tcp", []), list) else ["unknown"],
            "udp_types": [str(item.get("type") or "unknown") for item in finalmask.get("udp", []) if isinstance(item, dict)] if isinstance(finalmask.get("udp", []), list) else ["unknown"],
        },
        "unsupported_settings": unsupported,
        "unknown_stream_fields": unknown_stream_fields,
        "conflicting_settings_alias": conflicting_alias,
        "requires_adapter_review": bool(
            transport not in {"tcp", "raw", "udp", "both", "ws", "httpupgrade", "grpc", "http", "xhttp", "kcp", "quic", "hysteria"}
            or unsupported or mask_present or conflicting_alias or unknown_stream_fields
            or (metadata is not None and not isinstance(metadata, dict))
        ),
    }
    download = settings.get("downloadSettings")
    if isinstance(extra, dict) and "downloadSettings" in extra:
        download = extra["downloadSettings"]
    if download is not None:
        details["requires_adapter_review"] = True
        details["download"] = {"present": True, "fingerprint": _metadata_fingerprint(download)}
        if isinstance(download, dict):
            method = _extract_transport({}, download)
            path, hosts, mode = _extract_transport_metadata(method, download)
            details["download"].update(
                address=_normalize_host(download.get("address")), port=_safe_int(download.get("port")),
                transport=method, security=_extract_security(download), network=_extract_network("", {}, download),
                transport_path=path, transport_hosts=hosts, transport_mode=mode, alpn=_extract_alpn(download),
            )
    return details


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _extract_udp_over_tcp(settings: dict[str, Any], stream: dict[str, Any]) -> bool:
    for source in (settings, stream):
        for key in ("uot", "udpOverTcp", "udp_over_tcp"):
            if key in source:
                return _truthy(source.get(key))
    return False


def _is_shadowsocks_2022(protocol: str, settings: dict[str, Any]) -> bool:
    if protocol != "shadowsocks":
        return False
    methods = [settings.get("method")]
    clients = settings.get("clients")
    if isinstance(clients, list):
        methods.extend(item.get("method") for item in clients if isinstance(item, dict))
    return any(str(method or "").strip().lower().startswith("2022-") for method in methods)


def _extract_security(stream: dict[str, Any]) -> str:
    return str(stream.get("security") or "").strip().lower()


def _extract_server_names(settings: dict[str, Any], stream: dict[str, Any]) -> list[str]:
    raw: list[Any] = []
    for key in ("serverNames", "server_names", "sni"):
        value = settings.get(key)
        if isinstance(value, list):
            raw.extend(value)
        elif value:
            raw.append(value)
    reality = stream.get("realitySettings")
    if isinstance(reality, dict):
        value = reality.get("serverNames")
        if isinstance(value, list):
            raw.extend(value)
    tls = stream.get("tlsSettings")
    if isinstance(tls, dict) and tls.get("serverName"):
        raw.append(tls.get("serverName"))
    result: list[str] = []
    for value in raw:
        host = _normalize_host(value)
        if host and host not in result:
            result.append(host)
    return result


def _extract_public_port(row_port: int, settings: dict[str, Any], share_addr: str = "") -> int:
    if share_addr:
        try:
            parsed = urlsplit(share_addr if "://" in share_addr else "//" + share_addr)
            if parsed.port and 1 <= parsed.port <= 65535:
                return parsed.port
        except ValueError:
            pass
    for key in ("share_port", "sharePort", "externalPort", "external_port", "publicPort"):
        value = _safe_int(settings.get(key))
        if 1 <= value <= 65535:
            return value
    return row_port


def _extract_port_bindings(
    protocol: str, row_port: int, settings: dict[str, Any], stream: dict[str, Any]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    raw_bindings = settings.get("portBindings")
    if isinstance(raw_bindings, list):
        for raw in raw_bindings:
            if not isinstance(raw, dict):
                continue
            transport = str(raw.get("protocol") or "TCP").upper()
            if transport not in {"TCP", "UDP"}:
                continue
            port = _safe_int(raw.get("port"))
            port_range = str(raw.get("portRange") or "").strip()
            if 1 <= port <= 65535:
                result.append({"port": port, "protocol": transport})
            elif port_range and re.fullmatch(r"\d{1,5}-\d{1,5}", port_range):
                low, high = (int(part) for part in port_range.split("-", 1))
                if 1 <= low <= high <= 65535:
                    result.append({"port_range": port_range, "protocol": transport})

    if protocol == "qwdtt":
        for key, default, transport in (
            ("listenAddr", row_port or 56000, "TCP_UDP"),
            ("wgPort", 56001, "UDP"),
            ("listenRaw", 56003, "UDP"),
            ("listenDirect", 0, "UDP"),
        ):
            raw = settings.get(key)
            port = 0
            if isinstance(raw, int):
                port = raw
            elif raw:
                text = str(raw)
                port = _safe_int(text.rsplit(":", 1)[-1])
            elif default:
                port = default
            if 1 <= port <= 65535:
                item = {"port": port, "protocol": transport}
                if item not in result:
                    result.append(item)

    if not result and 1 <= row_port <= 65535:
        network = _extract_network(protocol, settings, stream)
        transports = {
            "tcp": ["TCP"],
            "udp": ["UDP"],
            "both": ["TCP", "UDP"],
        }.get(network, [])
        if protocol == "qwdtt":
            transports = ["TCP_UDP"]
        result.extend({"port": row_port, "protocol": transport} for transport in transports)
    return result


def _read_os_release(fs: TargetFS) -> tuple[str, str]:
    result: dict[str, str] = {}
    for line in fs.read_text("/etc/os-release").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"')
    return result.get("ID", ""), result.get("VERSION_ID", "")


def find_database(fs: TargetFS, requested: str | None = None) -> str:
    candidates = [requested] if requested else []
    candidates.extend(["/etc/x-ui/x-ui.db", "/etc/lucx/x-ui.db"])
    for candidate in candidates:
        if candidate and fs.exists(candidate):
            return str(candidate)
    return str(requested or "/etc/x-ui/x-ui.db")


def read_lucx_database(fs: TargetFS, db_path: str) -> tuple[dict[str, str], list[Inbound], bool, list[str]]:
    actual = fs.path(db_path)
    warnings: list[str] = []
    if not actual.is_file():
        return {}, [], False, [f"LucX database not found at {db_path}"]
    uri = actual.as_uri() + "?mode=ro"
    try:
        database = sqlite3.connect(uri, uri=True, timeout=5)
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA query_only=ON")
    except sqlite3.Error as exc:
        return {}, [], False, [f"cannot open LucX database read-only: {exc}"]

    try:
        return read_lucx_connection(database)
    finally:
        database.close()


def read_lucx_connection(database: sqlite3.Connection) -> tuple[dict[str, str], list[Inbound], bool, list[str]]:
    """Нормализация внутри уже открытого read-only SQLite snapshot; connection не закрывается."""
    database.row_factory = sqlite3.Row
    warnings: list[str] = []
    settings: dict[str, str] = {}
    inbounds: list[Inbound] = []
    supported = False
    try:
        tables = {
            row[0]
            for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "settings" in tables:
            placeholders = ",".join("?" for _ in ALLOWED_SETTING_KEYS)
            query = f"SELECT key, value FROM settings WHERE key IN ({placeholders})"
            for row in database.execute(query, tuple(sorted(ALLOWED_SETTING_KEYS))):
                settings[str(row["key"])] = str(row["value"] or "")
        else:
            warnings.append("settings table is missing")

        if "inbounds" not in tables:
            warnings.append(
                "inbounds table is missing; safe options: update this configurator for the installed LucX schema, use a matching LucX release, or export --audit output for adapter review"
            )
            return settings, inbounds, False, warnings

        # Current LucX releases publish per-inbound endpoints from the hosts
        # table.  An enabled Host has precedence over inbounds.share_addr in
        # raw, JSON, and Clash subscriptions, so discovery must use the same
        # precedence or a plan can silently keep advertising an old port.
        host_endpoints: dict[int, tuple[str, int]] = {}
        host_server_names: dict[int, list[str]] = {}
        all_host_endpoints: dict[int, list[dict[str, Any]]] = {}
        if "hosts" in tables:
            host_columns = {
                str(row[1]) for row in database.execute("PRAGMA table_info(hosts)")
            }
            required_host_columns = {"id", "inbound_id", "address", "port"}
            if required_host_columns.issubset(host_columns):
                where = " WHERE is_disabled = 0" if "is_disabled" in host_columns else ""
                order = []
                if "sort_order" in host_columns:
                    order.append("sort_order")
                order.append("id")
                optional = sorted(host_columns - HOST_METADATA_COLUMNS)
                query = (
                    "SELECT id, inbound_id, address, port"
                    + (", " + ", ".join('"' + name.replace('"', '""') + '"'
                                          for name in optional) if optional else "")
                    + " FROM hosts"
                    + where
                    + " ORDER BY "
                    + ", ".join(order)
                )
                for host_row in database.execute(query):
                    inbound_id = _safe_int(host_row["inbound_id"])
                    if inbound_id <= 0:
                        continue
                    address = _normalize_host(host_row["address"])
                    if inbound_id not in host_endpoints:
                        host_endpoints[inbound_id] = (
                            address,
                            _safe_int(host_row["port"]),
                        )
                    names = host_server_names.setdefault(inbound_id, [])
                    override = _truthy(
                        host_row["override_sni_from_address"]
                        if "override_sni_from_address" in host_row.keys()
                        else False
                    )
                    keep_blank = _truthy(
                        host_row["keep_sni_blank"]
                        if "keep_sni_blank" in host_row.keys()
                        else False
                    )
                    explicit_sni = _normalize_host(
                        host_row["sni"] if "sni" in host_row.keys() else ""
                    )
                    selected_sni = address if override else explicit_sni
                    if selected_sni and not keep_blank and selected_sni not in names:
                        names.append(selected_sni)
                    host_port = _safe_int(host_row["port"])
                    override_facts = _host_override_facts(host_row)
                    all_host_endpoints.setdefault(inbound_id, []).append({
                        "host_id": _safe_int(host_row["id"]),
                        "address": address,
                        "port": host_port,
                        "sni": "" if keep_blank else selected_sni,
                        "sni_source": "blank" if keep_blank else "address" if override else "explicit" if explicit_sni else "inherited",
                        "keep_sni_blank": keep_blank,
                        **override_facts,
                        "valid": bool(address and 1 <= host_port <= 65535
                                      and not override_facts.get("unsupported_overrides")),
                    })
            else:
                missing = ", ".join(sorted(required_host_columns - host_columns))
                warnings.append(
                    f"hosts table is present but cannot be used safely; missing columns: {missing}"
                )
        columns = {row[1] for row in database.execute("PRAGMA table_info(inbounds)")}
        if not REQUIRED_INBOUND_COLUMNS.issubset(columns):
            missing = ", ".join(sorted(REQUIRED_INBOUND_COLUMNS - columns))
            warnings.append(
                f"unsupported inbounds schema; missing columns: {missing}. Safe options: update the read-only schema adapter, use a matching LucX release, or export --audit output for review"
            )
            return settings, inbounds, False, warnings

        wanted = [
            name
            for name in (
                "id",
                "protocol",
                "remark",
                "enable",
                "listen",
                "port",
                "settings",
                "stream_settings",
                "streamSettings",
                "share_addr",
                "share_addr_strategy",
            )
            if name in columns
        ]
        rows = database.execute("SELECT " + ", ".join(wanted) + " FROM inbounds ORDER BY id")
        for raw in rows:
            row = dict(raw)
            inbound_id = _safe_int(row.get("id"))
            protocol = normalize_protocol(str(row.get("protocol") or ""))
            inbound_settings = _parse_json_object(row.get("settings"))
            stream = _parse_json_object(row.get("stream_settings") or row.get("streamSettings"))
            legacy_share_addr = str(
                row.get("share_addr")
                or inbound_settings.get("share_addr")
                or inbound_settings.get("shareAddr")
                or inbound_settings.get("domain")
                or ""
            )
            host_address, host_port = host_endpoints.get(inbound_id, ("", 0))
            share_addr = host_address or _normalize_host(legacy_share_addr)
            remark = str(inbound_settings.get("remark") or row.get("remark") or "")
            row_port = _safe_int(row.get("port"))
            suggested_public_port = _extract_public_port(
                row_port, inbound_settings, legacy_share_addr
            )
            if 1 <= host_port <= 65535:
                suggested_public_port = host_port
            if protocol in {"vless", "trojan"} and stream.get("security") == "reality":
                server_names = _extract_server_names({}, {"realitySettings": stream.get("realitySettings")})
            elif protocol == "trusttunnel":
                hostname = _normalize_host(inbound_settings.get("hostname"))
                server_names = [hostname] if hostname else []
            else:
                server_names = _extract_server_names(inbound_settings, stream)
            public_endpoints = all_host_endpoints.get(inbound_id, [])
            if not public_endpoints:
                public_endpoints = [{
                    "host_id": 0, "address": share_addr, "port": suggested_public_port,
                    "sni": "", "sni_source": "inherited", "keep_sni_blank": False,
                    "http_host": "", "valid": bool(share_addr and 1 <= suggested_public_port <= 65535),
                }]
            # LucX genNaiveLink/ClientURLFor задаёт HTTPS authority, без отдельного
            # Xray TLS SNI. Только стандартный native профиль с отсутствующим SNI;
            # явный blank, overrides и raw Caddy config не переопределяются.
            naive_authority = (protocol == 'naive' and not server_names
                               and inbound_settings.get('useRawConfig', False) is False)
            for endpoint in public_endpoints:
                if endpoint["sni_source"] == "inherited":
                    if naive_authority:
                        endpoint['sni'] = endpoint['address']
                        endpoint['sni_source'] = 'address'
                    elif len(server_names) == 1:
                        endpoint["sni"] = server_names[0]
                    elif len(server_names) > 1:
                        if (protocol in {"vless", "trojan"} and stream.get("security") == "reality"
                                and all(valid_domain(name) and not name.startswith("*.") for name in server_names)):
                            endpoint["sni_source"] = "inherited_set"
                            endpoint["inherited_sni_names"] = list(server_names)
                        else:
                            endpoint["sni_source"] = "ambiguous"
            for endpoint in public_endpoints:
                if naive_authority and endpoint['sni_source'] == 'address' and endpoint['sni'] not in server_names:
                    server_names.append(endpoint['sni'])
            for name in host_server_names.get(inbound_id, []):
                if name not in server_names:
                    server_names.append(name)
            transport = _extract_transport(inbound_settings, stream)
            transport_path, transport_hosts, transport_mode = _extract_transport_metadata(
                transport, stream
            )
            raw_client_random_prefix = str(
                inbound_settings.get("clientRandomPrefix")
                or inbound_settings.get("client_random_prefix")
                or ""
            ).strip()
            client_random_prefix = (
                exact_client_random_prefix(raw_client_random_prefix)
                if protocol in {"trusttunnel", "trust-tunnel"}
                else ""
            )
            inbounds.append(
                Inbound(
                    id=inbound_id,
                    protocol=protocol,
                    remark=remark,
                    enable=bool(row.get("enable", True)),
                    listen=str(row.get("listen") or ""),
                    port=row_port,
                    share_addr=share_addr,
                    share_addr_strategy=str(row.get("share_addr_strategy") or ""),
                    network=_extract_network(protocol, inbound_settings, stream),
                    security=_extract_security(stream),
                    transport=transport,
                    transport_path=transport_path,
                    transport_hosts=transport_hosts,
                    transport_mode=transport_mode,
                    public_endpoints=public_endpoints,
                    transport_details={
                        **_extract_transport_details(transport, stream),
                        "inbound_settings_fingerprint": _metadata_fingerprint(inbound_settings),
                    },
                    alpn=_extract_alpn(stream),
                    shadowsocks_2022=_is_shadowsocks_2022(protocol, inbound_settings),
                    udp_over_tcp=_extract_udp_over_tcp(inbound_settings, stream),
                    clienthello_match_fingerprint=(
                        stable_fingerprint(raw_client_random_prefix)
                        if client_random_prefix
                        else ""
                    ),
                    suggested_public_port=suggested_public_port,
                    server_names=server_names,
                    port_bindings=_extract_port_bindings(
                        protocol, row_port, inbound_settings, stream
                    ),
                )
            )
        supported = True
    except sqlite3.Error as exc:
        warnings.append(
            f"LucX read-only query failed: {exc}. No write fallback is allowed; update the schema adapter or use a matching LucX release"
        )
    return settings, inbounds, supported, warnings


def _service_state(service: str) -> str:
    if not shutil.which("systemctl"):
        return "unknown"
    result = subprocess.run(
        ["systemctl", "is-active", service],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
    )
    return result.stdout.strip() or "inactive"


def _ssh_ports(fs: TargetFS) -> list[int]:
    ports: list[int] = []
    candidates = [fs.path("/etc/ssh/sshd_config")]
    dropins = fs.path("/etc/ssh/sshd_config.d")
    if dropins.is_dir():
        candidates.extend(sorted(dropins.glob("*.conf")))
    for path in candidates:
        if not path.is_file():
            continue
        in_match = False
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.lower().startswith("match "):
                in_match = True
            if in_match:
                continue
            match = re.match(r"(?i)^port\s+(\d{1,5})$", line)
            if match:
                port = int(match.group(1))
                if 1 <= port <= 65535 and port not in ports:
                    ports.append(port)
    return ports or [22]


def _public_addresses(fs: TargetFS) -> list[str]:
    if not fs.is_live or not shutil.which("ip"):
        return []
    result = subprocess.run(
        ["ip", "-j", "route", "get", "1.1.1.1"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
    )
    try:
        rows = json.loads(result.stdout) if result.returncode == 0 else []
    except ValueError:
        rows = []
    addresses: list[str] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        address = str(row.get("prefsrc") or row.get("src") or "")
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.version == 4 and not parsed.is_loopback and address not in addresses:
            addresses.append(address)
    return addresses


def audit_system(root: str | Path = "/", db_path: str | None = None) -> Audit:
    fs = TargetFS(root)
    os_id, os_version = _read_os_release(fs)
    selected_db = find_database(fs, db_path)
    settings, inbounds, schema_supported, warnings = read_lucx_database(fs, selected_db)
    tools = {
        name: bool(shutil.which(name)) if fs.is_live else fs.exists(f"/usr/bin/{name}") or fs.exists(f"/usr/sbin/{name}")
        for name in ("python3", "haproxy", "nginx", "nft", "logrotate", "openssl", "resolvconf", "certbot", "acme.sh")
    }
    services = {}
    if fs.is_live:
        for service in ("x-ui", "haproxy", "nginx", "nftables", "systemd-resolved", "lucx-sub-sidecar"):
            services[service] = _service_state(service)

    caddy_files = [
        _caddy_metadata(fs, candidate)
        for candidate in _naive_caddy_paths(fs, inbounds)
    ]
    caddy_info: dict[str, Any] = {"found": False, "modified": False, "files": []}
    if caddy_files:
        caddy_info = dict(caddy_files[0])
        caddy_info["files"] = caddy_files
        caddy_info["binary_path"] = _naive_binary_path(fs)

    if os_id != "debian" or os_version not in {"12", "13"}:
        warnings.append(f"unsupported operating system: {os_id or 'unknown'} {os_version or 'unknown'}")
    if not inbounds:
        warnings.append("no LucX inbounds were discovered")
    if any(item.protocol == "naive" for item in inbounds) and not caddy_info["found"]:
        warnings.append(
            "Naive Caddyfile was not located; any planned SNI route requires a successful read-only TLS probe of its existing internal listener"
        )

    return Audit(
        os_id=os_id,
        os_version=os_version,
        supported_os=os_id == "debian" and os_version in {"12", "13"},
        db_path=selected_db,
        db_schema_supported=schema_supported,
        settings=settings,
        inbounds=inbounds,
        tools=tools,
        services=services,
        ssh_ports=_ssh_ports(fs),
        public_addresses=_public_addresses(fs),
        naive_caddyfile=caddy_info,
        warnings=warnings,
    )


def redacted_audit_dict(audit: Audit) -> dict[str, Any]:
    """Return only allowlisted metadata; no clients, tokens, keys, or passwords."""
    from .diagnostics import redact

    result = redact(audit.as_dict())
    return result if isinstance(result, dict) else {}
