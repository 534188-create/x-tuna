"""Ограниченный read-only источник существующих Xray-клиентов LucX.

Формы полей сверены с AlexeyLCP/lucx-ui, commit
dad03470cffe916607d5ad8268b375b416ec560e: model.go, host_sub.go,
json_service.go, client_link.go и xray.go. Версия установленной панели
из этого факта не выводится; неизвестные формы блокируются.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sqlite3
import ssl
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .discovery import read_lucx_connection
from .models import Inbound
from .routing_profiles import (
    inbound_routing_metadata,
    routing_fingerprint,
    source_routing_fingerprint,
)
from .sqlite_snapshot import open_snapshot
from .targetfs import TargetFS
from .vpn_probes import XrayProbeCredential

_MAX_FIELD = 256 * 1024
_MAX_TOTAL = 8 * 1024 * 1024
_INBOUND_COLUMNS = {"id", "user_id", "up", "down", "total", "remark", "sub_sort_index", "enable",
    "expiry_time", "traffic_reset", "traffic_reset_day", "last_traffic_reset_time", "listen", "port",
    "protocol", "settings", "stream_settings", "streamSettings", "tag", "sniffing", "node_id",
    "share_addr_strategy", "share_addr", "disable_flow", "origin_node_guid"}
_HOST_COLUMNS = {"id", "group_id", "inbound_id", "sort_order", "remark", "server_description",
    "is_disabled", "is_hidden", "tags", "address", "port", "security", "sni", "host", "host_header",
    "path", "alpn", "fingerprint", "override_sni_from_address", "keep_sni_blank", "pinned_peer_cert_sha256",
    "verify_peer_cert_by_name", "allow_insecure", "ech_config_list", "mux_params", "sockopt_params",
    "final_mask", "vless_route", "exclude_from_sub_types", "mihomo_ip_version", "mihomo_x25519",
    "shuffle_host", "node_guids", "created_at", "updated_at"}
_CLIENT_COLUMNS = {"id", "email", "uuid", "sub_id", "password", "auth", "flow", "security", "reverse",
    "wg_private_key", "wg_public_key", "wg_allowed_ips", "wg_pre_shared_key", "wg_keep_alive",
    "wg_forwarded_ports", "secret", "ad_tag", "limit_ip", "limit_hwid", "total_gb", "expiry_time",
    "enable", "tg_id", "group_name", "comment", "reset", "reset_day", "reset_max", "traffic_reset",
    "traffic_reset_day", "created_at", "updated_at", "sync_orphaned_at"}
_TRAFFIC_COLUMNS = {"id", "inbound_id", "enable", "email", "up", "down", "expiry_time", "total",
    "reset", "reset_day", "reset_max", "reset_count", "last_online", "last_sub_fetch"}
_EMBEDDED_POLICY_FIELDS = {"id", "email", "enable", "totalGB", "expiryTime", "limitIp",
    "flow", "security", "alterId", "reset"}
_RELATIONAL_POLICY_FIELDS = _CLIENT_COLUMNS - {"sub_id", "tg_id", "comment", "created_at", "updated_at"}
_INBOUND_POLICY_FIELDS = {"id", "user_id", "enable", "total", "expiry_time", "traffic_reset",
    "traffic_reset_day", "node_id", "origin_node_guid", "disable_flow"}
_TRAFFIC_POLICY_FIELDS = _TRAFFIC_COLUMNS - {"up", "down", "reset_count", "last_online", "last_sub_fetch"}


def _json_object(value: Any) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("Повтор поля JSON")
            result[key] = item
        return result
    if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_FIELD:
        raise ValueError("Неподтверждённый размер JSON")
    result = json.loads(value, object_pairs_hook=unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Недопустимое число")))
    if not isinstance(result, dict):
        raise TypeError("Ожидался объект JSON")
    return result


def _zero(value: Any) -> bool:
    return type(value) is int and value == 0


def _unexpired(value: Any) -> bool:
    # Положительное expiry — Unix milliseconds; отрицательное требует активации.
    return type(value) is int and (value == 0 or int(time.time() * 1000) + 60000 < value < 2**63)


def _empty(value: Any) -> bool:
    return value is None or value == "" or value == "[]" or value == "{}" or value == "null"


def _columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in db.execute(f'PRAGMA table_info("{table}")')}


def _bounded_schema(db: sqlite3.Connection) -> dict[str, set[str]]:
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 129")}
    if len(tables) > 128 or not {"settings", "inbounds", "hosts", "client_traffics"} <= tables:
        raise ValueError("Схема источника не подтверждена")
    requirements = {
        "inbounds": ({"id", "protocol", "enable", "listen", "port", "settings", "total", "expiry_time"}, _INBOUND_COLUMNS, 256),
        "hosts": ({"id", "inbound_id", "address", "port", "sni", "override_sni_from_address", "keep_sni_blank", "is_disabled"}, _HOST_COLUMNS, 2048),
        "client_traffics": ({"email", "enable", "total", "expiry_time", "inbound_id"}, _TRAFFIC_COLUMNS, 4096),
        "settings": ({"key", "value"}, {"id", "key", "value"}, 1024),
    }
    if "clients" in tables or "client_inbounds" in tables:
        if not {"clients", "client_inbounds"} <= tables:
            raise ValueError("Не подтверждён источник действующих клиентов")
        requirements["clients"] = ({"id", "email", "uuid", "enable", "total_gb", "expiry_time", "flow", "security", "limit_ip", "limit_hwid"}, _CLIENT_COLUMNS, 4096)
        requirements["client_inbounds"] = ({"client_id", "inbound_id", "flow_override"}, {"client_id", "inbound_id", "flow_override", "created_at"}, 8192)
    schema, total = {}, 0
    for table, (required, allowed, limit) in requirements.items():
        columns = _columns(db, table)
        if not required <= columns or columns - allowed:
            raise ValueError("Неизвестные поля источника")
        schema[table] = columns
        if db.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0] > limit:
            raise ValueError("Слишком много записей источника")
        # Имена столбцов уже входят в неизменяемый allowlist.
        terms = "+".join(f'length(CAST(COALESCE("{name}",\'\') AS BLOB))' for name in sorted(columns))
        size = db.execute(f'SELECT COALESCE(sum({terms}),0) FROM "{table}"').fetchone()[0]
        total += size
        if total > _MAX_TOTAL:
            raise ValueError("Слишком большой снимок источника")
    streams = schema["inbounds"] & {"stream_settings", "streamSettings"}
    if len(streams) != 1:
        raise ValueError("Неоднозначное поле streamSettings")
    return schema


def _same_profile(inbound: Inbound, protocol: dict[str, Any]) -> bool:
    expected = {"inbound_id": inbound.id, "protocol": inbound.protocol, "network": inbound.network,
        "security": inbound.security, "internal_port": inbound.port, "public_port": inbound.suggested_public_port,
        "domain": inbound.share_addr, "sni_names": inbound.server_names, "port_bindings": inbound.port_bindings,
        **inbound_routing_metadata(inbound)}
    host = inbound.listen
    if host in {"", "0.0.0.0", "::", "[::]", "localhost"}:
        host = "127.0.0.1"
    expected["internal_host"] = host
    return (inbound.enable and protocol.get("exposure") == "tcp_sni"
        and protocol.get("source_routing_fingerprint") == source_routing_fingerprint(inbound)
        and all(protocol.get(name) == value for name, value in expected.items()))


def _simple_stream(stream: dict[str, Any], inbound: Inbound) -> bool:
    transport = inbound.transport
    key = {"ws": "wsSettings", "httpupgrade": "httpupgradeSettings", "grpc": "grpcSettings", "xhttp": "xhttpSettings"}.get(transport)
    if (not key or set(stream) - {"network", "security", "tlsSettings", key}
            or stream.get("network") != transport or stream.get("security") != "tls"):
        return False
    options = stream.get(key)
    allowed = {"ws": {"path"}, "httpupgrade": {"path", "host"}, "grpc": {"serviceName", "authority"}, "xhttp": {"path", "host", "mode"}}[transport]
    if not isinstance(options, dict) or set(options) - allowed:
        return False
    path = options.get("serviceName" if transport == "grpc" else "path")
    pattern = r"[A-Za-z0-9_.-]+" if transport == "grpc" else r"/[A-Za-z0-9/_.~-]*"
    if not isinstance(path, str) or len(path) > 1024 or not re.fullmatch(pattern, path):
        return False
    if transport == "xhttp" and (path == "/" or options.get("mode", "auto") not in {"auto", "packet-up", "stream-up", "stream-one"}):
        return False
    tls = stream.get("tlsSettings")
    if not isinstance(tls, dict) or set(tls) - {"serverName", "alpn", "certificates", "settings", "allowInsecure"}:
        return False
    if tls.get("allowInsecure", False) is not False or tls.get("settings", {}) != {}:
        return False
    if tls.get("alpn") != (["http/1.1"] if transport in {"ws", "httpupgrade"} else ["h2"]):
        return False
    certs = tls.get("certificates")
    if not isinstance(certs, list) or not certs or len(certs) > 8:
        return False
    if any(not isinstance(cert, dict) or set(cert) != {"certificateFile", "keyFile"}
           or any(not isinstance(value, str) or not value.startswith("/") for value in cert.values()) for cert in certs):
        return False
    # Доказанный узкий экспорт: SNI, endpoint address и отсутствие Host override совпадают.
    for endpoint in inbound.public_endpoints:
        if (endpoint.get("valid") is not True or endpoint.get("keep_sni_blank") is not False
                or endpoint.get("sni_source") not in {"address", "explicit", "inherited"}
                or endpoint.get("address") != endpoint.get("sni") or endpoint.get("http_host")
                or tls.get("serverName") != endpoint.get("sni")):
            return False
        declared_host = options.get("host") or options.get("authority")
        if declared_host is not None and declared_host != endpoint["sni"]:
            return False
    return bool(inbound.public_endpoints)


def _hosts_safe(db: sqlite3.Connection, inbound_id: int) -> bool:
    rows = db.execute("SELECT * FROM hosts WHERE inbound_id=? AND is_disabled=0 ORDER BY id", (inbound_id,)).fetchall()
    active_overrides = {"host", "host_header", "path", "alpn", "fingerprint", "pinned_peer_cert_sha256",
        "verify_peer_cert_by_name", "ech_config_list", "mux_params", "sockopt_params", "final_mask",
        "vless_route", "exclude_from_sub_types", "mihomo_ip_version", "node_guids"}
    for raw in rows:
        row = dict(raw)
        if row.get("security", "same") not in {"", "same"}:
            return False
        if any(not _empty(row.get(key)) for key in active_overrides):
            return False
        if any(row.get(key, 0) != 0 for key in ("allow_insecure", "mihomo_x25519", "shuffle_host", "is_hidden")):
            return False
    return bool(rows)


def _client_safe(client: dict[str, Any], protocol: str) -> bool:
    allowed = {"id", "email", "enable", "totalGB", "expiryTime", "limitIp", "flow", "security", "alterId",
        "subId", "tgId", "comment", "reset", "created_at", "updated_at"}
    if (set(client) - allowed or client.get("enable") is not True
            or not _zero(client.get("totalGB")) or not _unexpired(client.get("expiryTime"))
            or not _zero(client.get("limitIp")) or client.get("flow", "") != ""
            or client.get("security", "") not in {"", "auto"}
            or not _zero(client.get("alterId", 0)) or not _zero(client.get("reset", 0))):
        return False
    value, email = client.get("id"), client.get("email")
    try:
        return (isinstance(value, str) and str(uuid.UUID(value)) == value
            and isinstance(email, str) and 0 < len(email) <= 256 and email.strip() == email)
    except ValueError:
        return False


def _active_clients(db: sqlite3.Connection, schema: dict[str, set[str]], settings: dict[str, Any], inbound: Inbound) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    embedded = settings.get("clients")
    if not isinstance(embedded, list) or len(embedded) > 4096 or any(not isinstance(item, dict) for item in embedded):
        raise ValueError("Клиенты исходного inbound не подтверждены")
    if "clients" not in schema:
        return [(client, {"source": "embedded", "client": {
            key: client.get(key) for key in _EMBEDDED_POLICY_FIELDS}}) for client in embedded]
    rows = db.execute("SELECT c.*, ci.flow_override AS selected_flow FROM clients c JOIN client_inbounds ci ON c.id=ci.client_id WHERE ci.inbound_id=? ORDER BY c.id LIMIT 4097", (inbound.id,)).fetchall()
    result, ids = [], set()
    for raw in rows:
        row = dict(raw)
        if row["id"] in ids:
            raise ValueError("Неоднозначное прикрепление клиента")
        ids.add(row["id"])
        inert = {"password", "auth", "reverse", "wg_private_key", "wg_public_key", "wg_allowed_ips",
            "wg_pre_shared_key", "wg_forwarded_ports", "secret", "ad_tag", "group_name", "selected_flow"}
        if any(not _empty(row.get(key)) for key in inert):
            continue
        if row.get("wg_keep_alive", "0") not in {0, "0", ""} or row.get("traffic_reset", "never") not in {"", "never"}:
            continue
        if any(not _zero(row.get(key, 0)) for key in ("limit_hwid", "reset", "reset_day", "reset_max", "sync_orphaned_at")):
            continue
        client = {"id": row["uuid"], "email": row["email"], "enable": row["enable"] == 1,
            "totalGB": row["total_gb"], "expiryTime": row["expiry_time"], "limitIp": row["limit_ip"],
            "flow": row["flow"], "security": row["security"]}
        policy = {"source": "relational", "client": {
            key: row.get(key) for key in _RELATIONAL_POLICY_FIELDS}, "attachment": {
                "client_id": row["id"], "inbound_id": inbound.id, "flow_override": row["selected_flow"]}}
        result.append((client, policy))
    return result


def _eligible_traffic(db: sqlite3.Connection, client: dict[str, Any]) -> dict[str, Any] | None:
    rows = db.execute("SELECT * FROM client_traffics WHERE lower(email)=lower(?) LIMIT 2", (client["email"],)).fetchall()
    if len(rows) != 1:
        return None
    row = dict(rows[0])
    if (row["enable"] == 1 and _zero(row["total"]) and _unexpired(row["expiry_time"])
            and all(_zero(row.get(key, 0)) for key in ("reset", "reset_day", "reset_max"))):
        return row
    return None


def _policy_fingerprint(inbound: dict[str, Any], client: dict[str, Any], traffic: dict[str, Any]) -> str:
    """Внутренняя привязка identity и ограничений; статистика и metadata исключены."""
    policy = {"version": 1, "selected_client": client,
        "inbound": {key: inbound.get(key) for key in _INBOUND_POLICY_FIELDS},
        "traffic": {key: traffic.get(key) for key in _TRAFFIC_POLICY_FIELDS}}
    encoded = json.dumps(policy, sort_keys=True, ensure_ascii=True,
                         separators=(",", ":"), allow_nan=False).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class LucXXrayCredentialSource:
    fs: TargetFS = field(repr=False)
    db_path: str = field(repr=False)
    shared_tcp_port: int
    ca_provider: Callable[[dict[str, Any]], str] | None = field(default=None, repr=False)

    def __call__(self, protocol: dict[str, Any]) -> XrayProbeCredential | None:
        database = None
        try:
            if (not isinstance(protocol, dict) or type(self.shared_tcp_port) is not int
                    or not 1 <= self.shared_tcp_port <= 65535 or type(protocol.get("inbound_id")) is not int):
                return None
            database = open_snapshot(self.fs, self.db_path)
            database.row_factory = sqlite3.Row
            database.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _MAX_FIELD)
            database.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16384)
            database.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 256)
            deadline = time.monotonic() + 3
            steps = 0
            def budget() -> int:
                nonlocal steps
                steps += 1000
                return int(steps > 500000 or time.monotonic() >= deadline)
            database.set_progress_handler(budget, 1000)
            database.execute("PRAGMA query_only=ON")
            database.execute("PRAGMA trusted_schema=OFF")
            schema = _bounded_schema(database)
            _, inbounds, supported, warnings = read_lucx_connection(database)
            matches = [item for item in inbounds if item.id == protocol["inbound_id"]]
            if not supported or warnings or len(matches) != 1:
                return None
            inbound = matches[0]
            if inbound.protocol not in {"vless", "vmess"} or not _same_profile(inbound, protocol):
                return None
            raw = dict(database.execute("SELECT * FROM inbounds WHERE id=?", (inbound.id,)).fetchone())
            if (raw["enable"] != 1 or not _zero(raw["total"]) or not _unexpired(raw["expiry_time"])
                    or raw.get("node_id") is not None or raw.get("origin_node_guid", "") != ""):
                return None
            settings = _json_object(raw["settings"])
            allowed_settings = {"clients", "decryption", "encryption"} if inbound.protocol == "vless" else {"clients"}
            if set(settings) - allowed_settings or (inbound.protocol == "vless" and (
                    settings.get("decryption") != "none" or settings.get("encryption") != "none")):
                return None
            stream_key = next(iter(schema["inbounds"] & {"stream_settings", "streamSettings"}))
            if not _simple_stream(_json_object(raw[stream_key]), inbound) or not _hosts_safe(database, inbound.id):
                return None
            for row in database.execute("SELECT value FROM settings WHERE key IN ('subJsonMux','subJsonFinalMask')"):
                if not _empty(row[0]):
                    return None
            clients = _active_clients(database, schema, settings, inbound)
            eligible = []
            for client, policy in clients:
                if _client_safe(client, inbound.protocol):
                    traffic = _eligible_traffic(database, client)
                    if traffic is not None:
                        eligible.append((client, policy, traffic))
            if not eligible or len({item[0]["id"] for item in eligible}) != len(eligible):
                return None
            ca = self.ca_provider(copy.deepcopy(protocol)) if self.ca_provider else ""
            if not isinstance(ca, str) or len(ca) > 65536:
                return None
            if ca:
                ssl.create_default_context(cadata=ca)
            selected, policy, traffic = eligible[0]
            return XrayProbeCredential(selected["id"], routing_fingerprint(protocol, self.shared_tcp_port), ca,
                                       policy_fingerprint=_policy_fingerprint(raw, policy, traffic))
        except Exception:  # noqa: BLE001 — секретный payload исключения не выходит из источника.
            return None
        finally:
            if database is not None:
                database.close()
