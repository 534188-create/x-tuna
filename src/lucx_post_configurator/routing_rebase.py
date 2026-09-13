from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from .discovery import read_lucx_connection
from .integrity import VOLATILE_INBOUND_COLUMNS, capture_integrity
from .models import Audit
from .routing_profiles import source_routing_fingerprint
from .targetfs import TargetFS


# settings/stream_settings проверяются полностью; из существующего реестра
# исключаются только счётчики, а не транспорт или credentials.
_COUNTERS = VOLATILE_INBOUND_COLUMNS - {"settings", "stream_settings"}
_SETTING_KEYS = {"webDomain", "subDomain", "webBasePath", "subURI", "subJsonURI", "subClashURI", "subAwgURI",
                 "webCertFile", "webKeyFile", "subCertFile", "subKeyFile"}
_JSON_COLUMNS = {"settings", "stream_settings", "streamSettings"}


@dataclass(frozen=True, slots=True)
class RebaseBaseline:
    """В памяти остаются только хэши; сырой SQL/JSON не попадает в repr или отчёт."""
    db_path: str = field(repr=False)
    row_digests: dict[str, Any] = field(repr=False)
    schema: dict[str, list[str]] = field(repr=False)
    source_fingerprints: dict[int, str] = field(repr=False)
    naive_audit_snapshot: dict[str, Any] = field(repr=False)
    naive_integrity: dict[str, Any] = field(repr=False)


def _json_object(raw: Any) -> dict[str, Any]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Неоднозначный JSON в receipt или снимке LucX")
            result[key] = value
        return result
    try:
        value = json.loads(str(raw or "{}"), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, TypeError):
        raise ValueError("Некорректный JSON в receipt или снимке LucX") from None


def _digest(value: Any, *, json_column: bool = False) -> str:
    if json_column:
        value = _json_object(value)
    elif isinstance(value, bytes):
        value = {"bytes": value.hex()}
    encoded = json.dumps({"type": type(value).__name__, "value": value}, sort_keys=True,
                         ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _row_digests(rows: dict[str, Any]) -> dict[str, Any]:
    return {table: {key: {column: _digest(value, json_column=table == "inbounds" and column in _JSON_COLUMNS)
                         for column, value in row.items()}
                    for key, row in items.items()} for table, items in rows.items()}


@contextmanager
def _snapshot(fs: TargetFS, db_path: str):
    path = fs.path(db_path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("Rebase требует обычную read-only базу LucX")
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        # Все rows и нормализованный audit читаются из одной SQLite snapshot.
        tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        rows: dict[str, Any] = {}
        schema: dict[str, list[str]] = {}
        for table in ("settings", "inbounds", "hosts"):
            if table not in tables:
                continue
            columns = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")]
            schema[table] = columns
            selected = [name for name in columns if table != "inbounds" or name not in _COUNTERS]
            quoted = ",".join('"' + name.replace('"', '""') + '"' for name in selected)
            key_column = "key" if table == "settings" else "id"
            if key_column not in columns:
                raise ValueError("Схема LucX не подтверждает exact rebase")
            rows[table] = {}
            for raw in connection.execute(f"SELECT {quoted} FROM {table}"):
                key = str(raw[key_column])
                if key in rows[table]:
                    raise ValueError("Дубликаты строк LucX запрещают exact rebase")
                rows[table][key] = dict(raw)
        settings, inbounds, supported, _warnings = read_lucx_connection(connection)
        if not supported:
            raise ValueError("Discovery не подтверждает схему exact rebase")
        yield schema, rows, settings, {item.id: source_routing_fingerprint(item) for item in inbounds}
    except sqlite3.Error:
        raise ValueError("Не удалось прочитать единый SQLite snapshot для rebase") from None
    finally:
        connection.close()


def capture_rebase_baseline(fs: TargetFS, db_path: str, preaudit: Audit) -> RebaseBaseline:
    """Вызывать до разрешённой mutation; baseline сверяется с уже проверенным audit."""
    if not preaudit.db_schema_supported:
        raise ValueError("Исходный audit не подтверждает схему LucX")
    expected = {item.id: source_routing_fingerprint(item) for item in preaudit.inbounds}
    with _snapshot(fs, db_path) as (schema, rows, settings, fingerprints):
        if expected != fingerprints or settings != preaudit.settings:
            raise ValueError("LucX изменился между исходным audit и baseline snapshot")
        return RebaseBaseline(db_path, _row_digests(rows), schema, fingerprints,
            copy.deepcopy(preaudit.naive_caddyfile),
            capture_integrity(fs, db_path, preaudit.naive_caddyfile)["naive_caddyfile"])


def _replace(row: dict[str, Any], column: str, old: Any, new: Any) -> None:
    if column not in row or _digest(row[column], json_column=column in _JSON_COLUMNS) != _digest(new, json_column=column in _JSON_COLUMNS):
        raise ValueError("Фактическое поле LucX не совпадает с точным receipt")
    row[column] = old


def _path_parent(document: Any, path: list[Any]) -> tuple[Any, Any]:
    current = document
    try:
        for part in path[:-1]:
            current = current[part]
        current[path[-1]]
    except (KeyError, IndexError, TypeError):
        raise ValueError("Поле endpoint receipt отсутствует в JSON") from None
    return current, path[-1]


def _allowed_endpoint_path(column: str, path: Any) -> bool:
    if not isinstance(path, list) or not path:
        return False
    if column == "settings":
        return len(path) == 1 and path[0] in {"domain", "hostname", "sni", "serverName", "certFile", "keyFile"}
    return (path == ["tlsSettings", "serverName"] or
            len(path) == 4 and path[:2] == ["tlsSettings", "certificates"]
            and type(path[2]) is int and path[2] >= 0 and path[3] in {"certificateFile", "keyFile"})


def _reverse_receipt(rows: dict[str, Any], receipt: dict[str, Any]) -> None:
    kind = receipt.get("kind")
    if kind == "setting":
        key = receipt.get("key")
        if key not in _SETTING_KEYS or type(receipt.get("existed")) is not bool:
            raise ValueError("Неизвестное setting изменение в receipt")
        row = rows.get("settings", {}).get(key)
        if row is None:
            raise ValueError("Setting receipt не найден в снимке")
        _replace(row, "value", receipt["old_value"], receipt["new_value"])
        if not receipt["existed"]:
            del rows["settings"][key]
        return
    inbound_id = str(int(receipt.get("inbound_id") or 0))
    row = rows.get("inbounds", {}).get(inbound_id)
    if row is None:
        raise ValueError("Inbound receipt отсутствует в снимке")
    if kind == "inbound_share_addr":
        _replace(row, "share_addr", receipt["old_value"], receipt["new_value"])
    elif kind == "inbound_host_created":
        host_id = receipt.get("host_id")
        expected = receipt.get("new_row")
        host = rows.get("hosts", {}).get(str(host_id))
        if (type(host_id) is not int or host_id <= 0 or not isinstance(expected, dict)
                or host is None or host.get("id") != host_id
                or str(host.get("inbound_id")) != inbound_id or host.get("is_disabled") != 0
                or _row_digests({"hosts": {str(host_id): host}})
                != _row_digests({"hosts": {str(host_id): expected}})):
            raise ValueError("Созданный Host не совпадает с точным receipt")
        del rows["hosts"][str(host_id)]
    elif kind == "inbound_host_endpoint":
        host = rows.get("hosts", {}).get(str(int(receipt.get("host_id") or 0)))
        if host is None or str(host.get("inbound_id")) != inbound_id or host.get("is_disabled") != 0:
            raise ValueError("Host receipt не относится к включённому endpoint")
        _replace(host, "address", receipt["old_address"], receipt["new_address"])
        _replace(host, "port", receipt["old_port"], receipt["new_port"])
    elif kind == "inbound_transport_path":
        old, new = _json_object(receipt["old_value"]), _json_object(receipt["new_value"])
        if (row.get("protocol") not in {"vless", "vmess"} or not isinstance(old.get("xhttpSettings"), dict)
                or not isinstance(new.get("xhttpSettings"), dict)):
            raise ValueError("Path receipt не относится к известному XHTTP")
        path = new["xhttpSettings"].get("path")
        if not isinstance(path, str) or not path.startswith("/") or path == "/" or ".." in path.split("/"):
            raise ValueError("Path receipt содержит неподтверждённый путь")
        expected = copy.deepcopy(old)
        expected["xhttpSettings"]["path"] = path
        if expected != new:
            raise ValueError("Path receipt меняет поля вне transport_path")
        _replace(row, "stream_settings", receipt["old_value"], receipt["new_value"])
    elif kind == "inbound_endpoint":
        if row.get("protocol") != receipt.get("protocol"):
            raise ValueError("Протокол endpoint receipt не совпадает")
        for rewrite in reversed(receipt.get("rewrites") or []):
            column = rewrite.get("column")
            if column not in {"settings", "stream_settings"} or column not in row:
                raise ValueError("Неизвестная колонка endpoint receipt")
            document = _json_object(row[column])
            if column == "stream_settings" and document.get("security") == "reality":
                raise ValueError("Reality нельзя изменять через endpoint receipt")
            for change in reversed(rewrite.get("fields") or []):
                path = change.get("path")
                if not _allowed_endpoint_path(column, path) or change.get("existed") is not True:
                    raise ValueError("Неизвестное поле endpoint receipt")
                parent, key = _path_parent(document, path)
                if parent[key] != change.get("new") or not isinstance(change.get("old"), str) or not isinstance(change.get("new"), str):
                    raise ValueError("Endpoint JSON не соответствует receipt")
                parent[key] = change["old"]
            row[column] = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    else:
        raise ValueError("Неизвестный вид transaction receipt для rebase")


def verify_authorized_rebase(fs: TargetFS, db_path: str, baseline: RebaseBaseline,
                             receipts: list[dict[str, Any]]) -> dict[int, str]:
    """Только engine после явного разрешения: проверяем receipt, а не выдаём разрешение.

    Обратное применение выполняется исключительно в RAM. Если хоть одно поле
    не возвращается к baseline, новый routing fingerprint не выдаётся.
    """
    if db_path != baseline.db_path:
        raise ValueError("База LucX не совпадает с baseline rebase")
    with _snapshot(fs, db_path) as (schema, rows, _settings, fingerprints):
        if schema != baseline.schema:
            raise ValueError("Схема LucX изменилась после baseline")
        try:
            for receipt in reversed(receipts):
                _reverse_receipt(rows, receipt)
        except (KeyError, TypeError, IndexError, OverflowError, ValueError):
            raise ValueError("Некорректная структура или несоответствие transaction receipt") from None
        if _row_digests(rows) != baseline.row_digests:
            raise ValueError("Снимок LucX содержит изменения вне разрешённых receipt")
        return fingerprints
