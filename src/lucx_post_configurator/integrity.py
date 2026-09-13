from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from typing import Any

from .targetfs import TargetFS


VOLATILE_INBOUND_COLUMNS = {
    "up",
    "down",
    "total",
    "expiry_time",
    "last_reset_time",
    "last_traffic_reset_time",
    # Protocol/transport settings are mutable between updates: LucX and its
    # updater may normalise or extend them, and the user may change transports
    # in the panel. Only structural columns (id/protocol/port/listen/enable,
    # share_addr, host publication) and the Naive Caddyfile remain protected.
    "settings",
    "stream_settings",
}


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _digest(value: Any) -> str:
    payload = json.dumps(
        {"type": type(value).__name__, "value": _json_value(value)},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _normalize_inbound_value(protocol: str, column: str, value: Any) -> Any:
    """Normalize values LucX rewrites without changing their meaning."""
    if column == "share_addr" and isinstance(value, str):
        if value.lower().endswith(":443"):
            return value[:-4]
    return value


def _normalize_public_address(value: Any) -> Any:
    if isinstance(value, str) and value.lower().endswith(":443"):
        return value[:-4]
    return value


def _table_columns(connection: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")]


def _snapshot_lucx(fs: TargetFS, db_path: str) -> dict[str, Any]:
    path = fs.path(db_path)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"LucX database is not a regular file: {db_path}")
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        schema: dict[str, list[str]] = {}
        settings: dict[str, list[str]] = {}
        inbounds: dict[str, dict[str, str]] = {}
        hosts: dict[str, dict[str, str]] = {}

        if "settings" in tables:
            columns = _table_columns(connection, "settings")
            schema["settings"] = columns
            if {"key", "value"}.issubset(columns):
                for row in connection.execute(
                    "SELECT key, value FROM settings ORDER BY key, id"
                    if "id" in columns
                    else "SELECT key, value FROM settings ORDER BY key"
                ):
                    settings.setdefault(str(row["key"]), []).append(_digest(row["value"]))

        if "inbounds" in tables:
            columns = _table_columns(connection, "inbounds")
            schema["inbounds"] = columns
            if "id" in columns:
                selected = [name for name in columns if name not in VOLATILE_INBOUND_COLUMNS]
                quoted = ", ".join('"' + name.replace('"', '""') + '"' for name in selected)
                for row in connection.execute(f"SELECT {quoted} FROM inbounds ORDER BY id"):
                    inbound_id = str(int(row["id"]))
                    protocol = str(row["protocol"] or "").lower()
                    item = {
                        name: _digest(_normalize_inbound_value(protocol, name, row[name]))
                        for name in selected
                        if name not in {"id", "settings"}
                    }
                    inbounds[inbound_id] = item

        if "hosts" in tables:
            columns = _table_columns(connection, "hosts")
            schema["hosts"] = columns
            if "id" in columns:
                quoted = ", ".join('"' + name.replace('"', '""') + '"' for name in columns)
                for row in connection.execute(f"SELECT {quoted} FROM hosts ORDER BY id"):
                    host_id = str(int(row["id"]))
                    hosts[host_id] = {
                        name: _digest(row[name]) for name in columns if name != "id"
                    }
    finally:
        connection.close()
    return {
        "db_path": db_path,
        "schema": schema,
        "settings": settings,
        "inbounds": inbounds,
        "hosts": hosts,
    }


def _snapshot_caddy(fs: TargetFS, caddy: dict[str, Any]) -> dict[str, Any]:
    configured_files = caddy.get("files")
    if isinstance(configured_files, list) and configured_files:
        snapshots = [
            _snapshot_caddy(fs, item)
            for item in configured_files
            if isinstance(item, dict)
        ]
        snapshots.sort(key=lambda item: str(item.get("path") or ""))
        if not snapshots:
            return {"found": False, "files": []}
        result = dict(snapshots[0])
        result["files"] = snapshots
        return result
    target = str(caddy.get("path") or "") if caddy.get("found") else ""
    if not target:
        return {"found": False}
    path = fs.path(target)
    if not path.exists() and not path.is_symlink():
        return {"found": False, "path": target}
    metadata = path.lstat()
    if path.is_symlink():
        kind = "symlink"
    elif path.is_file():
        kind = "file"
    else:
        kind = "other"
    result: dict[str, Any] = {
        "found": True,
        "path": target,
        "kind": kind,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": int(metadata.st_uid),
        "gid": int(metadata.st_gid),
    }
    if kind == "symlink":
        result["link_target"] = os.readlink(path)
    if path.is_file():
        result["sha256"] = fs.sha256(target)
    return result


def capture_integrity(
    fs: TargetFS,
    db_path: str,
    caddy: dict[str, Any],
) -> dict[str, Any]:
    return {
        "protected_lucx": _snapshot_lucx(fs, db_path),
        "naive_caddyfile": _snapshot_caddy(fs, caddy),
    }


def compare_caddy(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    ignore_content: bool = False,
) -> list[str]:
    labels = {
        "found": "existence",
        "path": "path",
        "kind": "file type",
        "mode": "mode",
        "uid": "owner uid",
        "gid": "owner gid",
        "link_target": "symlink target",
    }
    if not ignore_content:
        labels["sha256"] = "content sha256"
    before_files = before.get("files")
    after_files = after.get("files")
    if isinstance(before_files, list) or isinstance(after_files, list):
        old = {
            str(item.get("path") or ""): item
            for item in (before_files or ([before] if before.get("found") else []))
            if isinstance(item, dict)
        }
        new = {
            str(item.get("path") or ""): item
            for item in (after_files or ([after] if after.get("found") else []))
            if isinstance(item, dict)
        }
        errors: list[str] = []
        if set(old) != set(new):
            errors.append("Naive Caddyfile set changed")
        for path in sorted(set(old) & set(new)):
            for key, label in labels.items():
                if old[path].get(key) != new[path].get(key):
                    errors.append(f"Naive Caddyfile {path} {label} changed")
        return errors
    errors: list[str] = []
    for key, label in labels.items():
        if before.get(key) != after.get(key):
            errors.append(f"Naive Caddyfile {label} changed")
    return errors


def _allowed_paths(changes: list[dict[str, Any]]) -> dict[tuple[str, ...], tuple[Any, Any]]:
    result: dict[tuple[str, ...], tuple[Any, Any]] = {}
    for change in changes:
        kind = str(change.get("kind") or "setting")
        if kind == "setting":
            before = [_digest(change.get("old_value"))] if change.get("existed") else None
            after = [_digest(change.get("new_value"))]
            result[("settings", str(change["key"]))] = (before, after)
        elif kind == "inbound_share_addr":
            result[("inbounds", str(int(change["inbound_id"])), "share_addr")] = (
                _digest(change.get("old_value")),
                _digest(_normalize_public_address(change.get("new_value"))),
            )
        elif kind == "inbound_host_created":
            row = change.get("new_row")
            if (isinstance(row, dict) and type(row.get("id")) is int
                    and type(row.get("inbound_id")) is int
                    and row["id"] == change.get("host_id")
                    and row["inbound_id"] == change.get("inbound_id")):
                result[("hosts", str(row["id"]))] = (
                    None, {name: _digest(value) for name, value in row.items() if name != "id"},
                )
        elif kind == "inbound_host_endpoint":
            host_id = str(int(change["host_id"]))
            result[("hosts", host_id, "address")] = (
                _digest(change.get("old_address")),
                _digest(change.get("new_address")),
            )
            result[("hosts", host_id, "port")] = (
                _digest(int(change.get("old_port") or 0)),
                _digest(int(change.get("new_port") or 0)),
            )
        elif kind == "inbound_transport_path":
            result[("inbounds", str(int(change["inbound_id"])), "stream_settings")] = (
                _digest(change.get("old_value")),
                _digest(change.get("new_value")),
            )
    return result


def _is_allowed(
    path: tuple[str, ...],
    before: Any,
    after: Any,
    allowed: dict[tuple[str, ...], tuple[Any, Any]],
) -> bool:
    expected = allowed.get(path)
    return bool(expected is not None and expected == (before, after))


def compare_lucx(
    before: dict[str, Any],
    after: dict[str, Any],
    allowed_changes: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    if before.get("db_path") != after.get("db_path"):
        errors.append("LucX database path changed")
    if before.get("schema") != after.get("schema"):
        errors.append("LucX protected table schema changed")
    allowed = _allowed_paths(allowed_changes)

    old_settings = before.get("settings") or {}
    new_settings = after.get("settings") or {}
    for key in sorted(set(old_settings) | set(new_settings)):
        old = old_settings.get(key)
        new = new_settings.get(key)
        if old != new and not _is_allowed(("settings", key), old, new, allowed):
            errors.append(f"LucX setting {key} changed")

    for section, label in (("inbounds", "inbound"), ("hosts", "host")):
        old_rows = before.get(section) or {}
        new_rows = after.get(section) or {}
        for row_id in sorted(set(old_rows) | set(new_rows), key=lambda value: int(value)):
            if row_id not in old_rows:
                if not _is_allowed((section, row_id), None, new_rows[row_id], allowed):
                    errors.append(f"{label} #{row_id} was added")
                continue
            if row_id not in new_rows:
                errors.append(f"{label} #{row_id} was removed")
                continue
            old_row = old_rows[row_id]
            new_row = new_rows[row_id]
            protocol = str(new_row.get("protocol") or old_row.get("protocol") or "").lower()
            for field in sorted(set(old_row) | set(new_row)):
                if field in {
                    "settings",
                    "settings_raw_digest",
                    "settings_legacy_digests",
                    "settings_clients_digest",
                }:
                    continue
                if field not in new_row:
                    # The stored baseline predates the current volatile-column
                    # policy: the field (e.g. stream_settings) is excluded from
                    # new snapshots but still present in the old state. LucX
                    # owns this data, so dropping the guard for it is safe.
                    continue
                old = old_row.get(field)
                new = new_row.get(field)
                if (
                    old != new
                    and not _is_allowed((section, row_id, field), old, new, allowed)
                ):
                    errors.append(f"{label} #{row_id} {field} changed")
    return errors


def compare_integrity(
    before: dict[str, Any],
    after: dict[str, Any],
    allowed_changes: list[dict[str, Any]],
    *,
    naive_content_volatile: bool = False,
) -> list[str]:
    return compare_lucx(
        before.get("protected_lucx") or {},
        after.get("protected_lucx") or {},
        allowed_changes,
    ) + compare_caddy(
        before.get("naive_caddyfile") or {},
        after.get("naive_caddyfile") or {},
        ignore_content=naive_content_volatile,
    )
