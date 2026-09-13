from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import urllib.parse
from pathlib import PurePosixPath
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .renderers import GeneratedFile
from .targetfs import TargetFS


STATE_PATH = "/var/lib/lucx-post-configurator/state.json"
FAILED_STATE_PATH = "/var/lib/lucx-post-configurator/failed-state.json"
BACKUP_ROOT = "/var/backups/lucx-post-configurator"
STAGING_ROOT = "/var/lib/lucx-post-configurator/staging"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9T_-]{0,127}$")


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"


def _check_run_id(run_id: str) -> None:
    if not RUN_ID_RE.fullmatch(run_id):
        raise RuntimeError("invalid backup/staging run identifier")


@dataclass(slots=True)
class Backup:
    run_id: str
    directory: Path
    metadata: dict[str, Any]


def _backup_copy_path(directory: Path, target: str) -> Path:
    return directory / "files" / target.lstrip("/")


def create_backup(
    fs: TargetFS,
    generated: dict[str, GeneratedFile],
    run_id: str,
    *,
    extra_targets: list[str] | None = None,
    directory_targets: dict[str, int] | None = None,
) -> Backup:
    _check_run_id(run_id)
    directory = fs.path(f"{BACKUP_ROOT}/{run_id}")
    if directory.exists():
        raise RuntimeError(f"backup directory already exists: {directory}")
    directory.mkdir(parents=True, mode=0o700)
    entries: list[dict[str, Any]] = []
    targets = set(generated)
    targets.update(extra_targets or [])
    directory_targets = dict(directory_targets or {})
    # Родители, которых ещё нет, тоже будут созданы нашей записью. Их пустые
    # записи нужны для точечного отката; непустой внешний каталог не удаляется.
    for target in [*targets, *directory_targets]:
        parent = fs.path(target).parent
        while parent != fs.root and not parent.exists() and not parent.is_symlink():
            directory_targets.setdefault("/" + parent.relative_to(fs.root).as_posix(), 0o755)
            parent = parent.parent
    for target in sorted(targets):
        path = fs.path(target)
        is_link = path.is_symlink()
        entry: dict[str, Any] = {"target": target, "existed": path.exists() or is_link}
        if is_link:
            entry.update({"kind": "symlink", "link_target": os.readlink(path)})
        elif path.exists():
            if not path.is_file():
                raise RuntimeError(f"managed target is not a regular file: {target}")
            destination = _backup_copy_path(directory, target)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination, follow_symlinks=False)
            original_metadata = path.stat(follow_symlinks=False)
            entry.update(
                {
                    "sha256": fs.sha256(target),
                    "mode": stat.S_IMODE(original_metadata.st_mode),
                    "uid": original_metadata.st_uid,
                    "gid": original_metadata.st_gid,
                    "kind": "file",
                }
            )
        entries.append(entry)
    for target in sorted(directory_targets or {}):
        if target in targets:
            raise RuntimeError(f"managed directory conflicts with file target: {target}")
        path = fs.path(target)
        if path.is_symlink():
            raise RuntimeError(f"managed directory is a symlink: {target}")
        existed = path.exists()
        if existed and not path.is_dir():
            raise RuntimeError(f"managed directory target is not a directory: {target}")
        entry = {"target": target, "existed": existed, "kind": "directory"}
        if existed:
            entry["mode"] = stat.S_IMODE(path.stat().st_mode)
        entries.append(entry)
    metadata = {"schema_version": 1, "run_id": run_id, "created_at": datetime.now(timezone.utc).isoformat(), "entries": entries}
    metadata_path = directory / "backup.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    os.chmod(metadata_path, 0o600)
    return Backup(run_id, directory, metadata)


def stage_files(fs: TargetFS, generated: dict[str, GeneratedFile], run_id: str) -> dict[str, Path]:
    _check_run_id(run_id)
    root = fs.path(f"{STAGING_ROOT}/{run_id}")
    if root.exists():
        raise RuntimeError(f"staging directory already exists: {root}")
    staged: dict[str, Path] = {}
    for target, artifact in generated.items():
        destination = root / target.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if artifact.symlink_target:
            if artifact.content or not artifact.symlink_target.startswith("/"):
                raise RuntimeError(f"invalid generated symlink artifact: {target}")
            os.symlink(artifact.symlink_target, destination)
        else:
            destination.write_bytes(artifact.content)
            os.chmod(destination, artifact.mode)
        staged[target] = destination
    return staged


def remove_staging(fs: TargetFS, run_id: str) -> None:
    _check_run_id(run_id)
    root = fs.path(f"{STAGING_ROOT}/{run_id}")
    expected_parent = fs.path(STAGING_ROOT)
    if root.parent != expected_parent:
        raise RuntimeError("refusing to remove an unexpected staging path")
    if root.is_dir() and not root.is_symlink():
        shutil.rmtree(root)


def backup_lucx_database(fs: TargetFS, backup: Backup, db_path: str) -> dict[str, Any]:
    source_path = fs.path(db_path)
    if not source_path.is_file():
        raise RuntimeError(f"LucX database disappeared before backup: {db_path}")
    free_bytes = shutil.disk_usage(backup.directory).free
    if free_bytes < max(source_path.stat().st_size * 3, 16 * 1024 * 1024):
        raise RuntimeError("insufficient free space for a consistent LucX database backup")
    destination = backup.directory / "lucx" / "x-ui.db"
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    source = sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True, timeout=10)
    target = sqlite3.connect(destination)
    try:
        source.execute("PRAGMA query_only=ON")
        source.backup(target)
        integrity = target.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise RuntimeError("LucX backup failed SQLite integrity_check")
    finally:
        target.close()
        source.close()
    os.chmod(destination, 0o600)
    digest = hashlib.sha256()
    with destination.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    record = {
        "path": "lucx/x-ui.db",
        "source": db_path,
        "size": destination.stat().st_size,
        "sha256": digest.hexdigest(),
        "sensitive": True,
        "restore_policy": "targeted public-URL metadata rollback is automatic; full snapshot restore is manual disaster recovery",
    }
    backup.metadata["lucx_database_snapshot"] = record
    metadata_path = backup.directory / "backup.json"
    metadata_path.write_text(
        json.dumps(backup.metadata, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(metadata_path, 0o600)
    return record


MISSING = object()

# Hostname-like inbound settings keys used by LucX tunnel protocols. Only a key
# that already exists and still holds the previous public domain is rewritten,
# so a protocol or LucX version we do not know cannot be corrupted.
ENDPOINT_NAME_KEYS = ("domain", "hostname", "sni", "serverName")
ENDPOINT_CERT_KEYS = (("certFile", "cert"), ("keyFile", "key"))


def _json_get(obj: Any, path: tuple[Any, ...]) -> Any:
    current = obj
    for step in path:
        if isinstance(step, int):
            if not isinstance(current, list) or step >= len(current):
                return MISSING
            current = current[step]
            continue
        if not isinstance(current, dict) or step not in current:
            return MISSING
        current = current[step]
    return current


def _json_set(obj: Any, path: tuple[Any, ...], value: Any) -> None:
    current = obj
    for step in path[:-1]:
        current = current[step]
    current[path[-1]] = value


def _json_unset(obj: Any, path: tuple[Any, ...]) -> None:
    current = obj
    for step in path[:-1]:
        current = current[step]
    if isinstance(path[-1], int):
        return
    if isinstance(current, dict):
        current.pop(path[-1], None)


def _endpoint_field_plan(
    document: Any,
    *,
    old_domain: str,
    new_domain: str,
    cert_path: str,
    key_path: str,
    name_paths: tuple[tuple[Any, ...], ...],
    cert_paths: tuple[tuple[tuple[Any, ...], str], ...],
) -> list[dict[str, Any]]:
    """Return the exact field rewrites required for one JSON column."""

    planned: list[dict[str, Any]] = []
    for path in name_paths:
        current = _json_get(document, path)
        if current is MISSING or not isinstance(current, str):
            continue
        if current.strip().lower() != old_domain:
            continue
        if current == new_domain:
            continue
        planned.append({"path": list(path), "old": current, "new": new_domain, "existed": True})
    for path, kind in cert_paths:
        current = _json_get(document, path)
        if current is MISSING or not isinstance(current, str):
            continue
        if not current.startswith("/"):
            continue
        replacement = cert_path if kind == "cert" else key_path
        if current == replacement:
            continue
        planned.append({"path": list(path), "old": current, "new": replacement, "existed": True})
    return planned


def _settings_endpoint_paths(
    document: Any,
) -> tuple[tuple[tuple[Any, ...], ...], tuple[tuple[tuple[Any, ...], str], ...]]:
    if not isinstance(document, dict):
        return (), ()
    names = tuple((key,) for key in ENDPOINT_NAME_KEYS if key in document)
    certs = tuple(((key,), kind) for key, kind in ENDPOINT_CERT_KEYS if key in document)
    return names, certs


def _stream_endpoint_paths(
    document: Any,
) -> tuple[tuple[tuple[Any, ...], ...], tuple[tuple[tuple[Any, ...], str], ...]]:
    if not isinstance(document, dict):
        return (), ()
    if str(document.get("security") or "").strip().lower() == "reality":
        # Reality camouflage serverNames are third-party domains; never rewrite.
        return (), ()
    tls = document.get("tlsSettings")
    if not isinstance(tls, dict):
        return (), ()
    names: list[tuple[Any, ...]] = []
    if "serverName" in tls:
        names.append(("tlsSettings", "serverName"))
    certs: list[tuple[tuple[Any, ...], str]] = []
    certificates = tls.get("certificates")
    if isinstance(certificates, list):
        for index, entry in enumerate(certificates):
            if not isinstance(entry, dict):
                continue
            if "certificateFile" in entry:
                certs.append((("tlsSettings", "certificates", index, "certificateFile"), "cert"))
            if "keyFile" in entry:
                certs.append((("tlsSettings", "certificates", index, "keyFile"), "key"))
    return tuple(names), tuple(certs)


def _new_publication_host(
    connection: sqlite3.Connection, inbound_id: int, domain: str, public_port: int,
) -> dict[str, Any]:
    # LucX lucx.230: пустые overrides наследуют TLS/Reality/HTTP Host inbound.
    text_fields = {
        "group_id", "remark", "server_description", "tags", "address", "security", "sni",
        "host_header", "path", "alpn", "fingerprint", "pinned_peer_cert_sha256",
        "verify_peer_cert_by_name", "ech_config_list", "mux_params", "sockopt_params",
        "final_mask", "vless_route", "exclude_from_sub_types", "mihomo_ip_version", "node_guids",
    }
    number_fields = {
        "is_disabled", "is_hidden", "override_sni_from_address", "keep_sni_blank",
        "allow_insecure", "mihomo_x25519", "shuffle_host",
    }
    integer_fields = {"id", "inbound_id", "sort_order", "port", "created_at", "updated_at"}
    expected_types = {**dict.fromkeys(text_fields, "TEXT"),
                      **dict.fromkeys(number_fields, "NUMERIC"),
                      **dict.fromkeys(integer_fields, "INTEGER")}
    schema = list(connection.execute("PRAGMA table_xinfo(hosts)"))
    if connection.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND lower(tbl_name)='hosts' LIMIT 1").fetchone():
        raise RuntimeError("LucX hosts содержит неподтверждённые SQL triggers")
    if ({str(row["name"]): str(row["type"]).upper() for row in schema} != expected_types
            or any(row["hidden"] for row in schema)
            or [row["name"] for row in schema if row["pk"]] != ["id"]):
        raise RuntimeError("LucX hosts schema не поддерживает безопасное создание Host")
    inbound = connection.execute(
        "SELECT enable, stream_settings FROM inbounds WHERE id = ?", (inbound_id,),
    ).fetchone()
    if inbound is None or not inbound["enable"]:
        raise RuntimeError(f"inbound #{inbound_id}: создание Host требует включённый inbound")
    try:
        stream = json.loads(str(inbound["stream_settings"] or "{}"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"inbound #{inbound_id}: некорректный stream_settings") from exc
    if not isinstance(stream, dict) or stream.get("externalProxy"):
        raise RuntimeError(f"inbound #{inbound_id}: создание Host не может заменить legacy externalProxy")
    if not domain or ":" in domain or not 1 <= public_port <= 65535:
        raise RuntimeError(f"inbound #{inbound_id}: некорректный публичный endpoint")
    values: dict[str, Any] = {**dict.fromkeys(text_fields, ""),
                              **dict.fromkeys(number_fields | (integer_fields - {"id"}), 0)}
    for field in ("tags", "alpn", "pinned_peer_cert_sha256", "exclude_from_sub_types", "node_guids"):
        values[field] = "[]"
    timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)
    values.update(group_id=os.urandom(8).hex(), inbound_id=inbound_id, address=domain,
                  port=public_port, security="same", created_at=timestamp, updated_at=timestamp)
    return values


def _created_host_matches(row: sqlite3.Row | None, change: dict[str, Any]) -> bool:
    expected = change.get("new_row")
    if row is None or not isinstance(expected, dict):
        return False
    actual = dict(row)
    return (
        expected.get("id") == change.get("host_id")
        and expected.get("inbound_id") == change.get("inbound_id")
        and actual.keys() == expected.keys()
        and all(type(actual[key]) is type(expected[key]) and actual[key] == expected[key]
                for key in actual)
    )


def synchronize_lucx_publication(
    fs: TargetFS,
    db_path: str,
    *,
    panel_domain: str | None,
    subscription_domain: str | None,
    panel_path: str | None = None,
    subscription_base_url: str | None = None,
    naive_publications: list[dict[str, Any]] | None = None,
    public_publications: list[dict[str, Any]] | None = None,
    certificate_paths: dict[str, str] | None = None,
    endpoint_updates: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Synchronize the explicitly allowed public URL metadata atomically.

    Only webDomain, subDomain, optional webBasePath/subURI family, and the
    public endpoint metadata of explicitly selected inbounds are writable.
    New LucX releases render subscriptions from enabled hosts rows before
    falling back to inbounds.share_addr, so both stores are synchronized.
    Listener ports, clients, credentials, and unrelated inbound settings are
    never selected or modified.  The sole exception is ``endpoint_updates``:
    when the user explicitly confirms a DNS zone migration, hostname-like
    fields (Naive ``domain``, TrustTunnel ``hostname``, AnyTLS ``sni``,
    Xray ``tlsSettings.serverName``) and previously configured absolute
    certificate/key paths are rewritten so LucX itself regenerates tunnel
    configuration files at the next restart.  The tool never edits generated
    tunnel files directly.
    """

    path = fs.path(db_path)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"LucX database is not a regular file: {db_path}")
    desired: dict[str, str] = {}
    if panel_domain is not None:
        desired["webDomain"] = str(panel_domain).strip().lower()
    if subscription_domain is not None:
        desired["subDomain"] = str(subscription_domain).strip().lower()
    if panel_path is not None:
        desired["webBasePath"] = str(panel_path)
    if subscription_base_url is not None:
        base = str(subscription_base_url).strip().rstrip("/")
        parsed = urllib.parse.urlsplit(base + "/")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError(
                "subscription base URL must be an absolute http(s) URL"
            )
        desired["subURI"] = base + "/sub/"
        desired["subJsonURI"] = base + "/json/"
        desired["subClashURI"] = base + "/clash/"
        desired["subAwgURI"] = base + "/awg/"
    if certificate_paths is not None:
        desired.update(
            {
                "webCertFile": str(certificate_paths["cert_path"]),
                "webKeyFile": str(certificate_paths["key_path"]),
                "subCertFile": str(certificate_paths["cert_path"]),
                "subKeyFile": str(certificate_paths["key_path"]),
            }
        )
    publications = list(naive_publications or []) + list(public_publications or [])
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    changes: list[dict[str, Any]] = []
    try:
        connection.execute("PRAGMA busy_timeout=10000")
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(settings)")
        }
        if not {"key", "value"}.issubset(columns):
            raise RuntimeError("LucX settings table does not expose key/value columns")
        connection.execute("BEGIN IMMEDIATE")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise RuntimeError("LucX database failed integrity_check before domain synchronization")
        tables = {
            str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        host_columns: set[str] = set()
        publication_hosts: dict[int, list[sqlite3.Row]] = {}
        new_publication_hosts: dict[int, dict[str, Any]] = {}
        if publications:
            inbound_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(inbounds)")
            }
            if not {"id", "protocol", "share_addr"}.issubset(inbound_columns):
                raise RuntimeError("LucX inbounds table cannot safely synchronize Naive share_addr")
            if "hosts" not in tables:
                raise RuntimeError("LucX hosts table отсутствует; публикация остановлена")
            if "hosts" in tables:
                host_columns = {
                    str(row[1]) for row in connection.execute("PRAGMA table_info(hosts)")
                }
                required = {"id", "inbound_id", "address", "port", "is_disabled"}
                if not required.issubset(host_columns):
                    raise RuntimeError("LucX hosts schema cannot safely select enabled Host endpoints")
                order = "sort_order, id" if "sort_order" in host_columns else "id"
                # Проверяем весь запрос до первой записи: scalar publication не
                # описывает преобразование нескольких независимых Host aliases.
                for publication in publications:
                    inbound_id = int(publication["inbound_id"])
                    rows = list(connection.execute(
                        "SELECT id, address, port FROM hosts WHERE inbound_id = ? AND is_disabled = 0 ORDER BY " + order,
                        (inbound_id,)))
                    publication_hosts[inbound_id] = rows
                    if not rows:
                        if connection.execute(
                            "SELECT 1 FROM hosts WHERE inbound_id = ? LIMIT 1", (inbound_id,),
                        ).fetchone():
                            raise RuntimeError(f"inbound #{inbound_id}: disabled Hosts не включаются и не подменяются")
                        new_publication_hosts[inbound_id] = _new_publication_host(
                            connection, inbound_id, str(publication["domain"]).strip().lower(),
                            int(publication["public_port"]),
                        )
                    if len(rows) > 1 and (
                        str(rows[0]["address"] or "").strip().lower() != str(publication["domain"]).strip().lower()
                        or int(rows[0]["port"] or 0) != int(publication["public_port"])
                    ):
                        raise RuntimeError(
                            f"inbound #{inbound_id}: несколько enabled Host endpoints; миграция требует явной карты по Host, scalar publication запрещена"
                        )
        for key, new_value in desired.items():
            rows = list(connection.execute("SELECT value FROM settings WHERE key = ?", (key,)))
            if len(rows) > 1:
                raise RuntimeError(f"LucX settings contains duplicate {key} rows")
            existed = bool(rows)
            old_value = str(rows[0]["value"] or "") if rows else ""
            if old_value == new_value:
                continue
            if existed:
                connection.execute("UPDATE settings SET value = ? WHERE key = ?", (new_value, key))
            else:
                connection.execute("INSERT INTO settings(key, value) VALUES (?, ?)", (key, new_value))
            changes.append(
                {
                    "kind": "setting",
                    "key": key,
                    "old_value": old_value,
                    "new_value": new_value,
                    "existed": existed,
                }
            )
        for update in endpoint_updates or []:
            inbound_id = int(update["inbound_id"])
            row = connection.execute(
                "SELECT protocol, settings, stream_settings FROM inbounds WHERE id = ?",
                (inbound_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError(f"inbound #{inbound_id} does not exist")
            protocol_name = str(row["protocol"] or "").strip().lower()
            new_domain = str(update["domain"]).strip().lower()
            old_domain = str(update.get("old_domain") or "").strip().lower()
            approved = certificate_paths or {}
            cert_path = str(update.get("cert_path") or approved.get("cert_path") or "")
            key_path = str(update.get("key_path") or approved.get("key_path") or "")
            if not cert_path or not key_path:
                raise RuntimeError(
                    f"endpoint sync for inbound #{inbound_id} requires the approved certificate pair"
                )
            rewrites: list[dict[str, Any]] = []
            for column, path_builder in (
                ("settings", _settings_endpoint_paths),
                ("stream_settings", _stream_endpoint_paths),
            ):
                raw = str(row[column] or "{}")
                try:
                    document = json.loads(raw) if raw.strip() else {}
                except json.JSONDecodeError as exc:
                    raise RuntimeError(
                        f"inbound #{inbound_id} {column} is not valid JSON; refusing to update"
                    ) from exc
                names, certs = path_builder(document)
                planned = _endpoint_field_plan(
                    document,
                    old_domain=old_domain,
                    new_domain=new_domain,
                    cert_path=cert_path,
                    key_path=key_path,
                    name_paths=names,
                    cert_paths=certs,
                )
                if not planned:
                    continue
                for item in planned:
                    path = tuple(item["path"])
                    _json_set(document, path, item["new"])
                connection.execute(
                    f"UPDATE inbounds SET {column} = ? WHERE id = ?",
                    (json.dumps(document, ensure_ascii=False), inbound_id),
                )
                rewrites.append({"column": column, "fields": planned})
            if not rewrites:
                continue
            changes.append(
                {
                    "kind": "inbound_endpoint",
                    "inbound_id": inbound_id,
                    "protocol": protocol_name,
                    "rewrites": rewrites,
                }
            )
        for publication in publications:
            inbound_id = int(publication["inbound_id"])
            domain = str(publication["domain"]).strip().lower()
            public_port = int(publication["public_port"])
            # Host хранит порт отдельно; share_addr всегда остаётся чистым hostname.
            new_value = domain
            row = connection.execute(
                "SELECT protocol, share_addr FROM inbounds WHERE id = ?", (inbound_id,)
            ).fetchone()
            if row is None:
                raise RuntimeError(f"inbound #{inbound_id} does not exist")
            old_value = str(row["share_addr"] or "")
            if old_value != new_value:
                connection.execute(
                    "UPDATE inbounds SET share_addr = ? WHERE id = ?", (new_value, inbound_id)
                )
                changes.append(
                    {
                        "kind": "inbound_share_addr",
                        "inbound_id": inbound_id,
                        "old_value": old_value,
                        "new_value": new_value,
                    }
                )

            if host_columns:
                host_rows = publication_hosts[inbound_id]
                if not host_rows:
                    values = new_publication_hosts[inbound_id]
                    names = sorted(values)
                    quoted = ", ".join('"' + name + '"' for name in names)
                    cursor = connection.execute(
                        f"INSERT INTO hosts ({quoted}) VALUES ({', '.join('?' for _ in names)})",
                        tuple(values[name] for name in names),
                    )
                    host_id = int(cursor.lastrowid)
                    created = connection.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
                    if created is None:
                        raise RuntimeError("созданный Host отсутствует после INSERT")
                    expected = {"kind": "inbound_host_created", "inbound_id": inbound_id,
                                "host_id": host_id, "new_row": dict(values, id=host_id)}
                    if not _created_host_matches(created, expected):
                        raise RuntimeError("созданный Host не совпадает с подтверждёнными параметрами")
                    changes.append({"kind": "inbound_host_created", "inbound_id": inbound_id,
                                    "host_id": host_id, "new_row": dict(created)})
                    publication_hosts[inbound_id] = [created]
                    continue
                if len(host_rows) > 1:
                    # Запрос уже совпадает с primary: aliases и их порты/SNI/Host
                    # сохраняются полностью; обновлялся только legacy share_addr.
                    continue
                for host_row in host_rows:
                    host_id = int(host_row["id"])
                    old_address = str(host_row["address"] or "")
                    old_port = int(host_row["port"] or 0)
                    if old_address.strip().lower() == domain and old_port == public_port:
                        continue
                    connection.execute(
                        "UPDATE hosts SET address = ?, port = ? WHERE id = ? AND inbound_id = ?",
                        (domain, public_port, host_id, inbound_id),
                    )
                    changes.append(
                        {
                            "kind": "inbound_host_endpoint",
                            "inbound_id": inbound_id,
                            "host_id": host_id,
                            "old_address": old_address,
                            "new_address": domain,
                            "old_port": old_port,
                            "new_port": public_port,
                        }
                    )
        connection.commit()
        for change in changes:
            if change["kind"] == "setting":
                row = connection.execute(
                    "SELECT value FROM settings WHERE key = ?", (change["key"],)
                ).fetchone()
                label = change["key"]
                value = str(row["value"] or "") if row else None
            elif change["kind"] == "inbound_share_addr":
                row = connection.execute(
                    "SELECT share_addr FROM inbounds WHERE id = ?", (change["inbound_id"],)
                ).fetchone()
                label = f"inbound #{change['inbound_id']} share_addr"
                value = str(row["share_addr"] or "") if row else None
                if value != change["new_value"]:
                    raise RuntimeError(f"LucX publication synchronization verification failed for {label}")
                continue
            elif change["kind"] == "inbound_host_created":
                row = connection.execute(
                    "SELECT * FROM hosts WHERE id = ? AND inbound_id = ?",
                    (change["host_id"], change["inbound_id"]),
                ).fetchone()
                if not _created_host_matches(row, change):
                    raise RuntimeError("LucX publication synchronization verification failed for created Host")
                continue
            elif change["kind"] in ("inbound_naive_endpoint", "inbound_endpoint"):
                # Legacy records keep only the three Naive fields; generalized
                # records carry a per-field rewrite list for verification.
                row = connection.execute(
                    "SELECT settings FROM inbounds WHERE id = ?", (change["inbound_id"],)
                ).fetchone()
                label = f"inbound #{change['inbound_id']} endpoint"
                if change["kind"] == "inbound_naive_endpoint":
                    try:
                        parsed = json.loads(str(row["settings"] or "{}")) if row else {}
                    except json.JSONDecodeError:
                        parsed = {}
                    value = (
                        str(parsed.get("domain") or ""),
                        str(parsed.get("certFile") or ""),
                        str(parsed.get("keyFile") or ""),
                    ) if isinstance(parsed, dict) else None
                    expected = (change["new_domain"], change["new_cert"], change["new_key"])
                    if value != expected:
                        raise RuntimeError(f"LucX publication synchronization verification failed for {label}")
                    continue
                try:
                    parsed = json.loads(str(row["settings"] or "{}")) if row else {}
                except json.JSONDecodeError:
                    parsed = {}
                failed = False
                for rewrite in change.get("rewrites", []):
                    if rewrite.get("column") != "settings":
                        continue
                    document = parsed if isinstance(parsed, dict) else {}
                    for field in rewrite.get("fields", []):
                        current = _json_get(document, tuple(field["path"]))
                        if current is MISSING or current != field["new"]:
                            failed = True
                if failed:
                    raise RuntimeError(f"LucX publication synchronization verification failed for {label}")
                continue
            else:
                row = connection.execute(
                    "SELECT address, port FROM hosts WHERE id = ? AND inbound_id = ?",
                    (change["host_id"], change["inbound_id"]),
                ).fetchone()
                label = f"host #{change['host_id']} for inbound #{change['inbound_id']}"
                value = (
                    (str(row["address"] or ""), int(row["port"] or 0)) if row else None
                )
                expected = (change["new_address"], int(change["new_port"]))
                if value != expected:
                    raise RuntimeError(f"LucX publication synchronization verification failed for {label}")
                continue
            if value != change["new_value"]:
                raise RuntimeError(f"LucX publication synchronization verification failed for {label}")
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return changes


def synchronize_lucx_inbound_changes(
    fs: TargetFS,
    db_path: str,
    changes_requested: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Apply the narrow, explicitly approved inbound transport changes."""

    if not changes_requested:
        return []
    path = fs.path(db_path)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    changes: list[dict[str, Any]] = []
    try:
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("BEGIN IMMEDIATE")
        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(inbounds)")}
        if not {"id", "protocol", "stream_settings"}.issubset(columns):
            raise RuntimeError("LucX inbounds table cannot safely update transport_path")
        for requested in changes_requested:
            inbound_id = int(requested["inbound_id"])
            if requested.get("field") != "transport_path":
                raise RuntimeError(f"unsupported inbound change for #{inbound_id}")
            new_path = str(requested.get("value") or "")
            if not new_path.startswith("/") or new_path == "/" or ".." in PurePosixPath(new_path).parts:
                raise RuntimeError(f"invalid XHTTP path for inbound #{inbound_id}")
            row = connection.execute(
                "SELECT protocol, stream_settings FROM inbounds WHERE id = ?", (inbound_id,)
            ).fetchone()
            if row is None or str(row["protocol"] or "").lower() not in {"vless", "vmess"}:
                raise RuntimeError(f"inbound #{inbound_id} is not a supported XHTTP inbound")
            try:
                stream = json.loads(str(row["stream_settings"] or "{}"))
            except (TypeError, ValueError) as exc:
                raise RuntimeError(f"inbound #{inbound_id} stream_settings is invalid JSON") from exc
            if not isinstance(stream, dict) or not isinstance(stream.get("xhttpSettings"), dict):
                raise RuntimeError(f"inbound #{inbound_id} has no XHTTP settings")
            old_raw = str(row["stream_settings"] or "")
            stream["xhttpSettings"]["path"] = new_path
            new_raw = json.dumps(stream, ensure_ascii=False, separators=(",", ":"))
            if old_raw == new_raw:
                continue
            connection.execute(
                "UPDATE inbounds SET stream_settings = ? WHERE id = ? AND stream_settings = ?",
                (new_raw, inbound_id, old_raw),
            )
            if connection.total_changes < 1:
                raise RuntimeError(f"inbound #{inbound_id} changed during transport update")
            changes.append({
                "kind": "inbound_transport_path",
                "inbound_id": inbound_id,
                "old_value": old_raw,
                "new_value": new_raw,
            })
        connection.commit()
        return changes
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def rollback_lucx_publication(
    fs: TargetFS,
    db_path: str,
    changes: list[dict[str, Any]],
) -> None:
    """Guardedly undo publication changes without overwriting later edits."""

    if not changes:
        return
    path = fs.path(db_path)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("BEGIN IMMEDIATE")
        for change in reversed(changes):
            if change.get("kind", "setting") == "setting":
                key = str(change["key"])
                row = connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
                current = str(row["value"] or "") if row else None
                if current != str(change["new_value"]):
                    raise RuntimeError(
                        f"refusing LucX publication rollback because {key} changed after apply"
                    )
                if change.get("existed"):
                    connection.execute(
                        "UPDATE settings SET value = ? WHERE key = ?",
                        (str(change.get("old_value") or ""), key),
                    )
                else:
                    connection.execute("DELETE FROM settings WHERE key = ?", (key,))
            elif change.get("kind") == "inbound_share_addr":
                inbound_id = int(change["inbound_id"])
                row = connection.execute(
                    "SELECT share_addr FROM inbounds WHERE id = ?", (inbound_id,)
                ).fetchone()
                current = str(row["share_addr"] or "") if row else None
                if current != str(change["new_value"]):
                    raise RuntimeError(
                        f"refusing LucX publication rollback because inbound #{inbound_id} changed after apply"
                    )
                connection.execute(
                    "UPDATE inbounds SET share_addr = ? WHERE id = ?",
                    (str(change.get("old_value") or ""), inbound_id),
                )
            elif change.get("kind") == "inbound_host_created":
                row = connection.execute(
                    "SELECT * FROM hosts WHERE id = ? AND inbound_id = ?",
                    (change["host_id"], change["inbound_id"]),
                ).fetchone()
                if not _created_host_matches(row, change):
                    raise RuntimeError("refusing created Host rollback because its row changed after apply")
                connection.execute(
                    "DELETE FROM hosts WHERE id = ? AND inbound_id = ?",
                    (change["host_id"], change["inbound_id"]),
                )
            elif change.get("kind") == "inbound_transport_path":
                inbound_id = int(change["inbound_id"])
                row = connection.execute(
                    "SELECT stream_settings FROM inbounds WHERE id = ?", (inbound_id,)
                ).fetchone()
                current = str(row["stream_settings"] or "") if row else None
                if current != str(change["new_value"]):
                    raise RuntimeError(
                        f"refusing inbound transport rollback because inbound #{inbound_id} changed after apply"
                    )
                connection.execute(
                    "UPDATE inbounds SET stream_settings = ? WHERE id = ?",
                    (str(change.get("old_value") or ""), inbound_id),
                )
            elif change.get("kind") == "inbound_endpoint":
                inbound_id = int(change["inbound_id"])
                row = connection.execute(
                    "SELECT settings, stream_settings FROM inbounds WHERE id = ?", (inbound_id,)
                ).fetchone()
                if row is None:
                    raise RuntimeError(f"inbound #{inbound_id} disappeared before rollback")
                documents: dict[str, Any] = {}
                for column in ("settings", "stream_settings"):
                    raw = str(row[column] or "{}")
                    try:
                        documents[column] = json.loads(raw) if raw.strip() else {}
                    except json.JSONDecodeError as exc:
                        raise RuntimeError(
                            f"inbound #{inbound_id} {column} is not valid JSON; rollback refused"
                        ) from exc
                refused = False
                for rewrite in change.get("rewrites", []):
                    column = str(rewrite.get("column") or "")
                    document = documents.get(column)
                    if not isinstance(document, dict):
                        continue
                    for field in rewrite.get("fields", []):
                        path = tuple(field["path"])
                        current = _json_get(document, path)
                        if current is MISSING or current != field["new"]:
                            refused = True
                            continue
                        if field.get("existed") and field.get("old"):
                            _json_set(document, path, field["old"])
                        else:
                            _json_unset(document, path)
                if refused:
                    raise RuntimeError(
                        f"refusing endpoint rollback because inbound #{inbound_id} "
                        "changed after apply"
                    )
                for column, document in documents.items():
                    connection.execute(
                        f"UPDATE inbounds SET {column} = ? WHERE id = ?",
                        (json.dumps(document, ensure_ascii=False), inbound_id),
                    )
            elif change.get("kind") == "inbound_naive_endpoint":
                inbound_id = int(change["inbound_id"])
                row = connection.execute(
                    "SELECT protocol, settings FROM inbounds WHERE id = ?", (inbound_id,)
                ).fetchone()
                if row is None:
                    raise RuntimeError(f"inbound #{inbound_id} disappeared before rollback")
                protocol_name = str(row["protocol"] or "").strip().lower()
                if protocol_name != "naive":
                    raise RuntimeError(
                        f"refusing Naive endpoint rollback because inbound #{inbound_id} is {protocol_name}"
                    )
                raw_settings = str(row["settings"] or "{}")
                try:
                    parsed = json.loads(raw_settings) if raw_settings.strip() else {}
                except json.JSONDecodeError as exc:
                    raise RuntimeError(
                        f"Naive inbound #{inbound_id} settings are not valid JSON; rollback refused"
                    ) from exc
                if not isinstance(parsed, dict):
                    raise RuntimeError(
                        f"Naive inbound #{inbound_id} settings are not a JSON object; rollback refused"
                    )
                current_fields = {
                    "domain": str(parsed.get("domain") or ""),
                    "certFile": str(parsed.get("certFile") or ""),
                    "keyFile": str(parsed.get("keyFile") or ""),
                }
                expected_fields = {
                    "domain": str(change["new_domain"]),
                    "certFile": str(change["new_cert"]),
                    "keyFile": str(change["new_key"]),
                }
                if current_fields != expected_fields:
                    raise RuntimeError(
                        f"refusing Naive endpoint rollback because inbound #{inbound_id} "
                        "changed after apply"
                    )
                old_fields = {
                    "domain": str(change["old_domain"]),
                    "certFile": str(change["old_cert"]),
                    "keyFile": str(change["old_key"]),
                }
                for field, value in old_fields.items():
                    if value:
                        parsed[field] = value
                    else:
                        parsed.pop(field, None)
                connection.execute(
                    "UPDATE inbounds SET settings = ? WHERE id = ?",
                    (json.dumps(parsed, ensure_ascii=False), inbound_id),
                )
            else:
                inbound_id = int(change["inbound_id"])
                host_id = int(change["host_id"])
                row = connection.execute(
                    "SELECT address, port FROM hosts WHERE id = ? AND inbound_id = ?",
                    (host_id, inbound_id),
                ).fetchone()
                current = (
                    (str(row["address"] or ""), int(row["port"] or 0)) if row else None
                )
                expected = (str(change["new_address"]), int(change["new_port"]))
                if current != expected:
                    raise RuntimeError(
                        "refusing LucX publication rollback because "
                        f"host #{host_id} for inbound #{inbound_id} changed after apply"
                    )
                connection.execute(
                    "UPDATE hosts SET address = ?, port = ? WHERE id = ? AND inbound_id = ?",
                    (
                        str(change.get("old_address") or ""),
                        int(change.get("old_port") or 0),
                        host_id,
                        inbound_id,
                    ),
                )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def managed_target_digest(fs: TargetFS, target: str) -> str:
    path = fs.path(target)
    if path.is_symlink():
        link_target = os.readlink(path)
        return "symlink:" + hashlib.sha256(link_target.encode("utf-8")).hexdigest()
    return fs.sha256(target)


def _atomic_symlink(fs: TargetFS, target: str, link_target: str) -> dict[str, Any]:
    if not link_target.startswith("/") or any(value in link_target for value in ("\x00", "\r", "\n")):
        raise RuntimeError(f"unsafe generated symlink target for {target}")
    path = fs.path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(descriptor)
    temporary_path = Path(temporary)
    temporary_path.unlink()
    try:
        os.symlink(link_target, temporary_path)
        metadata = temporary_path.lstat()
        receipt = {"existed": True, "kind": "symlink", "link_target": link_target,
                   "mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid, "gid": metadata.st_gid,
                   "inode": metadata.st_ino, "device": metadata.st_dev}
        os.replace(temporary_path, path)
        return receipt
    finally:
        if temporary_path.exists() or temporary_path.is_symlink():
            temporary_path.unlink()


def managed_target_state(fs: TargetFS, target: str) -> dict[str, Any]:
    """Состояние самого target; symlink не разрешается в содержимое назначения."""
    path = fs.path(target)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"existed": False}
    kind = "symlink" if stat.S_ISLNK(metadata.st_mode) else "file" if stat.S_ISREG(metadata.st_mode) else "directory" if stat.S_ISDIR(metadata.st_mode) else "other"
    state = {"existed": True, "kind": kind, "mode": stat.S_IMODE(metadata.st_mode),
             "uid": metadata.st_uid, "gid": metadata.st_gid,
             "inode": metadata.st_ino, "device": metadata.st_dev}
    if kind == "symlink":
        state["link_target"] = os.readlink(path)
    elif kind == "file":
        state["sha256"] = fs.sha256(target)
    return state


def _check_backup_target(fs: TargetFS, target: str, entries: dict[str, dict[str, Any]]) -> None:
    entry = entries.get(target)
    if entry is None:
        raise RuntimeError(f"Нет исходного backup для target: {target}")
    current = managed_target_state(fs, target)
    fields = ("existed", "kind", "mode", "uid", "gid", "sha256", "link_target") if entry["existed"] else ("existed",)
    if any(current.get(field) != entry.get(field) for field in fields if field in entry or field in ("existed", "sha256", "link_target")):
        raise RuntimeError(f"Управляемый target изменился после backup: {target}")


def _mkdir_tracked(fs: TargetFS, target: str, journal: dict[str, dict[str, Any]] | None) -> None:
    path = fs.path(target)
    missing = []
    while path != fs.root and not path.exists() and not path.is_symlink():
        missing.append(path)
        path = path.parent
    for path in reversed(missing):
        path.mkdir()
        if journal is not None:
            created = "/" + path.relative_to(fs.root).as_posix()
            journal[created] = managed_target_state(fs, created)


def ensure_managed_directories(fs: TargetFS, directory_targets: dict[str, int], *,
                               mutation_journal: dict[str, dict[str, Any]] | None = None,
                               baseline_entries: dict[str, dict[str, Any]] | None = None) -> None:
    for target, mode in sorted(
        directory_targets.items(), key=lambda item: (len(Path(item[0]).parts), item[0])
    ):
        if not 0 <= int(mode) <= 0o777:
            raise RuntimeError(f"invalid managed directory mode for {target}")
        path = fs.path(target)
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise RuntimeError(f"managed directory target is unsafe: {target}")
        if baseline_entries is not None and (mutation_journal is None or target not in mutation_journal):
            _check_backup_target(fs, target, baseline_entries)
        _mkdir_tracked(fs, target, mutation_journal)
        if mutation_journal is not None:
            mutation_journal[target] = managed_target_state(fs, target)
        os.chmod(path, int(mode))
        if mutation_journal is not None:
            expected = {**mutation_journal[target], "mode": stat.S_IMODE(path.lstat().st_mode) if os.name == "nt" else int(mode)}
            mutation_journal[target] = expected
            if managed_target_state(fs, target) != expected:
                raise RuntimeError(f"Каталог изменился во время commit: {target}")


def commit_files(
    fs: TargetFS,
    generated: dict[str, GeneratedFile],
    *,
    directory_targets: dict[str, int] | None = None,
    mutation_journal: dict[str, dict[str, Any]] | None = None,
    baseline_entries: dict[str, dict[str, Any]] | None = None,
) -> dict[str, str]:
    hashes: dict[str, str] = {}
    ensure_managed_directories(fs, directory_targets or {}, mutation_journal=mutation_journal,
                               baseline_entries=baseline_entries)
    for target, artifact in generated.items():
        if baseline_entries is not None:
            _check_backup_target(fs, target, baseline_entries)
        parent = fs.path(target).parent
        if parent != fs.root:
            _mkdir_tracked(fs, "/" + parent.relative_to(fs.root).as_posix(), mutation_journal)
        if artifact.symlink_target:
            if artifact.content:
                raise RuntimeError(f"generated symlink also contains file content: {target}")
            receipt = _atomic_symlink(fs, target, artifact.symlink_target)
        else:
            receipt = fs.atomic_write(target, artifact.content, mode=artifact.mode)
        if mutation_journal is not None:
            mutation_journal[target] = receipt
            if managed_target_state(fs, target) != receipt:
                raise RuntimeError(f"Target изменился сразу после commit: {target}")
        hashes[target] = managed_target_digest(fs, target)
    return hashes


def validated_removal_targets(
    fs: TargetFS,
    installed_hashes: dict[str, str],
    requested_targets: list[str],
) -> list[str]:
    """Select only unchanged files previously written by this configurator."""

    result: list[str] = []
    for target in sorted(set(requested_targets)):
        expected = installed_hashes.get(target)
        if not expected:
            continue
        path = fs.path(target)
        if not path.exists() and not path.is_symlink():
            continue
        if not path.is_symlink() and not path.is_file():
            raise RuntimeError(f"managed target changed type after the previous apply: {target}")
        if managed_target_digest(fs, target) != expected:
            raise RuntimeError(f"managed target changed after the previous apply: {target}")
        result.append(target)
    return result


def remove_managed_targets(
    fs: TargetFS,
    targets: list[str],
    installed_hashes: dict[str, str],
    *, mutation_journal: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Delete a validated managed file set, rechecking hashes at commit time."""

    validated = validated_removal_targets(fs, installed_hashes, targets)
    if validated != sorted(set(targets)):
        missing = sorted(set(targets) - set(validated))
        raise RuntimeError(
            "managed removal target disappeared before commit: " + ", ".join(missing)
        )
    for target in validated:
        # Повторная сверка непосредственно перед каждым удалением.
        validated_removal_targets(fs, installed_hashes, [target])
        fs.path(target).unlink()
        if mutation_journal is not None:
            mutation_journal[target] = {"existed": False}


def commit_managed_transition(
    fs: TargetFS,
    generated: dict[str, GeneratedFile],
    removal_targets: list[str],
    previous_hashes: dict[str, str],
    *,
    directory_targets: dict[str, int] | None = None,
    baseline: Backup | None = None,
    mutation_journal: dict[str, dict[str, Any]] | None = None,
) -> dict[str, str]:
    """Commit desired files and an already backed-up component removal set."""

    entries = {item["target"]: item for item in baseline.metadata["entries"]} if baseline else None
    if entries is not None:
        for target in [*generated, *removal_targets, *(directory_targets or {})]:
            _check_backup_target(fs, target, entries)
    validated = validated_removal_targets(fs, previous_hashes, removal_targets)
    if validated != sorted(set(removal_targets)):
        missing = sorted(set(removal_targets) - set(validated))
        raise RuntimeError(
            "managed removal target disappeared before commit: " + ", ".join(missing)
        )
    installed_hashes = commit_files(
        fs,
        generated,
        directory_targets=directory_targets,
        mutation_journal=mutation_journal,
        baseline_entries=entries,
    )
    remove_managed_targets(fs, validated, previous_hashes, mutation_journal=mutation_journal)
    return installed_hashes


def restore_backup(fs: TargetFS, backup: Backup, *,
                   expected_current: dict[str, dict[str, Any]] | None = None) -> list[str]:
    directory_entries: list[dict[str, Any]] = []
    conflicts: list[str] = []
    for entry in backup.metadata["entries"]:
        target = entry["target"]
        if expected_current is not None:
            if target not in expected_current:
                continue
            if managed_target_state(fs, target) != expected_current[target]:
                conflicts.append(target)
                continue
        path = fs.path(target)
        if entry.get("kind") == "directory":
            directory_entries.append(entry)
            continue
        if entry["existed"]:
            if entry.get("kind") == "symlink":
                if path.is_symlink() or path.is_file():
                    path.unlink()
                elif path.exists():
                    raise RuntimeError(f"refusing to replace non-file target during rollback: {target}")
                path.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(entry["link_target"], path)
                continue
            source = _backup_copy_path(backup.directory, target)
            if not source.is_file():
                raise RuntimeError(f"backup payload is missing for {target}")
            owner = (entry["uid"], entry["gid"]) if "uid" in entry and "gid" in entry else None
            options = {"owner": owner} if owner is not None else {}
            fs.atomic_write(target, source.read_bytes(), mode=int(entry.get("mode", 0o644)), **options)
        elif path.exists() or path.is_symlink():
            if not path.is_file() and not path.is_symlink():
                raise RuntimeError(f"refusing to remove non-file target during rollback: {target}")
            path.unlink()
    for entry in sorted(
        directory_entries,
        key=lambda item: (len(Path(item["target"]).parts), item["target"]),
        reverse=True,
    ):
        target = entry["target"]
        path = fs.path(target)
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise RuntimeError(f"refusing to restore unsafe managed directory: {target}")
        if entry["existed"]:
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, int(entry.get("mode", 0o755)))
        elif path.exists():
            try:
                path.rmdir()
            except OSError as exc:
                if expected_current is not None:
                    conflicts.append(target)
                    continue
                raise RuntimeError(
                    f"refusing to remove non-empty managed directory during rollback: {target}"
                ) from exc
    return conflicts


def save_state(fs: TargetFS, state: dict[str, Any]) -> dict[str, Any]:
    persisted = json.loads(json.dumps(state))
    backend = (persisted.get("manifest") or {}).get("trusttunnel_backend")
    if isinstance(backend, dict) and backend.get("credentials"):
        backend["credentials"] = []
        backend["credentials_file"] = "/etc/x-tuna/trusttunnel/credentials.toml"
    return fs.atomic_write_text(STATE_PATH, json.dumps(persisted, ensure_ascii=False, indent=2) + "\n", mode=0o600)


def load_state(fs: TargetFS) -> dict[str, Any]:
    path = fs.path(STATE_PATH)
    if not path.is_file():
        raise RuntimeError("no lucx-post-configurator state exists")
    state = json.loads(path.read_text(encoding="utf-8"))
    manifest = state.get("manifest")
    if isinstance(manifest, dict):
        from .migrations import migrate_manifest

        state["manifest"] = migrate_manifest(manifest)
        backend = state["manifest"].get("trusttunnel_backend") or {}
        credentials_path = backend.get("credentials_file")
        if credentials_path and fs.exists(str(credentials_path)):
            from .trusttunnel_backend import read_backend_credentials

            backend["credentials"] = read_backend_credentials(fs.path(str(credentials_path)))
    return state


def save_failed_state(fs: TargetFS, state: dict[str, Any]) -> None:
    from .diagnostics import redact

    fs.atomic_write_text(
        FAILED_STATE_PATH,
        # Это root-only вход --resume; публичные отчёты обезличиваются отдельно.
        json.dumps(redact(state, network=False), ensure_ascii=False, indent=2) + "\n",
        mode=0o600,
    )


def load_failed_state(fs: TargetFS) -> dict[str, Any]:
    path = fs.path(FAILED_STATE_PATH)
    if not path.is_file():
        raise RuntimeError("no failed lucx-post-configurator run exists")
    state = json.loads(path.read_text(encoding="utf-8"))
    manifest = state.get("manifest")
    if isinstance(manifest, dict):
        from .migrations import migrate_manifest

        state["manifest"] = migrate_manifest(manifest)
    return state


def clear_failed_state(fs: TargetFS) -> None:
    path = fs.path(FAILED_STATE_PATH)
    if path.is_file() and not path.is_symlink():
        path.unlink()


def load_backup(fs: TargetFS, run_id: str) -> Backup:
    _check_run_id(run_id)
    directory = fs.path(f"{BACKUP_ROOT}/{run_id}")
    metadata_path = directory / "backup.json"
    if not metadata_path.is_file():
        raise RuntimeError(f"backup metadata not found for run {run_id}")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    return Backup(run_id, directory, metadata)


def rollback_latest(fs: TargetFS, *, force: bool = False) -> str:
    state = load_state(fs)
    installed_hashes = state.get("installed_hashes") or {}
    changed: list[str] = []
    for target, expected in installed_hashes.items():
        path = fs.path(target)
        if (path.is_file() or path.is_symlink()) and managed_target_digest(fs, target) != expected:
            changed.append(target)
        elif not path.exists() and expected:
            changed.append(target)
    if changed and not force:
        raise RuntimeError(
            "managed files changed after apply; refusing rollback without --force: " + ", ".join(changed)
        )
    backup = load_backup(fs, state.get("rollback_backup_id", state["run_id"]))
    restore_backup(fs, backup)
    return backup.run_id
