#!/usr/bin/env python3
"""Compare live and pre-update LucX databases without printing secrets."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sqlite3
from typing import Any


def connect(path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(pathlib.Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}


def signature(connection: sqlite3.Connection, table: str, selected: list[str]) -> tuple[int, str]:
    available = columns(connection, table)
    fields = [field for field in selected if field in available]
    if not fields:
        return 0, ""
    rows = [tuple(row) for row in connection.execute(
        "SELECT " + ", ".join(fields) + f" FROM {table} ORDER BY " + fields[0]
    )]
    encoded = json.dumps(rows, ensure_ascii=False, separators=(",", ":"), default=str).encode()
    return len(rows), hashlib.sha256(encoded).hexdigest()


def changed_row_fields(
    before: sqlite3.Connection,
    after: sqlite3.Connection,
    table: str,
    selected: list[str],
) -> dict[str, list[str]]:
    shared = columns(before, table) & columns(after, table)
    fields = [field for field in selected if field in shared]
    if "id" not in fields:
        return {}
    query = "SELECT " + ", ".join(fields) + f" FROM {table} ORDER BY id"
    old_rows = {str(row["id"]): row for row in before.execute(query)}
    new_rows = {str(row["id"]): row for row in after.execute(query)}
    result: dict[str, list[str]] = {}
    for row_id in sorted(set(old_rows) | set(new_rows)):
        if row_id not in old_rows or row_id not in new_rows:
            result[row_id] = ["row-presence"]
            continue
        changed = [
            field for field in fields if old_rows[row_id][field] != new_rows[row_id][field]
        ]
        if changed:
            result[row_id] = changed
    return result


def json_diff_paths(before: Any, after: Any, prefix: str = "") -> list[str]:
    if type(before) is not type(after):
        return [prefix or "$"]
    if isinstance(before, dict):
        paths: list[str] = []
        for key in sorted(set(before) | set(after)):
            child = f"{prefix}.{key}" if prefix else str(key)
            if key not in before or key not in after:
                paths.append(child)
            else:
                paths.extend(json_diff_paths(before[key], after[key], child))
        return paths
    if isinstance(before, list):
        if len(before) != len(after):
            return [prefix + ".length"]
        paths: list[str] = []
        for index, (left, right) in enumerate(zip(before, after)):
            paths.extend(json_diff_paths(left, right, f"{prefix}[{index}]"))
        return paths
    return [] if before == after else [prefix or "$"]


def inbound_rows(connection: sqlite3.Connection) -> dict[int, sqlite3.Row]:
    return {
        int(row["id"]): row
        for row in connection.execute(
            "SELECT id, protocol, port, listen, enable, remark, settings FROM inbounds ORDER BY id"
        )
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("before")
    parser.add_argument("after")
    args = parser.parse_args()
    before = connect(args.before)
    after = connect(args.after)
    try:
        old_inbounds = inbound_rows(before)
        new_inbounds = inbound_rows(after)
        identities_before = [
            (key, row["protocol"], row["port"], row["listen"], row["enable"], row["remark"])
            for key, row in old_inbounds.items()
        ]
        identities_after = [
            (key, row["protocol"], row["port"], row["listen"], row["enable"], row["remark"])
            for key, row in new_inbounds.items()
        ]
        changed_settings: dict[str, list[str]] = {}
        for inbound_id in sorted(set(old_inbounds) & set(new_inbounds)):
            old_raw = old_inbounds[inbound_id]["settings"] or "{}"
            new_raw = new_inbounds[inbound_id]["settings"] or "{}"
            if old_raw == new_raw:
                continue
            try:
                paths = json_diff_paths(json.loads(old_raw), json.loads(new_raw))
            except (TypeError, json.JSONDecodeError):
                paths = ["unparseable-settings"]
            changed_settings[str(inbound_id)] = sorted(set(paths))

        credential_fields = [
            "id", "sub_id", "uuid", "password", "auth", "flow", "security", "reverse",
            "wg_private_key", "wg_public_key", "wg_allowed_ips", "wg_pre_shared_key",
            "wg_keep_alive", "wg_forwarded_ports", "secret", "enable", "group_name",
        ]
        old_client_count, old_client_hash = signature(before, "clients", credential_fields)
        new_client_count, new_client_hash = signature(after, "clients", credential_fields)
        changed_client_fields = changed_row_fields(
            before, after, "clients", credential_fields
        )
        old_links_count, old_links_hash = signature(
            before, "client_inbounds", ["id", "client_id", "inbound_id", "enable"]
        )
        new_links_count, new_links_hash = signature(
            after, "client_inbounds", ["id", "client_id", "inbound_id", "enable"]
        )
        old_hosts_count, old_hosts_hash = signature(
            before, "hosts", ["id", "inbound_id", "address", "port", "is_disabled", "sort_order"]
        )
        new_hosts_count, new_hosts_hash = signature(
            after, "hosts", ["id", "inbound_id", "address", "port", "is_disabled", "sort_order"]
        )
        report = {
            "ok": identities_before == identities_after
            and old_client_hash == new_client_hash
            and old_links_hash == new_links_hash,
            "inbound_identity_and_listeners_preserved": identities_before == identities_after,
            "enabled_inbound_ids_preserved": [
                row[0] for row in identities_before if row[4]
            ] == [row[0] for row in identities_after if row[4]],
            "client_credentials_preserved": old_client_hash == new_client_hash,
            "changed_client_fields": changed_client_fields,
            "client_counts": {"before": old_client_count, "after": new_client_count},
            "client_inbound_links_preserved": old_links_hash == new_links_hash,
            "client_inbound_link_counts": {"before": old_links_count, "after": new_links_count},
            "public_host_rows_preserved": old_hosts_hash == new_hosts_hash,
            "public_host_counts": {"before": old_hosts_count, "after": new_hosts_count},
            "changed_inbound_setting_paths": changed_settings,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ok"] else 1
    finally:
        before.close()
        after.close()


if __name__ == "__main__":
    raise SystemExit(main())
