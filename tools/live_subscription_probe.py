#!/usr/bin/env python3
"""Redacted live probe for an explicitly authorized LucX test server.

The probe reads one subscription id into memory, never prints it, and reports
only status/count/compatibility booleans. It does not write the database.
"""

from __future__ import annotations

import base64
import http.client
import json
import sqlite3
import ssl
import sys
import urllib.parse
from typing import Any


DB = "/etc/x-ui/x-ui.db"
SIDECAR_HOST = "127.0.0.1"
SIDECAR_PORT = 21000


def settings(connection: sqlite3.Connection) -> dict[str, str]:
    return {str(key): str(value or "") for key, value in connection.execute("SELECT key, value FROM settings")}


def strings_for_keys(value: Any, wanted: set[str]) -> list[str]:
    result: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower().replace("_", "") in wanted and isinstance(child, str):
                result.append(child)
            result.extend(strings_for_keys(child, wanted))
    elif isinstance(value, list):
        for child in value:
            result.extend(strings_for_keys(child, wanted))
    return result


def subscription_id(connection: sqlite3.Connection) -> str:
    for (raw,) in connection.execute("SELECT settings FROM inbounds WHERE enable = 1 ORDER BY id"):
        try:
            parsed = json.loads(raw or "{}")
        except (TypeError, json.JSONDecodeError):
            continue
        for candidate in strings_for_keys(parsed, {"subid", "subscriptionid"}):
            if 4 <= len(candidate) <= 512 and "\x00" not in candidate:
                return candidate
    raise RuntimeError("no subscription id found")


def join_path(prefix: str, identifier: str) -> str:
    return "/" + prefix.strip("/") + "/" + urllib.parse.quote(identifier, safe="")


def fetch(port: int, host: str, path: str, user_agent: str) -> tuple[int, dict[str, str], bytes]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=30, context=context)
    try:
        connection.request(
            "GET",
            path,
            headers={"Host": host, "User-Agent": user_agent, "Accept-Encoding": "identity"},
        )
        response = connection.getresponse()
        body = response.read()
        return response.status, {key.lower(): value for key, value in response.getheaders()}, body
    finally:
        connection.close()


def decode_subscription(body: bytes) -> list[str]:
    compact = b"".join(body.split())
    raw = base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
    return [line for line in raw.decode("utf-8").splitlines() if line]


def schemes(lines: list[str]) -> list[str]:
    return sorted(line.split("://", 1)[0].lower() for line in lines if "://" in line)


def qwdtt(lines: list[str]) -> list[str]:
    return [line for line in lines if line.lower().startswith(("qwdtt://", "wdtt://"))]


def awg_name_preserved(original: list[str], throne: list[str]) -> bool:
    native = [line for line in original if line.lower().startswith("amneziawg://")]
    converted = [line for line in throne if line.lower().startswith("wg://")]
    if not native:
        return True
    if len(native) != len(converted):
        return False
    return [line.partition("#")[2] for line in native] == [line.partition("#")[2] for line in converted]


def awg_values_raw(lines: list[str]) -> bool:
    converted = [line for line in lines if line.lower().startswith("wg://")]
    return bool(converted) and all("%2f" not in line.lower() and "%2b" not in line.lower() for line in converted)


def mieru_pattern_raw(lines: list[str]) -> bool:
    mieru = [line for line in lines if line.lower().startswith(("mierus://", "mieru://"))]
    if not mieru:
        return True
    for line in mieru:
        query = line.partition("?")[2].partition("#")[0]
        found = False
        for item in query.split("&"):
            key, separator, value = item.partition("=")
            if separator and urllib.parse.unquote(key).lower().replace("_", "-") in {"traffic-pattern", "trafficpattern"}:
                found = True
                if "%2f" in value.lower() or "%2b" in value.lower():
                    return False
                try:
                    base64.b64decode(value, validate=True)
                except ValueError:
                    return False
        if not found:
            return False
    return True


def main() -> int:
    connection = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        current = settings(connection)
        identifier = subscription_id(connection)
    finally:
        connection.close()
    host = current.get("subDomain", "")
    port = int(current.get("subPort", "2096") or 2096)
    sub_path = join_path(current.get("subPath", "/sub/"), identifier)
    clash_path = join_path(current.get("subClashPath", "/clash/"), identifier)

    native_status, _, native_body = fetch(port, host, sub_path, "NekoBox/1.3")
    side_status, side_headers, side_body = fetch(SIDECAR_PORT, host, sub_path, "NekoBox/1.3")
    throne_status, _, throne_body = fetch(SIDECAR_PORT, host, sub_path, "Throne/1.0")
    clash_native_status, _, clash_native = fetch(port, host, clash_path, "Clash.Meta")
    clash_side_status, _, clash_side = fetch(SIDECAR_PORT, host, clash_path, "Clash.Meta")

    native_lines = decode_subscription(native_body)
    side_lines = decode_subscription(side_body)
    throne_lines = decode_subscription(throne_body)
    result = {
        "http_200": all(
            value == 200
            for value in (native_status, side_status, throne_status, clash_native_status, clash_side_status)
        ),
        "sidecar_header": side_headers.get("x-lucx-subscription-sidecar") == "active",
        "nekobox_scheme_counts_equal": schemes(native_lines) == schemes(side_lines),
        "nekobox_qwdtt_exact": qwdtt(native_lines) == qwdtt(side_lines),
        "throne_awg_name_preserved": awg_name_preserved(native_lines, throne_lines),
        "throne_awg_values_raw": awg_values_raw(throne_lines),
        "throne_mieru_pattern_raw": mieru_pattern_raw(throne_lines),
        "throne_qwdtt_exact": qwdtt(native_lines) == qwdtt(throne_lines),
        "clash_mihomo_exact": clash_native == clash_side,
        "native_count": len(native_lines),
        "throne_count": len(throne_lines),
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if all(value for key, value in result.items() if isinstance(value, bool)) else 3


if __name__ == "__main__":
    raise SystemExit(main())
