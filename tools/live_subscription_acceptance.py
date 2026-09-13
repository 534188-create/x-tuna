#!/usr/bin/env python3
"""Read-only live acceptance test for a managed LucX subscription sidecar.

The script deliberately prints only pass/fail metadata.  Subscription IDs,
credentials, complete URIs and decoded client configuration never leave the
process.
"""

from __future__ import annotations

import base64
import http.client
import json
import pathlib
import sqlite3
import ssl
import struct
import sys
import urllib.parse
import zlib


STATE_PATH = pathlib.Path("/var/lib/lucx-post-configurator/state.json")


class AcceptanceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def selected_subscription_id(db_path: str) -> str:
    connection = sqlite3.connect(
        pathlib.Path(db_path).resolve().as_uri() + "?mode=ro", uri=True, timeout=2
    )
    try:
        connection.execute("PRAGMA query_only=ON")
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "client_inbounds" in tables:
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(client_inbounds)")
            }
        else:
            columns = set()
        if {"client_id", "inbound_id"}.issubset(columns):
            row = connection.execute(
                "SELECT c.sub_id FROM clients c "
                "LEFT JOIN client_inbounds ci ON ci.client_id = c.id "
                "WHERE COALESCE(c.enable, 0) = 1 AND COALESCE(c.sub_id, '') <> '' "
                "GROUP BY c.id ORDER BY COUNT(ci.inbound_id) DESC, c.id LIMIT 1"
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT sub_id FROM clients "
                "WHERE COALESCE(enable, 0) = 1 AND COALESCE(sub_id, '') <> '' "
                "ORDER BY id LIMIT 1"
            ).fetchone()
        require(bool(row and row[0]), "no enabled subscription client is available")
        return str(row[0])
    finally:
        connection.close()


def request(
    host: str, port: int, path: str, user_agent: str
) -> tuple[int, dict[str, str], bytes]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(
        "127.0.0.1", port, timeout=20, context=context
    )
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Host": host,
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        body = response.read(4 * 1024 * 1024 + 1)
        return (
            response.status,
            {key.lower(): value for key, value in response.getheaders()},
            body,
        )
    finally:
        connection.close()


def raw_lines(body: bytes) -> list[str]:
    compact = b"".join(body.split())
    try:
        decoded = base64.b64decode(
            compact + b"=" * (-len(compact) % 4), validate=True
        ).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise AcceptanceError("raw subscription is not valid base64 UTF-8") from error
    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    require(any("://" in line for line in lines), "raw subscription has no URI entries")
    return lines


def scheme(line: str) -> str:
    return line.split("://", 1)[0].lower() if "://" in line else ""


def find_line(lines: list[str], schemes: tuple[str, ...]) -> str:
    for line in lines:
        if scheme(line) in schemes:
            return line
    return ""


def raw_fragment(line: str) -> str:
    return line.split("#", 1)[1] if "#" in line else ""


def valid_mieru_pattern(line: str) -> bool:
    if not line:
        return False
    query = line.split("?", 1)[1].split("#", 1)[0] if "?" in line else ""
    for part in query.split("&"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        normalized = urllib.parse.unquote(key).lower().replace("_", "-")
        if normalized not in {"traffic-pattern", "trafficpattern"}:
            continue
        if "%2f" in value.lower() or "%2b" in value.lower():
            return False
        try:
            base64.b64decode(value, validate=True)
        except ValueError:
            return False
        return True
    return False


def valid_throne_awg(line: str) -> bool:
    if scheme(line) != "wg" or "?" not in line:
        return False
    query = line.split("?", 1)[1].split("#", 1)[0]
    lowered = query.lower()
    if any(token in lowered for token in ("%2f", "%2b", "%3d")):
        return False
    values = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    address = values.get("local_address", "")
    return bool(address and "/" in address and "%" not in address)


def valid_nekobox_awg(line: str) -> bool:
    if scheme(line) != "vpn":
        return False
    try:
        payload = line.split("://", 1)[1]
        packed = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        require(len(packed) >= 5, "NekoBox AWG envelope is truncated")
        declared = struct.unpack(">I", packed[:4])[0]
        data = zlib.decompress(packed[4:])
        require(declared == len(data), "NekoBox AWG envelope length mismatch")
        value = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, zlib.error):
        return False
    if value.get("defaultContainer") == "amnezia-awg":
        return True
    return any(
        isinstance(item, dict)
        and (item.get("container") == "amnezia-awg" or "awg" in item)
        for item in value.get("containers", [])
    )


def anytls_public_443(lines: list[str]) -> bool:
    line = find_line(lines, ("anytls",))
    if not line:
        return False
    try:
        return urllib.parse.urlsplit(line).port == 443
    except ValueError:
        return False


def main() -> int:
    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    manifest = state["manifest"]
    subscription = manifest["lucx"]["subscription"]
    sidecar = manifest["sidecar"]
    host = str(subscription["domain"])
    port = int(sidecar["listen_port"])
    prefix = str(subscription["path_prefix"])
    if not prefix.endswith("/"):
        prefix += "/"
    sub_id = selected_subscription_id(str(manifest["lucx"]["db_path"]))
    path = prefix + urllib.parse.quote(sub_id, safe="")

    responses: dict[str, tuple[int, dict[str, str], bytes]] = {}
    for label, agent in {
        "generic": "lucx-live-acceptance/1",
        "throne": "Throne/1 live-acceptance",
        "nekobox": "NekoBox/1 live-acceptance",
    }.items():
        responses[label] = request(host, port, path, agent)
        status, headers, body = responses[label]
        require(status == 200 and bool(body), f"{label} subscription request failed")
        require(
            headers.get("x-lucx-subscription-sidecar") == "active",
            f"{label} request did not traverse sidecar",
        )

    generic = raw_lines(responses["generic"][2])
    throne = raw_lines(responses["throne"][2])
    nekobox = raw_lines(responses["nekobox"][2])

    require(anytls_public_443(generic), "AnyTLS generic endpoint is not public :443")
    require(anytls_public_443(throne), "AnyTLS Throne endpoint is not public :443")
    require(anytls_public_443(nekobox), "AnyTLS NekoBox endpoint is not public :443")

    throne_mieru = find_line(throne, ("mieru", "mierus"))
    generic_mieru = find_line(generic, ("mieru", "mierus"))
    require(valid_mieru_pattern(throne_mieru), "Throne Mieru traffic pattern is invalid")
    require(
        raw_fragment(throne_mieru) == raw_fragment(generic_mieru),
        "Mieru display name changed",
    )

    throne_awg = find_line(throne, ("wg",))
    generic_awg = find_line(generic, ("amneziawg",))
    require(valid_throne_awg(throne_awg), "Throne AWG URI is invalid")
    require(generic_awg != "", "generic native AWG entry is absent")
    require(
        raw_fragment(throne_awg) == raw_fragment(generic_awg),
        "AWG display name changed for Throne",
    )

    nekobox_awg = find_line(nekobox, ("vpn",))
    require(valid_nekobox_awg(nekobox_awg), "NekoBox AWG envelope is invalid")

    generic_qwdtt = find_line(generic, ("qwdtt", "wdtt"))
    throne_qwdtt = find_line(throne, ("qwdtt", "wdtt"))
    require(generic_qwdtt != "", "qWDTT entry is absent")
    require(generic_qwdtt == throne_qwdtt, "qWDTT entry changed for Throne")

    mihomo_ok = False
    for candidate in (path, "/clash/" + urllib.parse.quote(sub_id, safe="")):
        status, headers, body = request(host, port, candidate, "mihomo/1.19 live-acceptance")
        if status != 200 or headers.get("x-lucx-subscription-sidecar") != "active":
            continue
        text = body.decode("utf-8", errors="replace")
        if "proxies:" in text or ('"proxies"' in text and text.lstrip().startswith("{")):
            mihomo_ok = True
            break
    require(mihomo_ok, "Clash/Mihomo subscription is not YAML or JSON")

    print(
        json.dumps(
            {
                "ok": True,
                "sidecar": "active",
                "generic_subscription": "valid",
                "clash_mihomo": "valid",
                "throne_awg": "valid",
                "throne_mieru": "valid",
                "nekobox_awg": "valid",
                "anytls_public_port": 443,
                "qwdtt_unchanged": True,
                "display_names_preserved": True,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AcceptanceError as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False))
        raise SystemExit(1)
