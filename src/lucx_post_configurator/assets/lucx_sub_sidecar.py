#!/usr/bin/env python3
"""Fail-open LucX subscription compatibility proxy.

The proxy changes a native ``amneziawg://`` line requested by Throne and
works around Throne's reserved-character handling for Mieru traffic patterns.
Only the unambiguous TCP/HTTPS TrustTunnel profile is published: LucX TLV
deep links are converted to the Throne URI form for Throne, QUIC/HTTP3
variants are removed, and qWDTT lines are never published (qWDTT is a
standalone service for its dedicated client). The known LucX AnyTLS raw-link
port issue is repaired from the enabled Host public endpoint for every base64
client. Clash/Mihomo YAML stays passthrough. All credentials, parameters and
display names are preserved.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import ipaddress
import json
import os
import pathlib
import re
import sqlite3
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


LISTEN_HOST = os.getenv("SIDECAR_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("SIDECAR_LISTEN_PORT", "21000"))
UPSTREAM_HOST = os.getenv("XUI_SUB_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.getenv("XUI_SUB_PORT", "2096"))
UPSTREAM_SCHEME = os.getenv("XUI_SUB_SCHEME", "https").lower()
UPSTREAM_TLS_VERIFY = os.getenv("XUI_SUB_TLS_VERIFY", "false").lower() in {
    "1", "true", "yes", "on",
}
TLS_CERT = os.getenv("SIDECAR_CERT", "/etc/lucx-sub-sidecar/fullchain.pem")
TLS_KEY = os.getenv("SIDECAR_KEY", "/etc/lucx-sub-sidecar/privkey.pem")
ALLOWED_HOSTS = {
    item.strip().lower().rstrip(".")
    for item in os.getenv("SIDECAR_ALLOWED_HOSTS", "").split(",")
    if item.strip()
}
ALLOWED_PATH_PREFIXES = tuple(
    item.strip()
    for item in os.getenv(
        "SIDECAR_ALLOWED_PATH_PREFIXES", "/sub/,/clash/,/awg/,/json/"
    ).split(",")
    if item.strip()
)
XUI_AWG_PATH = os.getenv("XUI_AWG_PATH", "/awg/")
DB_PATH = os.getenv("XUI_DB", "/etc/x-ui/x-ui.db")
UPSTREAM_TIMEOUT = 15
MAX_UPSTREAM_BODY = 4 * 1024 * 1024
MAX_CONCURRENT_REQUESTS = 64


def normalize_host(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urllib.parse.urlsplit(text if "://" in text else "//" + text)
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _host_port(value: Any) -> tuple[str, int]:
    text = str(value or "").strip()
    if not text:
        return "", 0
    try:
        parsed = urllib.parse.urlsplit(text if "://" in text else "//" + text)
        return (parsed.hostname or "").lower().rstrip("."), int(parsed.port or 0)
    except (TypeError, ValueError):
        return "", 0


def load_public_endpoint_snapshot() -> list[dict[str, Any]]:
    """Read non-secret AnyTLS publication metadata plus client passwords.

    The LucX Clash generator silently drops anytls/mieru/trusttunnel inbounds
    (its ``buildProxy`` switch has no case for them).  For AnyTLS we can
    safely rebuild the proxy entry from LucX metadata: password comes from
    the enabled client row, server/port from the enabled Host endpoint.
    """

    try:
        uri = pathlib.Path(DB_PATH).resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        inbound_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(inbounds)")
        }
        required = {"id", "protocol", "port", "enable"}
        if "inbounds" not in tables or not required.issubset(inbound_columns):
            return []
        select = ["id", "protocol", "port"]
        if "settings" in inbound_columns:
            select.append("settings")
        if "share_addr" in inbound_columns:
            select.append("share_addr")
        rows = list(
            connection.execute(
                "SELECT " + ", ".join(select)
                + " FROM inbounds WHERE enable = 1 AND lower(protocol) IN ('anytls', 'mieru') ORDER BY id"
            )
        )
        host_columns = (
            {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(hosts)")
            }
            if "hosts" in tables
            else set()
        )
        result: list[dict[str, Any]] = []
        for row in rows:
            host = ""
            public_port = 0
            if {"inbound_id", "address", "port"}.issubset(host_columns):
                conditions = ["inbound_id = ?"]
                if "is_disabled" in host_columns:
                    conditions.append("COALESCE(is_disabled, 0) = 0")
                order = []
                if "sort_order" in host_columns:
                    order.append("sort_order")
                if "id" in host_columns:
                    order.append("id")
                host_row = connection.execute(
                    "SELECT address, port FROM hosts WHERE "
                    + " AND ".join(conditions)
                    + (" ORDER BY " + ", ".join(order) if order else "")
                    + " LIMIT 1",
                    (int(row["id"]),),
                ).fetchone()
                if host_row:
                    host = normalize_host(host_row["address"])
                    public_port = int(host_row["port"] or 0)
            if not host and "share_addr" in inbound_columns:
                host, share_port = _host_port(row["share_addr"])
                public_port = public_port or share_port
            if host and 1 <= public_port <= 65535:
                passwords: list[str] = []
                settings_raw = row["settings"] if "settings" in row.keys() else None
                try:
                    settings_obj = json.loads(settings_raw or "{}")
                except (TypeError, ValueError):
                    settings_obj = {}
                for client in settings_obj.get("clients") or []:
                    if not isinstance(client, dict):
                        continue
                    password = str(client.get("password") or "").strip()
                    if password:
                        passwords.append(password)
                entry: dict[str, Any] = {
                    "inbound_id": int(row["id"]),
                    "protocol": "anytls",
                    "internal_port": int(row["port"] or 0),
                    "host": host,
                    "public_port": public_port,
                    "passwords": passwords,
                    "sni": host,
                }
                if str(row["protocol"]).lower() == "mieru":
                    entry["protocol"] = "mieru"
                    # LucX 3.7 producers emit `port=<first binding port>` and
                    # drop the configured range; restore the full range from
                    # settings.portBindings so both clients can hop ports.
                    for binding in settings_obj.get("portBindings") or []:
                        if not isinstance(binding, dict):
                            continue
                        port_range = str(binding.get("portRange") or "").strip()
                        if port_range:
                            entry["port_range"] = port_range
                            break
                result.append(entry)
        return result
    except (OSError, sqlite3.Error, TypeError, ValueError):
        return []
    finally:
        if "connection" in locals():
            connection.close()


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def upstream_request(
    method: str, path: str, host_header: str, user_agent: str = ""
) -> tuple[int, str, list[tuple[str, str]], bytes]:
    headers = {
        "Host": host_header,
        "User-Agent": user_agent or "lucx-sub-sidecar",
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if UPSTREAM_SCHEME == "https":
        if UPSTREAM_TLS_VERIFY:
            context = ssl.create_default_context()
        else:
            if not _is_loopback(UPSTREAM_HOST):
                raise RuntimeError("TLS verification may be disabled only for a loopback upstream")
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            UPSTREAM_HOST, UPSTREAM_PORT, timeout=UPSTREAM_TIMEOUT, context=context
        )
    elif UPSTREAM_SCHEME == "http" and _is_loopback(UPSTREAM_HOST):
        connection = http.client.HTTPConnection(
            UPSTREAM_HOST, UPSTREAM_PORT, timeout=UPSTREAM_TIMEOUT
        )
    else:
        raise RuntimeError("upstream must be loopback HTTP or HTTPS")
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read(MAX_UPSTREAM_BODY + 1)
        if len(body) > MAX_UPSTREAM_BODY:
            raise RuntimeError("upstream response is too large")
        return response.status, response.reason, list(response.getheaders()), body
    finally:
        connection.close()


def decode_subscription(body: bytes) -> str | None:
    compact = b"".join(body.split())
    if not compact or len(compact) > MAX_UPSTREAM_BODY:
        return None
    try:
        raw = base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
        text = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if "://" in text else None


def encode_subscription(text: str) -> bytes:
    return base64.b64encode(text.encode("utf-8"))


def parse_awg_conf(text: str) -> tuple[dict[str, str], dict[str, str]]:
    section: dict[str, str] | None = None
    interface: dict[str, str] = {}
    peer: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[Interface]":
            section = interface
            continue
        if line == "[Peer]":
            section = peer
            continue
        if section is not None and "=" in line:
            key, value = line.split("=", 1)
            section[key.strip()] = value.strip()
    return interface, peer


def parse_endpoint(value: str) -> tuple[str, int]:
    text = (value or "").strip()
    if text.startswith("["):
        close = text.rfind("]")
        if close < 0 or not text[close + 1 :].startswith(":"):
            return "", 0
        try:
            return text[1:close], int(text[close + 2 :])
        except ValueError:
            return "", 0
    try:
        host, port = text.rsplit(":", 1)
        return host, int(port)
    except ValueError:
        return "", 0


def normalize_bool(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def native_fragment(uri: str) -> str:
    """Return the original encoded display-name fragment without normalizing it."""
    try:
        return urllib.parse.urlsplit(uri).fragment
    except ValueError:
        return ""


def build_awg_wg_uri(conf_text: str, fragment: str = "") -> str:
    interface, peer = parse_awg_conf(conf_text)
    endpoint_host, endpoint_port = parse_endpoint(peer.get("Endpoint", ""))
    if not endpoint_host or not endpoint_port:
        raise ValueError("AWG endpoint missing")
    if not interface.get("PrivateKey") or not peer.get("PublicKey"):
        raise ValueError("AWG key missing")
    query: list[tuple[str, str]] = []

    def add(key: str, value: Any) -> None:
        text = str(value or "").strip()
        if text:
            query.append((key, text))

    add("private_key", interface["PrivateKey"])
    address = interface.get("Address", "")
    if address:
        add("local_address", "-".join(item.strip() for item in address.split(",") if item.strip()))
    add("mtu", interface.get("MTU"))
    add("enable_amnezia", "true")
    mapping = {
        "Jc": "jc", "Jmin": "jmin", "Jmax": "jmax",
        "S1": "s1", "S2": "s2", "S3": "s3", "S4": "s4",
        "H1": "h1", "H2": "h2", "H3": "h3", "H4": "h4",
        "I1": "i1", "I2": "i2", "I3": "i3", "I4": "i4", "I5": "i5",
        "HeaderProtectionKey": "header_protection_key",
        "ContentPaddingAddition": "content_padding_addition",
        "RekeyAfterTime": "rekey_after_time",
        "RekeyTimeout": "rekey_timeout",
        "RejectAfterTime": "reject_after_time",
        "KeepaliveTimeout": "keepalive_timeout",
        "MaxHandshakeAttempts": "max_handshake_attempts",
    }
    for source, target in mapping.items():
        add(target, interface.get(source))
    for source, target in (
        ("RandomTrailers", "random_trailers"),
        ("DisableCookies", "disable_cookies"),
    ):
        if source in interface:
            add(target, "true" if normalize_bool(interface[source]) else "false")
    add("public_key", peer["PublicKey"])
    add("pre_shared_key", peer.get("PresharedKey"))
    add("persistent_keepalive_interval", peer.get("PersistentKeepalive"))
    if peer.get("Reserved"):
        add("reserved", peer["Reserved"].replace(",", "-").replace(" ", ""))
    # Throne builds QUrlQuery from url.query() and leaves percent-encoded
    # reserved characters such as %2F and %2B in queryItemValue().  Fully
    # encoding a CIDR or a WireGuard base64 key therefore produces invalid
    # values such as 10.0.0.2%2F32/32.  Preserve only the reserved characters
    # that are valid inside these AWG values. Query delimiters '&' and '#'
    # remain encoded; base64 padding '=' is intentionally left raw.
    query_string = "&".join(
        urllib.parse.quote(key, safe="")
        + "="
        + urllib.parse.quote(value, safe="/+=")
        for key, value in query
    )
    hostpart = f"[{endpoint_host}]" if ":" in endpoint_host else endpoint_host
    suffix = "#" + fragment if fragment else ""
    return f"wg://{hostpart}:{endpoint_port}?{query_string}{suffix}"


def rewrite_mieru_for_throne(uri: str) -> str:
    """Expose only a validated traffic-pattern base64 value to Throne.

    The standard mierus:// producer correctly URL-escapes its query.  Current
    Throne releases keep %2F/%2B in the value before validating base64.  This
    function changes no endpoint, credential, port, profile or display name;
    it only restores the raw base64 alphabet for traffic-pattern.
    """

    if not uri.strip().lower().startswith(("mierus://", "mieru://")):
        return uri
    query_start = uri.find("?")
    if query_start < 0:
        return uri
    fragment_start = uri.find("#", query_start + 1)
    query_end = fragment_start if fragment_start >= 0 else len(uri)
    raw_query = uri[query_start + 1 : query_end]
    changed = False
    parts: list[str] = []
    for part in raw_query.split("&"):
        if "=" not in part:
            parts.append(part)
            continue
        raw_key, raw_value = part.split("=", 1)
        key = urllib.parse.unquote(raw_key).strip().lower().replace("_", "-")
        if key not in {"traffic-pattern", "trafficpattern"}:
            parts.append(part)
            continue
        try:
            decoded = urllib.parse.unquote(raw_value)
            base64.b64decode(decoded, validate=True)
        except (ValueError, UnicodeError):
            parts.append(part)
            continue
        parts.append(raw_key + "=" + decoded)
        changed = changed or decoded != raw_value
    if not changed:
        return uri
    return uri[: query_start + 1] + "&".join(parts) + uri[query_end:]


def rewrite_mieru_port_range(
    uri: str,
    snapshot: list[dict[str, Any]],
) -> str:
    """Restore the configured Mieru port range in ``port=``.

    LucX producers emit ``port=20100`` (the first binding port) even when the
    inbound advertises a range such as ``20100-20200``.  Clients use the
    range to hop ports, so replace only that query value when the enabled
    Host endpoint matches the link host.
    """

    if not uri.strip().lower().startswith(("mierus://", "mieru://")):
        return uri
    query_start = uri.find("?")
    if query_start < 0:
        return uri
    try:
        parsed = urllib.parse.urlsplit(uri)
        link_host = (parsed.hostname or "").lower().rstrip(".")
    except (TypeError, ValueError):
        return uri
    matched_range = ""
    for item in snapshot:
        if str(item.get("protocol") or "").lower() != "mieru":
            continue
        if link_host and link_host == normalize_host(item.get("host")):
            matched_range = str(item.get("port_range") or "").strip()
            if matched_range:
                break
    if not matched_range:
        return uri
    fragment_start = uri.find("#", query_start + 1)
    query_end = fragment_start if fragment_start >= 0 else len(uri)
    raw_query = uri[query_start + 1 : query_end]
    changed = False
    parts: list[str] = []
    for part in raw_query.split("&"):
        if "=" not in part:
            parts.append(part)
            continue
        raw_key, raw_value = part.split("=", 1)
        key = urllib.parse.unquote(raw_key).strip().lower()
        if key != "port":
            parts.append(part)
            continue
        value = urllib.parse.unquote(raw_value).strip()
        if value == matched_range:
            parts.append(part)
            continue
        parts.append(raw_key + "=" + urllib.parse.quote(matched_range, safe="-"))
        changed = True
    if not changed:
        return uri
    return uri[: query_start + 1] + "&".join(parts) + uri[query_end:]


def extract_sub_id(path: str) -> str:
    parsed = urllib.parse.urlsplit(path)
    for prefix in ALLOWED_PATH_PREFIXES:
        if parsed.path.startswith(prefix):
            remainder = parsed.path[len(prefix) :].lstrip("/")
            if remainder:
                return urllib.parse.unquote(remainder.split("/", 1)[0])
    return ""


def fetch_awg_conf(sub_id: str, host_header: str, user_agent: str) -> str | None:
    if not sub_id or len(sub_id) > 512:
        return None
    prefix = XUI_AWG_PATH if XUI_AWG_PATH.endswith("/") else XUI_AWG_PATH + "/"
    path = prefix + urllib.parse.quote(sub_id, safe="") + "?format=conf"
    try:
        status, _, _, body = upstream_request("GET", path, host_header, user_agent)
    except (OSError, http.client.HTTPException, RuntimeError):
        return None
    if status != 200:
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if "[Interface]" in text and "[Peer]" in text else None


def rewrite_anytls_public_endpoint(
    uri: str,
    snapshot: list[dict[str, Any]],
) -> str:
    """Replace only AnyTLS authority host/port from an enabled LucX Host row."""

    if not uri.strip().lower().startswith("anytls://"):
        return uri
    # LucX can emit a malformed bracketed authority for a domain host:
    #   anytls://pass@[domain:443]:18443/
    # urlsplit rejects that as an invalid IPv6 literal, so normalize it to
    #   anytls://pass@domain:18443/
    # before parsing, keeping only the password and the real internal port.
    bracketed = re.match(
        r"^(anytls://[^@/]*@)\[([^[\]]+):(\d+)\]:(\d+)(/.*)$",
        uri.strip(),
        re.IGNORECASE,
    )
    if bracketed:
        uri = (
            bracketed.group(1)
            + bracketed.group(2)
            + ":"
            + bracketed.group(4)
            + bracketed.group(5)
        )
    try:
        parsed = urllib.parse.urlsplit(uri)
        current_host = (parsed.hostname or "").lower().rstrip(".")
        current_port = int(parsed.port or 0)
    except (TypeError, ValueError):
        return uri
    scored: list[tuple[int, int, dict[str, Any]]] = []
    for item in snapshot:
        if str(item.get("protocol") or "").lower() != "anytls":
            continue
        score = 0
        if current_host and current_host == normalize_host(item.get("host")):
            score += 100
        if current_port and current_port == int(item.get("internal_port") or 0):
            score += 30
        if current_port and current_port == int(item.get("public_port") or 0):
            score += 20
        scored.append((score, -int(item.get("inbound_id") or 0), item))
    if not scored:
        return uri
    scored.sort(key=lambda value: (value[0], value[1]), reverse=True)
    score, _, selected = scored[0]
    if score <= 0:
        return uri
    host = normalize_host(selected.get("host"))
    port = int(selected.get("public_port") or 0)
    if not host or not 1 <= port <= 65535:
        return uri
    raw_netloc = parsed.netloc
    userinfo = raw_netloc.rsplit("@", 1)[0] if "@" in raw_netloc else ""
    hostpart = f"[{host}]" if ":" in host else host
    netloc = (userinfo + "@" if userinfo else "") + f"{hostpart}:{port}"
    return urllib.parse.urlunsplit(
        (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
    )


def is_trusttunnel_https_profile(uri: str) -> bool:
    """Accept only an explicit TCP/HTTPS TrustTunnel URL for every client."""

    if not isinstance(uri, str):
        return False
    try:
        parsed = urllib.parse.urlsplit(uri.strip())
        if parsed.scheme.lower() != "tt" or not parsed.netloc:
            return False
        query: dict[str, list[str]] = {}
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            # Регистр повторного ключа не должен скрывать небезопасное значение.
            query.setdefault(key.lower(), []).append(value.lower())
    except (TypeError, ValueError):
        return False
    # Throne 1.2.4 включает QUIC по наличию ключа, даже с пустым значением.
    if "congestion_control" in query:
        return False
    alpns = {
        item.strip()
        for value in query.get("alpn", [])
        for item in value.split(",")
        if item.strip()
    }
    quic_keys = {"quic", "http3", "udp", "h3", "upstream_protocol", "transport", "protocol"}
    quic_values = [value for key in quic_keys for value in query.get(key, [])]
    if any(value in {"1", "true", "yes", "h3", "http3", "quic", "udp"} for value in quic_values):
        return False
    return "h2" in alpns and not (alpns & {"h3", "http3", "quic"})


def _tt_tlv_varint(value: int) -> bytes:
    """Mirror LucX tlsVarint: 1/2/4-byte big-endian with marker bits."""

    if value < 1 << 6:
        return bytes([value])
    if value < 1 << 14:
        return bytes([value >> 8 | 0x40, value & 0xFF])
    if value < 1 << 30:
        return bytes([value >> 24 | 0x80, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
    packed = value.to_bytes(8, "big")
    return bytes([packed[0] | 0xC0]) + packed[1:]


def _tt_tlv_read_varint(payload: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(payload):
        raise ValueError("truncated varint")
    first = payload[offset]
    for marker, width in ((0x40, 2), (0x80, 4), (0xC0, 8)):
        if first & marker == marker:
            if offset + width > len(payload):
                raise ValueError("truncated varint")
            raw = bytes([first & (marker - 1)]) + payload[offset + 1:offset + width]
            if marker == 0xC0:
                raw = bytes([first & 0x3F]) + payload[offset + 1:offset + width]
            return int.from_bytes(raw, "big"), width
    return first, 1


def _tt_tlv_parse(payload: bytes) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    offset = 0
    while offset < len(payload):
        tag = payload[offset]
        offset += 1
        length, consumed = _tt_tlv_read_varint(payload, offset)
        offset += consumed
        if offset + length > len(payload):
            raise ValueError("truncated field")
        fields[tag] = payload[offset:offset + length]
        offset += length
    return fields


def decode_trusttunnel_deeplink(uri: str) -> dict[str, Any] | None:
    """Decode a LucX ``tt://?<base64url TLV>`` deep link.

    Returns None when the payload is not a valid version-1 TLV record; callers
    then drop the line instead of guessing (fail-closed for unknown data).
    """

    stripped = uri.strip()
    if not stripped.lower().startswith("tt://?"):
        return None
    encoded = stripped[len("tt://?"):].split("#", 1)[0].strip()
    if not encoded or not re.fullmatch(r"[A-Za-z0-9_\-=]+", encoded):
        return None
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = base64.urlsafe_b64decode(padded.encode("ascii"))
        fields = _tt_tlv_parse(payload)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    version_bytes = fields.get(0x00)
    if not version_bytes:
        return None
    try:
        version, _ = _tt_tlv_read_varint(version_bytes, 0)
    except ValueError:
        return None
    if version != 1:
        return None
    return {
        "hostname": fields.get(0x01, b"").decode("utf-8", "replace").strip(),
        "address": fields.get(0x02, b"").decode("utf-8", "replace").strip(),
        "user": fields.get(0x05, b"").decode("utf-8", "replace").strip(),
        "password": fields.get(0x06, b"").decode("utf-8", "replace"),
        "client_random_prefix": fields.get(0x0B, b"").decode("utf-8", "replace").strip(),
        "upstream": "http3" if fields.get(0x09) else "http2",
        "remark": fields.get(0x0C, b"").decode("utf-8", "replace").strip(),
    }


def build_trusttunnel_throne_uri(link: dict[str, Any]) -> str:
    """Build the Throne URI form (LucX ``ClientURI`` contract, lucx.142)."""

    address = link.get("address") or ""
    user = link.get("user") or ""
    if not address or not user:
        return ""
    query = ["security=tls"]
    sni = link.get("hostname") or ""
    if sni:
        query.append("sni=" + urllib.parse.quote(sni, safe=""))
    query.append("alpn=h2" if link.get("upstream") != "http3" else "alpn=h3")
    prefix = link.get("client_random_prefix") or ""
    if prefix:
        # NekoBox+ does not URL-decode %2F: leave `/` raw (lucx.145).
        query.append("client_random_prefix=" + prefix)
    netloc = user + ":" + urllib.parse.quote(link.get("password") or "", safe="") + "@" + address
    return urllib.parse.urlunsplit(
        ("tt", netloc, "", "&".join(query), link.get("remark") or "")
    )


def is_throne_trusttunnel_https_uri(uri: str) -> bool:
    """Accept only the TCP/HTTP2 TrustTunnel URI in Throne output."""

    return is_trusttunnel_https_profile(uri)


def rewrite_vmess_grpc_for_throne(uri: str) -> str:
    """Сохранить gRPC serviceName известного LucX JSON при импорте Throne 1.2.4.

    Неизвестные поля/формы остаются исходными: общий transport Throne не
    переносит gRPC authority/multiMode. add/port уже содержат публичный
    endpoint LucX и не требуют повторного сопоставления со снимком БД.
    """

    if not uri.startswith("vmess://") or len(uri) > MAX_UPSTREAM_BODY:
        return uri

    def unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value = dict(pairs)
        if len(value) != len(pairs):
            raise ValueError("Повторяющиеся поля VMess JSON")
        return value

    try:
        encoded = uri[len("vmess://"):]
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode("ascii") != encoded:
            return uri
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
    except (ValueError, RecursionError):
        return uri
    required = {"v", "add", "port", "id", "scy", "net", "type", "path",
        "tls", "alpn", "sni", "ps"}
    empty_options = {"authority", "host", "fp", "fm", "ech", "pcs", "vcn"}
    if not isinstance(obj, dict) or not required.issubset(obj):
        return uri
    if set(obj) - required - empty_options:
        return uri
    if any(not isinstance(obj[key], str) for key in required - {"port"}):
        return uri
    if any(obj.get(key, "") != "" for key in empty_options):
        return uri
    if any(obj[key] != value for key, value in {
        "v": "2", "net": "grpc", "type": "none", "tls": "tls", "alpn": "h2",
    }.items()):
        return uri
    if obj["scy"] not in {"auto", "aes-128-gcm", "chacha20-poly1305"}:
        return uri
    if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", obj["id"]):
        return uri
    if type(obj["port"]) is not int or not 1 <= obj["port"] <= 65535:
        return uri
    # ASCII DNS/IP без URL-синтаксиса: QUrl не должен переосмыслить SNI.
    dns_name = r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.?"
    if not re.fullmatch(dns_name, obj["sni"]) or not obj["path"]:
        return uri
    address = obj["add"]
    if ":" in address:
        literal = address[1:-1] if address.startswith("[") and address.endswith("]") else address
        try:
            ipaddress.IPv6Address(literal)
        except ValueError:
            return uri
        if "%" in literal:
            return uri
        authority = "[" + literal + "]"
    elif re.fullmatch(dns_name, address):
        authority = address
    else:
        return uri
    try:
        # quote, не quote_plus: QUrlQuery::FullyDecoded сохраняет буквальный '+'.
        query = urllib.parse.urlencode({
            "type": "grpc", "serviceName": obj["path"], "encryption": obj["scy"],
            "security": "tls", "sni": obj["sni"], "alpn": "h2",
        }, quote_via=urllib.parse.quote, safe="")
        fragment = urllib.parse.quote(obj["ps"], safe="")
    except UnicodeError:
        return uri
    return f"vmess://{obj['id']}@{authority}:{obj['port']}?{query}#{fragment}"


def rewrite_subscription(
    text: str,
    user_agent: str,
    request_path: str,
    host_header: str,
    snapshot: Any = None,
) -> str:
    """Repair AnyTLS publication for all raw clients plus Throne-only transforms.

    qWDTT lines are removed for every client (standalone service). TrustTunnel
    TLV deep links are converted to Throne's URI form for Throne and kept
    byte-for-byte for official clients; QUIC/HTTP3 variants never pass.
    """

    throne = "throne" in (user_agent or "").lower()
    has_awg = any(
        line.strip().lower().startswith("amneziawg://") for line in text.splitlines()
    )
    conf = (
        fetch_awg_conf(extract_sub_id(request_path), host_header, user_agent)
        if has_awg
        else None
    )
    endpoints = load_public_endpoint_snapshot() if snapshot is None else list(snapshot)
    output: list[str] = []
    for raw_line in text.splitlines(keepends=True):
        if raw_line.endswith("\r\n"):
            line, ending = raw_line[:-2], "\r\n"
        elif raw_line.endswith(("\n", "\r")):
            line, ending = raw_line[:-1], raw_line[-1:]
        else:
            line, ending = raw_line, ""
        low = line.strip().lower()
        if low.startswith(("qwdtt://", "wdtt://")):
            # qWDTT is a standalone service for its dedicated client; it is
            # intentionally never published through subscription endpoints.
            continue
        if low.startswith("tt://"):
            if low.startswith("tt://?"):
                # LucX TLV deep link. Official clients (NekoBox+) parse it
                # natively; Throne understands only the URI form, so it gets
                # a converted line. QUIC/HTTP3 entries are dropped for
                # everyone because the managed shared listener is TCP-only.
                link = decode_trusttunnel_deeplink(line)
                if link is None:
                    continue
                if link.get("upstream") == "http3":
                    continue
                if throne:
                    converted = build_trusttunnel_throne_uri(link)
                    if converted:
                        output.append(converted + ending)
                else:
                    output.append(line + ending)
                continue
            if is_trusttunnel_https_profile(line) and (
                not throne or is_throne_trusttunnel_https_uri(line)
            ):
                output.append(line + ending)
        elif low.startswith("anytls://"):
            try:
                output.append(rewrite_anytls_public_endpoint(line, endpoints) + ending)
            except (TypeError, ValueError):
                output.append(line + ending)
        elif throne and low.startswith("vmess://"):
            output.append(rewrite_vmess_grpc_for_throne(line) + ending)
        elif low.startswith("amneziawg://"):
            replacement = line
            if conf:
                try:
                    replacement = build_awg_wg_uri(
                        conf, native_fragment(line.strip())
                    )
                except (AttributeError, TypeError, ValueError):
                    replacement = line
            output.append(replacement + ending)
        elif throne and low.startswith(("mierus://", "mieru://")):
            try:
                updated = rewrite_mieru_port_range(line, endpoints)
                output.append(rewrite_mieru_for_throne(updated) + ending)
            except (TypeError, ValueError):
                output.append(line + ending)
        elif low.startswith(("mierus://", "mieru://")):
            try:
                output.append(rewrite_mieru_port_range(line, endpoints) + ending)
            except (TypeError, ValueError):
                output.append(line + ending)
        else:
            output.append(line + ending)
    return "".join(_dedupe_lines(output))


def _dedupe_lines(lines: list[str]) -> list[str]:
    """Drop exact duplicate entries while preserving order and separators.

    LucX publishes each link in several native shapes (URI form plus TLV
    deep link); after Throne-side conversion both shapes can collapse into
    the same URI. Clients import duplicates as separate broken profiles,
    so identical lines are emitted once.
    """

    seen: set[str] = set()
    result: list[str] = []
    for item in lines:
        key = item.strip()
        if key and key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def rewrite_structured_subscription(text: str, user_agent: str) -> str:
    """Remove only TrustTunnel QUIC entries from a safely parsed JSON response."""

    try:
        value = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return text

    changed = False

    def transform(item: Any) -> Any:
        nonlocal changed
        if isinstance(item, list):
            result = []
            for child in item:
                transformed = transform(child)
                if transformed is not None:
                    result.append(transformed)
                else:
                    changed = True
            return result
        if isinstance(item, dict):
            kind = str(item.get("type") or item.get("protocol") or "").strip().lower()
            if kind in {"qwdtt", "wdtt"}:
                changed = True
                return None
            candidates = [item.get("url"), item.get("uri"), item.get("address")]
            has_tt_url = any(
                isinstance(candidate, str)
                and candidate.strip().lower().startswith("tt://")
                for candidate in candidates
            )
            if (kind in {"trusttunnel", "trust-tunnel", "tt"} or has_tt_url) and any(
                isinstance(candidate, str)
                and (
                    candidate.strip().lower().startswith("tt://?")
                    and decode_trusttunnel_deeplink(candidate) is None
                    or candidate.strip().lower().startswith("tt://?")
                    and decode_trusttunnel_deeplink(candidate)
                    and decode_trusttunnel_deeplink(candidate).get("upstream") == "http3"
                    or candidate.strip().lower().startswith("tt://")
                    and not candidate.strip().lower().startswith("tt://?")
                    and not is_trusttunnel_https_profile(candidate)
                )
                for candidate in candidates
            ):
                changed = True
                return None
            result = {key: transform(child) for key, child in item.items()}
            if result != item:
                changed = True
            return result
        if isinstance(item, str):
            stripped = item.strip().lower()
            if stripped.startswith(("qwdtt://", "wdtt://")):
                changed = True
                return None
            if stripped.startswith("tt://?"):
                link = decode_trusttunnel_deeplink(item)
                if link is None or link.get("upstream") == "http3":
                    changed = True
                    return None
                return item
            if stripped.startswith("tt://"):
                if is_trusttunnel_https_profile(item):
                    return item
                changed = True
                return None
        return item

    transformed = transform(value)
    return (
        json.dumps(transformed, ensure_ascii=False, separators=(",", ":"))
        if changed
        else text
    )


def is_clash_yaml_response(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return "yaml" in lowered or "yml" in lowered


def inject_anytls_into_clash_yaml(
    text: str,
    snapshot: list[dict[str, Any]],
) -> str:
    """Add AnyTLS proxies the LucX Clash generator silently drops.

    Uses a minimal regex-based YAML edit instead of a full YAML parser: only
    ``proxies:`` list entries are appended and the PROXY group list is
    extended with the same names. Any parse anomaly fails open unchanged.
    """

    if not text.lstrip().startswith(("proxies:", "port:", "mixed-port:", "mode:", "#")):
        # Conservative: only touch documents that look like the LucX Clash profile.
        return text
    entries: list[tuple[str, str]] = []
    for item in snapshot:
        passwords = [p for p in (item.get("passwords") or []) if p]
        if not passwords:
            continue
        host = normalize_host(item.get("host"))
        port = int(item.get("public_port") or 0)
        if not host or not 1 <= port <= 65535:
            continue
        for password in passwords:
            name = f"test-anytls-{host}"
            entries.append(
                (
                    name,
                    "- {name: %s, type: anytls, server: %s, port: %d, password: %s, "
                    "sni: %s, udp: true, skip-cert-verify: false}"
                    % (name, host, port, yaml_scalar(password), host),
                )
            )
    if not entries:
        return text
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    inserted = False
    for line in lines:
        output.append(line)
        if not inserted and line.rstrip("\r\n") == "proxies:":
            for _, entry in entries:
                output.append("  " + entry + "\n")
            inserted = True
    if not inserted:
        return text
    result = "".join(output)
    for name, _ in entries:
        result = result.replace("  - DIRECT", f"  - {name}\n  - DIRECT", 1)
    return result


def yaml_scalar(value: str) -> str:
    """Quote a scalar for a flow-mapping context when required."""

    if re.fullmatch(r"[A-Za-z0-9._/@+=-]+", value):
        return value
    escaped = value.replace("\\", "\\\\").replace("'", "''")
    return "'" + escaped + "'"


def request_host_allowed(raw_host: str) -> bool:
    host = normalize_host(raw_host)
    return bool(host and host in ALLOWED_HOSTS)


def request_path_allowed(raw_path: str) -> bool:
    try:
        path = urllib.parse.urlsplit(raw_path).path
    except ValueError:
        return False
    return any(path.startswith(prefix) for prefix in ALLOWED_PATH_PREFIXES)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_HEAD(self) -> None:
        self.proxy(send_body=False)

    def do_GET(self) -> None:
        self.proxy(send_body=True)

    def proxy(self, send_body: bool) -> None:
        host_header = self.headers.get("Host") or ""
        user_agent = self.headers.get("User-Agent") or ""
        if not request_host_allowed(host_header) or not request_path_allowed(self.path):
            self.send_error(404, "Not found")
            return
        try:
            status, reason, headers, body = upstream_request(
                self.command, self.path, host_header, user_agent
            )
        except Exception:
            self.send_error(502, "Subscription upstream unavailable")
            return
        original_body = body
        if status == 200 and self.command == "GET":
            endpoints = load_public_endpoint_snapshot()
            text = decode_subscription(body)
            if text is not None:
                try:
                    rewritten = rewrite_subscription(
                        text, user_agent, self.path, host_header,
                        snapshot=endpoints,
                    )
                    if rewritten != text:
                        body = encode_subscription(rewritten)
                except Exception:
                    body = original_body
            else:
                content_type = ""
                for key, value in headers:
                    if key.lower() == "content-type":
                        content_type = value
                        break
                try:
                    structured = body.decode("utf-8")
                except UnicodeDecodeError:
                    structured = ""
                if structured and is_clash_yaml_response(content_type):
                    try:
                        injected = inject_anytls_into_clash_yaml(structured, endpoints)
                        if injected != structured:
                            body = injected.encode("utf-8")
                    except Exception:
                        body = original_body
                elif structured:
                    try:
                        rewritten = rewrite_structured_subscription(structured, user_agent)
                        if rewritten != structured:
                            body = rewritten.encode("utf-8")
                    except (TypeError, ValueError):
                        body = original_body
        self.send_response(status, reason)
        skipped = {"content-length", "transfer-encoding", "connection", "content-encoding"}
        for key, value in headers:
            if key.lower() not in skipped:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(body) if send_body else 0))
        self.send_header("Connection", "close")
        self.send_header("X-LucX-Subscription-Sidecar", "active")
        self.end_headers()
        if send_body:
            self.wfile.write(body)
        self.close_connection = True


class LimitedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def validate_startup() -> None:
    if LISTEN_HOST not in {"127.0.0.1", "::1", "localhost"}:
        raise SystemExit("sidecar listener must be loopback")
    if not _is_loopback(UPSTREAM_HOST):
        raise SystemExit("sidecar upstream must be loopback")
    if not ALLOWED_HOSTS:
        raise SystemExit("SIDECAR_ALLOWED_HOSTS must not be empty")
    if not ALLOWED_PATH_PREFIXES or any(
        not prefix.startswith("/") or "\x00" in prefix
        for prefix in ALLOWED_PATH_PREFIXES
    ):
        raise SystemExit("invalid SIDECAR_ALLOWED_PATH_PREFIXES")
    if not XUI_AWG_PATH.startswith("/") or "\x00" in XUI_AWG_PATH:
        raise SystemExit("invalid XUI_AWG_PATH")
    for path in (TLS_CERT, TLS_KEY):
        if not os.path.isfile(path):
            raise SystemExit(f"required file not found: {path}")


def main() -> None:
    validate_startup()
    server = LimitedThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(TLS_CERT, TLS_KEY)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
