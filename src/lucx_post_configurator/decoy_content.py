"""Ограниченная проверка документа и его прямых локальных ресурсов."""
from __future__ import annotations

import io
import http.client
import re
import time
from html.parser import HTMLParser
from typing import Any, Callable
from urllib.parse import quote, urljoin, urlsplit

MAX_BODY_BYTES = 65536
MAX_HEADER_BYTES = 8192
MAX_RESOURCE_COUNT = 16
MAX_TOTAL_BYTES = 512 * 1024


def response_content(raw: bytes, method: str) -> dict[str, Any]:
    header, separator, body = raw.partition(b"\r\n\r\n")
    if not separator or len(header) > MAX_HEADER_BYTES or len(body) > MAX_BODY_BYTES:
        raise ValueError("Ответ отсутствует или превышает лимит")
    lines = header.split(b"\r\n")
    match = re.fullmatch(rb"HTTP/(?:1\.[01]|2) ([0-9]{3})(?: [^\r\n]*)?", lines[0])
    if not match:
        raise ValueError("Некорректный HTTP статус")
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError("Некорректный заголовок")
        headers.setdefault(name.decode("ascii").lower(), []).append(value.decode("latin1").strip())
    types = headers.get("content-type", [])
    mime = types[0].split(";", 1)[0].strip().lower() if len(types) == 1 else ""
    if headers.get("content-encoding", ["identity"]) != ["identity"]:
        raise ValueError("Непроверенное кодирование ответа")
    if method == "HEAD" and body:
        raise ValueError("HEAD содержит запрещённое тело")
    # curl уже декодировал framing h2 и проверил завершение transfer.
    if method == "GET" and not raw.startswith(b"HTTP/2 "):
        class Source:
            def makefile(self, mode: str) -> io.BytesIO:
                return io.BytesIO(raw)
        parsed = http.client.HTTPResponse(Source(), method=method)
        parsed.begin()
        try:
            body = parsed.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES or (parsed.length is not None and parsed.length != 0):
                raise ValueError("Тело ответа неполно или превышает лимит")
        finally:
            parsed.close()
    return {"status": int(match[1]), "mime": mime, "body": body}


class Resources(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references: list[tuple[str, str]] = []
        self.base = ""
        self.html_open = False
        self.html_closed = False

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "html": self.html_open = True
        if tag == "base" and not self.base: self.base = attrs.get("href") or ""
        kind, value = "", ""
        if tag == "link" and "stylesheet" in (attrs.get("rel") or "").lower().split():
            kind, value = "style", attrs.get("href") or ""
        elif tag in {"script", "img"} and "src" in attrs:
            kind, value = tag, attrs.get("src") or ""
        if kind: self.references.append((kind, value))

    def handle_endtag(self, tag):
        if tag == "html": self.html_closed = True


def verify_site(raw: bytes, method: str, origin: str,
                fetch: Callable[[str, float], bytes], timeout: float,
                *, deadline: float | None = None) -> dict[str, Any]:
    """Возвращает только состояния/счётчики, без HTML и URL ресурсов."""
    result = {"state": "http_error", "content_verified": False,
              "resources_complete": False, "resource_count": 0, "verified_resources": 0,
              "resource_scope": "direct_html_resources"}
    if deadline is None:
        deadline = time.monotonic() + timeout
    try:
        if time.monotonic() >= deadline:
            return result
        response = response_content(raw, method)
        if response["status"] != 200 or response["mime"] != "text/html":
            return result
        if method == "HEAD":
            result.update(state="healthy", content_verified=True, body_absence_verified=True)
            return result
        parser = Resources()
        parser.feed(response["body"].decode("utf-8", "strict"))
        parser.close()
        if not parser.html_open or not parser.html_closed:
            return result
        result["content_verified"] = True
        if "\\" in parser.base or any(ord(char) < 32 for char in parser.base):
            return result
        root = urlsplit(origin)
        def same_origin(url):
            parsed = urlsplit(url)
            return (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)) == (
                root.scheme, root.hostname, root.port or (443 if root.scheme == "https" else 80)) and not parsed.username and not parsed.password
        base = urljoin(origin, parser.base) if parser.base else origin
        if not same_origin(base):
            return result
        resources = {}
        for kind, value in parser.references:
            if value.startswith("data:"):
                continue
            if not value or "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
                return result
            absolute = urljoin(base, value)
            if not same_origin(absolute):
                return result
            parsed = urlsplit(absolute)
            path = quote(parsed.path or "/", safe="/%:@-._~!$&'()*+,;=")
            if parsed.query:
                path += "?" + quote(parsed.query, safe="/%:@-._~!$&'()*+,;=?")
            resources.setdefault(path, set()).add(kind)
        result["resource_count"] = len(resources)
        if len(resources) > MAX_RESOURCE_COUNT:
            return result
        total = len(response["body"])
        for path, kinds in resources.items():
            remaining = deadline - time.monotonic()
            if remaining <= 0 or total >= MAX_TOTAL_BYTES:
                return result
            resource = response_content(fetch(path, remaining), "GET")
            total += len(resource["body"])
            compatible = all(
                resource["mime"] == "text/css" if kind == "style" else
                resource["mime"] in {"text/javascript", "application/javascript", "application/ecmascript", "text/ecmascript"} if kind == "script" else
                resource["mime"].startswith("image/") for kind in kinds)
            if resource["status"] != 200 or not resource["body"] or not compatible or total > MAX_TOTAL_BYTES:
                return result
            result["verified_resources"] += 1
        if time.monotonic() >= deadline:
            return result
        result.update(state="healthy", resources_complete=True)
    except (ValueError, OSError, UnicodeError, http.client.HTTPException):
        pass
    return result
