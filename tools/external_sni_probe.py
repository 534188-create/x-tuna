#!/usr/bin/env python3
"""Probe Cloudflare-only SNI from outside the origin host."""

from __future__ import annotations

import argparse
import json
import socket
import ssl


def probe(address: str, domain: str) -> dict[str, object]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((address, 443), timeout=10)
        with context.wrap_socket(raw, server_hostname=domain) as connection:
            connection.settimeout(10)
            connection.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode()
            )
            first = connection.recv(1024).split(b"\r\n", 1)[0].decode(
                "ascii", errors="replace"
            )
        return {"tls": True, "status_line": first}
    except (OSError, ssl.SSLError) as error:
        return {"tls": False, "error_class": type(error).__name__}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("origin")
    parser.add_argument("domains", nargs="+")
    args = parser.parse_args()
    result: dict[str, object] = {"origin": {}, "cloudflare": {}}
    for domain in args.domains:
        result["origin"][domain] = probe(args.origin, domain)  # type: ignore[index]
        result["cloudflare"][domain] = probe(socket.gethostbyname(domain), domain)  # type: ignore[index]
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
