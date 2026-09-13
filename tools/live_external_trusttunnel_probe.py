#!/usr/bin/env python3
import base64
import socket
import ssl
import struct
import sys
import tomllib


def header(name, value):
    left = name.encode("ascii")
    right = value.encode("utf-8")
    return b"\0" + bytes([len(left)]) + left + bytes([len(right)]) + right


def frame(kind, flags, stream, payload=b""):
    return (
        struct.pack("!I", len(payload))[1:]
        + bytes([kind, flags])
        + struct.pack("!I", stream & 0x7FFFFFFF)
        + payload
    )


def read_frame(conn):
    data = b""
    while len(data) < 9:
        part = conn.recv(9 - len(data))
        if not part:
            raise OSError("peer closed before HTTP/2 header")
        data += part
    size = int.from_bytes(data[:3], "big")
    payload = b""
    while len(payload) < size:
        part = conn.recv(size - len(payload))
        if not part:
            raise OSError("peer closed before HTTP/2 payload")
        payload += part
    return data[3], data[4], int.from_bytes(data[5:9], "big") & 0x7FFFFFFF, payload


def main():
    if len(sys.argv) < 4:
        raise SystemExit("Использование: probe.py HOST PORT SNI [CONNECT_TARGET]")
    origin = sys.argv[1]
    port = int(sys.argv[2])
    sni = sys.argv[3]
    target = sys.argv[4] if len(sys.argv) > 4 else "example.com:80"
    with open("/etc/x-tuna/trusttunnel/credentials.toml", "rb") as stream:
        client = tomllib.load(stream)["client"][0]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    with socket.create_connection((origin, port), 10) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as conn:
            print("alpn=" + str(conn.selected_alpn_protocol()))
            auth = base64.b64encode(
                (client["username"] + ":" + client["password"]).encode()
            ).decode("ascii")
            headers = b"".join(
                [
                    header(":method", "CONNECT"),
                    header(":authority", target),
                    header("user-agent", "x-tuna-probe"),
                    header("proxy-authorization", "Basic " + auth),
                ]
            )
            conn.sendall(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                + frame(4, 0, 0)
                + frame(1, 4, 1, headers)
            )
            status_ok = False
            status_payload = b""
            for _ in range(30):
                kind, _flags, stream, payload = read_frame(conn)
                if kind == 1 and stream == 1:
                    status_payload = payload
                    status_ok = b"\x88" in payload or b"\x08\x03\x32\x30\x30" in payload
                    break
            print("response_header_bytes=" + str(len(status_payload)))
            print("connect_status_200=" + str(status_ok).lower())
            if not status_ok:
                raise SystemExit(1)


if __name__ == "__main__":
    main()
