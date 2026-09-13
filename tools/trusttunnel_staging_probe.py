from __future__ import annotations

import base64
import socket
import ssl
import struct
import subprocess
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes((kind, flags)) + (stream & 0x7FFFFFFF).to_bytes(4, "big") + payload


def header(name: str, value: str) -> bytes:
    n, v = name.encode("ascii"), value.encode()
    return b"\0" + bytes((len(n),)) + n + bytes((len(v),)) + v


def read_frame(conn: ssl.SSLSocket) -> tuple[int, int, int, bytes]:
    head = b""
    while len(head) < 9:
        part = conn.recv(9 - len(head))
        if not part:
            raise RuntimeError("peer closed before frame header")
        head += part
    size = int.from_bytes(head[:3], "big")
    body = b""
    while len(body) < size:
        part = conn.recv(size - len(body))
        if not part:
            raise RuntimeError("peer closed before frame payload")
        body += part
    return head[3], head[4], int.from_bytes(head[5:9], "big") & 0x7FFFFFFF, body


def connect_probe(host: str, port: int, user: str, password: str, target: str, *, sni: str) -> None:
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    payload = b"".join(
        header(*item)
        for item in (
            (":method", "CONNECT"),
            (":authority", target),
            ("user-agent", "x-tuna-staging"),
            ("proxy-authorization", f"Basic {auth}"),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    with socket.create_connection((host, port), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as conn:
            if conn.selected_alpn_protocol() != "h2":
                raise RuntimeError("endpoint did not negotiate h2")
            conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b"") + frame(1, 4, 1, payload))
            status = False
            for _ in range(20):
                kind, flags, stream, body = read_frame(conn)
                if kind == 1 and stream == 1 and (b"\x88" in body or b"200" in body):
                    status = True
                    break
            if not status:
                raise RuntimeError("CONNECT did not return HTTP/2 200")
            marker = b"x-tuna-staging-roundtrip"
            # Keep the CONNECT stream open while the echo target replies.
            conn.sendall(frame(0, 0, 1, marker))
            for _ in range(20):
                kind, flags, stream, body = read_frame(conn)
                if kind == 0 and stream == 1:
                    if marker in body:
                        return
            raise RuntimeError("CONNECT byte round-trip failed")


class DecoyHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"x-tuna-staging-decoy"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-LucX-Decoy", "staging")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:
        body = b"x-tuna-staging-decoy"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-LucX-Decoy", "staging")
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        return


def get_probe(host: str, port: int, *, sni: str) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["http/1.1"])
    with socket.create_connection((host, port), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as conn:
            conn.sendall(
                b"GET / HTTP/1.1\r\n"
                + f"Host: {sni}\r\nConnection: close\r\n\r\n".encode()
            )
            response = b""
            while True:
                part = conn.recv(4096)
                if not part:
                    break
                response += part
            if b" 200 " not in response.split(b"\r\n", 1)[0]:
                raise RuntimeError("decoy GET did not return HTTP 200")
            if b"x-tuna-staging-decoy" not in response:
                raise RuntimeError("decoy GET did not reach HTTP origin")


def main() -> int:
    root = Path(sys.argv[1])
    cert = sys.argv[2]
    key = sys.argv[3]
    port = int(sys.argv[4])
    user, password = "x-tuna-probe", "x-tuna-probe-secret"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    (root / "credentials.toml").write_text(f'[[client]]\nusername = "{user}"\npassword = "{password}"\n', encoding="utf-8")
    (root / "rules.toml").write_text('[[rule]]\naction = "allow"\n', encoding="utf-8")
    (root / "vpn.toml").write_text(
        f'listen_address = "127.0.0.1:{port}"\nipv6_available = false\nallow_private_network_connections = true\ncredentials_file = "{root}/credentials.toml"\nrules_file = "{root}/rules.toml"\nauth_failure_status_code = 407\n[listen_protocols.http1]\n[listen_protocols.http2]\n[forward_protocol]\ndirect = {{}}\n', encoding="utf-8"
    )
    (root / "hosts.toml").write_text(f'[[main_hosts]]\nhostname = "example.test"\ncert_chain_path = "{cert}"\nprivate_key_path = "{key}"\n', encoding="utf-8")
    echo = subprocess.Popen(["socat", "TCP-LISTEN:26445,bind=127.0.0.1,reuseaddr,fork", "EXEC:cat"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    decoy = ThreadingHTTPServer(("127.0.0.1", 26446), DecoyHandler)
    decoy_thread = threading.Thread(target=decoy.serve_forever, daemon=True)
    decoy_thread.start()
    (root / "vpn.toml").write_text(
        (root / "vpn.toml").read_text(encoding="utf-8")
        + "[reverse_proxy]\nserver_address = \"127.0.0.1:26446\"\npath_mask = \"/\"\nh3_backward_compatibility = false\n",
        encoding="utf-8",
    )
    endpoint = subprocess.Popen([str(root / "trusttunnel_endpoint"), str(root / "vpn.toml"), str(root / "hosts.toml"), "--loglvl", "info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    connect_probe("127.0.0.1", port, user, password, "127.0.0.1:26445", sni="example.test")
                    get_probe("127.0.0.1", port, sni="example.test")
                    print("protocol_handshake=true")
                    return 0
            if endpoint.poll() is not None:
                raise RuntimeError("endpoint exited before listening")
            time.sleep(0.2)
        raise RuntimeError("endpoint did not start")
    finally:
        endpoint.terminate()
        echo.terminate()
        decoy.shutdown()
        decoy.server_close()
        endpoint.wait(timeout=5)
        echo.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
