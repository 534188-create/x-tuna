from __future__ import annotations

import socketserver
import shutil
import ssl
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from lucx_post_configurator import decoy_health as health
from lucx_post_configurator.models import default_manifest
from lucx_post_configurator.runner import CommandResult, Runner


class DecoyAcceptanceTests(unittest.TestCase):
    def test_vpn_observer_cannot_modify_manifest_nested_identity(self):
        manifest = default_manifest()
        manifest["protocols"] = [{"inbound_id": 7, "protocol": "vless", "exposure": "tcp_sni", "port_bindings": [{"port": 9443}]}]

        def observer(protocol, runner):
            protocol["port_bindings"][0]["port"] = 443
            return {"state": "healthy", "functional": True, "public": True}

        health.observe_vpn_capabilities(manifest, Runner(dry_run=True), observers={"vless": observer})
        self.assertEqual(manifest["protocols"][0]["port_bindings"][0]["port"], 9443)

    def test_real_h2c_uses_http2_preface_and_frames_when_cli_supports_it(self):
        runner = Runner()
        if not runner.available("curl") or "HTTP2" not in runner.run(["curl", "--disable", "--version"]).stdout.split():
            self.skipTest("Установленный curl не поддерживает HTTP2")
        prefaces = []

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                def read(size):
                    value = b""
                    while len(value) < size:
                        chunk = self.request.recv(size - len(value))
                        if not chunk:
                            raise ConnectionError("incomplete HTTP/2 frame")
                        value += chunk
                    return value

                self.request.settimeout(3)
                prefaces.append(read(24))
                self.request.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
                while True:
                    frame = read(9)
                    read(int.from_bytes(frame[:3], "big"))
                    if frame[3] == 1:
                        block = b"\x88\x00\x0cx-lucx-decoy\x11site.example.test"
                        self.request.sendall(len(block).to_bytes(3, "big") + b"\x01\x05" + frame[5:] + block)
                        return

        with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for method in ("GET", "HEAD"):
                    result = health.observe_decoy("site.example.test", "127.0.0.1", server.server_address[1],
                        "X-LucX-Decoy: site.example.test", use_tls=False, method=method, http_version="h2", runner=runner)
                    self.assertEqual(result["state"], "healthy", result)
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual(prefaces, [b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"] * 2)

    def test_real_tls_trust_hostname_and_explicit_internal_selfsigned_policy(self):
        openssl = shutil.which("openssl") or "C:/Program Files/Git/usr/bin/openssl.exe"
        if not Path(openssl).is_file():
            self.skipTest("Нет openssl для временного тестового сертификата")
        with tempfile.TemporaryDirectory() as temporary:
            cert, key = Path(temporary) / "cert.pem", Path(temporary) / "key.pem"
            Runner().run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=site.example.test", "-addext", "subjectAltName=DNS:site.example.test",
                "-keyout", str(key), "-out", str(cert)])
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert, key)

            class Handler(socketserver.BaseRequestHandler):
                def handle(self):
                    try:
                        with server_context.wrap_socket(self.request, server_side=True) as stream:
                            stream.recv(4096)
                            stream.sendall(b"HTTP/1.1 200 OK\r\nX-LucX-Decoy: site.example.test\r\n\r\n")
                    except ssl.SSLError:
                        pass

            with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    args = ("site.example.test", "127.0.0.1", server.server_address[1], "X-LucX-Decoy: site.example.test")
                    self.assertEqual(health.observe_decoy(*args)["state"], "tls_error")
                    self.assertEqual(health.observe_decoy(*args, verify_tls=False)["state"], "healthy")
                    trusted = ssl.create_default_context(cafile=str(cert))
                    with mock.patch.object(health.ssl, "create_default_context", return_value=trusted):
                        self.assertEqual(health.observe_decoy(*args)["state"], "healthy")
                        self.assertEqual(health.observe_decoy("wrong.example.test", *args[1:])["state"], "tls_error")
                finally:
                    server.shutdown()
                    thread.join()

    def test_incomplete_matrix_fails_managed_health(self):
        manifest = default_manifest()
        manifest["decoys"].update(enabled=True, sites=[{"domain": "site.example.test"}])
        observations = [{"domain": "site.example.test", "managed": True, "path": "public_tls",
            "method": "GET", "http_version": "h1", "state": "healthy", "tls_verified": True}]
        self.assertFalse(health.decoy_acceptance_summary(manifest, observations)["complete"])
        self.assertTrue(health.validate_decoy_observations(manifest, observations))
        with mock.patch.object(health, "observe_decoy", return_value={"state": "healthy", "status": 200, "detail": "ok"}):
            observations = health.observe_decoy_capabilities(manifest, "192.0.2.1")
        self.assertEqual({(row["method"], row["http_version"]) for row in observations},
                         {("GET", "h1"), ("GET", "h2"), ("HEAD", "h1"), ("HEAD", "h2")})
        self.assertEqual(health.validate_decoy_observations(manifest, observations), [])
        self.assertTrue(health.decoy_acceptance_summary(manifest, observations)["complete"])

    def test_unverified_tls_requires_explicit_internal_loopback_policy(self):
        with mock.patch.object(health.socket, "create_connection") as connect:
            result = health.observe_decoy("site.example.test", "192.0.2.1", 443, None, verify_tls=False)
        self.assertEqual(result["state"], "http_error")
        connect.assert_not_called()

    def test_marker_must_be_a_single_complete_header(self):
        for header in (
            b"Other: X-LucX-Decoy: site.example.test",
            b"X-LucX-Decoy: site.example.test.evil.test",
            b"X-LucX-Decoy: site.example.test\r\nX-LucX-Decoy: site.example.test",
            b"X-LucX-Decoy: site.example.test\r\n continuation",
            b"X-LucX-Decoy : site.example.test",
        ):
            with self.subTest(header=header):
                self.assertEqual(health.evaluate_http_response(
                    b"HTTP/1.1 200 OK\r\n" + header + b"\r\n\r\n",
                    "X-LucX-Decoy: site.example.test")["state"], "http_error")

    def test_h1_get_and_head_reach_local_server(self):
        requests = []

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                requests.append(self.request.recv(4096))
                self.request.sendall(b"HTTP/1.1 200 OK\r\nX-LucX-Decoy: site.example.test\r\n\r\n")

        with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for method in ("GET", "HEAD"):
                    result = health.observe_decoy("site.example.test", "127.0.0.1", server.server_address[1],
                        "X-LucX-Decoy: site.example.test", use_tls=False, method=method)
                    self.assertEqual(result["state"], "healthy")
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual([r.split(b" ")[0] for r in requests], [b"GET", b"HEAD"])

    def test_public_tls_keeps_hostname_and_trust_verification(self):
        context = mock.MagicMock()
        context.check_hostname = True
        context.verify_mode = 2
        context.wrap_socket.return_value.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        with mock.patch.object(health.ssl, "create_default_context", return_value=context), \
                mock.patch.object(health.socket, "create_connection"):
            health.observe_decoy("site.example.test", "192.0.2.1", 443, None)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, 2)

    def test_h2_downgrade_and_missing_binary_are_not_success(self):
        runner = mock.Mock(spec=Runner)
        runner.dry_run = False
        runner.available.return_value = False
        result = health.observe_decoy("site.example.test", "192.0.2.1", 443, None,
                                     http_version="h2", runner=runner)
        self.assertEqual(result["state"], "not_tested")
        runner.available.return_value = True
        runner.run.side_effect = [
            CommandResult([], 0, "curl 8.0\nFeatures: SSL HTTP2\n", ""),
            CommandResult([], 0, "HTTP/1.1 200 OK\nX-LucX-Decoy: site.example.test\n\n\nLUCX_HTTP_VERSION:1.1", ""),
        ]
        result = health.observe_decoy("site.example.test", "192.0.2.1", 443,
            "X-LucX-Decoy: site.example.test", http_version="h2", runner=runner)
        self.assertEqual(result["state"], "http_error")

    def test_h2_cli_uses_stdin_destination_and_checks_wire_version(self):
        runner = mock.Mock(spec=Runner)
        runner.dry_run = False
        runner.available.return_value = True
        runner.run.side_effect = [
            CommandResult([], 0, "curl 8.0\nFeatures: SSL HTTP2\n", ""),
            CommandResult([], 0, "HTTP/2 200\nX-LucX-Decoy: site.example.test\n\n\nLUCX_HTTP_VERSION:2", ""),
        ]
        result = health.observe_decoy("site.example.test", "192.0.2.1", 8445,
            "X-LucX-Decoy: site.example.test", use_tls=False, method="HEAD", http_version="h2", runner=runner)
        self.assertEqual(result["state"], "healthy")
        args, kwargs = runner.run.call_args
        self.assertIn("--http2-prior-knowledge", args[0])
        self.assertNotIn("192.0.2.1", " ".join(args[0]))
        self.assertNotIn("site.example.test", " ".join(args[0]))
        self.assertIn("192.0.2.1", kwargs["input_text"])
        self.assertIn("head", kwargs["input_text"])

    def test_requested_sites_are_not_lost_when_capability_missing_or_blocked(self):
        manifest = default_manifest()
        manifest["decoys"].update(enabled=True, sites=[{"domain": "example.test"}, {"domain": "vpn.example.test"}],
            capabilities=[{"domain": "vpn.example.test", "managed": False, "probe_mode": "none", "status": "blocked"}])
        summary = health.decoy_acceptance_summary(manifest, [])
        self.assertFalse(summary["complete"])
        self.assertEqual(summary["requested_sites"], 2)
        self.assertEqual(summary["verified_sites"], 0)

    def test_vpn_without_functional_observer_is_not_tested(self):
        manifest = default_manifest()
        manifest["protocols"] = [{"inbound_id": 7, "protocol": "vless", "exposure": "tcp_sni"}]
        result = health.observe_vpn_capabilities(manifest, Runner(dry_run=True))
        self.assertEqual(result[0]["state"], "not_tested")
        runner = Runner(dry_run=True)
        observations = health.observe_vpn_capabilities(manifest, runner, observers={
            "vless": lambda protocol, command_runner: {"state": "healthy", "functional": True, "public": True}
        })
        self.assertEqual(observations[0]["state"], "healthy")
        observations = health.observe_vpn_capabilities(manifest, runner, observers={
            "vless": lambda protocol, command_runner: {"state": "healthy", "functional": False, "public": True}
        })
        self.assertEqual(observations[0]["state"], "not_tested")
