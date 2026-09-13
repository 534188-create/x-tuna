from __future__ import annotations

import tempfile
import unittest
from unittest import mock

from lucx_post_configurator.engine import Engine
from lucx_post_configurator.protocol_test import (
    ProbeResult,
    probe_anytls_handshake,
    probe_https_decoy,
    probe_naive_proxy_tunnel,
    probe_panel_service,
    probe_subscription_sidecar,
    probe_udp_socket,
    render_protocol_test_table,
    run_comprehensive_protocol_test,
)
from lucx_post_configurator.runner import Runner


class ProtocolTestTests(unittest.TestCase):
    def test_probe_result_structure(self) -> None:
        res = ProbeResult(
            category="Decoy",
            name="Decoy (example.test)",
            endpoint="example.test",
            port=443,
            transport="HTTPS/H2",
            ok=True,
            latency_ms=4.5,
            status_code=200,
            detail="H2 200 OK",
        )
        self.assertTrue(res.ok)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.latency_ms, 4.5)

    def test_render_protocol_test_table(self) -> None:
        lines: list[str] = []
        results = [
            ProbeResult(
                category="Decoy",
                name="Decoy (example.test)",
                endpoint="example.test",
                port=443,
                transport="HTTPS/H2",
                ok=True,
                latency_ms=4.2,
                status_code=200,
                detail="H2 200 OK",
            ),
            ProbeResult(
                category="Протокол",
                name="NaiveProxy Inbound",
                endpoint="test5.example.test",
                port=443,
                transport="HTTPS/H2",
                ok=True,
                latency_ms=8.1,
                status_code=407,
                detail="407 Auth Req",
            ),
            ProbeResult(
                category="UDP",
                name="AmneziaWG (UDP:8443)",
                endpoint="test4.example.test",
                port=8443,
                transport="UDP",
                ok=False,
                latency_ms=None,
                status_code=None,
                detail="Timeout",
            ),
        ]
        render_protocol_test_table(results, output_fn=lines.append)
        combined = "\n".join(lines)
        self.assertIn("КОМПЛЕКСНЫЙ АВТОТЕСТ", combined)
        self.assertIn("example.test", combined)
        self.assertIn("NaiveProxy Inbound", combined)
        self.assertIn("2/3 проверок успешно", combined)

    @mock.patch("socket.create_connection")
    def test_probe_https_decoy_failure(self, mock_conn: mock.MagicMock) -> None:
        mock_conn.side_effect = ConnectionRefusedError("Connection refused")
        res = probe_https_decoy("nonexistent.domain", 443, timeout=0.1)
        self.assertFalse(res.ok)
        self.assertIn("Connection refused", res.detail)

    @mock.patch("ssl.SSLContext.wrap_socket")
    @mock.patch("socket.create_connection")
    def test_probe_subscription_sidecar_ok(self, mock_conn: mock.MagicMock, mock_wrap: mock.MagicMock) -> None:
        mock_ssock = mock.MagicMock()
        mock_ssock.recv.side_effect = [
            b"HTTP/1.1 200 OK\r\nX-LucX-Subscription-Sidecar: active\r\n\r\n",
            b"",
        ]
        mock_wrap.return_value.__enter__.return_value = mock_ssock

        res = probe_subscription_sidecar(local_port=21000)
        self.assertTrue(res.ok)
        self.assertEqual(res.status_code, 200)
        self.assertIn("AWG/AnyTLS", res.detail)

    def test_run_comprehensive_protocol_test_with_mocked_network(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            engine = Engine(root=tempdir, runner=Runner(dry_run=True))
            with mock.patch("socket.create_connection") as mock_sock, \
                 mock.patch("socket.socket") as mock_udp, \
                 mock.patch("http.client.HTTPConnection") as mock_http:

                mock_sock.side_effect = OSError("network unreachable")
                mock_udp_inst = mock.MagicMock()
                mock_udp.return_value = mock_udp_inst

                mock_http_inst = mock.MagicMock()
                mock_resp = mock.MagicMock()
                mock_resp.status = 200
                mock_resp.getheader.return_value = "active"
                mock_resp.read.return_value = b""
                mock_http_inst.getresponse.return_value = mock_resp
                mock_http.return_value = mock_http_inst

                results = run_comprehensive_protocol_test(engine)
                self.assertGreater(len(results), 5)
                # Ensure at least Decoys, Panel, Sidecar, Naive, AnyTLS, UDP are tested
                categories = {r.category for r in results}
                self.assertIn("Decoy", categories)
                self.assertIn("Панель", categories)
                self.assertIn("Подписка", categories)
                self.assertIn("UDP", categories)
