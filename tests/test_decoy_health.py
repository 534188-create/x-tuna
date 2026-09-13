from __future__ import annotations

import unittest
from unittest import mock

from lucx_post_configurator.decoy_health import (
    decoy_probe_targets,
    evaluate_http_response,
    observe_decoy_capabilities,
)
from lucx_post_configurator.models import default_manifest


class DecoyHealthTests(unittest.TestCase):
    def test_managed_site_requires_success_and_exact_marker(self) -> None:
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"X-LucX-Decoy: free.example.com\r\n"
            b"Content-Length: 2\r\n\r\nok"
        )
        self.assertEqual(
            evaluate_http_response(response, "X-LucX-Decoy: free.example.com"),
            {"state": "healthy", "status": 200, "detail": "managed marker observed"},
        )

    def test_wrong_marker_is_not_healthy(self) -> None:
        response = b"HTTP/1.1 200 OK\r\nX-LucX-Decoy: other.example.com\r\n\r\n"
        self.assertEqual(
            evaluate_http_response(response, "X-LucX-Decoy: free.example.com")["state"],
            "http_error",
        )

    def test_passive_success_is_observation_not_managed_health(self) -> None:
        response = b"HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"
        self.assertEqual(
            evaluate_http_response(response, None),
            {"state": "site_observed", "status": 302, "detail": "HTTPS response observed"},
        )

    def test_invalid_or_error_response_is_reported(self) -> None:
        self.assertEqual(evaluate_http_response(b"garbage", None)["state"], "http_error")
        self.assertEqual(
            evaluate_http_response(b"HTTP/1.1 503 Unavailable\r\n\r\n", None)["state"],
            "http_error",
        )

    def test_extended_mode_probes_public_tls_and_both_internal_delivery_paths(self) -> None:
        manifest = default_manifest()
        manifest["network"]["public_tcp_port"] = 443
        manifest["decoys"].update(
            {
                "enabled": True,
                "routing_mode": "extended",
                "listen_host": "127.0.0.1",
                "listen_port": 8444,
                "capabilities": [
                    {
                        "domain": "site.example.net",
                        "status": "extended_ready",
                        "managed": True,
                        "probe_mode": "active",
                    }
                ],
            }
        )

        targets = decoy_probe_targets(manifest, "192.0.2.15")

        self.assertEqual(
            targets,
            [
                {
                    "domain": "site.example.net",
                    "path": "public_tls",
                    "address": "192.0.2.15",
                    "port": 443,
                    "tls": True,
                },
                {
                    "domain": "site.example.net",
                    "path": "internal_tls",
                    "address": "127.0.0.1",
                    "port": 8444,
                    "tls": True,
                },
                {
                    "domain": "site.example.net",
                    "path": "internal_h2c",
                    "address": "127.0.0.1",
                    "port": 8445,
                    "tls": False,
                },
            ],
        )

    @mock.patch("lucx_post_configurator.decoy_health.observe_decoy")
    def test_extended_observation_keeps_route_status_separate_from_http_status(
        self, observe: mock.Mock
    ) -> None:
        observe.return_value = {
            "state": "healthy",
            "status": 200,
            "detail": "managed marker observed",
        }
        manifest = default_manifest()
        manifest["decoys"].update(
            {
                "enabled": True,
                "routing_mode": "extended",
                "capabilities": [
                    {
                        "domain": "site.example.net",
                        "status": "extended_ready",
                        "managed": True,
                        "probe_mode": "active",
                    }
                ],
            }
        )

        results = observe_decoy_capabilities(manifest, "192.0.2.15")

        self.assertEqual(results[0]["capability_status"], "extended_ready")
        self.assertEqual(results[0]["http_status"], 200)
        self.assertNotIn("status", results[0])


if __name__ == "__main__":
    unittest.main()
