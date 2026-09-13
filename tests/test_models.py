from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lucx_post_configurator.discovery import audit_system
from lucx_post_configurator.models import ConfigurationError, default_manifest, normalize_protocol, validate_manifest

from helpers import make_target


class ManifestTests(unittest.TestCase):
    def test_extended_decoy_mode_has_safe_defaults(self) -> None:
        manifest = default_manifest()
        self.assertEqual(manifest["schema_version"], 3)
        self.assertEqual(manifest["decoys"]["routing_mode"], "strict")
        self.assertFalse(manifest["decoys"]["extended_user_confirmed"])
        self.assertEqual(manifest["decoys"]["extended_routes"], [])
        self.assertEqual(manifest["decoys"]["naive_frontends"], [])
        self.assertFalse(manifest["components"]["extended_tls_split"])
        self.assertFalse(manifest["components"]["naive_frontend"])

    def test_extended_decoy_mode_requires_explicit_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = default_manifest(audit_system(root))
            manifest["decoys"].update(
                {
                    "enabled": True,
                    "routing_mode": "extended",
                    "create_content": True,
                    "sites": [
                        {
                            "domain": "vpn.example.com",
                            "root": "/var/www/lucx-decoys/vpn.example.com",
                        }
                    ],
                    "capabilities": [
                        {
                            "domain": "vpn.example.com",
                            "status": "extended_ready",
                            "managed": True,
                        }
                    ],
                }
            )
            manifest["components"]["nginx"] = True
            with self.assertRaisesRegex(ConfigurationError, "explicit confirmation"):
                validate_manifest(manifest)
            manifest["decoys"]["extended_user_confirmed"] = True
            validate_manifest(manifest)

    def test_invalid_decoy_routing_mode_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = default_manifest(audit_system(root))
            manifest["decoys"]["routing_mode"] = "automatic"
            with self.assertRaisesRegex(ConfigurationError, "routing_mode"):
                validate_manifest(manifest)

    def test_ready_managed_naive_route_requires_its_component(self) -> None:
        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.com"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.com"
        manifest["certificates"]["cert_path"] = "/cert/fullchain.pem"
        manifest["certificates"]["key_path"] = "/cert/privkey.pem"
        manifest["decoys"].update(
            {
                "enabled": True,
                "routing_mode": "extended",
                "extended_user_confirmed": True,
                "extended_routes": [
                    {
                        "inbound_id": 7,
                        "strategy": "naive_managed",
                        "status": "ready",
                    }
                ],
            }
        )
        manifest["components"].update(
            {"haproxy": True, "nginx": True, "extended_tls_split": True}
        )

        with self.assertRaisesRegex(ConfigurationError, "naive_frontend"):
            validate_manifest(manifest)

    def test_extended_cleartext_decoy_listener_cannot_overlap_tcp_inbound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = default_manifest(audit_system(root))
            manifest["decoys"].update(
                {
                    "enabled": True,
                    "routing_mode": "extended",
                    "extended_user_confirmed": True,
                    "listen_port": 8444,
                    "sites": [
                        {"domain": "tcp.example.net", "root": "/var/www/lucx-decoys/tcp.example.net"}
                    ],
                }
            )
            manifest["protocols"] = [
                {
                    "inbound_id": 77,
                    "protocol": "future",
                    "domain": "tcp.example.net",
                    "internal_host": "127.0.0.1",
                    "internal_port": 8445,
                    "public_port": 8445,
                    "network": "tcp",
                    "exposure": "tcp_direct",
                    "security": "",
                    "sni_names": [],
                    "port_bindings": [{"port": 8445, "protocol": "TCP"}],
                }
            ]

            with self.assertRaisesRegex(ConfigurationError, "extended decoy.*8445"):
                validate_manifest(manifest)

    def test_amneziawg_and_awg_remain_distinct_protocols(self) -> None:
        self.assertEqual(normalize_protocol("amneziawg"), "amneziawg")
        self.assertEqual(normalize_protocol("awg"), "awg")

    def test_sidecar_requires_explicit_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = default_manifest(audit_system(root))
            manifest["protocols"] = [
                {
                    "inbound_id": 5,
                    "protocol": "awg",
                    "remark": "SITE AWG",
                    "domain": "userapi.example.com",
                    "internal_host": "127.0.0.1",
                    "internal_port": 56712,
                    "public_port": 56712,
                    "network": "udp",
                    "exposure": "udp_direct",
                    "security": "",
                    "sni_names": [],
                    "port_bindings": [{"port": 56712, "protocol": "UDP"}],
                }
            ]
            manifest["components"]["sidecar"] = True
            manifest["sidecar"]["allowed_hosts"] = ["sub.example.com"]
            with self.assertRaisesRegex(ConfigurationError, "confirmation"):
                validate_manifest(manifest)
            manifest["sidecar"]["user_confirmed"] = True
            validate_manifest(manifest)

    def test_unknown_sni_decoy_is_never_implicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = default_manifest(audit_system(root))
            manifest["network"]["unknown_sni_action"] = "decoy"
            with self.assertRaisesRegex(ConfigurationError, "decoys.enabled"):
                validate_manifest(manifest)

    def test_sidecar_can_be_confirmed_before_awg_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = default_manifest(audit_system(root))
            manifest["protocols"] = [
                {
                    "inbound_id": 1,
                    "protocol": "vless",
                    "remark": "ONLY VLESS",
                    "domain": "vless.example.com",
                    "internal_host": "127.0.0.1",
                    "internal_port": 54703,
                    "public_port": 443,
                    "network": "tcp",
                    "exposure": "tcp_sni",
                    "security": "reality",
                    "sni_names": ["www.example.com"],
                    "port_bindings": [],
                }
            ]
            manifest["components"]["sidecar"] = True
            manifest["sidecar"]["user_confirmed"] = True
            manifest["sidecar"]["allowed_hosts"] = ["sub.example.com"]
            validate_manifest(manifest)

    def test_cloudflare_restriction_requires_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = default_manifest(audit_system(root))
            manifest["cloudflare"]["enabled"] = True
            with self.assertRaisesRegex(ConfigurationError, "confirmation"):
                validate_manifest(manifest)

    def test_cloudflare_restriction_accepts_only_documented_https_ports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = default_manifest(audit_system(root))
            manifest["cloudflare"].update({"enabled": True, "user_confirmed": True})
            manifest["lucx"]["panel"]["public_port"] = 2083
            manifest["lucx"]["subscription"]["public_port"] = 2096
            validate_manifest(manifest)
            manifest["lucx"]["subscription"]["public_port"] = 9443
            with self.assertRaisesRegex(ConfigurationError, "Cloudflare HTTPS proxy port"):
                validate_manifest(manifest)

    def test_domain_sync_requires_explicit_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = default_manifest(audit_system(root))
            manifest["lucx"]["settings_management"]["sync_domains"] = True
            with self.assertRaisesRegex(ConfigurationError, "publication synchronization"):
                validate_manifest(manifest)
            manifest["lucx"]["settings_management"]["user_confirmed"] = True
            validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
