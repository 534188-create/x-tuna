from __future__ import annotations

import unittest
from pathlib import Path

from lucx_post_configurator.models import Audit, ConfigurationError, Inbound, default_manifest, validate_manifest
from lucx_post_configurator.validation import validate_audit_against_manifest
from lucx_post_configurator.validation import (
    _direct_decoy_domains,
    _managed_naive_adapt_commands,
    _managed_naive_live_requirements,
    _parse_ss_listener_ports,
    _parse_ss_tcp_listeners,
    _validate_trusttunnel_firewall_listing,
    validate_certificate,
)


class ValidationTests(unittest.TestCase):
    def test_empty_lucx_sub_port_is_allowed_for_fresh_install(self) -> None:
        audit = Audit(
            os_id="debian",
            os_version="13",
            supported_os=True,
            db_path="/etc/x-ui/x-ui.db",
            db_schema_supported=True,
            settings={
                "webDomain": "panel.example.test",
                "webPort": "2083",
                "subDomain": "sub.example.test",
                "subPath": "/sub/",
                "subPort": "",
            },
        )
        audit.settings["subPort"] = ""
        manifest = default_manifest(audit)
        manifest["lucx"]["settings_management"].update(
            {"sync_domains": True, "user_confirmed": True}
        )
        errors = validate_audit_against_manifest(audit, manifest)
        self.assertNotIn(
            "LucX subPort is <invalid>",
            "\n".join(errors),
        )
    def test_naive_endpoint_sync_defers_caddyfile_checks_until_after_restart(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            from pathlib import Path as _Path

            root = _Path(temporary)
            audit = Audit(
                os_id="debian",
                os_version="13",
                supported_os=True,
                db_path="/etc/x-ui/x-ui.db",
                db_schema_supported=True,
                settings={
                    "webDomain": "panel.new-zone.test",
                    "webPort": "2083",
                    "subDomain": "sub.new-zone.test",
                    "subPort": "2096",
                    "subPath": "/sub/",
                    "webCertFile": "/certs/old/fullchain.pem",
                    "webKeyFile": "/certs/old/privkey.pem",
                },
                inbounds=[
                    Inbound(
                        id=5,
                        protocol="naive",
                        remark="naive",
                        enable=True,
                        listen="",
                        port=52354,
                        share_addr="test5.old-zone.test",
                        suggested_public_port=443,
                        network="tcp",
                        security="tls",
                        server_names=[],
                        port_bindings=[],
                    )
                ],
                naive_caddyfile={
                    "found": True,
                    "path": "/usr/local/x-ui/bin/tunnel/naive-5.caddyfile",
                    "files": [
                        {
                            "path": "/usr/local/x-ui/bin/tunnel/naive-5.caddyfile",
                            "found": True,
                        }
                    ],
                },
            )
            manifest = default_manifest(audit)
            manifest["lucx"]["panel"]["domain"] = "panel.new-zone.test"
            manifest["lucx"]["subscription"]["domain"] = "sub.new-zone.test"
            manifest["lucx"]["settings_management"].update(
                {
                    "sync_domains": True,
                    "sync_certificate_paths": True,
                    "sync_naive_endpoint": True,
                    "user_confirmed": True,
                }
            )
            manifest["certificates"]["cert_path"] = "/certs/new/fullchain.pem"
            manifest["certificates"]["key_path"] = "/certs/new/privkey.pem"
            manifest["protocols"] = [
                {
                    "inbound_id": 5,
                    "protocol": "naive",
                    "remark": "naive",
                    "domain": "test5.new-zone.test",
                    "internal_host": "127.0.0.1",
                    "internal_port": 52354,
                    "public_port": 443,
                    "network": "tcp",
                    "exposure": "tcp_sni",
                    "security": "tls",
                    "sni_names": ["test5.new-zone.test"],
                    "sync_naive_endpoint": True,
                    "sync_public_endpoint": True,
                }
            ]
            # The staged Caddyfile still describes the old zone: with a
            # confirmed endpoint sync the strict text checks must be deferred
            # to the post-restart health phase instead of blocking apply.
            (root / "usr/local/x-ui/bin/tunnel").mkdir(parents=True)
            (root / "usr/local/x-ui/bin/tunnel/naive-5.caddyfile").write_text(
                "test5.old-zone.test:52354 {\n  tls /certs/old/fullchain.pem /certs/old/privkey.pem\n}\n",
                encoding="utf-8",
            )
            # The new certificate pair must exist for other checks.
            (root / "certs/new").mkdir(parents=True)
            (root / "certs/new/fullchain.pem").write_text("stub", encoding="utf-8")
            (root / "certs/new/privkey.pem").write_text("stub", encoding="utf-8")

            from lucx_post_configurator.runner import Runner
            from lucx_post_configurator.targetfs import TargetFS

            fs = TargetFS(root)
            runner = Runner(dry_run=True)
            errors = validate_certificate(fs, manifest, runner)
            caddy_errors = [
                item for item in errors if "visibly cover" in item or "Caddyfile" in item
            ]
            self.assertEqual(caddy_errors, [])

    def test_live_configuration_verifies_regenerated_naive_caddyfile(self) -> None:
        import tempfile

        from lucx_post_configurator.runner import Runner
        from lucx_post_configurator.targetfs import TargetFS
        from lucx_post_configurator.validation import validate_live_configuration

        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.new-zone.test"
        manifest["lucx"]["subscription"]["domain"] = "sub.new-zone.test"
        manifest["certificates"]["cert_path"] = "/certs/new/fullchain.pem"
        manifest["certificates"]["key_path"] = "/certs/new/privkey.pem"
        manifest["certificates"]["managed"] = False
        manifest["protocols"] = [
            {
                "inbound_id": 5,
                "protocol": "naive",
                "remark": "naive",
                "domain": "test5.new-zone.test",
                "internal_host": "127.0.0.1",
                "internal_port": 52354,
                "public_port": 443,
                "network": "tcp",
                "exposure": "tcp_sni",
                "security": "tls",
                "sni_names": ["test5.new-zone.test"],
                "sync_naive_endpoint": True,
                "sync_public_endpoint": True,
            }
        ]

        def build_audit(caddy_text: str):
            audit = Audit(
                os_id="debian",
                os_version="13",
                supported_os=True,
                db_path="/etc/x-ui/x-ui.db",
                db_schema_supported=True,
                settings={},
                inbounds=[
                    Inbound(
                        id=5,
                        protocol="naive",
                        remark="naive",
                        enable=True,
                        listen="",
                        port=52354,
                        share_addr="test5.new-zone.test",
                        suggested_public_port=443,
                        network="tcp",
                        security="tls",
                    )
                ],
                naive_caddyfile={
                    "found": True,
                    "files": [
                        {"path": "/usr/local/x-ui/bin/tunnel/naive-5.caddyfile", "found": True}
                    ],
                },
            )
            return audit

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            caddy_dir = root / "usr/local/x-ui/bin/tunnel"
            caddy_dir.mkdir(parents=True)
            caddy_path = caddy_dir / "naive-5.caddyfile"
            fs = TargetFS(root)
            runner = Runner(dry_run=True)

            # Positive: LucX regenerated the file with the new zone and pair.
            caddy_path.write_text(
                "test5.new-zone.test:52354 {\n"
                "  tls /certs/new/fullchain.pem /certs/new/privkey.pem\n"
                "}\n",
                encoding="utf-8",
            )
            errors = validate_live_configuration(
                manifest, runner, fs=fs, audit=build_audit(caddy_path.read_text(encoding="utf-8"))
            )
            self.assertEqual(
                [item for item in errors if "did not regenerate" in item],
                [],
            )

            # Negative: the file still describes the old zone.
            caddy_path.write_text(
                "test5.old-zone.test:52354 {\n"
                "  tls /certs/old/fullchain.pem /certs/old/privkey.pem\n"
                "}\n",
                encoding="utf-8",
            )
            errors = validate_live_configuration(
                manifest, runner, fs=fs, audit=build_audit(caddy_path.read_text(encoding="utf-8"))
            )
            self.assertTrue(
                any(
                    "did not regenerate" in item and "inbound #5" in item
                    for item in errors
                ),
                errors,
            )
    def test_live_firewall_requires_both_trusttunnel_transport_drop_rules(self) -> None:
        manifest = default_manifest()
        manifest["decoys"]["routing_mode"] = "extended"
        manifest["protocols"] = [
            {
                "inbound_id": 9,
                "protocol": "trusttunnel",
                "internal_port": 9443,
                "public_port": 443,
                "exposure": "tcp_sni",
            }
        ]
        manifest["decoys"]["extended_routes"] = [
            {
                "inbound_id": 9,
                "strategy": "trusttunnel_clienthello_split",
                "status": "ready",
                "managed": True,
                "internal_port": 9443,
                "public_tcp_port": 443,
            }
        ]
        tcp_only = (
            'chain protect_internal {\n'
            '  iifname != "lo" tcp dport 9443 counter drop '
            'comment "TrustTunnel internal TCP"\n'
            '}\n'
        )

        self.assertEqual(
            _validate_trusttunnel_firewall_listing(manifest, tcp_only),
            ["TrustTunnel internal UDP firewall drop is missing for port 9443"],
        )
        both = tcp_only.replace(
            "}\n",
            '  iifname != "lo" udp dport 9443 counter drop '
            'comment "TrustTunnel internal UDP"\n}\n',
        )
        self.assertEqual(_validate_trusttunnel_firewall_listing(manifest, both), [])

    def test_managed_naive_live_requirements_include_service_and_loopback_port(self) -> None:
        manifest = default_manifest()
        manifest["decoys"]["extended_routes"] = [
            {
                "inbound_id": 7,
                "strategy": "naive_managed",
                "status": "ready",
                "managed_listen_port": 26443,
            },
            {
                "inbound_id": 8,
                "strategy": "naive_native",
                "status": "ready",
            },
        ]

        self.assertEqual(
            _managed_naive_live_requirements(manifest),
            (["lucx-naive-decoy-7.service"], {26443}),
        )

    def test_managed_naive_frontend_is_adapted_with_its_discovered_binary(self) -> None:
        manifest = default_manifest()
        manifest["decoys"]["extended_routes"] = [
            {
                "inbound_id": 7,
                "strategy": "naive_managed",
                "status": "ready",
                "binary_path": "/usr/local/x-ui/bin/caddy-naive-linux-amd64",
            }
        ]
        staged_path = Path("/tmp/staged-naive-7.caddyfile")
        staged = {
            "/etc/lucx-post-configurator/naive/naive-7.caddyfile": staged_path
        }

        self.assertEqual(
            _managed_naive_adapt_commands(manifest, staged),
            [
                (
                    [
                        "/usr/local/x-ui/bin/caddy-naive-linux-amd64",
                        "adapt",
                        "--config",
                        str(staged_path),
                        "--adapter",
                        "caddyfile",
                    ],
                    "managed Naive inbound #7",
                )
            ],
        )

    def test_managed_decoy_cannot_overlap_protocol_owned_sni(self) -> None:
        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.com"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.com"
        manifest["certificates"]["cert_path"] = "/cert/fullchain.pem"
        manifest["certificates"]["key_path"] = "/cert/privkey.pem"
        manifest["protocols"] = [
            {
                "inbound_id": 1,
                "protocol": "trojan",
                "domain": "owned.example.com",
                "internal_host": "127.0.0.1",
                "internal_port": 10443,
                "public_port": 443,
                "network": "tcp",
                "exposure": "tcp_sni",
                "security": "tls",
                "sni_names": ["owned.example.com"],
                "port_bindings": [],
            }
        ]
        manifest["decoys"].update(
            {
                "enabled": True,
                "sites": [
                    {"domain": "owned.example.com", "root": "/var/www/lucx-decoys/owned.example.com"}
                ],
                "capabilities": [
                    {
                        "domain": "owned.example.com",
                        "status": "direct_tcp_decoy",
                        "managed": True,
                        "protocol_ids": [1],
                        "evidence": [],
                        "reason": "incorrectly free",
                        "probe_mode": "active",
                    }
                ],
            }
        )

        with self.assertRaisesRegex(ConfigurationError, "decoy route.*protocol SNI"):
            validate_manifest(manifest)

    def test_only_free_browser_sni_is_probed_as_direct_nginx_decoy(self) -> None:
        manifest = {
            "network": {"public_tcp_port": 443},
            "protocols": [
                {
                    "protocol": "vless",
                    "network": "tcp",
                    "security": "reality",
                    "exposure": "tcp_sni",
                    "public_port": 443,
                    "domain": "endpoint.example.com",
                    "sni_names": ["occupied.example.com"],
                }
            ],
            "decoys": {
                "zone_apex": "example.com",
                "sites": [
                    {"domain": "endpoint.example.com"},
                    {"domain": "occupied.example.com"},
                ]
            },
        }
        self.assertEqual(_direct_decoy_domains(manifest), ["endpoint.example.com", "example.com"])

    def test_parses_ipv4_ipv6_and_process_from_ss(self) -> None:
        output = (
            'LISTEN 0 4096 127.0.0.1:443 0.0.0.0:* users:(("caddy",pid=1,fd=7))\n'
            'LISTEN 0 128 [::]:49283 [::]:* users:(("sshd",pid=2,fd=3))\n'
        )
        self.assertEqual(
            _parse_ss_tcp_listeners(output),
            [
                ("127.0.0.1", 443, 'users:(("caddy",pid=1,fd=7))'),
                ("::", 49283, 'users:(("sshd",pid=2,fd=3))'),
            ],
        )

    def test_parses_tcp_and_udp_listener_ports(self) -> None:
        output = (
            "LISTEN 0 4096 127.0.0.1:2083 0.0.0.0:*\n"
            "UNCONN 0 0 [::]:443 [::]:*\n"
        )
        self.assertEqual(_parse_ss_listener_ports(output), {443, 2083})


if __name__ == "__main__":
    unittest.main()
