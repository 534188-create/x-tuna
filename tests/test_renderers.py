from __future__ import annotations

import tempfile
import unittest
import re
from pathlib import Path
from unittest import mock

from lucx_post_configurator import cloudflare
from lucx_post_configurator.discovery import audit_system, Audit
from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
from lucx_post_configurator.models import default_manifest, validate_manifest
from lucx_post_configurator.renderers import (
    render_files,
    render_cloudflare_acl,
    render_cloudflare_update_unit,
    render_haproxy,
    render_logrotate,
    render_nginx_decoys,
    render_nftables,
    render_resolvconf,
)

from helpers import make_target


def fixture_manifest(root: Path) -> dict:
    audit = audit_system(root)
    manifest = default_manifest(audit)
    manifest["certificates"]["cert_path"] = "/cert/fullchain.pem"
    manifest["certificates"]["key_path"] = "/cert/privkey.pem"
    manifest["protocols"] = [
        {
            "inbound_id": item.id,
            "protocol": item.protocol,
            "remark": item.remark,
            "domain": item.share_addr,
            "internal_host": item.listen or "127.0.0.1",
            "internal_port": item.port,
            "public_port": 443 if item.protocol == "vless" else item.port,
            "network": item.network,
            "exposure": (
                "tcp_sni"
                if item.protocol == "vless"
                else "udp_direct"
                if item.network == "udp"
                else "tcp_udp_direct"
                if item.network == "both"
                else "tcp_direct"
            ),
            "security": item.security,
            "port_bindings": item.port_bindings,
        }
        for item in audit.inbounds
    ]
    manifest["network"]["non_tls_backend_inbound_id"] = 1
    manifest["decoys"].update(
        {
            "enabled": True,
            "create_content": True,
            "default_server": False,
            "sites": [
                {"domain": item.share_addr, "root": f"/var/www/lucx-decoys/{item.share_addr}"}
                for item in audit.inbounds
            ],
        }
    )
    return manifest


class RendererTests(unittest.TestCase):
    def test_confirmed_trusttunnel_backend_owns_only_its_public_sni(self) -> None:
        from lucx_post_configurator.models import default_manifest
        from lucx_post_configurator.renderers import render_haproxy

        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.test"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.test"
        manifest["certificates"].update({"cert_path": "/etc/ssl/cert.pem", "key_path": "/etc/ssl/key.pem"})
        manifest["network"]["public_bind_address"] = "203.0.113.10"
        manifest["components"].update({"trusttunnel_backend": True, "extended_tls_split": True})
        manifest["trusttunnel_backend"].update({
            "user_confirmed": True,
            "listen_port": 26444,
            "public_domain": "tt.example.test",
            "binary_path": "/opt/trusttunnel/trusttunnel_endpoint",
            "sha256": "0" * 64,
            "credentials": [{"username": "probe", "password": "secret"}],
        })
        manifest["decoys"]["enabled"] = True
        manifest["decoys"]["extended_user_confirmed"] = True
        manifest["decoys"]["routing_mode"] = "extended"
        manifest["decoys"]["sites"].append({"domain": "tt.example.test", "root": "/var/www/lucx-decoys/tt.example.test"})
        manifest["protocols"] = [{
            "inbound_id": 9,
            "protocol": "trusttunnel",
            "domain": "tt.example.test",
            "public_port": 443,
            "internal_host": "127.0.0.1",
            "internal_port": 9443,
            "exposure": "tcp_sni",
            "network": "tcp",
            "security": "tls",
            "sni_names": ["tt.example.test"],
            "clienthello_match_fingerprint": "sha256:0123456789ab",
        }]
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        rendered = render_haproxy(manifest, routing_material={9: {"clienthello_hex_prefix": "A1B2C3D4"}})
        self.assertIn("be_trusttunnel_compatible", rendered)
        self.assertIn("127.0.0.1:26444", rendered)
        self.assertNotIn("be_inbound_9", rendered)
    def _extended_manifest(self) -> dict:
        manifest = default_manifest()
        manifest["lucx"]["panel"].update(
            {"domain": "panel.example.net", "internal_host": "127.0.0.1", "internal_port": 2083}
        )
        manifest["lucx"]["subscription"].update(
            {"domain": "sub.example.net", "internal_host": "127.0.0.1", "internal_port": 2096}
        )
        manifest["certificates"].update(
            {"cert_path": "/cert/fullchain.pem", "key_path": "/cert/privkey.pem"}
        )
        manifest["decoys"].update(
            {
                "enabled": True,
                "routing_mode": "extended",
                "extended_user_confirmed": True,
                "listen_host": "127.0.0.1",
                "listen_port": 8444,
                "sites": [
                    {"domain": "upgrade.example.net", "root": "/var/www/lucx-decoys/upgrade.example.net"},
                    {"domain": "binary.example.net", "root": "/var/www/lucx-decoys/binary.example.net"},
                    {"domain": "trust.example.net", "root": "/var/www/lucx-decoys/trust.example.net"},
                ],
            }
        )
        manifest["components"]["extended_tls_split"] = True
        manifest["protocols"] = [
            {
                "inbound_id": 11,
                "protocol": "vmess",
                "remark": "Upgrade",
                "domain": "upgrade.example.net",
                "internal_host": "127.0.0.1",
                "internal_port": 58111,
                "public_port": 443,
                "network": "tcp",
                "exposure": "tcp_sni",
                "security": "tls",
                "transport": "httpupgrade",
                "transport_path": "/connection",
                "transport_hosts": ["upgrade.example.net"],
                "alpn": ["h2", "http/1.1"],
                "sni_names": ["upgrade.example.net"],
                "port_bindings": [{"port": 58111, "protocol": "TCP"}],
            },
            {
                "inbound_id": 12,
                "protocol": "anytls",
                "remark": "Binary",
                "domain": "binary.example.net",
                "internal_host": "127.0.0.1",
                "internal_port": 18443,
                "public_port": 443,
                "network": "tcp",
                "exposure": "tcp_sni",
                "security": "tls",
                "transport": "tcp",
                "sni_names": ["binary.example.net"],
                "port_bindings": [{"port": 18443, "protocol": "TCP"}],
            },
            {
                "inbound_id": 13,
                "protocol": "trusttunnel",
                "remark": "Trust",
                "domain": "trust.example.net",
                "internal_host": "127.0.0.1",
                "internal_port": 19443,
                "public_port": 443,
                "network": "tcp",
                "exposure": "tcp_sni",
                "security": "tls",
                "transport": "tcp",
                "sni_names": ["trust.example.net"],
                "port_bindings": [{"port": 19443, "protocol": "TCP"}],
                "clienthello_match_fingerprint": "sha256:0123456789ab",
            },
        ]
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        return manifest

    def test_extended_haproxy_has_outer_sni_and_loopback_tls_split(self) -> None:
        manifest = self._extended_manifest()

        rendered = render_haproxy(
            manifest,
            routing_material={13: {"clienthello_hex_prefix": "A1B2C3D4"}},
        )

        self.assertIn("frontend lucx_tls_443", rendered)
        self.assertIn("bind *:443", rendered)
        self.assertNotIn("bind *:443 ssl", rendered)
        self.assertRegex(rendered, r"use_backend be_split_11 if sni_[^ ]+")
        self.assertRegex(rendered, r"use_backend be_split_12 if sni_[^ ]+")
        self.assertIn("frontend lucx_split_11", rendered)
        self.assertIn("frontend lucx_split_12", rendered)
        self.assertIn(
            "ssl crt /etc/lucx-post-configurator/tls/certificate.pem alpn h2,http/1.1",
            rendered,
        )
        self.assertIn("acl is_http2 req.payload(0,24),hex -m str 505249202A20485454502F322E300D0A0D0A534D0D0A0D0A", rendered)
        self.assertIn("server local 127.0.0.1:18443 ssl verify required ca-file /etc/ssl/certs/ca-certificates.crt verifyhost binary.example.net sni str(binary.example.net)", rendered)

    def test_extended_haproxy_known_sni_reject_is_bounded_for_many_names(self) -> None:
        manifest = self._extended_manifest()
        route = next(
            item
            for item in manifest["decoys"]["extended_routes"]
            if item["strategy"] == "http_tls_split"
        )
        sni_list = [route["domain"], *(f"sni-{index}.example.net" for index in range(70))]
        route["sni_names"] = sni_list
        protocol = next(
            item
            for item in manifest["protocols"]
            if item["inbound_id"] == route["inbound_id"]
        )
        protocol["sni_names"] = sni_list
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)

        rendered = render_haproxy(
            manifest,
            routing_material={13: {"clienthello_hex_prefix": "A1B2C3D4"}},
        )

        known_sni_lines = [
            line
            for line in rendered.splitlines()
            if line.startswith("    acl known_sni_443 req.ssl_sni -i ")
        ]
        self.assertGreaterEqual(len(known_sni_lines), 70)
        self.assertIn(
            "    tcp-request content reject if is_tls !known_sni_443",
            rendered,
        )
        self.assertTrue(
            all(
                len(line.split()) < 64
                for line in rendered.splitlines()
                if line.startswith("    tcp-request content reject")
            )
        )

    def test_extended_haproxy_unknown_sni_action_decoy(self) -> None:
        manifest = self._extended_manifest()
        manifest["network"]["unknown_sni_action"] = "decoy"
        manifest["decoys"]["default_server"] = True
        rendered = render_haproxy(
            manifest,
            routing_material={13: {"clienthello_hex_prefix": "A1B2C3D4"}},
        )
        self.assertNotIn("    tcp-request content reject if is_tls !known_sni_443", rendered)
        self.assertIn("    default_backend be_decoy_tls", rendered)

    def test_strict_haproxy_known_sni_reject_is_bounded_for_many_names(self) -> None:
        manifest = self._extended_manifest()
        manifest["decoys"]["routing_mode"] = "strict"
        manifest["protocols"][0]["sni_names"] = [
            f"strict-sni-{index}.example.net" for index in range(70)
        ]

        rendered = render_haproxy(manifest)

        known_sni_lines = [
            line
            for line in rendered.splitlines()
            if line.startswith("    acl known_sni_443 req.ssl_sni -i ")
        ]
        self.assertGreaterEqual(len(known_sni_lines), 70)
        self.assertIn(
            "    tcp-request content reject if is_tls !known_sni_443",
            rendered,
        )

    def test_extended_http_transport_routes_by_path_and_host_after_tls(self) -> None:
        manifest = self._extended_manifest()

        rendered = render_haproxy(
            manifest,
            routing_material={13: {"clienthello_hex_prefix": "A1B2C3D4"}},
        )

        start = rendered.index("frontend lucx_split_11")
        end = rendered.index("frontend lucx_split_12")
        frontend = rendered[start:end]
        self.assertIn("acl protocol_path_11 path /connection", frontend)
        self.assertIn("acl protocol_host_11 hdr(host) -i upgrade.example.net", frontend)
        self.assertIn(
            "acl protocol_connection_11 hdr(Connection) -m reg -i (^|,)[[:space:]]*upgrade[[:space:]]*(,|$)",
            frontend,
        )
        self.assertIn("acl protocol_upgrade_11 hdr(Upgrade) -i websocket", frontend)
        self.assertIn(
            "use_backend be_http_reencrypt_11 if { var(sess.vpn_upgrade) -m bool }",
            frontend,
        )
        self.assertIn("default_backend be_decoy_h2c_http", frontend)
        self.assertRegex(
            rendered,
            r"backend be_http_reencrypt_11\n    mode tcp\n    server local 127\.0\.0\.1:58111 ssl verify required",
        )

    def test_extended_xhttp_routes_only_dedicated_path_and_leaves_root_to_decoy(self) -> None:
        manifest = self._extended_manifest()
        xhttp = manifest["protocols"][0]
        xhttp.update(
            {
                "transport": "xhttp",
                "transport_path": "/private-xhttp",
                "transport_hosts": ["upgrade.example.net"],
                "transport_mode": "stream-one",
            }
        )
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)

        rendered = render_haproxy(
            manifest,
            routing_material={13: {"clienthello_hex_prefix": "A1B2C3D4"}},
        )

        start = rendered.index("frontend lucx_split_11")
        end = rendered.index("frontend lucx_split_12")
        frontend = rendered[start:end]
        self.assertIn("acl protocol_path_11 path /private-xhttp", frontend)
        self.assertIn("acl protocol_path_11 path_beg /private-xhttp/", frontend)
        self.assertNotIn("path_beg /private-xhttp\n", frontend)
        self.assertIn(
            "use_backend be_http_reencrypt_11 if protocol_path_11 protocol_host_11",
            frontend,
        )
        self.assertNotIn("protocol_connection_11", frontend)
        self.assertNotIn("protocol_upgrade_11", frontend)
        self.assertIn("default_backend be_decoy_h2c_http", frontend)

    def test_extended_trusttunnel_match_is_masked_and_precedes_browser_sni(self) -> None:
        manifest = self._extended_manifest()

        rendered = render_haproxy(
            manifest,
            routing_material={13: {"clienthello_hex_prefix": "A1B2C3D4"}},
        )

        self.assertIn(
            "acl trust_clienthello_13 req.payload(11,4),hex -m str -i A1B2C3D4",
            rendered,
        )

    def test_binary_tls_split_uses_exact_http_prefixes_before_reencrypting(self) -> None:
        rendered = render_haproxy(
            self._extended_manifest(),
            routing_material={13: {"clienthello_hex_prefix": "A1B2C3D4"}},
        )

        start = rendered.index("frontend lucx_split_12")
        frontend = rendered[start : rendered.index("frontend lucx_split_13", start)] if "frontend lucx_split_13" in rendered[start:] else rendered[start:]
        self.assertIn(
            "acl is_http1 req.payload(0,16),hex -m beg 47455420",
            frontend,
        )
        self.assertIn(
            "acl is_http1 req.payload(0,16),hex -m beg 4845414420",
            frontend,
        )
        self.assertNotIn("req.payload(0,16),hex -m reg", frontend)
        self.assertIn("tcp-request content accept if is_http1", frontend)
        trust_rule = rendered.index("use_backend be_inbound_13 if trust_clienthello_13")
        site_rule = rendered.index("use_backend be_split_13 if sni_443_", rendered.index("trust.example.net"))
        self.assertLess(trust_rule, site_rule)
        self.assertIn("frontend lucx_split_13", rendered)
        self.assertIn("use_backend be_trusttunnel_13 if is_connect or is_proxy_auth", rendered)
        self.assertIn("backend be_trusttunnel_13", rendered)

    def test_extended_renderer_refuses_trusttunnel_without_ephemeral_matcher(self) -> None:
        with self.assertRaisesRegex(ValueError, "routing material"):
            render_haproxy(self._extended_manifest())

    def test_extended_renderer_rejects_ambiguous_duplicate_endpoint_sni(self) -> None:
        manifest = self._extended_manifest()
        duplicate = dict(manifest["protocols"][1], inbound_id=99, internal_port=19999)
        manifest["protocols"].append(duplicate)
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)

        with self.assertRaisesRegex(ValueError, "conflicting extended SNI"):
            render_haproxy(
                manifest,
                routing_material={13: {"clienthello_hex_prefix": "A1B2C3D4"}},
            )

    def test_extended_files_reference_selected_tls_pair_with_managed_symlinks(self) -> None:
        manifest = self._extended_manifest()
        manifest["protocols"] = [
            item for item in manifest["protocols"] if item["protocol"] != "trusttunnel"
        ]
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)

        files = render_files(manifest, resolver="resolvconf")

        cert = files["/etc/lucx-post-configurator/tls/certificate.pem"]
        key = files["/etc/lucx-post-configurator/tls/certificate.pem.key"]
        self.assertEqual(cert.symlink_target, "/cert/fullchain.pem")
        self.assertEqual(key.symlink_target, "/cert/privkey.pem")
        self.assertEqual(cert.content, b"")
        self.assertEqual(key.content, b"")

    def test_extended_nginx_has_loopback_tls_and_cleartext_http2_decoys(self) -> None:
        manifest = self._extended_manifest()

        rendered = render_nginx_decoys(manifest)

        self.assertIn("listen 127.0.0.1:8444 ssl http2;", rendered)
        self.assertIn("listen 127.0.0.1:8445 http2;", rendered)
        self.assertNotIn("listen 443", rendered)
        for domain in ("upgrade.example.net", "binary.example.net", "trust.example.net"):
            self.assertIn(f"server_name {domain};", rendered)
            self.assertIn(f'add_header X-LucX-Decoy "{domain}" always;', rendered)
        h2c_line = next(line for line in rendered.splitlines() if ":8445" in line)
        self.assertNotIn("ssl", h2c_line)

    def test_managed_naive_frontend_is_generated_from_ephemeral_source_only(self) -> None:
        source = """{
 admin off
 skip_install_trust
 auto_https off
 servers {
  protocols h1 h2
 }
}
:47863, naive.example.net:47863 {
 bind 127.0.0.1
 tls /old/cert.pem /old/key.pem
 route {
  forward_proxy {
   basic_auth test-user test-pass
   hide_ip
   hide_via
  }
 }
}
"""
        import hashlib

        manifest = self._extended_manifest()
        manifest["components"]["naive_frontend"] = True
        manifest["protocols"] = [
            {
                "inbound_id": 7,
                "protocol": "naive",
                "remark": "Naive",
                "domain": "naive.example.net",
                "internal_host": "127.0.0.1",
                "internal_port": 47863,
                "public_port": 443,
                "network": "tcp",
                "exposure": "tcp_sni",
                "security": "tls",
                "transport": "tcp",
                "sni_names": ["naive.example.net"],
                "port_bindings": [{"port": 47863, "protocol": "TCP"}],
            }
        ]
        manifest["decoys"]["sites"] = [
            {"domain": "naive.example.net", "root": "/var/www/lucx-decoys/naive.example.net"}
        ]
        routes = classify_extended_decoy_routes(
            manifest,
            Audit(
                naive_caddyfile={
                    "binary_path": "/usr/local/x-ui/bin/caddy-naive-linux-amd64",
                    "files": [
                        {
                            "path": "/usr/local/x-ui/bin/tunnel/naive-7.caddyfile",
                            "sha256": hashlib.sha256(source.encode()).hexdigest(),
                            "capabilities": {"forward_proxy": True, "native_decoy": False},
                        }
                    ],
                }
            ),
        )
        routes[0]["managed_listen_port"] = 26443
        manifest["decoys"]["extended_routes"] = routes

        files = render_files(
            manifest,
            resolver="resolvconf",
            routing_material={7: {"naive_caddyfile_text": source}},
        )

        config_path = "/etc/lucx-post-configurator/naive/naive-7.caddyfile"
        unit_path = "/etc/systemd/system/lucx-naive-decoy-7.service"
        self.assertIn(config_path, files)
        self.assertIn(unit_path, files)
        self.assertEqual(files[config_path].mode, 0o600)
        self.assertIn(b"basic_auth \"test-user\" \"test-pass\"", files[config_path].content)
        self.assertNotIn("/usr/local/x-ui/bin/tunnel/naive-7.caddyfile", files)
        haproxy = files["/etc/haproxy/haproxy.cfg"].content.decode()
        self.assertIn(
            "backend be_naive_frontend_7\n    mode tcp\n    server local 127.0.0.1:26443",
            haproxy,
        )

        with self.assertRaisesRegex(ValueError, "changed after planning"):
            render_files(
                manifest,
                resolver="resolvconf",
                routing_material={7: {"naive_caddyfile_text": source + "\n# drift"}},
            )

    def test_logrotate_bounds_lucx_and_optional_sidecar_logs(self) -> None:
        rendered = render_logrotate()
        self.assertIn("/var/log/x-ui/*.log", rendered)
        self.assertIn("/var/log/lucx-sub-sidecar/*.log", rendered)
        self.assertIn("maxsize 10M", rendered)
        self.assertIn("maxsize 5M", rendered)
        self.assertIn("maxage 30", rendered)

    def test_sidecar_receives_manifest_database_path_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = fixture_manifest(root)
            manifest["components"]["sidecar"] = True
            manifest["sidecar"]["user_confirmed"] = True
            manifest["sidecar"]["allowed_hosts"] = ["sub.example.com"]
            manifest["lucx"]["db_path"] = "/srv/lucx/custom-x-ui.db"

            files = render_files(manifest, resolver="resolvconf")
            environment = files["/etc/lucx-sub-sidecar/env"].content.decode()

            self.assertIn('XUI_DB="/srv/lucx/custom-x-ui.db"\n', environment)

    def test_capability_matrix_routes_only_managed_domains_to_decoy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = fixture_manifest(root)
            manifest["decoys"]["sites"] = [
                {"domain": "free.example.com", "root": "/var/www/lucx-decoys/free.example.com"},
                {"domain": "owned.example.com", "root": "/var/www/lucx-decoys/owned.example.com"},
            ]
            manifest["decoys"]["capabilities"] = [
                {
                    "domain": "free.example.com",
                    "status": "direct_tcp_decoy",
                    "managed": True,
                    "protocol_ids": [1],
                    "evidence": [],
                    "reason": "free",
                    "probe_mode": "active",
                },
                {
                    "domain": "owned.example.com",
                    "status": "blocked_sni_collision",
                    "managed": False,
                    "protocol_ids": [2],
                    "evidence": [],
                    "reason": "owned",
                    "probe_mode": "passive",
                },
            ]

            rendered = render_haproxy(manifest)

            free_acl = re.search(r"acl (\S+) req\.ssl_sni -i free\.example\.com", rendered)
            self.assertIsNotNone(free_acl)
            self.assertIn(f"use_backend be_decoy if {free_acl.group(1)}", rendered)
            self.assertNotRegex(rendered, r"req\.ssl_sni -i owned\.example\.com")
            self.assertIn("X-LucX-Decoy", render_nginx_decoys(manifest))

    def test_endpoint_domains_free_on_tcp_443_are_routed_to_decoy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = fixture_manifest(root)
            reality = manifest["protocols"][0]
            reality["domain"] = "test2.example.test"
            reality["sni_names"] = ["www.microsoft.com"]
            awg = next(item for item in manifest["protocols"] if item["protocol"] == "awg")
            awg["domain"] = "test6.example.test"
            manifest["decoys"]["sites"] = [
                {"domain": "test2.example.test", "root": "/var/www/lucx-decoys/test2.example.test"},
                {"domain": "test6.example.test", "root": "/var/www/lucx-decoys/test6.example.test"},
            ]
            rendered = render_haproxy(manifest)
            for domain in ("test2.example.test", "test6.example.test"):
                match = re.search(rf"acl (\S+) req\.ssl_sni -i {re.escape(domain)}", rendered)
                self.assertIsNotNone(match)
                self.assertIn(f"use_backend be_decoy if {match.group(1)}", rendered)
            camouflage = re.search(
                r"acl (\S+) req\.ssl_sni -i www\.microsoft\.com", rendered
            )
            self.assertIsNotNone(camouflage)
            self.assertIn(
                f"use_backend be_inbound_1 if {camouflage.group(1)}", rendered
            )

    def test_panel_and_subscription_can_use_different_cloudflare_ports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = default_manifest(audit_system(root))
            manifest["lucx"]["panel"]["public_port"] = 2083
            manifest["lucx"]["subscription"]["public_port"] = 2096
            rendered = render_haproxy(manifest)
            self.assertIn("frontend lucx_tls_2083", rendered)
            self.assertIn("frontend lucx_tls_2096", rendered)

    def test_no_default_server_or_caddy_target_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = fixture_manifest(root)
            validate_manifest(manifest)
            nginx = render_nginx_decoys(manifest)
            self.assertNotIn("default_server", nginx)
            haproxy = render_haproxy(manifest)
            self.assertIn("api.example.com", haproxy)
            self.assertIn("be_inbound_1", haproxy)
            self.assertIn("use_backend be_inbound_1 if !is_tls", haproxy)
            files = render_files(manifest, resolver="resolvconf")
            self.assertFalse(any("Caddyfile" in path for path in files))
            self.assertEqual(
                files["/etc/resolvconf/resolv.conf.d/head"].content.decode().splitlines()[1:],
                ["nameserver 9.9.9.9", "nameserver 77.88.8.8", "nameserver 45.90.28.147"],
            )

    def test_default_server_requires_explicit_unknown_sni_decoy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = fixture_manifest(root)
            manifest["network"]["unknown_sni_action"] = "decoy"
            manifest["decoys"]["default_server"] = True
            validate_manifest(manifest)
            self.assertIn("ssl default_server", render_nginx_decoys(manifest))

    def test_strict_firewall_preserves_ssh_and_discovered_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = fixture_manifest(root)
            manifest["firewall"]["mode"] = "strict_allowlist"
            manifest["network"]["ssh_ports"] = [49283, 2222]
            rendered = render_nftables(manifest)
            self.assertIn("policy drop", rendered)
            self.assertIn("49283", rendered)
            self.assertIn("2222", rendered)
            self.assertIn("27015-27035", rendered)
            self.assertIn("56001", rendered)

    def test_shared_tcp_and_direct_udp_inbound_keeps_udp_public_port(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = fixture_manifest(root)
            protocol = manifest["protocols"][0]
            protocol["network"] = "both"
            protocol["exposure"] = "tcp_sni"
            protocol["udp_public_port"] = protocol["internal_port"]
            manifest["firewall"]["mode"] = "strict_allowlist"
            rendered = render_nftables(manifest)
            self.assertRegex(rendered, r"udp dport \{[^}]*54703")

    def test_protect_internal_blocks_ready_trusttunnel_listener_on_tcp_and_udp(self) -> None:
        manifest = self._extended_manifest()
        trust = next(
            item for item in manifest["protocols"] if item["protocol"] == "trusttunnel"
        )
        trust["network"] = "both"
        trust["port_bindings"] = [{"port": 19443, "protocol": "TCP_UDP"}]

        rendered = render_nftables(manifest)

        self.assertIn(
            'iifname != "lo" tcp dport { 19443 } counter drop comment "TrustTunnel internal TCP"',
            rendered,
        )
        self.assertIn(
            'iifname != "lo" udp dport { 19443 } counter drop comment "TrustTunnel internal UDP"',
            rendered,
        )
        self.assertNotIn("18443 } counter drop comment \"TrustTunnel", rendered)

    def test_trusttunnel_listener_is_not_blocked_without_ready_shared_443_route(self) -> None:
        manifest = self._extended_manifest()
        route = next(
            item
            for item in manifest["decoys"]["extended_routes"]
            if item["protocol"] == "trusttunnel"
        )
        route["status"] = "blocked"
        route["managed"] = False

        rendered = render_nftables(manifest)

        self.assertNotIn("TrustTunnel internal TCP", rendered)
        self.assertNotIn("TrustTunnel internal UDP", rendered)

    def test_strict_firewall_does_not_allow_ready_trusttunnel_internal_udp(self) -> None:
        manifest = self._extended_manifest()
        trust = next(
            item for item in manifest["protocols"] if item["protocol"] == "trusttunnel"
        )
        trust["network"] = "both"
        trust["port_bindings"] = [{"port": 19443, "protocol": "TCP_UDP"}]
        manifest["firewall"]["mode"] = "strict_allowlist"

        rendered = render_nftables(manifest)

        udp_line = next(
            line for line in rendered.splitlines() if 'comment "LucX public UDP"' in line
        )
        self.assertNotIn("19443", udp_line)
        self.assertRegex(rendered, r"tcp dport \{[^}]*443")

    def test_dns_replaces_nameservers_but_preserves_search_and_options(self) -> None:
        rendered = render_resolvconf(
            ["9.9.9.9", "77.88.8.8"],
            "search internal.example\nnameserver 1.1.1.1\noptions timeout:2\n",
        )
        self.assertNotIn("1.1.1.1", rendered)
        self.assertIn("search internal.example", rendered)
        self.assertIn("options timeout:2", rendered)

    def test_cloudflare_acl_protects_only_panel_and_subscription_sni(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            manifest = fixture_manifest(root)
            manifest["cloudflare"].update(
                {
                    "enabled": True,
                    "user_confirmed": True,
                    "networks": {
                        "ipv4": ["8.8.8.0/24"],
                        "ipv6": ["2606:4700::/32"],
                    },
                }
            )
            with mock.patch.dict(cloudflare.MINIMUM_COUNTS, {4: 1, 6: 1}):
                validate_manifest(manifest)
                rendered = render_haproxy(manifest)
                acl = render_cloudflare_acl(manifest)
                nftables = render_nftables(manifest)
            self.assertIn("acl from_cloudflare src -f /etc/haproxy/cloudflare-ips.lst", rendered)
            self.assertIn("acl from_local_health src", rendered)
            self.assertIn("be_panel", rendered)
            self.assertIn("!from_cloudflare", rendered)
            self.assertIn("8.8.8.0/24", acl)
            self.assertIn("2606:4700::/32", acl)
            self.assertIn("set cloudflare4", nftables)
            self.assertIn("set cloudflare6", nftables)
            self.assertIn("@cloudflare4", nftables)
            self.assertIn("@cloudflare6", nftables)

    def test_cloudflare_refresh_unit_allows_nftables_netlink_validation(self) -> None:
        rendered = render_cloudflare_update_unit()
        self.assertIn(
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
            rendered,
        )
        self.assertIn("ProtectHome=read-only", rendered)
        self.assertNotIn("ProtectHome=yes", rendered)


if __name__ == "__main__":
    unittest.main()
