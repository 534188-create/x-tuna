from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lucx_post_configurator.discovery import audit_system, redacted_audit_dict
from lucx_post_configurator.diagnostics import stable_fingerprint

from helpers import make_target


class TransportProfileDiscoveryTests(unittest.TestCase):
    def test_trusttunnel_sni_comes_from_hostname_not_public_address(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            with sqlite3.connect(database) as connection:
                connection.execute("UPDATE inbounds SET protocol='trusttunnel', settings=?, stream_settings='{}', share_addr=? WHERE id=1",
                                   (json.dumps({"hostname": "tls.example.test", "sni": "stale.example.test"}), "public.example.test"))
            connection.close()
            inbound = audit_system(root).inbounds[0]
            self.assertEqual(inbound.server_names, ["tls.example.test"])
            self.assertEqual(inbound.public_endpoints[0]["sni"], "tls.example.test")
            self.assertEqual(inbound.public_endpoints[0]["address"], "public.example.test")

    def test_reality_inherited_sni_set_excludes_other_hosts_explicit_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            names = ["one.example.test", "two.example.test"]
            with sqlite3.connect(database) as connection:
                connection.execute("UPDATE inbounds SET settings=?, stream_settings=? WHERE id=1",
                                   (json.dumps({"sni": "stale.example.test"}),
                                    json.dumps({"security": "reality", "network": "xhttp",
                                                "tlsSettings": {"serverName": "extra.example.test"},
                                                "realitySettings": {"serverNames": names}})))
                connection.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, address TEXT, port INTEGER, is_disabled INTEGER, sni TEXT, override_sni_from_address INTEGER, keep_sni_blank INTEGER)")
                connection.executemany("INSERT INTO hosts VALUES (?,1,?,443,0,?,0,0)", [
                    (1, "public.example.test", ""), (2, "alias.example.test", "override.example.test"),
                ])
            connection.close()
            inbound = audit_system(root).inbounds[0]
            self.assertEqual(len(inbound.public_endpoints), 2)
            self.assertEqual(inbound.public_endpoints[0]["inherited_sni_names"], names)
            self.assertEqual(inbound.public_endpoints[0]["sni_source"], "inherited_set")
            self.assertNotIn("inherited_sni_names", inbound.public_endpoints[1])
            self.assertIn("override.example.test", inbound.server_names)
            self.assertNotIn("stale.example.test", inbound.server_names)
            self.assertNotIn("extra.example.test", inbound.server_names)

    def _audit_stream(self, stream: dict, settings: dict | None = None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "UPDATE inbounds SET stream_settings = ?, settings = ? WHERE id = 1",
                    (json.dumps(stream), json.dumps(settings or {})),
                )
            connection.close()
            return audit_system(root)

    def test_versioned_names_normalize_without_claiming_runtime_support(self) -> None:
        for old, new, canonical, settings_key, network in (
            ("ws", "websocket", "ws", "wsSettings", "tcp"),
            ("kcp", "mkcp", "kcp", "kcpSettings", "udp"),
            ("splithttp", "xhttp", "xhttp", "splithttpSettings", "tcp"),
        ):
            with self.subTest(method=new):
                inbound = self._audit_stream({
                    "network": old, "method": new, "security": "tls",
                    settings_key: {"path": "/vpn", "mode": "packet-up"},
                }).inbounds[0]
                self.assertEqual(inbound.transport, canonical)
                self.assertEqual(inbound.network, network)
                if canonical == "xhttp":
                    self.assertEqual(inbound.transport_path, "/vpn")
                    self.assertEqual(inbound.transport_mode, "packet-up")
                details = getattr(inbound, "transport_details", {})
                self.assertEqual(details.get("support_status"), "unverified")

    def test_unknown_or_conflicting_transport_never_invents_tcp_binding(self) -> None:
        for stream in (
            {"network": "ws", "method": "grpc"},
            {"method": "future-transport"},
        ):
            with self.subTest(stream=stream):
                inbound = self._audit_stream(stream).inbounds[0]
                self.assertEqual(inbound.network, "unknown")
                self.assertEqual(inbound.port_bindings, [])
                self.assertTrue(inbound.transport_details["requires_adapter_review"])

    def test_direct_xhttp_h3_uses_udp_only_for_effective_tls_h3(self) -> None:
        for security, alpn, expected in (
            ("tls", ["h3"], "udp"),
            ("tls", ["h2", "h3"], "tcp"),
            ("tls", ["h2"], "tcp"),
            ("none", ["h3"], "tcp"),
        ):
            with self.subTest(security=security, alpn=alpn):
                inbound = self._audit_stream({
                    "method": "xhttp", "security": security,
                    "tlsSettings": {"alpn": alpn}, "xhttpSettings": {"path": "/vpn"},
                }).inbounds[0]
                self.assertEqual(inbound.network, expected)
                self.assertEqual(inbound.port_bindings, [{"port": 54703, "protocol": expected.upper()}])

    def test_unknown_stream_extension_is_not_an_approved_plain_tls_route(self) -> None:
        inbound = self._audit_stream({
            "network": "ws", "security": "tls", "wsSettings": {"path": "/vpn"},
            "futureEnvelope": {"credential": "hidden-envelope-value"},
        }).inbounds[0]
        self.assertTrue(inbound.transport_details["requires_adapter_review"])
        self.assertNotIn("hidden-envelope-value", json.dumps(inbound.as_dict()))

    def test_empty_finalmask_does_not_claim_an_active_mask(self) -> None:
        inbound = self._audit_stream({
            "network": "ws", "security": "tls", "wsSettings": {"path": "/vpn"},
            "finalmask": {"tcp": [], "udp": [], "quicParams": {}},
        }).inbounds[0]
        self.assertFalse(inbound.transport_details["masks"]["present"])
        self.assertFalse(inbound.transport_details["requires_adapter_review"])

    def test_transport_hysteria_and_native_udp_are_not_legacy_tcp(self) -> None:
        inbound = self._audit_stream({"method": "hysteria", "security": "tls"}).inbounds[0]
        self.assertEqual(inbound.network, "udp")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            with sqlite3.connect(database) as connection:
                connection.execute("UPDATE inbounds SET stream_settings = ? WHERE id = 2", (json.dumps({"network": "tcp"}),))
            connection.close()
            native = next(item for item in audit_system(root).inbounds if item.id == 2)
            self.assertEqual(native.network, "udp")

    def test_l4_conflict_is_unknown_except_documented_native_shadowsocks_udp(self) -> None:
        inbound = self._audit_stream({"method": "quic"}, {"network": "tcp"}).inbounds[0]
        self.assertEqual(inbound.network, "unknown")
        self.assertEqual(inbound.port_bindings, [])

    def test_metadata_fingerprints_extras_masks_and_download_without_values_of_secrets(self) -> None:
        stream = {
            "method": "xhttp", "security": "tls", "tlsSettings": {"alpn": ["h2"]},
            "xhttpSettings": {
                "path": "/vpn", "mode": "stream-up",
                "headers": {"Authorization": "hidden-auth-value"},
                "extra": {
                    "futureOption": "hidden-extra-value",
                    "downloadSettings": {
                        "address": "download.example.test", "port": 8443,
                        "network": "xhttp", "security": "tls", "tlsSettings": {"alpn": ["h3"]},
                        "xhttpSettings": {"path": "/download", "host": "authority.example.test", "mode": "packet-up"},
                        "password": "hidden-download-value",
                    },
                },
            },
            "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "hidden-mask-value"}}]},
        }
        first = self._audit_stream(stream).inbounds[0]
        details = getattr(first, "transport_details", {})
        self.assertIn("settings_fingerprint", details)
        self.assertTrue(details["requires_adapter_review"])
        self.assertEqual(details["masks"]["udp_types"], ["salamander"])
        self.assertEqual(details["download"]["address"], "download.example.test")
        self.assertEqual(details["download"]["port"], 8443)
        self.assertEqual(details["download"]["network"], "udp")
        self.assertEqual(details["download"]["transport_path"], "/download")
        serialized = json.dumps(first.as_dict())
        for secret in ("hidden-auth-value", "hidden-extra-value", "hidden-download-value", "hidden-mask-value"):
            self.assertNotIn(secret, serialized)
        stream["xhttpSettings"]["extra"]["futureOption"] = "changed-extra-value"
        changed = self._audit_stream(stream).inbounds[0]
        self.assertNotEqual(details["settings_fingerprint"], changed.transport_details["settings_fingerprint"])
        stream["finalmask"]["udp"][0]["settings"]["password"] = "changed-mask-value"
        mask_changed = self._audit_stream(stream).inbounds[0]
        self.assertNotEqual(details["masks"]["fingerprint"], mask_changed.transport_details["masks"]["fingerprint"])

    def test_all_enabled_hosts_keep_endpoint_sni_authority_and_port_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER, sni TEXT, override_sni_from_address INTEGER, keep_sni_blank INTEGER, host TEXT)")
                connection.executemany("INSERT INTO hosts VALUES (?,?,?,?,?,?,?,?,?,?)", [
                    (12, 1, 2, 0, "second.example.test", 8443, "tls.example.test", 0, 0, "http.example.test"),
                    (11, 1, 1, 0, "first.example.test", 443, "ignored.example.test", 1, 0, ""),
                    (13, 1, 3, 0, "blank.example.test", 9443, "hidden.example.test", 0, 1, ""),
                    (14, 1, 4, 1, "disabled.example.test", 443, "", 0, 0, ""),
                    (15, 1, 5, 0, "", 0, "", 0, 0, ""),
                ])
            connection.close()
            inbound = audit_system(root).inbounds[0]
            endpoints = getattr(inbound, "public_endpoints", [])
            self.assertEqual([item["host_id"] for item in endpoints], [11, 12, 13, 15])
            self.assertEqual(inbound.share_addr, "first.example.test")
            self.assertEqual(inbound.suggested_public_port, 443)
            self.assertEqual(endpoints[0]["sni"], "first.example.test")
            self.assertEqual(endpoints[0]["sni_source"], "address")
            self.assertEqual(endpoints[1]["sni"], "tls.example.test")
            self.assertEqual(endpoints[1]["http_host"], "http.example.test")
            self.assertEqual(endpoints[1]["port"], 8443)
            self.assertEqual(endpoints[2]["sni"], "")
            self.assertEqual(endpoints[2]["sni_source"], "blank")
            self.assertFalse(endpoints[3]["valid"])
            self.assertEqual(inbound.port, 54703)

    def test_legacy_endpoint_is_retained_when_hosts_table_is_absent(self) -> None:
        inbound = self._audit_stream({"network": "ws", "security": "tls", "tlsSettings": {"serverName": "tls.example.test"}}).inbounds[0]
        endpoints = getattr(inbound, "public_endpoints", [])
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["host_id"], 0)
        self.assertEqual(endpoints[0]["address"], inbound.share_addr)
        self.assertEqual(endpoints[0]["sni"], "tls.example.test")
        self.assertEqual(endpoints[0]["sni_source"], "inherited")


class DiscoveryTests(unittest.TestCase):
    def test_share_address_port_is_public_while_listener_port_remains_internal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            connection.execute(
                "UPDATE inbounds SET share_addr = 'api.example.com:443' WHERE id = 1"
            )
            connection.commit()
            connection.close()
            inbound = audit_system(root).inbounds[0]
            self.assertEqual(inbound.share_addr, "api.example.com")
            self.assertEqual(inbound.port, 54703)
            self.assertEqual(inbound.suggested_public_port, 443)

    def test_enabled_host_endpoint_has_subscription_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER)"
            )
            connection.execute(
                "INSERT INTO hosts(id,inbound_id,sort_order,is_disabled,address,port) VALUES (10,1,0,0,'host.example.com',8443)"
            )
            connection.execute(
                "UPDATE inbounds SET share_addr = 'legacy.example.com:443' WHERE id = 1"
            )
            connection.commit()
            connection.close()

            inbound = audit_system(root).inbounds[0]
            self.assertEqual(inbound.share_addr, "host.example.com")
            self.assertEqual(inbound.suggested_public_port, 8443)
            self.assertEqual(inbound.port, 54703)

    def test_host_sni_override_is_discovered_without_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER, sni TEXT, override_sni_from_address INTEGER, keep_sni_blank INTEGER)"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (10,1,0,0,'edge.example.com',443,'ignored.example.com',1,0)"
            )
            connection.commit()
            connection.close()

            inbound = audit_system(root).inbounds[0]
            self.assertIn("edge.example.com", inbound.server_names)
            self.assertNotIn("ignored.example.com", inbound.server_names)

    def test_reads_only_safe_metadata_and_all_protocol_ports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            audit = audit_system(root)
            self.assertTrue(audit.supported_os)
            self.assertTrue(audit.db_schema_supported)
            self.assertEqual(audit.ssh_ports, [49283])
            self.assertEqual(len(audit.inbounds), 5)
            payload = json.dumps(redacted_audit_dict(audit))
            self.assertNotIn("must-not-leak", payload)
            mieru = next(item for item in audit.inbounds if item.protocol == "mieru")
            self.assertEqual(mieru.port_bindings, [{"port_range": "27015-27035", "protocol": "TCP"}])
            qwdtt = next(item for item in audit.inbounds if item.protocol == "qwdtt")
            self.assertIn({"port": 56001, "protocol": "UDP"}, qwdtt.port_bindings)
            self.assertIn({"port": 56003, "protocol": "UDP"}, qwdtt.port_bindings)

    def test_unknown_newer_protocol_is_discovered_without_a_fixed_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        99,
                        "trusttunnel",
                        "Trust Tunnel",
                        1,
                        "127.0.0.1",
                        9443,
                        json.dumps(
                            {
                                "domain": "trust.example.com",
                                "clientRandomPrefix": "deadbeef/ffffffff",
                            }
                        ),
                        json.dumps({"network": "tcp", "security": "tls"}),
                        "trust.example.com",
                        "custom",
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            audit = audit_system(root)
            trust = next(item for item in audit.inbounds if item.id == 99)
            self.assertEqual(trust.protocol, "trusttunnel")
            self.assertEqual(trust.network, "tcp")
            self.assertEqual(trust.security, "tls")
            self.assertEqual(
                trust.clienthello_match_fingerprint,
                stable_fingerprint("deadbeef/ffffffff"),
            )
            self.assertNotIn("deadbeef", json.dumps(redacted_audit_dict(audit)))

    def test_discovers_transport_tls_and_shadowsocks_capabilities_without_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.executemany(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            61,
                            "shadowsocks",
                            "SS 2022",
                            1,
                            "127.0.0.1",
                            36133,
                            json.dumps(
                                {
                                    "method": "2022-blake3-aes-256-gcm",
                                    "network": "tcp,udp",
                                    "password": "must-not-leak",
                                }
                            ),
                            json.dumps(
                                {
                                    "network": "tcp",
                                    "security": "tls",
                                    "tlsSettings": {
                                        "serverName": "ss.edge.example.net",
                                        "alpn": ["h2", "http/1.1"],
                                    },
                                }
                            ),
                            "ss.edge.example.net:443",
                            "custom",
                        ),
                        (
                            62,
                            "vmess",
                            "HTTP upgrade",
                            1,
                            "127.0.0.1",
                            58111,
                            "{}",
                            json.dumps(
                                {
                                    "network": "httpupgrade",
                                    "security": "tls",
                                    "httpupgradeSettings": {
                                        "path": "/transport-path",
                                        "host": "upgrade.edge.example.net",
                                    },
                                    "tlsSettings": {"alpn": "h2,http/1.1"},
                                }
                            ),
                            "upgrade.edge.example.net:443",
                            "custom",
                        ),
                    ],
                )
                connection.commit()
            finally:
                connection.close()

            audit = audit_system(root)
            shadowsocks = next(item for item in audit.inbounds if item.id == 61)
            self.assertEqual(shadowsocks.network, "both")
            self.assertEqual(shadowsocks.transport, "tcp")
            self.assertTrue(shadowsocks.shadowsocks_2022)
            self.assertFalse(shadowsocks.udp_over_tcp)
            self.assertEqual(shadowsocks.alpn, ["h2", "http/1.1"])
            self.assertEqual(
                shadowsocks.port_bindings,
                [
                    {"port": 36133, "protocol": "TCP"},
                    {"port": 36133, "protocol": "UDP"},
                ],
            )

            upgrade = next(item for item in audit.inbounds if item.id == 62)
            self.assertEqual(upgrade.network, "tcp")
            self.assertEqual(upgrade.transport, "httpupgrade")
            self.assertEqual(upgrade.transport_path, "/transport-path")
            self.assertEqual(upgrade.transport_hosts, ["upgrade.edge.example.net"])
            self.assertEqual(upgrade.alpn, ["h2", "http/1.1"])

            payload = json.dumps(redacted_audit_dict(audit))
            self.assertNotIn("must-not-leak", payload)

    def test_discovers_udp_over_tcp_without_assuming_a_protocol_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        63,
                        "future-protocol",
                        "Future transport",
                        1,
                        "127.0.0.1",
                        30443,
                        json.dumps({"udpOverTcp": True}),
                        json.dumps(
                            {
                                "network": "xhttp",
                                "security": "tls",
                                "xhttpSettings": {
                                    "path": "/private-xhttp",
                                    "host": "future.edge.example.net",
                                    "mode": "packet-up",
                                },
                            }
                        ),
                        "future.edge.example.net:443",
                        "custom",
                    ),
                )
                connection.commit()
            finally:
                connection.close()

            inbound = next(item for item in audit_system(root).inbounds if item.id == 63)
            self.assertEqual(inbound.transport, "xhttp")
            self.assertEqual(inbound.transport_path, "/private-xhttp")
            self.assertEqual(inbound.transport_hosts, ["future.edge.example.net"])
            self.assertEqual(inbound.transport_mode, "packet-up")
            self.assertTrue(inbound.udp_over_tcp)

    def test_discovers_udp_l4_for_kcp_and_quic_transports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.executemany(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            64,
                            "vless",
                            "KCP transport",
                            1,
                            "127.0.0.1",
                            30444,
                            "{}",
                            json.dumps({"network": "kcp", "security": "none"}),
                            "kcp.edge.example.net:30444",
                            "custom",
                        ),
                        (
                            65,
                            "vmess",
                            "Legacy QUIC transport",
                            1,
                            "127.0.0.1",
                            30445,
                            "{}",
                            json.dumps({"network": "quic", "security": "none"}),
                            "quic.edge.example.net:30445",
                            "custom",
                        ),
                    ],
                )
                connection.commit()
            finally:
                connection.close()

            discovered = {item.id: item for item in audit_system(root).inbounds}

            self.assertEqual(discovered[64].transport, "kcp")
            self.assertEqual(discovered[64].network, "udp")
            self.assertEqual(discovered[65].transport, "quic")
            self.assertEqual(discovered[65].network, "udp")

    def test_all_global_ssh_ports_are_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            dropins = root / "etc/ssh/sshd_config.d"
            dropins.mkdir(parents=True)
            (dropins / "additional.conf").write_text("Port 2222\n", encoding="utf-8")
            self.assertEqual(audit_system(root).ssh_ports, [49283, 2222])

    def test_discovers_every_lucx_generated_naive_caddyfile_without_editing_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.executemany(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [
                        (7, "naive", "Naive A", 1, "", 47863, "{}", "{}", "a.example.com", "custom"),
                        (12, "naive", "Naive B", 1, "", 47864, "{}", "{}", "b.example.com", "custom"),
                    ],
                )
                connection.commit()
            finally:
                connection.close()
            tunnel = root / "usr/local/x-ui/bin/tunnel"
            tunnel.mkdir(parents=True)
            (tunnel / "naive-7.caddyfile").write_text("a.example.com {}\n", encoding="utf-8")
            (tunnel / "naive-12.caddyfile").write_text("b.example.com {}\n", encoding="utf-8")

            audit = audit_system(root)

            self.assertTrue(audit.naive_caddyfile["found"])
            self.assertEqual(
                [item["path"] for item in audit.naive_caddyfile["files"]],
                [
                    "/usr/local/x-ui/bin/tunnel/naive-7.caddyfile",
                    "/usr/local/x-ui/bin/tunnel/naive-12.caddyfile",
                ],
            )
            self.assertTrue(all("sha256" in item for item in audit.naive_caddyfile["files"]))
            self.assertFalse(any("not located" in warning for warning in audit.warnings))

    def test_naive_caddy_capabilities_are_detected_without_exposing_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (7, "naive", "Naive", 1, "127.0.0.1", 47863, "{}", "{}", "naive.example.net", "custom"),
                )
                connection.commit()
            finally:
                connection.close()
            tunnel = root / "usr/local/x-ui/bin/tunnel"
            tunnel.mkdir(parents=True)
            (tunnel / "naive-7.caddyfile").write_text(
                "naive.example.net {\n  route {\n    forward_proxy {\n      basic_auth hidden secret\n    }\n  }\n  file_server\n}\n",
                encoding="utf-8",
            )
            binary = root / "usr/local/x-ui/bin/caddy-naive-linux-amd64"
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(b"binary-placeholder")
            binary.chmod(0o755)

            caddy = audit_system(root).naive_caddyfile

            self.assertTrue(caddy["files"][0]["capabilities"]["forward_proxy"])
            self.assertTrue(caddy["files"][0]["capabilities"]["file_server"])
            self.assertTrue(caddy["files"][0]["capabilities"]["native_decoy"])
            self.assertEqual(
                caddy["binary_path"],
                "/usr/local/x-ui/bin/caddy-naive-linux-amd64",
            )
            self.assertNotIn("content", caddy["files"][0])
            self.assertNotIn("secret", json.dumps(caddy))


if __name__ == "__main__":
    unittest.main()
