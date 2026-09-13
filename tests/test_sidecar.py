from __future__ import annotations

import base64
import importlib.util
import json
import sqlite3
import tempfile
import unittest
import urllib.parse
import uuid
from pathlib import Path
from unittest import mock


ASSET = Path(__file__).parents[1] / "src/lucx_post_configurator/assets/lucx_sub_sidecar.py"
SPEC = importlib.util.spec_from_file_location("test_lucx_sub_sidecar", ASSET)
assert SPEC and SPEC.loader
sidecar = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sidecar)

AWG_CONF = """[Interface]
PrivateKey = AbC+/private-value=
Address = 10.0.0.2/32
MTU = 1420
Jc = 4
Jmin = 10
Jmax = 50
S1 = 12
H1 = 1234

[Peer]
PublicKey = DeF+/public-value=
PresharedKey = GhI+/preshared-value=
Endpoint = awg.example.com:8443
PersistentKeepalive = 25
"""


class SidecarTests(unittest.TestCase):
    def test_throne_congestion_control_never_publishes_a_quic_profile(self) -> None:
        # Throne 1.2.4 включает QUIC по наличию ключа, даже с пустым значением.
        prefix = 'tt://test-user:test-pass@vpn.example.test:443?alpn=h2'
        for suffix in ('&congestion_control', '&congestion_control=', '&congestion_control=bbr',
                       '&congestion_control=false', '&congestion_control=0',
                       '&%63ongestion_control=bbr', '&CONGESTION_CONTROL=bbr'):
            uri = prefix + suffix
            with self.subTest(suffix=suffix):
                self.assertFalse(sidecar.is_trusttunnel_https_profile(uri))
                self.assertFalse(sidecar.is_throne_trusttunnel_https_uri(uri))
                for user_agent in ('Throne/1.2.4', 'NekoBox', 'sing-box', ''):
                    self.assertEqual(sidecar.rewrite_subscription(uri + '\n', user_agent,
                        '/sub/synthetic', 'sub.example.test', snapshot=[]), '')
                    structured = json.dumps({'proxies': [{'type': 'trusttunnel', 'url': uri}]})
                    self.assertEqual(json.loads(sidecar.rewrite_structured_subscription(
                        structured, user_agent))['proxies'], [])

    def test_trusttunnel_query_case_alias_cannot_erase_an_unsafe_value(self) -> None:
        for query in ('alpn=h3&ALPN=h2', 'alpn=h2&quic=true&QUIC=false',
                      'alpn=h2&upstream_protocol=quic&UPSTREAM_PROTOCOL=https'):
            uri = 'tt://test-user:test-pass@vpn.example.test:443?' + query
            with self.subTest(query=query):
                self.assertFalse(sidecar.is_trusttunnel_https_profile(uri))
                self.assertFalse(sidecar.is_throne_trusttunnel_https_uri(uri))

    def test_trusttunnel_subscription_keeps_only_tcp_https_profile(self) -> None:
        source = (
            "tt://?AAECAwQ#official-quic\n"
            "tt://user:pass@example.com:443?security=tls&sni=example.com&alpn=h3#quic\n"
            "tt://user:pass@example.com:443?security=tls&sni=example.com&alpn=h2#https\n"
            "qwdtt://opaque#never-published\n"
        )

        rewritten = sidecar.rewrite_subscription(
            source,
            "NekoBox",
            "/sub/client-id",
            "sub.example.com",
            snapshot=[],
        )

        self.assertEqual(
            rewritten,
            "tt://user:pass@example.com:443?security=tls&sni=example.com&alpn=h2#https\n",
        )

    def test_trusttunnel_quic_is_removed_for_every_client_user_agent(self) -> None:
        source = (
            "tt://user:pass@example.com:443?alpn=h2#https\n"
            "tt://user:pass@example.com:443?alpn=h3#quic-alpn\n"
            "tt://user:pass@example.com:443?quic=true#quic-flag\n"
            "tt://user:pass@example.com:443?upstream_protocol=quic#quic-upstream\n"
            "qwdtt://opaque#never-published\n"
        )
        expected = "tt://user:pass@example.com:443?alpn=h2#https\n"
        for user_agent in ("NekoBox", "Throne", "sing-box", "Clash", "Mihomo", "", "future-client"):
            with self.subTest(user_agent=user_agent):
                self.assertEqual(
                    sidecar.rewrite_subscription(
                        source,
                        user_agent,
                        "/sub/client-id",
                        "sub.example.com",
                        snapshot=[],
                    ),
                    expected,
                )

    def test_trusttunnel_quic_is_removed_from_json_for_every_client(self) -> None:
        source = json.dumps(
            {
                "proxies": [
                    {"type": "trusttunnel", "url": "tt://example?alpn=h2"},
                    {"type": "trusttunnel", "url": "tt://example?quic=true"},
                    {"type": "vless", "url": "vless://opaque"},
                ]
            }
        )
        for user_agent in ("NekoBox", "Throne", "sing-box", "Clash", "Mihomo"):
            with self.subTest(user_agent=user_agent):
                rewritten = sidecar.rewrite_structured_subscription(source, user_agent)
                value = json.loads(rewritten)
                self.assertEqual(len(value["proxies"]), 2)
                self.assertEqual(value["proxies"][0]["url"], "tt://example?alpn=h2")
                self.assertEqual(value["proxies"][1]["type"], "vless")

    def test_anytls_uses_enabled_host_public_port_without_changing_name_or_credentials(self) -> None:
        source = (
            "anytls://p%40ss:test@test9.example.test:18443/"
            "?sni=test9.example.test&insecure=0#test10\n"
        )
        snapshot = [
            {
                "inbound_id": 10,
                "protocol": "anytls",
                "internal_port": 18443,
                "host": "test9.example.test",
                "public_port": 443,
            }
        ]
        expected = source.replace("test9.example.test:18443", "test9.example.test:443")
        for user_agent in ("Throne/1.0", "NekoBox", "sing-box"):
            with self.subTest(user_agent=user_agent):
                self.assertEqual(
                    sidecar.rewrite_subscription(
                        source,
                        user_agent,
                        "/sub/client-id",
                        "sub.example.com",
                        snapshot=snapshot,
                    ),
                    expected,
                )
        self.assertTrue(expected.endswith("#test10\n"))
        self.assertIn("p%40ss:test@", expected)

    def test_anytls_lucx_bracketed_authority_is_normalized_and_republished(self) -> None:
        source = (
            "anytls://p%40ss@[test9.example.test:443]:18443/"
            "?sni=test9.example.test#test10\n"
        )
        snapshot = [
            {
                "inbound_id": 10,
                "protocol": "anytls",
                "internal_port": 18443,
                "host": "test9.example.test",
                "public_port": 443,
            }
        ]
        for user_agent in ("Throne/1.0", "NekoBox", "sing-box"):
            with self.subTest(user_agent=user_agent):
                rewritten = sidecar.rewrite_subscription(
                    source,
                    user_agent,
                    "/sub/client-id",
                    "sub.example.com",
                    snapshot=snapshot,
                )
                self.assertIn("anytls://p%40ss@test9.example.test:443/", rewritten)
                self.assertNotIn("[test9", rewritten)
                self.assertNotIn("]:18443", rewritten)
                self.assertTrue(rewritten.endswith("#test10\n"))

    def test_anytls_public_endpoint_snapshot_reads_only_enabled_host_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "x-ui.db"
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE inbounds (id INTEGER PRIMARY KEY, protocol TEXT, port INTEGER, enable INTEGER, settings TEXT, share_addr TEXT)"
            )
            connection.execute(
                "CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER)"
            )
            connection.execute(
                "INSERT INTO inbounds VALUES (10,'anytls',18443,1,'','legacy.example.com')"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (20,10,0,0,'test9.example.test',443)"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (21,10,1,1,'disabled.example.com',8443)"
            )
            connection.commit()
            connection.close()
            with mock.patch.object(sidecar, "DB_PATH", str(database)):
                self.assertEqual(
                    sidecar.load_public_endpoint_snapshot(),
                    [
                        {
                            "inbound_id": 10,
                            "protocol": "anytls",
                            "internal_port": 18443,
                            "host": "test9.example.test",
                            "public_port": 443,
                            "passwords": [],
                            "sni": "test9.example.test",
                        }
                    ],
                )

    def test_reported_connection_names_and_transport_values_are_preserved(self) -> None:
        source = (
            "amneziawg://opaque#test6-testovik%20awg-testovi\n"
            "mierus://example.com:20100?profile=test8-testovi&"
            "traffic-pattern=CO%2FD%2FvIFGgQIARAUIgQIARABKgUIgAEQQDIECAMQBA%3D%3D"
            "#test8-testovi\n"
        )

        with mock.patch.object(sidecar, "fetch_awg_conf", return_value=AWG_CONF):
            rewritten = sidecar.rewrite_subscription(
                source,
                "Throne/1.0",
                "/sub/client-id",
                "sub.example.com",
            )

        awg, mieru = rewritten.splitlines()
        self.assertTrue(awg.endswith("#test6-testovik%20awg-testovi"))
        self.assertIn("local_address=10.0.0.2/32", awg)
        self.assertNotIn("10.0.0.2%2F32/32", awg)
        self.assertNotIn("awg-testovi%20AWG", awg)
        self.assertIn("profile=test8-testovi", mieru)
        self.assertTrue(mieru.endswith("#test8-testovi"))
        self.assertIn(
            "traffic-pattern=CO/D/vIFGgQIARAUIgQIARABKgUIgAEQQDIECAMQBA==",
            mieru,
        )
        self.assertNotIn("CO%2FD%2F", mieru)

    def test_non_anytls_lines_for_non_throne_clients_lose_only_qwdtt(self) -> None:
        text = (
            "amneziawg://opaque#Original%20AWG\r\n"
            "vpn://opaque-envelope\r\n"
            "naive+https://user:pass@example.com:7443#Original\r\n"
            "mierus://example.com:20100?profile=Original&traffic-pattern=CO%2FD%2FvIFGgQIARAUIgQIARABKgUIgAEQQDIECAMQBA%3D%3D#Original\r\n"
            "qwdtt://AbC-_/opaque?x=1#Name\r\n"
        )
        expected = (
            "amneziawg://opaque#Original%20AWG\r\n"
            "vpn://opaque-envelope\r\n"
            "naive+https://user:pass@example.com:7443#Original\r\n"
            "mierus://example.com:20100?profile=Original&traffic-pattern=CO%2FD%2FvIFGgQIARAUIgQIARABKgUIgAEQQDIECAMQBA%3D%3D#Original\r\n"
        )
        self.assertEqual(
            sidecar.rewrite_subscription(text, "NekoBox", "/sub/id", "sub.example.com"),
            expected,
        )
        self.assertEqual(
            sidecar.rewrite_subscription(text, "Mihomo", "/sub/id", "sub.example.com"),
            expected,
        )

    def test_throne_rewrites_only_native_awg_and_preserves_original_name(self) -> None:
        original_awg = "amneziawg://opaque#Original%20AWG"
        untouched = [
            "vpn://opaque-envelope",
            "naive+https://user:pass@example.com:7443#Original",
        ]
        mieru = (
            "mierus://example.com:20100?profile=Original&"
            "traffic-pattern=CO%2FD%2FvIFGgQIARAUIgQIARABKgUIgAEQQDIECAMQBA%3D%3D#Original"
        )
        text = "\r\n".join([original_awg, *untouched, mieru]) + "\r\n"
        with mock.patch.object(sidecar, "fetch_awg_conf", return_value=AWG_CONF):
            rewritten = sidecar.rewrite_subscription(
                text, "Throne/1.0", "/sub/client-id", "sub.example.com"
            )
        lines = rewritten.splitlines()
        self.assertTrue(lines[0].startswith("wg://awg.example.com:8443?"))
        self.assertTrue(lines[0].endswith("#Original%20AWG"))
        self.assertEqual(lines[1 : 1 + len(untouched)], untouched)
        self.assertEqual(
            lines[-1],
            "mierus://example.com:20100?profile=Original&"
            "traffic-pattern=CO/D/vIFGgQIARAUIgQIARABKgUIgAEQQDIECAMQBA==#Original",
        )
        raw_query = urllib.parse.urlsplit(lines[0]).query
        self.assertIn("local_address=10.0.0.2/32", raw_query)
        self.assertNotIn("%2F", raw_query.upper())
        self.assertNotIn("%2B", raw_query.upper())
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(lines[0]).query)
        self.assertEqual(query["enable_amnezia"], ["true"])
        self.assertIn("private_key", query)
        self.assertIn("public_key", query)
        self.assertIn("jc", query)

    def test_universal_clients_rewrite_native_awg(self) -> None:
        text = "amneziawg://opaque#My%20AWG\r\nvpn://envelope\r\n"
        with mock.patch.object(sidecar, "fetch_awg_conf", return_value=AWG_CONF):
            for client_ua in ["NekoBox/1.2.3", "Happ/2.0", "v2rayN/6.0", "", "Mozilla/5.0"]:
                rewritten = sidecar.rewrite_subscription(
                    text, client_ua, "/sub/client-id", "sub.example.com"
                )
                lines = rewritten.splitlines()
                self.assertTrue(
                    lines[0].startswith("wg://awg.example.com:8443?"),
                    f"Failed for UA: {client_ua}"
                )
                self.assertTrue(lines[0].endswith("#My%20AWG"))
                self.assertEqual(lines[1], "vpn://envelope")

    def test_throne_fails_open_when_awg_conf_is_unavailable(self) -> None:
        text = "amneziawg://opaque#Original\n"
        with mock.patch.object(sidecar, "fetch_awg_conf", return_value=None):
            self.assertEqual(
                sidecar.rewrite_subscription(
                    text, "Throne", "/sub/client-id", "sub.example.com"
                ),
                text,
            )

    def test_throne_repairs_mieru_traffic_pattern_without_awg(self) -> None:
        source = (
            "mierus://user:pass@example.com?profile=Keep%20Name&"
            "traffic-pattern=CO%2FD%2FvIFGgQIARAUIgQIARABKgUIgAEQQDIECAMQBA%3D%3D"
            "#Keep%20Name\n"
        )
        expected = source.replace(
            "CO%2FD%2FvIFGgQIARAUIgQIARABKgUIgAEQQDIECAMQBA%3D%3D",
            "CO/D/vIFGgQIARAUIgQIARABKgUIgAEQQDIECAMQBA==",
        )
        with mock.patch.object(sidecar, "fetch_awg_conf", return_value=None):
            self.assertEqual(
                sidecar.rewrite_subscription(
                    source, "Throne", "/sub/client-id", "sub.example.com"
                ),
                expected,
            )

    def test_clash_yaml_is_not_treated_as_base64_subscription(self) -> None:
        yaml = b"proxies:\n  - {name: test, type: wireguard}\nproxy-groups:\n"
        self.assertIsNone(sidecar.decode_subscription(yaml))

    def test_subscription_id_uses_configured_path_prefix(self) -> None:
        previous = sidecar.ALLOWED_PATH_PREFIXES
        sidecar.ALLOWED_PATH_PREFIXES = ("/custom-sub/", "/clash/", "/awg/")
        try:
            self.assertEqual(
                sidecar.extract_sub_id("/custom-sub/client-id?format=base64"),
                "client-id",
            )
            self.assertTrue(sidecar.request_path_allowed("/clash/client-id"))
            self.assertTrue(sidecar.request_path_allowed("/awg/client-id?format=conf"))
        finally:
            sidecar.ALLOWED_PATH_PREFIXES = previous

    # ------------------------------------------------------------------
    # LucX TrustTunnel deep-link (tt://?<base64url TLV>) handling.
    # LucX emits TLV links for NekoBox+ (official clients) while Throne
    # understands only tt://user:pass@host:port URIs.
    # ------------------------------------------------------------------

    def _tlv(self, tag: int, value: bytes) -> bytes:
        def varint(v: int) -> bytes:
            if v < 1 << 6:
                return bytes([v])
            if v < 1 << 14:
                return bytes([v >> 8 | 0x40, v])
            return bytes([v >> 24 | 0x80, v >> 16 & 0xFF, v >> 8 & 0xFF, v & 0xFF])

        return bytes([tag]) + varint(len(value)) + value

    def _tlv_link(self, *, quic: bool = False, prefix: bool = True) -> str:
        payload = self._tlv(0x00, bytes([1]))
        payload += self._tlv(0x01, b"test8.example.test")
        payload += self._tlv(0x02, b"test8.example.test:443")
        payload += self._tlv(0x04, bytes([0]))
        payload += self._tlv(0x05, b"testuser")
        payload += self._tlv(0x06, b"testpass")
        if prefix:
            payload += self._tlv(0x0B, b"7cb2c420/ffffffff")
        if quic:
            payload += self._tlv(0x09, bytes([2]))
        payload += self._tlv(0x0C, b"test9")
        encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        return "tt://?" + encoded

    def test_lucx_tlv_https_link_is_converted_to_throne_uri_for_throne(self) -> None:
        link = self._tlv_link(quic=False)
        rewritten = sidecar.rewrite_subscription(
            link + "\n", "Throne", "/sub/client-id", "sub.example.test", snapshot=[]
        )
        self.assertTrue(
            rewritten.startswith("tt://testuser:testpass@test8.example.test:443?"),
            rewritten,
        )
        self.assertIn("security=tls", rewritten)
        self.assertIn("sni=test8.example.test", rewritten)
        self.assertIn("alpn=h2", rewritten)
        self.assertIn("client_random_prefix=7cb2c420/ffffffff", rewritten)
        self.assertTrue(rewritten.rstrip("\n").endswith("#test9"))

    def test_lucx_tlv_quic_link_is_removed_for_every_client(self) -> None:
        link = self._tlv_link(quic=True)
        for user_agent in ("NekoBox", "Throne", "sing-box", "Mihomo", ""):
            with self.subTest(user_agent=user_agent):
                rewritten = sidecar.rewrite_subscription(
                    link + "\n", user_agent, "/sub/client-id", "sub.example.test",
                    snapshot=[],
                )
                self.assertEqual(rewritten, "")

    def test_throne_uri_form_keeps_only_http2_trusttunnel(self) -> None:
        source = (
            "tt://user:pass@example.test:443?security=tls&alpn=h2#https\n"
            "tt://user:pass@example.test:443?security=tls&alpn=h3#quic\n"
        )
        rewritten = sidecar.rewrite_subscription(
            source, "Throne", "/sub/client-id", "sub.example.test", snapshot=[]
        )
        self.assertIn("alpn=h2", rewritten)
        self.assertNotIn("alpn=h3", rewritten)
        self.assertNotIn("#quic", rewritten)

    def test_lucx_tlv_link_with_unsupported_version_is_dropped(self) -> None:
        payload = self._tlv(0x00, bytes([2]))
        payload += self._tlv(0x02, b"example.test:443")
        encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        rewritten = sidecar.rewrite_subscription(
            "tt://?" + encoded + "\n", "NekoBox", "/sub/c", "sub.example.test",
            snapshot=[],
        )
        self.assertEqual(rewritten, "")

    def test_tlv_parser_fails_open_on_garbage_payload(self) -> None:
        for payload in ("", "!!!!!", "AAAA"):
            with self.subTest(payload=payload):
                rewritten = sidecar.rewrite_subscription(
                    "tt://?" + payload + "#x\n", "NekoBox", "/sub/c",
                    "sub.example.test", snapshot=[],
                )
                self.assertEqual(rewritten, "")

    def test_lucx_tlv_link_is_converted_for_throne_only_uri_form(self) -> None:
        # NekoBox+ (official client) understands TLV directly: keep byte-for-byte.
        link = self._tlv_link(quic=False) + "\n"
        self.assertEqual(
            sidecar.rewrite_subscription(
                link, "NekoBox", "/sub/c", "sub.example.test", snapshot=[]
            ),
            link,
        )

    def test_qwdtt_is_never_published_in_subscriptions(self) -> None:
        source = "qwdtt://opaque#removed\nvless://keep-me#vless\n"
        for user_agent in ("NekoBox", "Throne", "sing-box", "Clash", "Mihomo", ""):
            with self.subTest(user_agent=user_agent):
                rewritten = sidecar.rewrite_subscription(
                    source, user_agent, "/sub/c", "sub.example.test", snapshot=[]
                )
                self.assertNotIn("qwdtt://", rewritten)
                self.assertNotIn("wdtt://", rewritten)
                self.assertIn("vless://keep-me#vless", rewritten)

    def test_qwdtt_removed_from_structured_subscription(self) -> None:
        source = json.dumps(
            {
                "proxies": [
                    {"type": "qwdtt", "url": "qwdtt://opaque"},
                    {"type": "vless", "url": "vless://opaque"},
                ]
            }
        )
        rewritten = sidecar.rewrite_structured_subscription(source, "Throne")
        value = json.loads(rewritten)
        self.assertEqual(len(value["proxies"]), 1)
        self.assertEqual(value["proxies"][0]["type"], "vless")

    # ------------------------------------------------------------------
    # AnyTLS injection into Clash YAML (LucX clash generator drops anytls).
    # ------------------------------------------------------------------

    def test_anytls_is_injected_into_clash_yaml(self) -> None:
        yaml = (
            "proxies:\n"
            "  - {name: vless-1, type: vless, server: a.example.test, port: 443}\n"
            "proxy-groups:\n"
            "  - name: PROXY\n"
            "    type: select\n"
            "    proxies:\n"
            "      - vless-1\n"
            "      - DIRECT\n"
        )
        snapshot = [
            {
                "inbound_id": 10,
                "protocol": "anytls",
                "internal_port": 18443,
                "host": "test9.example.test",
                "public_port": 443,
                "passwords": ["s3cret-pass"],
                "sni": "test9.example.test",
            }
        ]
        injected = sidecar.inject_anytls_into_clash_yaml(yaml, snapshot)
        self.assertIn("type: anytls", injected)
        self.assertIn("server: test9.example.test", injected)
        self.assertIn("port: 443", injected)
        self.assertIn("password: s3cret-pass", injected)
        self.assertIn("test-anytls-test9.example.test", injected)
        # group list got the new name and DIRECT still last
        self.assertIn("- test-anytls-test9.example.test\n  - DIRECT", injected)

    def test_anytls_injection_fails_open_without_passwords(self) -> None:
        yaml = "proxies:\n  - {name: vless-1}\nproxy-groups:\n"
        snapshot = [
            {
                "inbound_id": 10,
                "protocol": "anytls",
                "internal_port": 18443,
                "host": "test9.example.test",
                "public_port": 443,
                "passwords": [],
            }
        ]
        self.assertEqual(
            sidecar.inject_anytls_into_clash_yaml(yaml, snapshot), yaml
        )

    def test_yaml_scalar_quotes_special_values(self) -> None:
        self.assertEqual(sidecar.yaml_scalar("plain-Pass_1"), "plain-Pass_1")
        self.assertEqual(sidecar.yaml_scalar("with space"), "'with space'")
        self.assertEqual(sidecar.yaml_scalar("q'uote"), "'q''uote'")

    def test_snapshot_includes_anytls_client_passwords(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "x-ui.db"
            connection = sqlite3.connect(str(database))
            connection.executescript(
                """
                CREATE TABLE inbounds (
                    id INTEGER PRIMARY KEY, protocol TEXT, port INTEGER,
                    enable INTEGER, settings TEXT, share_addr TEXT
                );
                CREATE TABLE hosts (
                    id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER,
                    is_disabled INTEGER, address TEXT, port INTEGER
                );
                """
            )
            connection.execute(
                "INSERT INTO inbounds VALUES (10, 'anytls', 18443, 1, "
                "?, 'legacy.example.test')",
                (json.dumps({"clients": [{"password": "db-pass"}]}),),
            )
            connection.execute(
                "INSERT INTO hosts VALUES (20,10,0,0,'test9.example.test',443)"
            )
            connection.commit()
            connection.close()
            with mock.patch.object(sidecar, "DB_PATH", str(database)):
                snapshot = sidecar.load_public_endpoint_snapshot()
            self.assertEqual(len(snapshot), 1)
            self.assertEqual(snapshot[0]["passwords"], ["db-pass"])
            self.assertEqual(snapshot[0]["host"], "test9.example.test")
            self.assertEqual(snapshot[0]["public_port"], 443)

    def test_snapshot_includes_mieru_port_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "x-ui.db"
            connection = sqlite3.connect(str(database))
            connection.executescript(
                """
                CREATE TABLE inbounds (
                    id INTEGER PRIMARY KEY, protocol TEXT, port INTEGER,
                    enable INTEGER, settings TEXT, share_addr TEXT
                );
                CREATE TABLE hosts (
                    id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER,
                    is_disabled INTEGER, address TEXT, port INTEGER
                );
                """
            )
            connection.execute(
                "INSERT INTO inbounds VALUES (8, 'mieru', 20100, 1, ?, ?)",
                (
                    json.dumps(
                        {
                            "portBindings": [
                                {"portRange": "20100-20200", "protocol": "TCP"}
                            ]
                        }
                    ),
                    "test7.example.test:20100",
                ),
            )
            connection.execute(
                "INSERT INTO hosts VALUES (24,8,0,0,'test7.example.test',20100)"
            )
            connection.commit()
            connection.close()
            with mock.patch.object(sidecar, "DB_PATH", str(database)):
                snapshot = sidecar.load_public_endpoint_snapshot()
            self.assertEqual(len(snapshot), 1)
            self.assertEqual(snapshot[0]["protocol"], "mieru")
            self.assertEqual(snapshot[0]["port_range"], "20100-20200")

    def test_mieru_port_range_is_restored_for_every_client(self) -> None:
        link = (
            "mierus://user@test7.example.test?profile=test8&mtu=1400"
            "&port=20100&protocol=TCP&traffic-pattern=QUJD#test8"
        )
        snapshot = [
            {
                "inbound_id": 8,
                "protocol": "mieru",
                "host": "test7.example.test",
                "public_port": 20100,
                "port_range": "20100-20200",
            }
        ]
        updated = sidecar.rewrite_mieru_port_range(link, snapshot)
        self.assertIn("port=20100-20200", updated)
        self.assertNotIn("port=20100&", updated)
        self.assertIn("traffic-pattern=QUJD", updated)
        # Throne path also gets the range plus the existing traffic-pattern fix
        throne = sidecar.rewrite_subscription(
            link + "\n", "Throne", "/sub/x", "sub.example.test", snapshot=snapshot
        )
        self.assertIn("port=20100-20200", throne)
        # Non-Throne clients keep the escaping of other params untouched
        neko = sidecar.rewrite_subscription(
            link + "\n", "NekoBox", "/sub/x", "sub.example.test", snapshot=snapshot
        )
        self.assertIn("port=20100-20200", neko)

    def test_mieru_port_range_ignored_without_match(self) -> None:
        link = "mierus://user@other.example.test?profile=x&port=20100#x"
        snapshot = [
            {
                "inbound_id": 8,
                "protocol": "mieru",
                "host": "test7.example.test",
                "port_range": "20100-20200",
            }
        ]
        self.assertEqual(
            sidecar.rewrite_mieru_port_range(link, snapshot), link
        )

    def test_identical_throne_lines_are_deduplicated(self) -> None:
        def _varint(value: int) -> bytes:
            return bytes([value])

        def _field(tag: int, value: bytes) -> bytes:
            return bytes([tag]) + _varint(len(value)) + value

        payload = (
            _field(0x00, b"\x01")
            + _field(0x01, b"example.com")
            + _field(0x02, b"example.com:443")
            + _field(0x05, b"user")
            + _field(0x06, b"pass")
            + _field(0x0B, b"7cb2c420/ffffffff")
        )
        tlv_link = (
            "tt://?"
            + base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
            + "#test9"
        )
        uri_form = (
            "tt://user:pass@example.com:443"
            "?security=tls&sni=example.com&alpn=h2&client_random_prefix=7cb2c420%2Fffffffff"
            "#test9"
        )
        source = uri_form + "\n" + tlv_link + "\nvmess://first\nvmess://first\n"
        self.assertIsNotNone(sidecar.decode_trusttunnel_deeplink(tlv_link))
        with mock.patch.object(
            sidecar, "build_trusttunnel_throne_uri", return_value=uri_form
        ):
            rewritten = sidecar.rewrite_subscription(
                source,
                "Throne",
                "/sub/client-id",
                "sub.example.com",
                snapshot=[],
            )
        lines = rewritten.splitlines()
        self.assertEqual(lines.count(uri_form), 1)
        self.assertEqual(lines.count("vmess://first"), 1)
        self.assertEqual(len(lines), 2)


class ThroneVmessGrpcTests(unittest.TestCase):
    @staticmethod
    def profile(**changes: object) -> dict[str, object]:
        # Форма закреплённого LucX genVmessLink/buildEndpointVmessLinks.
        value: dict[str, object] = {
            "v": "2", "add": "public.example.test", "port": 8443,
            "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "vmess-synthetic.example.test")).upper(),
            "scy": "auto", "net": "grpc", "type": "none", "authority": "",
            "path": "Vpn.Service_v2", "tls": "tls", "alpn": "h2",
            "sni": "Tls.example.test", "ps": "Профиль + / ? # %",
        }
        value.update(changes)
        return value

    @staticmethod
    def link(value: object) -> str:
        raw = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
        return "vmess://" + base64.b64encode(raw).decode("ascii")

    @staticmethod
    def rewrite(text: str, user_agent: str = "Throne/1.2.4") -> str:
        return sidecar.rewrite_subscription(text, user_agent, "/sub/synthetic",
            "sub.example.test", snapshot=[])

    def test_lucx_grpc_json_preserves_credentials_tls_and_unicode_remark(self) -> None:
        for cipher in ("auto", "aes-128-gcm", "chacha20-poly1305"):
            profile = self.profile(scy=cipher)
            original = self.link(profile)
            with self.subTest(cipher=cipher):
                result = self.rewrite(original + "\r\n")
                self.assertNotEqual(result, original + "\r\n")
                self.assertTrue(result.endswith("\r\n"))
                parsed = urllib.parse.urlsplit(result[:-2])
                self.assertEqual(parsed.scheme, "vmess")
                self.assertEqual(parsed.username, profile["id"])
                self.assertIsNone(parsed.password)
                self.assertEqual(parsed.hostname, profile["add"])
                self.assertEqual(parsed.port, profile["port"])
                self.assertEqual(urllib.parse.parse_qs(parsed.query), {
                    "type": ["grpc"], "serviceName": [profile["path"]],
                    "encryption": [cipher], "security": ["tls"],
                    "sni": [profile["sni"]], "alpn": ["h2"],
                })
                self.assertEqual(urllib.parse.unquote(parsed.fragment), profile["ps"])

    def test_lucx_grpc_keeps_final_public_endpoints_before_outer_base64(self) -> None:
        # LucX уже применил Host endpoint к add/port, включая нестандартный порт.
        profiles = [self.profile(add="public.example.test", port=9443, ps="Основной"),
            self.profile(add="2001:db8::9", port=65535, ps="IPv6"),
            self.profile(add="[2001:db8::a]", port=443, ps="IPv6 в скобках")]
        text = "\n".join(self.link(item) for item in profiles)
        snapshot = [{"protocol": "anytls", "host": "public.example.test",
            "internal_port": 9443, "public_port": 443, "passwords": [],
            "sni": "other.example.test"}]
        encoded = sidecar.encode_subscription(text)
        rewritten = sidecar.rewrite_subscription(sidecar.decode_subscription(encoded),
            "Throne/1.2.4", "/sub/synthetic", "sub.example.test", snapshot=snapshot)
        result = sidecar.decode_subscription(sidecar.encode_subscription(rewritten))
        self.assertNotEqual(result, text)
        self.assertFalse(result.endswith("\n"))
        for line, profile in zip(result.splitlines(), profiles, strict=True):
            parsed = urllib.parse.urlsplit(line)
            self.assertEqual(parsed.hostname, str(profile["add"]).strip("[]"))
            self.assertEqual(parsed.port, profile["port"])
            self.assertEqual(parsed.username, profile["id"])
            self.assertEqual(urllib.parse.parse_qs(parsed.query)["sni"], [profile["sni"]])

    def test_lucx_grpc_service_name_survives_qurl_percent_decoding(self) -> None:
        profile = self.profile(path="Vpn.Service+name/part%20?x=y&z=1")
        original = self.link(profile)
        result = self.rewrite(original)
        self.assertNotEqual(result, original)
        query = urllib.parse.urlsplit(result).query
        # QUrl::FullyDecoded не превращает '+' в пробел как HTML form encoding.
        values = {key: urllib.parse.unquote(value) for key, value in
            (part.split("=", 1) for part in query.split("&"))}
        self.assertEqual(values["serviceName"], profile["path"])
        self.assertNotIn("+", query)

    def test_lucx_grpc_unknown_or_complex_options_remain_original(self) -> None:
        cases = [
            {"type": "multi"}, {"authority": "authority.example.test"},
            {"host": "host.example.test"}, {"fm": "opaque"}, {"ech": "opaque"},
            {"pcs": "opaque"}, {"vcn": "peer.example.test"}, {"fp": "chrome"},
            {"flow": "xtls-rprx-vision"}, {"mux": True}, {"unknown": ""},
            {"aid": 0}, {"net": "GRPC"}, {"tls": "TLS"}, {"type": "None"},
            {"v": 2}, {"scy": "none"}, {"scy": "zero"}, {"scy": "unknown"},
            {"alpn": "h2,http/1.1"}, {"alpn": ["h2"]}, {"port": "8443"},
            {"port": True}, {"port": 0}, {"port": 65536}, {"port": 8443.0},
            {"id": "not-a-uuid"}, {"id": None}, {"path": None},
            {"add": "public.example.test/path"}, {"sni": "tls.example.test%20"},
            {"authority": None}, {"host": []},
        ]
        for changes in cases:
            with self.subTest(fields=list(changes)):
                original = self.link(self.profile(**changes)) + "\r\n"
                self.assertEqual(self.rewrite(original), original)

    def test_lucx_grpc_malformed_unknown_forms_do_not_block_next_valid_line(self) -> None:
        valid = self.link(self.profile())
        duplicate = json.dumps(self.profile())[:-1] + ', "path": "other"}'
        unknown = ["vmess://%%%", "vmess://e30", "vmess://" + "A" * 5,
            "VMESS://" + valid[8:], valid + "#external", " " + valid,
            "vmess://" + base64.b64encode(duplicate.encode()).decode(),
            self.link([self.profile()]), self.link({"NET": "grpc"}),
            "vmess://opaque@public.example.test:443?type=grpc&serviceName=service",
            "vmess://" + base64.b64encode(b"auto:synthetic").decode()
            + "@public.example.test:443?type=grpc"]
        for original in unknown:
            with self.subTest(index=unknown.index(original)):
                result = self.rewrite(original + "\n" + valid)
                first, second = result.split("\n")
                self.assertEqual(first, original)
                self.assertNotEqual(second, valid)
                self.assertEqual(urllib.parse.urlsplit(second).username, self.profile()["id"])

    def test_lucx_grpc_other_clients_and_non_grpc_formats_remain_original(self) -> None:
        original = self.link(self.profile()) + "\r\n"
        for user_agent in ("NekoBox", "sing-box", "v2rayN", "Mihomo", "", "future-client"):
            with self.subTest(user_agent=user_agent):
                self.assertEqual(self.rewrite(original, user_agent), original)
        for changes in ({"net": "ws"}, {"net": "httpupgrade"}, {"net": "xhttp"},
                        {"tls": "none"}, {"tls": "reality"}):
            with self.subTest(fields=changes):
                original = self.link(self.profile(**changes))
                self.assertEqual(self.rewrite(original), original)


if __name__ == "__main__":
    unittest.main()
