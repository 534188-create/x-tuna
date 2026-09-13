from __future__ import annotations

import unittest

from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
from lucx_post_configurator.models import Audit, default_manifest


def protocol(
    inbound_id: int,
    name: str,
    domain: str,
    *,
    network: str = "tcp",
    security: str = "",
    transport: str = "tcp",
    public_port: int = 443,
    internal_port: int | None = None,
    sni_names: list[str] | None = None,
    port_bindings: list[dict] | None = None,
    **extra: object,
) -> dict:
    result = {
        "inbound_id": inbound_id,
        "protocol": name,
        "remark": f"Endpoint {inbound_id}",
        "domain": domain,
        "internal_host": "127.0.0.1",
        "internal_port": internal_port or 10000 + inbound_id,
        "public_port": public_port,
        "network": network,
        "security": security,
        "transport": transport,
        "transport_path": "",
        "transport_hosts": [],
        "alpn": [],
        "sni_names": list(sni_names or []),
        "port_bindings": list(port_bindings or []),
        "shadowsocks_2022": False,
        "udp_over_tcp": False,
    }
    result.update(extra)
    return result


class ExtendedDecoyStrategyTests(unittest.TestCase):
    def manifest(self, protocols: list[dict]) -> dict:
        manifest = default_manifest()
        manifest["network"]["public_tcp_port"] = 443
        manifest["protocols"] = protocols
        return manifest

    def test_protocol_matrix_uses_observed_topology_not_names_or_order(self) -> None:
        manifest = self.manifest(
            [
                protocol(
                    41,
                    "vless",
                    "reality-endpoint.example.net",
                    security="reality",
                    sni_names=["camouflage.example.org"],
                ),
                protocol(
                    17,
                    "vmess",
                    "upgrade.example.net",
                    security="tls",
                    transport="httpupgrade",
                    sni_names=["upgrade.example.net"],
                    transport_path="/connection",
                    transport_hosts=["upgrade.example.net"],
                ),
                protocol(
                    93,
                    "anytls",
                    "binary.example.net",
                    # LucX AnyTLS is TLS-native even when stream security is
                    # not redundantly reported as "tls".
                    security="",
                    sni_names=["binary.example.net"],
                ),
                protocol(
                    8,
                    "awg",
                    "datagram.example.net",
                    network="udp",
                    public_port=28443,
                    internal_port=28443,
                    port_bindings=[{"port": 28443, "protocol": "UDP"}],
                ),
                protocol(
                    56,
                    "mieru",
                    "separate.example.net",
                    public_port=20100,
                    internal_port=20100,
                    port_bindings=[{"port": 20100, "protocol": "TCP"}],
                ),
            ]
        )

        routes = {
            item["inbound_id"]: item for item in classify_extended_decoy_routes(manifest)
        }

        self.assertEqual(routes[41]["strategy"], "reality_endpoint_site")
        self.assertEqual(routes[17]["strategy"], "http_tls_split")
        self.assertEqual(routes[93]["strategy"], "binary_tls_split")
        self.assertEqual(routes[8]["strategy"], "tcp_side_site")
        self.assertEqual(routes[56]["strategy"], "tcp_side_site")
        self.assertTrue(all(item["status"] == "ready" for item in routes.values()))
        self.assertTrue(routes[17]["tls_termination"])
        self.assertFalse(routes[41]["tls_termination"])
        self.assertEqual(routes[8]["vpn_action"], "unchanged")

    def test_shadowsocks_2022_tls_split_never_claims_a_second_udp_listener(self) -> None:
        manifest = self.manifest(
            [
                protocol(
                    61,
                    "shadowsocks",
                    "ss.example.net",
                    network="both",
                    security="tls",
                    sni_names=["ss.example.net"],
                    internal_port=36133,
                    port_bindings=[
                        {"port": 36133, "protocol": "TCP"},
                        {"port": 36133, "protocol": "UDP"},
                    ],
                    shadowsocks_2022=True,
                )
            ]
        )

        route = classify_extended_decoy_routes(manifest)[0]

        self.assertEqual(route["strategy"], "binary_tls_split")
        self.assertEqual(route["public_tcp_port"], 443)
        self.assertEqual(route["existing_udp_bindings"], [{"port": 36133, "protocol": "UDP"}])
        self.assertEqual(route["managed_udp_bindings"], [])
        self.assertTrue(route["preserves_udp"])

    def test_trusttunnel_requires_a_safe_clienthello_match_fingerprint(self) -> None:
        ready = protocol(
            71,
            "trusttunnel",
            "trust.example.net",
            security="tls",
            sni_names=["trust.example.net"],
            clienthello_match_fingerprint="sha256:0123456789ab",
        )
        blocked = dict(ready, inbound_id=72, domain="unknown-trust.example.net")
        blocked.pop("clienthello_match_fingerprint")

        routes = classify_extended_decoy_routes(self.manifest([ready, blocked]))

        self.assertEqual(routes[0]["strategy"], "trusttunnel_clienthello_split")
        self.assertEqual(routes[0]["status"], "ready")
        self.assertEqual(routes[1]["strategy"], "blocked_unknown")
        self.assertEqual(routes[1]["status"], "blocked")

    def test_naive_selects_native_or_managed_without_editing_original_file(self) -> None:
        manifest = self.manifest(
            [
                protocol(81, "naive", "native.example.net", security="tls"),
                protocol(82, "naive", "managed.example.net", security="tls"),
            ]
        )
        audit = Audit(
            naive_caddyfile={
                "found": True,
                "binary_path": "/usr/local/x-ui/bin/caddy-naive-linux-amd64",
                "files": [
                    {
                        "path": "/usr/local/x-ui/bin/tunnel/naive-81.caddyfile",
                        "sha256": "a" * 64,
                        "capabilities": {"forward_proxy": True, "file_server": True, "native_decoy": True},
                    },
                    {
                        "path": "/usr/local/x-ui/bin/tunnel/naive-82.caddyfile",
                        "sha256": "b" * 64,
                        "capabilities": {"forward_proxy": True, "file_server": False, "native_decoy": False},
                    },
                ],
            }
        )

        routes = classify_extended_decoy_routes(manifest, audit)

        self.assertEqual(routes[0]["strategy"], "naive_native")
        self.assertEqual(routes[0]["naive_mode"], "native")
        self.assertEqual(routes[1]["strategy"], "naive_managed")
        self.assertEqual(routes[1]["naive_mode"], "managed")
        self.assertGreaterEqual(routes[1]["managed_listen_port"], 26443)
        self.assertLessEqual(routes[1]["managed_listen_port"], 65535)
        self.assertTrue(routes[1]["preflight_required"])
        self.assertNotIn("content", routes[0])
        self.assertNotIn("content", routes[1])

    def test_unknown_shared_sni_protocol_is_blocked_instead_of_guessed(self) -> None:
        manifest = self.manifest(
            [
                protocol(
                    91,
                    "future-secure-transport",
                    "future.example.net",
                    security="tls",
                    sni_names=["future.example.net"],
                )
            ]
        )

        route = classify_extended_decoy_routes(manifest)[0]

        self.assertEqual(route["strategy"], "blocked_unknown")
        self.assertEqual(route["status"], "blocked")

    def test_xhttp_with_dedicated_path_routes_vpn_and_keeps_browser_root(self) -> None:
        manifest = self.manifest(
            [
                protocol(
                    18,
                    "vless",
                    "xhttp.example.net",
                    internal_port=18443,
                    security="tls",
                    transport="xhttp",
                    exposure="tcp_sni",
                    sni_names=["xhttp.example.net"],
                    transport_path="/private-xhttp",
                    transport_hosts=["xhttp.example.net"],
                    transport_mode="packet-up",
                )
            ]
        )

        route = classify_extended_decoy_routes(manifest)[0]

        self.assertEqual(route["status"], "ready")
        self.assertEqual(route["strategy"], "xhttp_tls_split")
        self.assertEqual(route["transport_path"], "/private-xhttp")
        self.assertEqual(route["transport_mode"], "packet-up")
        self.assertTrue(route["tls_termination"])
        self.assertEqual(route["browser_action"], "decoy")

    def test_xhttp_root_path_is_blocked_instead_of_stealing_browser_get(self) -> None:
        manifest = self.manifest(
            [
                protocol(
                    19,
                    "vless",
                    "root-xhttp.example.net",
                    internal_port=19443,
                    security="tls",
                    transport="xhttp",
                    exposure="tcp_sni",
                    sni_names=["root-xhttp.example.net"],
                    transport_path="/",
                    transport_mode="auto",
                )
            ]
        )

        route = classify_extended_decoy_routes(manifest)[0]

        self.assertEqual(route["status"], "blocked")
        self.assertFalse(route["managed"])
        self.assertIn("отдельный непустой path", route["reason"])

    def test_direct_tcp_protocol_on_separate_port_uses_tcp_side_site(self) -> None:
        manifest = self.manifest(
            [
                protocol(
                    10,
                    "shadowsocks",
                    "ss-direct.example.net",
                    exposure="tcp_direct",
                    public_port=27860,
                    internal_port=27860,
                )
            ]
        )
        route = classify_extended_decoy_routes(manifest)[0]
        self.assertEqual(route["strategy"], "tcp_side_site")
        self.assertEqual(route["status"], "ready")


if __name__ == "__main__":
    unittest.main()
