from __future__ import annotations

import copy
import unittest

from lucx_post_configurator.decoy_capabilities import classify_decoy_capabilities
from lucx_post_configurator.discovery import _extract_transport_metadata, _extract_transport, _extract_network
from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
from lucx_post_configurator.models import default_manifest, validate_manifest
from lucx_post_configurator.questionnaire import protocol_decoy_sites, _yes_no, configure_protocol_decoys_interactively
from lucx_post_configurator.renderers import render_haproxy


def topology(transport: str = "ws", **changes) -> dict:
    manifest = default_manifest()
    manifest["lucx"]["panel"]["domain"] = "panel.example.test"
    manifest["lucx"]["subscription"]["domain"] = "sub.example.test"
    manifest["certificates"].update(cert_path="/cert/fullchain.pem", key_path="/cert/key.pem")
    manifest["components"]["extended_tls_split"] = True
    manifest["decoys"].update(
        enabled=True, routing_mode="extended", extended_user_confirmed=True,
        sites=[{"domain": name, "root": "/var/www/lucx-decoys/" + name}
               for name in ("vpn.example.test", "example.test")],
    )
    item = dict(inbound_id=7, protocol="vless", domain="vpn.example.test",
                network="tcp", exposure="tcp_sni", security="tls", transport=transport,
                internal_host="127.0.0.1", internal_port=18443, public_port=443,
                transport_path="/vpn", transport_hosts=["vpn.example.test"],
                sni_names=["vpn.example.test"], alpn=["h2", "http/1.1"])
    item.update(changes)
    manifest["protocols"] = [item]
    manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
    return manifest


class TransportRoutingRegressions(unittest.TestCase):
    def test_root_upgrade_transport_is_distinct_from_ordinary_browser_get(self):
        for transport in ("ws", "httpupgrade"):
            with self.subTest(transport=transport):
                manifest = topology(transport, transport_path="/")
                self.assertEqual(manifest["decoys"]["extended_routes"][0]["status"], "ready")
                self.assertIn("frontend lucx_split_7", render_haproxy(manifest))

    def test_backend_tls_verifies_certificate_chain_and_actual_backend_name(self):
        for transport, path, alpn in (("ws", "/vpn", "http/1.1"),
                                      ("httpupgrade", "/vpn", "http/1.1"),
                                      ("grpc", "VpnService", "h2"),
                                      ("xhttp", "/vpn", "h2,http/1.1")):
            with self.subTest(transport=transport):
                manifest = topology(transport, transport_path=path, sni_names=["tls.example.test"])
                rendered = render_haproxy(manifest)
                backend = rendered.split("backend be_http_reencrypt_7\n", 1)[1]
                self.assertIn("ssl verify required ca-file /etc/ssl/certs/ca-certificates.crt verifyhost tls.example.test sni str(tls.example.test)", backend)
                self.assertIn("alpn " + alpn, backend)
                self.assertNotIn("verify none", rendered)

    def test_backend_tls_accepts_explicit_safe_ca_and_rejects_insecure_policy(self):
        manifest = topology(backend_tls_policy={"ca_file": "/etc/lucx-post-configurator/tls/ca.pem"})
        self.assertIn("ca-file /etc/lucx-post-configurator/tls/ca.pem", render_haproxy(manifest))
        for policy in ({"verify": "none"}, {"insecure": True}, {"ca_file": "relative.pem"},
                       {"ca_file": "/tmp/../ca.pem"}, {"ca_file": "/tmp/ca.pem\noption unsafe"},
                       {"ca_file": "/tmp/ca.pem", "future": True}, [], "insecure"):
            with self.subTest(policy=policy):
                with self.assertRaises(ValueError):
                    render_haproxy(topology(backend_tls_policy=policy))

    def test_cached_backend_tls_policy_cannot_be_removed_or_tampered(self):
        for replacement in (None, {"ca_file": "/tmp/other.pem"}):
            with self.subTest(replacement=replacement):
                manifest = topology()
                if replacement is None:
                    manifest["decoys"]["extended_routes"][0].pop("backend_tls_policy", None)
                else:
                    manifest["decoys"]["extended_routes"][0]["backend_tls_policy"] = replacement
                with self.assertRaises(ValueError):
                    render_haproxy(manifest)

    def test_decoy_package_plan_includes_http2_probe_client(self):
        from lucx_post_configurator.planner import build_plan
        manifest = topology()
        manifest["components"]["install_packages"] = True
        self.assertIn("curl", build_plan(manifest)["packages"])

    def test_empty_confirmation_always_means_no_even_for_enabled_component(self):
        self.assertFalse(_yes_no("Включить", True, input_fn=lambda _: "", output_fn=lambda _: None))

    def test_blocked_known_route_retains_vpn_backend_instead_of_standalone_site(self):
        manifest = topology("http")
        rendered = render_haproxy(manifest)
        self.assertIn("backend be_inbound_7", rendered)
        self.assertIn("use_backend be_inbound_7 if sni_", rendered)
        self.assertNotIn("frontend lucx_split_7", rendered)
        self.assertIn("backend be_decoy_tls", rendered)

    def test_unknown_transport_never_uses_binary_tls_adapter(self):
        route = topology("future-transport")["decoys"]["extended_routes"][0]
        self.assertEqual(route["status"], "blocked")

    def test_raw_xray_requires_separate_migration_without_rewriting_inbound(self):
        for transport in ("tcp", "raw"):
            with self.subTest(transport=transport):
                manifest = topology(transport)
                self.assertEqual(manifest["decoys"]["extended_routes"][0]["status"], "blocked")
                original = copy.deepcopy(manifest["protocols"])
                classify_extended_decoy_routes(manifest)
                self.assertEqual(manifest["protocols"], original)

    def test_native_anytls_uses_binary_tls_split(self):
        manifest = topology("tcp", protocol="anytls")
        route = manifest["decoys"]["extended_routes"][0]
        self.assertEqual(route["status"], "ready")
        self.assertEqual(route["strategy"], "binary_tls_split")
        rendered = render_haproxy(manifest)
        self.assertIn("use_backend be_split_7", rendered)
        self.assertIn("default_backend be_reencrypt_7", rendered)
        self.assertIn("frontend lucx_split_7", rendered)

    def test_alpn_cannot_inject_haproxy_configuration(self):
        for value in ("h2\n    default_backend be_inbound_7", "future-alpn"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    render_haproxy(topology("xhttp", alpn=[value]))

    def test_all_sites_including_apex_have_capability_records(self):
        manifest = topology()
        records = {item["domain"]: item for item in classify_decoy_capabilities(manifest)}
        self.assertIn("example.test", records)
        self.assertTrue(records["example.test"]["managed"])

    def test_standalone_apex_cannot_claim_another_inbounds_reality_sni(self):
        manifest = topology("grpc", security="reality", sni_names=["example.test"])
        records = {item["domain"]: item for item in classify_decoy_capabilities(manifest)}
        self.assertFalse(records["example.test"]["managed"])

    def test_stale_ready_route_cannot_enable_raw_adapter(self):
        manifest = topology("tcp")
        manifest["decoys"]["extended_routes"][0].update(strategy="binary_tls_split", status="ready")
        with self.assertRaises(ValueError):
            render_haproxy(manifest)

    def test_stale_cached_backend_port_is_rejected_before_rendering(self):
        manifest = topology()
        manifest["decoys"]["extended_routes"][0]["internal_port"] = 29443
        with self.assertRaises(ValueError):
            render_haproxy(manifest)

    def test_missing_cached_inbound_cannot_become_standalone_site(self):
        manifest = topology()
        other = dict(manifest["protocols"][0], inbound_id=8, transport="tcp", domain="new.example.test", sni_names=["new.example.test"], internal_port=19443)
        manifest["protocols"].append(other)
        manifest["decoys"]["sites"].append({"domain": "new.example.test", "root": "/var/www/lucx-decoys/new.example.test"})
        with self.assertRaises(ValueError):
            render_haproxy(manifest)

    def test_duplicate_cached_route_id_is_rejected(self):
        manifest = topology()
        manifest["decoys"]["extended_routes"].append(dict(manifest["decoys"]["extended_routes"][0]))
        with self.assertRaises(ValueError):
            render_haproxy(manifest)

    def test_cached_naive_recipe_cannot_replace_another_protocol(self):
        manifest = topology("raw")
        manifest["components"]["naive_frontend"] = True
        manifest["decoys"]["extended_routes"][0].update(
            strategy="naive_managed", status="ready", managed_listen_port=28443,
        )
        with self.assertRaises(ValueError):
            render_haproxy(manifest)

    def test_optional_trusttunnel_domain_cannot_replace_another_protocol(self):
        manifest = topology("raw")
        manifest["components"]["trusttunnel_backend"] = True
        manifest["trusttunnel_backend"].update(public_domain="vpn.example.test", listen_port=26444)
        with self.assertRaises(ValueError):
            render_haproxy(manifest)

    def test_http_backend_uses_actual_unique_tls_sni_separately_from_host(self):
        manifest = topology("ws", sni_names=["tls.example.test"])
        rendered = render_haproxy(manifest)
        self.assertIn("sni str(tls.example.test) alpn http/1.1", rendered)
        self.assertIn("hdr(host) -i vpn.example.test", rendered)

    def test_nginx_public_decoy_listener_supports_browser_http2(self):
        from lucx_post_configurator.renderers import render_nginx_decoys
        self.assertIn("listen 127.0.0.1:8444 ssl http2;", render_nginx_decoys(topology()))

    def test_explicit_apex_overrides_legacy_panel_parent(self):
        manifest = topology()
        manifest["lucx"]["panel"]["domain"] = "panel.admin.example.test"
        manifest["decoys"]["zone_apex"] = "example.test"
        sites = {site["domain"] for site in protocol_decoy_sites(manifest)}
        self.assertIn("example.test", sites)
        self.assertNotIn("admin.example.test", sites)

    def test_decoy_wizard_records_operator_selected_zone_apex(self):
        manifest = topology()
        manifest["lucx"]["panel"]["domain"] = "panel.admin.example.test"
        answers = iter(["1", "1", "example.test", "2"])
        changed, _ = configure_protocol_decoys_interactively(manifest, input_fn=lambda _: next(answers), output_fn=lambda _: None)
        self.assertEqual(changed["decoys"]["zone_apex"], "example.test")

    def test_invalid_explicit_apex_is_rejected_by_manifest_validation(self):
        manifest = topology()
        manifest["decoys"]["zone_apex"] = "bad\nvalue"
        with self.assertRaisesRegex(ValueError, "zone_apex"):
            validate_manifest(manifest)

    def test_grpc_discovery_service_name_roundtrips_to_rpc_routes(self):
        path, hosts, mode = _extract_transport_metadata("grpc", {"grpcSettings": {"serviceName": "VpnService"}})
        manifest = topology("grpc", transport_path=path)
        rendered = render_haproxy(manifest)
        self.assertIn("path /VpnService/Tun /VpnService/TunMulti", rendered)
        self.assertIn("method POST", rendered)
        self.assertIn("proto h2", rendered)

    def test_empty_grpc_service_does_not_become_none_literal(self):
        path, _, _ = _extract_transport_metadata("grpc", {"grpcSettings": {}})
        self.assertEqual(path, "")
        manifest = topology("grpc", transport_path=path)
        self.assertEqual(manifest["decoys"]["extended_routes"][0]["status"], "blocked")

    def test_conflicting_transport_fields_do_not_silently_select_raw(self):
        self.assertEqual(_extract_transport({}, {"method": "grpc"}), "grpc")
        self.assertEqual(_extract_transport({}, {"network": "ws", "method": "grpc"}), "unknown")

    def test_native_network_is_not_overridden_by_default_xray_transport(self):
        self.assertEqual(_extract_network("qwdtt", {}, {}), "both")
        self.assertEqual(_extract_network("tuic", {}, {}), "udp")

    def test_ws_requires_exact_case_sensitive_path_and_websocket_upgrade(self):
        rendered = render_haproxy(topology("ws", transport_path="/Vpn"))
        self.assertIn("acl protocol_path_7 path /Vpn\n", rendered)
        self.assertNotIn("path_beg -i /Vpn", rendered)
        self.assertIn("hdr(Upgrade) -i websocket", rendered)
        self.assertIn("method GET", rendered)
        self.assertIn("vpn.example.test:443", rendered)
        backend = rendered.split("backend be_http_reencrypt_7\n", 1)[1]
        self.assertIn("alpn http/1.1", backend)
        self.assertNotIn("alpn h2,http/1.1", backend)

    def test_xhttp_path_boundaries_are_case_sensitive(self):
        rendered = render_haproxy(topology("xhttp", transport_path="/Vpn"))
        self.assertIn("acl protocol_path_7 path /Vpn\n", rendered)
        self.assertIn("acl protocol_path_7 path_beg /Vpn/\n", rendered)
        self.assertNotIn("path_beg -i", rendered)

    def test_direct_listener_collision_blocks_rendering_before_changes(self):
        manifest = topology("tcp", protocol="mieru", exposure="tcp_direct", internal_port=443)
        with self.assertRaises(ValueError):
            render_haproxy(manifest)


if __name__ == "__main__":
    unittest.main()
