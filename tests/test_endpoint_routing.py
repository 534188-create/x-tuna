from __future__ import annotations

import re
import unittest
import hashlib
import copy

from lucx_post_configurator.decoy_capabilities import classify_decoy_capabilities
from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
from lucx_post_configurator.engine import _ephemeral_routing_material
from lucx_post_configurator.models import Audit, validate_manifest
from lucx_post_configurator.questionnaire import protocol_decoy_sites
from lucx_post_configurator.renderers import extended_split_ports, render_files, render_haproxy, render_nftables
from test_transport_routing_regressions import topology


def aliased_topology(port=443):
    manifest = topology()
    manifest["protocols"][0]["public_endpoints"] = [
        {"host_id": 1, "address": "vpn.example.test", "port": 443,
         "sni": "vpn.example.test", "valid": True},
        {"host_id": 2, "address": "alias.example.test", "port": port,
         "sni": "vpn.example.test", "valid": True},
    ]
    manifest["decoys"]["sites"] = protocol_decoy_sites(manifest)
    manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
    return manifest


class EndpointRoutingTests(unittest.TestCase):
    def test_reality_inherited_set_requires_complete_confirmed_names(self):
        from lucx_post_configurator.routing_profiles import public_ingresses
        names = ["one.example.test", "two.example.test"]
        item = topology("xhttp", security="reality", sni_names=names)["protocols"][0]
        item["public_endpoints"] = [{"host_id": 1, "address": "vpn.example.test", "port": 8443,
            "sni": "", "sni_source": "inherited_set", "inherited_sni_names": names,
            "keep_sni_blank": False, "http_host": "", "valid": True}]
        ingresses = public_ingresses(item, 443)
        for name in names:
            self.assertIn((8443, name, "vpn"), ingresses)
        for change in ({"keep_sni_blank": True}, {"sni_source": "ambiguous"},
                       {"inherited_sni_names": ["*.example.test", names[1]]},
                       {"inherited_sni_names": [names[0], names[0]]}):
            altered = copy.deepcopy(item)
            altered["public_endpoints"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                public_ingresses(altered, 443)
        for change in ({"security": "tls"}, {"sni_names": names[:1]}, {"sni_names": [names]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                public_ingresses(dict(item, **change), 443)

    def _trusttunnel_with_shared_side_site(self, *, site_first=False):
        manifest = topology("tcp", protocol="trusttunnel",
                            clienthello_match_fingerprint="sha256:0123456789ab")
        side = dict(manifest["protocols"][0], inbound_id=11, protocol="qwdtt",
                    network="both", exposure="tcp_udp_direct", security="",
                    public_port=56000, internal_port=56000, sni_names=[],
                    port_bindings=[{"port": 56000, "protocol": "TCP"},
                                   {"port": 56000, "protocol": "UDP"}])
        side.pop("clienthello_match_fingerprint")
        manifest["protocols"].insert(0 if site_first else 1, side)
        manifest["decoys"]["sites"] = protocol_decoy_sites(manifest)
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        return manifest

    def test_shared_side_site_preserves_trusttunnel_priority_in_both_orders(self):
        for site_first in (False, True):
            with self.subTest(site_first=site_first):
                manifest = self._trusttunnel_with_shared_side_site(site_first=site_first)
                before = copy.deepcopy(manifest)
                self.assertTrue(all(route["status"] == "ready"
                                    for route in manifest["decoys"]["extended_routes"]))
                rendered = render_haproxy(manifest, routing_material={
                    7: {"clienthello_hex_prefix": "DEADBEEF"},
                })
                acl = re.search(r"^\s*acl (\S+) req.ssl_sni -i vpn\.example\.test$",
                                rendered, re.MULTILINE)
                self.assertIsNotNone(acl)
                vpn_rule = "use_backend be_inbound_7 if trust_clienthello_7 trust_clienthello_7_sni"
                site_rule = "use_backend be_split_7 if " + acl.group(1)
                self.assertIn(vpn_rule, rendered)
                self.assertIn(site_rule, rendered)
                self.assertLess(rendered.index(vpn_rule), rendered.index(site_rule))
                self.assertNotIn("use_backend be_decoy_tls if " + acl.group(1), rendered)
                self.assertNotIn("frontend lucx_tls_56000", rendered)
                self.assertEqual(manifest, before)

    def test_shared_side_site_does_not_hide_two_conflicting_vpn_routes(self):
        for site_first in (False, True):
            with self.subTest(site_first=site_first):
                manifest = self._trusttunnel_with_shared_side_site(site_first=site_first)
                manifest["protocols"].append(dict(
                    topology("tcp", protocol="anytls")["protocols"][0],
                    inbound_id=8, internal_port=19443,
                ))
                manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
                with self.assertRaisesRegex(ValueError, "conflicting extended SNI"):
                    render_haproxy(manifest, routing_material={
                        7: {"clienthello_hex_prefix": "DEADBEEF"},
                    })

    def test_side_site_priority_is_scoped_to_public_port(self):
        manifest = topology("xhttp", security="reality", public_port=8443,
                            sni_names=["cover.example.test"])
        manifest["protocols"].append(dict(
            inbound_id=11, protocol="qwdtt", domain="cover.example.test",
            network="both", exposure="tcp_udp_direct", security="", transport="tcp",
            internal_host="127.0.0.1", internal_port=56000, public_port=56000,
            sni_names=[], port_bindings=[{"port": 56000, "protocol": "TCP"},
                                        {"port": 56000, "protocol": "UDP"}],
        ))
        manifest["decoys"]["sites"] = protocol_decoy_sites(manifest)
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        rendered = render_haproxy(manifest)
        for port, target in ((443, "be_decoy_tls"), (8443, "be_inbound_7")):
            frontend = rendered.split(f"frontend lucx_tls_{port}\n", 1)[1].split("\nfrontend ", 1)[0]
            acl = re.search(r"^\s*acl (\S+) req.ssl_sni -i cover\.example\.test$",
                            frontend, re.MULTILINE)
            self.assertIsNotNone(acl)
            self.assertIn(f"use_backend {target} if " + acl.group(1), frontend)

    def test_naive_on_separate_port_renders_site_without_loading_caddyfile(self):
        class NoSourceFS:
            def __getattr__(self, name):
                raise AssertionError("Неожиданное чтение Naive source: " + name)

        for cached in (True, False):
            with self.subTest(cached=cached):
                manifest = topology("tcp", inbound_id=5, protocol="naive",
                                    exposure="tcp_direct", public_port=18443)
                audit = Audit(naive_caddyfile={"files": [{
                    "path": "/etc/example/naive-5.caddyfile", "sha256": "0" * 64,
                    "capabilities": {"forward_proxy": True, "native_decoy": True},
                }]})
                manifest["decoys"]["extended_routes"] = (
                    classify_extended_decoy_routes(manifest, audit) if cached else [])
                original = copy.deepcopy(manifest)
                material = _ephemeral_routing_material(NoSourceFS(), audit, manifest)
                files = render_files(manifest, routing_material=material)
                haproxy = files["/etc/haproxy/haproxy.cfg"].content.decode()
                acl = re.search(r"acl (sni_\S+) req.ssl_sni -i vpn\.example\.test", haproxy)
                self.assertIsNotNone(acl)
                self.assertIn("use_backend be_decoy_tls if " + acl.group(1), haproxy)
                self.assertNotIn("frontend lucx_tls_18443", haproxy)
                self.assertIn("vpn.example.test", files["/etc/nginx/conf.d/60-lucx-decoys.conf"].content.decode())
                self.assertFalse(any("naive" in path for path in files))
                self.assertEqual(manifest, original)

    def test_naive_source_requirement_cannot_be_bypassed_by_cached_side_site(self):
        manifest = topology("tcp", inbound_id=5, protocol="naive",
                            exposure="tcp_direct", public_port=18443)
        manifest["protocols"][0].update(exposure="tcp_sni", public_port=443)
        with self.assertRaises(ValueError):
            render_files(manifest)

    def test_naive_side_site_rejects_shared_port_conflict_and_changed_cache(self):
        for drift in ("shared_port", "cached_backend"):
            with self.subTest(drift=drift):
                manifest = topology("tcp", inbound_id=5, protocol="naive",
                                    exposure="tcp_direct", public_port=18443)
                if drift == "shared_port":
                    manifest["protocols"][0]["public_port"] = 443
                else:
                    manifest["decoys"]["extended_routes"][0]["internal_port"] = 19443
                with self.assertRaises(ValueError):
                    render_files(manifest)

    def test_capability_cache_cannot_hide_an_alias_or_keep_ready_after_transport_drift(self):
        manifest = aliased_topology()
        manifest["decoys"]["extended_routes"][0].pop("endpoint_domains")
        records = {item["domain"]: item for item in classify_decoy_capabilities(manifest)}
        self.assertIn("alias.example.test", records)
        self.assertFalse(records["alias.example.test"]["managed"])
        manifest = aliased_topology()
        manifest["protocols"][0]["transport"] = "raw"
        records = {item["domain"]: item for item in classify_decoy_capabilities(manifest)}
        self.assertFalse(records["alias.example.test"]["managed"])

    def test_strict_passthrough_preserves_additional_endpoint_port(self):
        manifest = aliased_topology(8443)
        manifest["decoys"]["routing_mode"] = "strict"
        self.assertIn("frontend lucx_tls_8443\n", render_haproxy(manifest))

    def test_strict_firewall_allows_the_existing_alias_port(self):
        manifest = aliased_topology(8443)
        manifest["firewall"]["mode"] = "strict_allowlist"
        line = next(line for line in render_nftables(manifest).splitlines() if "SSH and LucX public TCP" in line)
        self.assertIn("8443", line)

    def test_endpoint_collision_with_another_inbound_or_protected_sni_is_rejected(self):
        manifest = aliased_topology(8443)
        other = dict(manifest["protocols"][0], inbound_id=8, internal_port=19443,
                     domain="other.example.test", sni_names=["other.example.test"],
                     public_endpoints=[{"address": "alias.example.test", "sni": "other.example.test", "port": 8443}])
        manifest["protocols"].append(other)
        with self.assertRaises(ValueError):
            validate_manifest(manifest)
        manifest = aliased_topology()
        manifest["protocols"][0]["public_endpoints"][1]["address"] = "panel.example.test"
        with self.assertRaises(ValueError):
            validate_manifest(manifest)

    def test_native_naive_material_keeps_alias_port_and_checks_source_hash(self):
        source = "vpn.example.test {\n route {\n forward_proxy {\n basic_auth test-user test-pass\n }\n file_server\n }\n}\n"
        manifest = aliased_topology(8443)
        manifest["protocols"][0].update(protocol="naive", transport="tcp")
        metadata = {"path": "/etc/example/naive-7.caddyfile", "sha256": hashlib.sha256(source.encode()).hexdigest(),
                    "capabilities": {"native_decoy": True, "forward_proxy": True}}
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest, Audit(naive_caddyfile={"files": [metadata]}))
        material = {"naive_caddyfile_text": source, "naive_source_metadata": metadata}
        self.assertIn("frontend lucx_tls_8443\n", render_haproxy(manifest, routing_material={7: material}))
        with self.assertRaisesRegex(ValueError, "changed after planning"):
            render_haproxy(manifest, routing_material={7: dict(material, naive_caddyfile_text=source + "# drift")})

    def test_managed_naive_allocator_reserves_all_public_endpoint_ports(self):
        manifest = aliased_topology(26443)
        manifest["components"]["naive_frontend"] = True
        manifest["protocols"][0].update(protocol="naive", transport="tcp")
        audit = Audit(naive_caddyfile={"binary_path": "/opt/caddy-naive", "files": [{
            "path": "/etc/example/naive-7.caddyfile", "sha256": "0" * 64,
            "capabilities": {"forward_proxy": True, "native_decoy": False}}]})
        self.assertEqual(classify_extended_decoy_routes(manifest, audit)[0]["managed_listen_port"], 26444)

    def test_naive_forward_proxy_does_not_implicitly_enable_copied_auth_frontend(self):
        manifest = aliased_topology()
        manifest["protocols"][0].update(protocol="naive", transport="tcp")
        audit = Audit(naive_caddyfile={"binary_path": "/opt/caddy-naive", "files": [{
            "path": "/etc/example/naive-7.caddyfile", "sha256": "0" * 64,
            "capabilities": {"forward_proxy": True, "native_decoy": False}}]})
        route = classify_extended_decoy_routes(manifest, audit)[0]
        self.assertEqual(route["status"], "blocked")
        self.assertNotIn("managed_listen_port", route)
        self.assertFalse(manifest["components"]["naive_frontend"])

    def test_reality_alias_owning_camouflage_sni_is_not_a_ready_site(self):
        manifest = aliased_topology()
        manifest["protocols"][0].update(security="reality", sni_names=["alias.example.test"])
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        records = {item["domain"]: item for item in classify_decoy_capabilities(manifest)}
        self.assertFalse(records["alias.example.test"]["managed"])

    def test_blocked_alias_keeps_its_existing_public_port(self):
        manifest = aliased_topology(8443)
        manifest["protocols"][0]["transport"] = "raw"
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        rendered = render_haproxy(manifest)
        self.assertIn("frontend lucx_tls_8443\n", rendered)
        frontend = rendered.split("frontend lucx_tls_8443\n", 1)[1].split("\nfrontend ", 1)[0]
        self.assertIn("use_backend be_inbound_7", frontend)

    def test_reality_alias_keeps_its_existing_public_port(self):
        manifest = aliased_topology(8443)
        manifest["protocols"][0].update(security="reality", sni_names=["camouflage.example.test"])
        for endpoint in manifest["protocols"][0]["public_endpoints"]:
            endpoint["sni"] = "camouflage.example.test"
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        rendered = render_haproxy(manifest)
        self.assertIn("frontend lucx_tls_8443\n", rendered)
        frontend = rendered.split("frontend lucx_tls_8443\n", 1)[1].split("\nfrontend ", 1)[0]
        self.assertIn("use_backend be_inbound_7", frontend)

    def test_split_allocator_reserves_alias_and_binding_ports(self):
        manifest = aliased_topology(24443)
        manifest["protocols"][0]["port_bindings"] = [
            {"protocol": "TCP", "port": 24444},
            {"protocol": "TCP", "port_range": "24445-24447"},
        ]
        routes = classify_extended_decoy_routes(manifest)
        self.assertEqual(extended_split_ports(manifest, routes)[7], 24448)

    def test_alias_http_host_override_never_silently_uses_primary_host_matcher(self):
        manifest = aliased_topology(8443)
        manifest["protocols"][0]["public_endpoints"][1]["http_host"] = "alternate.example.test"
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        self.assertEqual(manifest["decoys"]["extended_routes"][0]["status"], "blocked")

    def test_default_http_authorities_cover_aliases_and_their_ports(self):
        manifest = aliased_topology(8443)
        manifest["protocols"][0]["transport_hosts"] = []
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        rendered = render_haproxy(manifest)
        matcher = next(line for line in rendered.splitlines() if "acl protocol_host_7 " in line)
        self.assertIn("alias.example.test", matcher)
        self.assertIn("alias.example.test:8443", matcher)

    def test_cache_cannot_drop_aliases_with_the_original_fingerprint(self):
        manifest = aliased_topology()
        manifest["protocols"][0]["transport"] = "raw"
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        manifest["decoys"]["extended_routes"][0].pop("endpoint_domains")
        with self.assertRaises(ValueError):
            render_haproxy(manifest)

    def test_cache_cannot_change_derived_tls_decisions_with_original_fingerprint(self):
        for field in ("tls_termination", "backend_tls", "preflight_required", "managed"):
            with self.subTest(field=field):
                manifest = aliased_topology()
                manifest["decoys"]["extended_routes"][0][field] = False
                with self.assertRaises(ValueError):
                    render_haproxy(manifest)

    def test_blank_or_ambiguous_endpoint_sni_cannot_be_guessed(self):
        for source in ("blank", "ambiguous"):
            with self.subTest(source=source):
                manifest = aliased_topology()
                manifest["protocols"][0]["public_endpoints"][1].update(
                    sni="", sni_source=source, keep_sni_blank=source == "blank")
                manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
                self.assertEqual(manifest["decoys"]["extended_routes"][0]["status"], "blocked")
                with self.assertRaises(ValueError):
                    render_haproxy(manifest)

    def test_unsafe_endpoint_names_and_ports_are_rejected_before_rendering(self):
        for field, value in (("address", "bad\nname"), ("sni", "bad\nname"), ("port", 0), ("port", 65536)):
            with self.subTest(field=field):
                manifest = aliased_topology()
                manifest["protocols"][0]["public_endpoints"][1][field] = value
                manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
                with self.assertRaises(ValueError):
                    render_haproxy(manifest)
                with self.assertRaises(ValueError):
                    validate_manifest(manifest)

    def test_native_naive_cached_recipe_requires_ephemeral_source(self):
        source = "vpn.example.test {\n route {\n forward_proxy {\n basic_auth test-user test-pass\n }\n file_server\n }\n}\n"
        manifest = aliased_topology()
        manifest["protocols"][0].update(protocol="naive", transport="tcp")
        metadata = {"path": "/etc/example/naive-7.caddyfile", "sha256": hashlib.sha256(source.encode()).hexdigest(),
                    "capabilities": {"native_decoy": True, "forward_proxy": True}}
        audit = Audit(naive_caddyfile={"files": [metadata]})
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest, audit)
        with self.assertRaises(ValueError):
            render_haproxy(manifest)

    def test_all_enabled_endpoints_receive_sites_and_capability_records(self):
        manifest = aliased_topology()
        self.assertEqual({site["domain"] for site in manifest["decoys"]["sites"]},
                         {"vpn.example.test", "alias.example.test", "example.test"})
        records = {item["domain"]: item for item in classify_decoy_capabilities(manifest)}
        self.assertEqual(records["alias.example.test"]["protocol_ids"], [7])
        self.assertEqual(records["alias.example.test"]["status"], "extended_ready")

    def test_alias_uses_same_vpn_frontend_instead_of_static_catchall(self):
        rendered = render_haproxy(aliased_topology())
        acl = re.search(r"acl (sni_\S+) req.ssl_sni -i alias\.example\.test", rendered)
        self.assertIsNotNone(acl)
        self.assertIn("use_backend be_split_7 if " + acl.group(1), rendered)

    def test_additional_public_endpoint_port_preserves_vpn_ingress(self):
        rendered = render_haproxy(aliased_topology(8443))
        self.assertIn("frontend lucx_tls_8443\n", rendered)
        frontend = rendered.split("frontend lucx_tls_8443\n", 1)[1].split("\nfrontend ", 1)[0]
        self.assertIn("use_backend be_split_7", frontend)

    def test_alias_of_raw_inbound_does_not_become_unowned_static_site(self):
        manifest = aliased_topology()
        manifest["protocols"][0]["transport"] = "raw"
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        records = {item["domain"]: item for item in classify_decoy_capabilities(manifest)}
        self.assertIn("alias.example.test", records)
        self.assertFalse(records["alias.example.test"]["managed"])

    def test_unknown_transport_wrapper_blocks_new_split(self):
        manifest = topology()
        manifest["protocols"][0]["transport_details"] = {
            "requires_adapter_review": True, "support_status": "unverified"}
        route = classify_extended_decoy_routes(manifest)[0]
        self.assertEqual(route["status"], "blocked")
