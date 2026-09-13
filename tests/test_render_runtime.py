from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import re
import unittest
from collections.abc import Mapping

from test_endpoint_routing import aliased_topology
from test_transport_routing_regressions import topology

from lucx_post_configurator import renderers
from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
from lucx_post_configurator.routing_profiles import routing_fingerprint


def legacy_cases():
    cases = {transport: topology(transport, transport_path=path)
             for transport, path in (("ws", "/"), ("httpupgrade", "/"),
                                     ("grpc", "VpnService"), ("xhttp", "/vpn"))}
    cases["alias"] = aliased_topology(8443)
    cases["strict"] = aliased_topology(8443)
    cases["strict"]["decoys"]["routing_mode"] = "strict"
    cases["cloudflare"] = aliased_topology(8443)
    cases["cloudflare"]["cloudflare"]["enabled"] = True
    cases["cloudflare"]["network"]["public_bind_address"] = "203.0.113.10"
    return cases


# Снято с прежнего renderer до добавления runtime, а не с проверяемой реализации.
LEGACY_SHA256 = {
    "ws": ("01c73e5f3337f6864f8c2aaca361efe63d5397c7cfc1e3e741e7b6ecfea59f29",
           "d78ca96ce9bbf25510e6c75f0b612dc403dc866a1413df3a454d8b087671aea0"),
    "httpupgrade": ("811150488aa422f176223b904403f31eb4a6744c7444d52ec7c383c4f9a4fa22",
                    "d78ca96ce9bbf25510e6c75f0b612dc403dc866a1413df3a454d8b087671aea0"),
    "grpc": ("a99ee5a211a186019a64d929a659f86e236ba702b48a1a691c27c85221a228cc",
             "d78ca96ce9bbf25510e6c75f0b612dc403dc866a1413df3a454d8b087671aea0"),
    "xhttp": ("dd312caa36ee9948b5d1fb1257ad3101951761c3a752cc13a2ba0413fd0ff9ad",
              "d78ca96ce9bbf25510e6c75f0b612dc403dc866a1413df3a454d8b087671aea0"),
    "alias": ("0c604b8a00992a2750004368b470f3682ab02427df2f389dfdb5e102bec21dd6",
              "964123ef4df2e9ddefead2525a34c413477e0910146683f155404b6668e36141"),
    "strict": ("3dcdd53f95e9d6e4dda3ab0659ea0b8a7b42a1155042fd4e08262d99cc72d518",
               "d70dc196911a2fa57e7911b261d4c434e2f3b7e470c81e0f063ea04bc674a756"),
    "cloudflare": ("f626f04ac082887d081bbaa45be1b33518e71d585b7703a222365ddac0ae83f2",
                   "964123ef4df2e9ddefead2525a34c413477e0910146683f155404b6668e36141"),
}


class DuplicateMapping(Mapping):
    """Mapping с повторной записью: конструктор не должен молча терять её."""

    def __init__(self, key, value):
        self.key, self.value = key, value

    def __getitem__(self, key):
        return self.value

    def __iter__(self):
        return iter((self.key, self.key))

    def __len__(self):
        return 2


class RenderRuntimeTests(unittest.TestCase):
    def test_split_ingress_identity_is_typed_distinct_and_keeps_legacy_repr(self):
        api = self._api()
        legacy = api.ListenerKey('split', 7)
        self.assertEqual(legacy.ingress_port, 0)
        self.assertEqual(repr(legacy), "ListenerKey(role='split', identity=7)")
        self.assertEqual(legacy, api.ListenerKey('split', 7, ingress_port=0))
        first = api.ListenerKey('split', 7, ingress_port=443)
        second = api.ListenerKey('split', 7, ingress_port=8443)
        self.assertEqual(len({legacy, first, second}), 3)
        self.assertIn('ingress_port=443', repr(first))
        for port in (1, 65535):
            self.assertEqual(api.ListenerKey('split', 7, port).ingress_port, port)
        for port in (-1, 65536, True, False, 443.0, '443', None):
            with self.subTest(port=port), self.assertRaises(ValueError):
                api.ListenerKey('split', 7, ingress_port=port)
        for role, identity in (('public', 443), ('decoy_tls', 0), ('decoy_h2c', 0), ('decoy_plain', 0)):
            with self.subTest(role=role), self.assertRaises(ValueError):
                api.ListenerKey(role, identity, ingress_port=443)

    def test_ingress_split_duplicate_and_port_collisions_fail_closed(self):
        api = self._api()
        first = api.ListenerKey('split', 7, ingress_port=443)
        second = api.ListenerKey('split', 7, ingress_port=8443)
        address = api.SocketAddress('127.0.0.1', 41001)
        with self.assertRaises(ValueError):
            api.RenderRuntime(DuplicateMapping(first, address))
        with self.assertRaises(ValueError):
            api.RenderRuntime({first: address, second: address})
        runtime = api.RenderRuntime({first: address, second: api.SocketAddress('127.0.0.1', 41002)})
        self.assertEqual(len(runtime.listeners), 2)

    def _api(self):
        self.assertTrue(callable(getattr(renderers, "frontend_listener_inventory", None)),
                        "Отсутствует code-owned inventory listener-ролей")
        self.assertIsNotNone(importlib.util.find_spec("lucx_post_configurator.render_runtime"),
                             "Отсутствует typed runtime overlay")
        return importlib.import_module("lucx_post_configurator.render_runtime")

    def _listeners(self, *, alias=True):
        api = self._api()
        result = {api.ListenerKey("public", 443): api.SocketAddress("127.0.0.1", 41001),
                  api.ListenerKey("split", 7): api.SocketAddress("127.0.0.1", 41003),
                  api.ListenerKey("decoy_tls"): api.SocketAddress("127.0.0.1", 41004),
                  api.ListenerKey("decoy_h2c"): api.SocketAddress("127.0.0.1", 41105),
                  api.ListenerKey("decoy_plain"): api.SocketAddress("127.0.0.1", 41206)}
        if alias:
            result[api.ListenerKey("public", 8443)] = api.SocketAddress("127.0.0.1", 41002)
        return result

    def test_inventory_uses_original_endpoints_and_all_decoy_roles(self):
        api = self._api()
        actual = renderers.frontend_listener_inventory(aliased_topology(8443))
        self.assertIsInstance(actual, tuple)
        self.assertEqual(actual, (api.ListenerKey("public", 443), api.ListenerKey("public", 8443),
                                 api.ListenerKey("split", 7), api.ListenerKey("decoy_tls"),
                                 api.ListenerKey("decoy_h2c"), api.ListenerKey("decoy_plain")))

    def test_material_inventory_drives_renderer_path_allowlist(self):
        api = self._api()
        manifest = aliased_topology(8443)
        inventory = renderers.frontend_material_inventory(manifest)
        paths = {source: f"/private/m{index}" for index, source in enumerate(inventory)}
        certificate = "/etc/lucx-post-configurator/tls/certificate.pem"
        paths[certificate + ".key"] = paths[certificate] + ".key"
        runtime = api.RenderRuntime(self._listeners(), paths=paths)
        haproxy = renderers.render_haproxy(manifest, runtime=runtime)
        nginx = renderers.render_nginx_decoys(manifest, runtime=runtime)
        for source, destination in paths.items():
            if source != certificate + ".key":
                self.assertIn(destination, haproxy + nginx)
        invalid = dict(paths)
        invalid['/unexpected'] = '/private/extra'
        with self.assertRaises(ValueError):
            renderers.render_haproxy(manifest, runtime=api.RenderRuntime(self._listeners(), paths=invalid))

    def test_inventory_error_does_not_reveal_invalid_source_value(self):
        for inventory in (renderers.frontend_material_inventory, renderers.frontend_listener_inventory):
            manifest = aliased_topology(8443)
            manifest['network']['public_tcp_port'] = 'private-sentinel-value'
            with self.subTest(inventory=inventory.__name__), self.assertRaises(ValueError) as caught:
                inventory(manifest)
            self.assertNotIn('private-sentinel-value', str(caught.exception))

    def test_runtime_none_matches_prechange_bytes_for_all_legacy_cases(self):
        for name, manifest in legacy_cases().items():
            for function, digest in zip((renderers.render_haproxy, renderers.render_nginx_decoys),
                                        LEGACY_SHA256[name]):
                with self.subTest(case=name, renderer=function.__name__):
                    self.assertEqual(hashlib.sha256(function(manifest).encode()).hexdigest(), digest)
                    self.assertEqual(hashlib.sha256(function(manifest, runtime=None).encode()).hexdigest(), digest)

    def test_only_owned_addresses_move_and_manifest_fingerprint_stays_original(self):
        api = self._api()
        manifest = aliased_topology(8443)
        before = copy.deepcopy(manifest)
        fingerprint = routing_fingerprint(manifest["protocols"][0], 443)
        runtime = api.RenderRuntime(self._listeners())
        haproxy = renderers.render_haproxy(manifest, runtime=runtime)
        nginx = renderers.render_nginx_decoys(manifest, runtime=runtime)
        self.assertEqual(re.findall(r"^    bind (\S+)", haproxy, re.MULTILINE),
                         ["127.0.0.1:41001", "127.0.0.1:41002", "127.0.0.1:41003"])
        for name, port in (("be_split_7", 41003), ("be_decoy_tls", 41004),
                           ("be_decoy_h2c", 41105), ("be_decoy_h2c_http", 41105)):
            self.assertRegex(haproxy, rf"backend {name}\n    mode \w+\n    server local 127\.0\.0\.1:{port}(?:\n| )")
        for port in (41004, 41105, 41206):
            self.assertIn(f"listen 127.0.0.1:{port}", nginx)
        backend = haproxy.split("backend be_http_reencrypt_7\n", 1)[1]
        self.assertIn("server local 127.0.0.1:18443 ssl verify required", backend)
        self.assertIn("ca-file /etc/ssl/certs/ca-certificates.crt verifyhost vpn.example.test sni str(vpn.example.test)", backend)
        self.assertIn("frontend lucx_tls_8443\n", haproxy)
        self.assertIn("ssl crt /etc/lucx-post-configurator/tls/certificate.pem", haproxy)
        self.assertEqual(manifest, before)
        self.assertEqual(routing_fingerprint(manifest["protocols"][0], 443), fingerprint)
        for service, backend_name in (("panel", "be_panel"), ("subscription", "be_subscription")):
            expected = manifest["lucx"][service]
            self.assertIn(f"backend {backend_name}\n    mode tcp\n    server local {expected['internal_host']}:{expected['internal_port']}\n", haproxy)

    def test_original_http_authority_sni_methods_and_paths_survive_overlay(self):
        api = self._api()
        for transport, path in (("ws", "/"), ("httpupgrade", "/"), ("grpc", "VpnService"),
                                ("xhttp", "/vpn")):
            for mode in (("", "auto", "packet-up", "stream-up", "stream-one") if transport == "xhttp" else ("",)):
                with self.subTest(transport=transport, mode=mode):
                    manifest = topology(transport, transport_path=path, transport_mode=mode,
                                        sni_names=["tls.example.test"])
                    original = renderers.render_haproxy(manifest)
                    staged = renderers.render_haproxy(manifest, runtime=api.RenderRuntime(self._listeners(alias=False)))
                    for line in original.splitlines():
                        if " acl " in line or "request " in line or "use_backend " in line:
                            self.assertIn(line, staged)
                    self.assertIn("verifyhost tls.example.test sni str(tls.example.test)", staged)
                    self.assertNotIn("verify none", staged)
        manifest = aliased_topology(8443)
        staged = renderers.render_haproxy(manifest, runtime=api.RenderRuntime(self._listeners()))
        authorities = [line for line in staged.splitlines() if "hdr(host)" in line]
        self.assertTrue(any("alias.example.test:8443" in line for line in authorities))
        self.assertFalse(any(":41001" in line or ":41002" in line for line in authorities))

    def test_overlay_copies_and_freezes_both_mappings(self):
        api = self._api()
        listeners = self._listeners()
        paths = {"/cert/key.pem": "/private/key.pem"}
        runtime = api.RenderRuntime(listeners, paths=paths)
        listeners.clear()
        paths.clear()
        self.assertEqual(len(runtime.listeners), 6)
        self.assertEqual(runtime.paths["/cert/key.pem"], "/private/key.pem")
        with self.assertRaises(TypeError):
            runtime.listeners[api.ListenerKey("split", 7)] = api.SocketAddress("127.0.0.1", 41009)
        with self.assertRaises(TypeError):
            runtime.paths["/cert/key.pem"] = "/private/other.pem"
        with self.assertRaises((AttributeError, TypeError)):
            runtime.foreground = True

    def test_existing_sidecar_and_several_inbound_targets_are_not_remapped(self):
        api = self._api()
        manifest = aliased_topology(8443)
        manifest["components"]["sidecar"] = True
        other = copy.deepcopy(manifest["protocols"][0])
        other.update(inbound_id=8, domain="other.example.test", internal_port=19443,
                     transport_hosts=["other.example.test"], sni_names=["other.example.test"],
                     public_endpoints=[{"host_id": 3, "address": "other.example.test", "port": 9443,
                                        "sni": "other.example.test", "valid": True}])
        manifest["protocols"].append(other)
        manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
        layout = self._listeners()
        layout[api.ListenerKey("public", 9443)] = api.SocketAddress("127.0.0.1", 41007)
        layout[api.ListenerKey("split", 8)] = api.SocketAddress("127.0.0.1", 41008)
        self.assertEqual(set(renderers.frontend_listener_inventory(manifest)), set(layout))
        result = renderers.render_haproxy(manifest, runtime=api.RenderRuntime(layout))
        self.assertIn("frontend lucx_tls_9443\n    bind 127.0.0.1:41007\n", result)
        self.assertIn("frontend lucx_split_8\n    bind 127.0.0.1:41008 ssl crt", result)
        self.assertIn("backend be_split_8\n    mode tcp\n    server local 127.0.0.1:41008\n", result)
        self.assertIn("backend be_http_reencrypt_8\n    mode http\n    server local 127.0.0.1:19443 ssl verify required", result)
        sidecar = manifest["sidecar"]
        self.assertIn(f"backend be_subscription\n    mode tcp\n    server local {sidecar['listen_host']}:{sidecar['listen_port']}\n", result)

    def test_path_overlay_does_not_replace_an_equal_http_transport_path(self):
        api = self._api()
        manifest = topology(transport_path="/cert/fullchain.pem")
        runtime = api.RenderRuntime(self._listeners(alias=False),
                                    paths={"/cert/fullchain.pem": "/private/fullchain.pem"})
        haproxy = renderers.render_haproxy(manifest, runtime=runtime)
        nginx = renderers.render_nginx_decoys(manifest, runtime=runtime)
        self.assertIn("acl protocol_path_7 path /cert/fullchain.pem\n", haproxy)
        self.assertNotIn("path /private/fullchain.pem", haproxy)
        self.assertIn("ssl_certificate /private/fullchain.pem;", nginx)

    def test_invalid_typed_roles_addresses_flags_and_duplicate_keys_fail_closed(self):
        api = self._api()
        for role, identity in (("future", 0), ("public", 0), ("public", 65536),
                               ("split", 0), ("split", True), ("decoy_tls", 7), ("public", "443")):
            with self.subTest(role=role, identity=identity), self.assertRaises(ValueError):
                api.ListenerKey(role, identity)
        for host in ("0.0.0.0", "::", "203.0.113.10", "localhost", "127.0.0.1\n    daemon", "127.0.0.1 ssl"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                api.SocketAddress(host, 41001)
        for port in (0, -1, 65536, True, 41001.0, "41001", "41001; return 200"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                api.SocketAddress("127.0.0.1", port)
        key, address = api.ListenerKey("public", 443), api.SocketAddress("127.0.0.1", 41001)
        for listeners in ({"public:443": address}, {key: "127.0.0.1:41001"},
                          [(key, address), (key, address)], DuplicateMapping(key, address)):
            with self.subTest(kind=type(listeners).__name__), self.assertRaises(ValueError):
                api.RenderRuntime(listeners)
        with self.assertRaises(ValueError):
            api.RenderRuntime({key: address}, paths=DuplicateMapping("/cert/key.pem", "/private/key.pem"))
        for flags in ({"foreground": "yes"}, {"suppress_system_log": 1}):
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                api.RenderRuntime({key: address}, **flags)

    def test_missing_extra_and_colliding_listener_layouts_fail_in_both_renderers(self):
        api = self._api()
        manifest = aliased_topology(8443)
        invalid = []
        for key in self._listeners():
            layout = self._listeners()
            del layout[key]
            invalid.append(layout)
        invalid.append(self._listeners())
        invalid[-1][api.ListenerKey("split", 8)] = api.SocketAddress("127.0.0.1", 41008)
        for port in (41003, 443, 8443, 18443, manifest["lucx"]["panel"]["internal_port"],
                     manifest["lucx"]["subscription"]["internal_port"], manifest["sidecar"]["listen_port"], 24443):
            layout = self._listeners()
            layout[api.ListenerKey("public", 443)] = api.SocketAddress("127.0.0.1", port)
            invalid.append(layout)
        for index, layout in enumerate(invalid):
            for renderer in (renderers.render_haproxy, renderers.render_nginx_decoys):
                with self.subTest(case=index, renderer=renderer.__name__), self.assertRaises(ValueError):
                    renderer(manifest, runtime=api.RenderRuntime(layout))
        with self.assertRaises(ValueError):
            renderers.render_haproxy(manifest, runtime={"listeners": self._listeners()})

    def test_unknown_strategies_disabled_components_and_stale_routes_fail_closed(self):
        api = self._api()
        manifests = []
        for field in ("haproxy", "nginx", "extended_tls_split"):
            manifest = aliased_topology(8443)
            manifest["components"][field] = False
            manifests.append(manifest)
        manifest = aliased_topology(8443)
        manifest["decoys"]["routing_mode"] = "strict"
        manifests.append(manifest)
        for transport in ("raw", "future-transport"):
            manifest = aliased_topology(8443)
            manifest["protocols"][0]["transport"] = transport
            manifest["decoys"]["extended_routes"] = classify_extended_decoy_routes(manifest)
            manifests.append(manifest)
        manifest = aliased_topology(8443)
        manifest["decoys"]["extended_routes"][0]["internal_port"] += 1
        manifests.append(manifest)
        manifest = aliased_topology(8443)
        manifest["decoys"]["sites"] = []
        manifests.append(manifest)
        for index, manifest in enumerate(manifests):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    renderers.frontend_listener_inventory(manifest)
                for renderer in (renderers.render_haproxy, renderers.render_nginx_decoys):
                    with self.assertRaises(ValueError):
                        renderer(manifest, runtime=api.RenderRuntime(self._listeners()))

    def test_duplicate_inbound_identity_is_not_silently_collapsed_into_one_role(self):
        api = self._api()
        manifest = topology()
        manifest["protocols"].append(copy.deepcopy(manifest["protocols"][0]))
        manifest["decoys"]["extended_routes"] = []
        with self.assertRaises(ValueError):
            renderers.frontend_listener_inventory(manifest)
        for renderer in (renderers.render_haproxy, renderers.render_nginx_decoys):
            with self.subTest(renderer=renderer.__name__), self.assertRaises(ValueError):
                renderer(manifest, runtime=api.RenderRuntime(self._listeners(alias=False)))

    def test_exact_owned_paths_only_and_haproxy_certificate_pair_stays_consistent(self):
        api = self._api()
        manifest = aliased_topology(8443)
        manifest["cloudflare"]["enabled"] = True
        cert = "/etc/lucx-post-configurator/tls/certificate.pem"
        paths = {cert: "/private/tls/certificate.pem", cert + ".key": "/private/tls/certificate.pem.key",
                 "/cert/fullchain.pem": "/private/tls/fullchain.pem", "/cert/key.pem": "/private/tls/key.pem",
                 "/etc/ssl/certs/ca-certificates.crt": "/private/tls/ca.crt",
                 "/etc/haproxy/cloudflare-ips.lst": "/private/cloudflare-ips.lst"}
        for index, site in enumerate(manifest["decoys"]["sites"]):
            paths[site["root"]] = f"/private/sites/{index}"
        runtime = api.RenderRuntime(self._listeners(), paths=paths)
        haproxy = renderers.render_haproxy(manifest, runtime=runtime)
        nginx = renderers.render_nginx_decoys(manifest, runtime=runtime)
        self.assertIn("ssl crt /private/tls/certificate.pem", haproxy)
        self.assertIn("ca-file /private/tls/ca.crt verifyhost vpn.example.test", haproxy)
        self.assertIn("src -f /private/cloudflare-ips.lst", haproxy)
        self.assertIn("ssl_certificate /private/tls/fullchain.pem;", nginx)
        self.assertIn("ssl_certificate_key /private/tls/key.pem;", nginx)
        for index, site in enumerate(manifest["decoys"]["sites"]):
            self.assertIn(f"root /private/sites/{index};", nginx)
            self.assertIn(f"server_name {site['domain']};", nginx)
        invalid_paths = [{"/unowned/file": "/private/file"},
                         {cert: "/private/cert.pem"}, {cert + ".key": "/private/key.pem"},
                         {cert: "/private/cert.pem", cert + ".key": "/private/wrong.key"},
                         {"/cert/fullchain.pem": "/cert/key.pem"},
                         {"/cert/fullchain.pem": "/private/same", "/cert/key.pem": "/private/same"}]
        for paths in invalid_paths:
            for renderer in (renderers.render_haproxy, renderers.render_nginx_decoys):
                with self.subTest(paths=tuple(paths), renderer=renderer.__name__), self.assertRaises(ValueError):
                    renderer(manifest, runtime=api.RenderRuntime(self._listeners(), paths=paths))

    def test_path_values_cannot_inject_directives_or_use_relative_paths(self):
        api = self._api()
        for path in ("private/key.pem", "/private/../key.pem", "/private/./key.pem", "/private//key.pem",
                     "/private/key.pem;", "/private/key.pem\n    daemon", "/private/$variable", "/private/key file"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                api.RenderRuntime(self._listeners(), paths={"/cert/key.pem": path})
        with self.assertRaises(ValueError):
            api.RenderRuntime(self._listeners(), paths={"/cert/key.pem\n": "/private/key.pem"})

    def test_foreground_and_log_flags_affect_only_runtime_global_directives(self):
        api = self._api()
        runtime = api.RenderRuntime(self._listeners(), foreground=True, suppress_system_log=True)
        output = renderers.render_haproxy(aliased_topology(8443), runtime=runtime)
        self.assertNotIn("    daemon\n", output)
        self.assertNotIn("log /dev/log", output)
        self.assertNotIn("    log global\n", output)
        self.assertNotIn("    option tcplog\n", output)
        self.assertIn("    timeout connect 5s\n", output)


if __name__ == "__main__":
    unittest.main()
