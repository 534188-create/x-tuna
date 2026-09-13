from __future__ import annotations

import copy
import hashlib
import inspect
import unittest

from test_transport_routing_regressions import topology

from lucx_post_configurator import extended_decoys, renderers
from lucx_post_configurator.decoy_capabilities import classify_decoy_capabilities
from lucx_post_configurator.models import Audit
from lucx_post_configurator.render_runtime import (
    ListenerKey,
    RenderRuntime,
    SocketAddress,
)
from lucx_post_configurator.routing_profiles import reserved_listener_ports

SOURCE = "vpn.example.test {\n route {\n forward_proxy {\n basic_auth synthetic-user synthetic-secret\n }\n }\n}\n"


def candidate_fixture():
    manifest = topology("tcp", protocol="naive", transport_path="", transport_hosts=[], alpn=["h2"])
    manifest["protocols"][0]["public_endpoints"] = [
        {"host_id": 1, "address": "vpn.example.test", "sni": "vpn.example.test", "port": 443,
         "sni_source": "address", "http_host": "", "keep_sni_blank": False, "valid": True},
        {"host_id": 2, "address": "alias.example.test", "sni": "alias.example.test", "port": 8443,
         "sni_source": "address", "http_host": "", "keep_sni_blank": False, "valid": True}]
    metadata = {"path": "/etc/example/naive-7.caddyfile", "kind": "file", "mode": 0o600,
                "uid": 0, "gid": 0, "sha256": hashlib.sha256(SOURCE.encode()).hexdigest(),
                "capabilities": {"forward_proxy": True, "native_decoy": False}}
    audit = Audit(naive_caddyfile={"files": [metadata]})
    material = {"naive_caddyfile_text": SOURCE, "naive_source_metadata": metadata}
    return manifest, audit, material


def common_fixture():
    manifest, audit, material = candidate_fixture()
    xray = topology('ws', inbound_id=8, domain='xray.example.test', internal_port=19443,
                    sni_names=['xray.example.test'], transport_hosts=['xray.example.test'], alpn=['http/1.1'])['protocols'][0]
    xray['public_endpoints'] = [{'host_id': 3, 'address': 'xray.example.test', 'sni': 'xray.example.test',
        'port': 443, 'sni_source': 'address', 'http_host': '', 'keep_sni_blank': False, 'valid': True}]
    manifest['protocols'].append(xray)
    manifest['decoys']['sites'].extend({'domain': name, 'root': '/var/www/lucx-decoys/' + name}
                                      for name in ('alias.example.test', 'xray.example.test'))
    manifest['decoys']['extended_routes'] = extended_decoys.classify_extended_decoy_routes(manifest, audit)
    return manifest, audit, {7: material}


class CommonNaiveFrontendTests(unittest.TestCase):
    def test_candidate_browser_targets_exist_only_in_staging_phase(self):
        from lucx_post_configurator.decoy_health import decoy_probe_targets
        manifest, audit, _ = common_fixture()
        manifest['decoys']['require_full_acceptance'] = False
        manifest['decoys']['capabilities'] = classify_decoy_capabilities(manifest, audit)
        before = copy.deepcopy(manifest)
        public = decoy_probe_targets(manifest, '127.0.0.1', audit=audit)
        self.assertNotIn('vpn.example.test', {row['domain'] for row in public})
        staging = decoy_probe_targets(manifest, '127.0.0.1', audit=audit, phase='staging')
        self.assertIn('vpn.example.test', {row['domain'] for row in staging})
        self.assertIn('alias.example.test', {row['domain'] for row in staging})
        self.assertEqual(manifest, before)
        restricted = copy.deepcopy(manifest)
        for item in restricted['decoys']['capabilities']:
            if item['domain'] == 'vpn.example.test':
                item['reason'] = 'Отдельный сохранённый запрет'
        self.assertNotIn('vpn.example.test', {row['domain'] for row in
            decoy_probe_targets(restricted, '127.0.0.1', audit=audit, phase='staging')})
        audit.naive_caddyfile['files'][0]['sha256'] = 'b' * 64
        stale = decoy_probe_targets(manifest, '127.0.0.1', audit=audit, phase='staging')
        self.assertNotIn('vpn.example.test', {row['domain'] for row in stale})

    def test_strict_public_and_rollback_probe_candidates_without_promoting_ready(self):
        from lucx_post_configurator.decoy_health import _capabilities, decoy_probe_targets
        manifest, audit, _ = common_fixture()
        manifest['decoys']['require_full_acceptance'] = True
        manifest['decoys']['capabilities'] = classify_decoy_capabilities(manifest, audit)
        before = copy.deepcopy(manifest)
        for phase in ('public', 'rollback'):
            with self.subTest(phase=phase):
                targets = decoy_probe_targets(manifest, '192.0.2.10', audit=audit, phase=phase)
                self.assertIn('vpn.example.test', {row['domain'] for row in targets})
                self.assertIn(('alias.example.test', 8443), {(row['domain'], row['port']) for row in targets})
                current = {row['domain']: row for row in _capabilities(manifest, audit=audit, phase=phase)}
                self.assertEqual(current['vpn.example.test']['status'], 'extended_candidate')
        self.assertEqual(manifest, before)
        audit.naive_caddyfile['files'][0]['sha256'] = 'b' * 64
        self.assertNotIn('vpn.example.test', {row['domain'] for row in
            decoy_probe_targets(manifest, '192.0.2.10', audit=audit)})

    def test_canonical_native_modes_remain_candidates_and_never_copy_auth(self):
        manifest, audit, material = common_fixture()
        source = '''{
 admin off
 auto_https off
 servers {
  protocols h1 h2
 }
}
:18443 {
 bind 127.0.0.1
 tls /cert/original.pem /cert/original.key
 route {
  forward_proxy {
   basic_auth synthetic-user synthetic-secret
   hide_ip
   hide_via
   probe_resistance
   upstream socks5://lucx:abcdefghijklmnopqrstuvwx@127.0.0.1:19444
  }
 }
}
'''
        metadata = material[7]['naive_source_metadata']
        metadata['sha256'] = hashlib.sha256(source.encode()).hexdigest()
        material[7]['naive_caddyfile_text'] = source
        audit.naive_caddyfile['files'][0].update(metadata)
        manifest['decoys']['extended_routes'] = extended_decoys.classify_extended_decoy_routes(manifest, audit)
        original = copy.deepcopy((manifest, material))
        output = renderers.render_haproxy(manifest, material)
        self.assertIn('be_naive_existing_7', output)
        for secret in ('synthetic-secret', 'abcdefghijklmnopqrstuvwx', 'basic_auth'):
            self.assertNotIn(secret, output)
        self.assertEqual(manifest['decoys']['extended_routes'][0]['status'], 'rendered_candidate')
        self.assertEqual((manifest, material), original)
        changed = copy.deepcopy(material)
        changed[7]['naive_caddyfile_text'] = source.replace('probe_resistance', 'unknown_native_directive')
        with self.assertRaises(ValueError):
            renderers.render_haproxy(manifest, changed)

    def test_common_l4_preserves_original_ingress_and_existing_xray_split(self):
        manifest, _, material = common_fixture()
        original = copy.deepcopy(manifest)
        text = renderers.render_haproxy(manifest, material)
        for port, other in ((443, 8443), (8443, 443)):
            section = text.split(f'frontend lucx_naive_split_7_{port}\n', 1)[1].split('\nfrontend ', 1)[0]
            host_line = next(line for line in section.splitlines() if 'acl site_host ' in line)
            self.assertIn(f':{port}', host_line)
            self.assertNotIn(f':{other}', host_line)
            self.assertIn('use_backend be_naive_existing_7 if { method CONNECT } vpn_sni', section)
            self.assertIn(f'use_backend be_naive_split_7_{port} if ', text)
        self.assertIn('frontend lucx_split_8\n    bind 127.0.0.1:24443 ssl', text)
        self.assertIn('server local 127.0.0.1:18443 ssl verify required', text)
        self.assertIn('verifyhost vpn.example.test sni str(vpn.example.test) alpn h2 proto h2', text)
        for secret in ('synthetic-user', 'synthetic-secret', 'basic_auth'):
            self.assertNotIn(secret, text)
        self.assertEqual(manifest, original)

    def test_full_runtime_and_nginx_use_same_source_and_all_sites(self):
        manifest, _, material = common_fixture()
        keys = renderers.frontend_listener_inventory(manifest, routing_material=material)
        expected = {ListenerKey('public', 443), ListenerKey('public', 8443), ListenerKey('split', 8),
                    ListenerKey('split', 7, ingress_port=443), ListenerKey('split', 7, ingress_port=8443),
                    ListenerKey('decoy_tls'), ListenerKey('decoy_h2c'), ListenerKey('decoy_plain')}
        self.assertEqual(set(keys), expected)
        inventory = renderers.frontend_material_inventory(manifest, routing_material=material)
        source = material[7]['naive_source_metadata']['path']
        self.assertNotIn(source, inventory)
        paths = {path: '/private/staging' + path for path in inventory}
        runtime = RenderRuntime({key: SocketAddress('127.0.0.1', 31000 + index)
                                 for index, key in enumerate(keys)}, paths)
        haproxy = renderers.render_haproxy(manifest, material, runtime=runtime)
        nginx = renderers.render_nginx_decoys(manifest, routing_material=material, runtime=runtime)
        for site in manifest['decoys']['sites']:
            self.assertIn('server_name ' + site['domain'] + ';', nginx)
            self.assertIn('root ' + paths[site['root']] + ';', nginx)
        for port in (443, 8443):
            address = runtime.listeners[ListenerKey('split', 7, ingress_port=port)]
            self.assertIn(f'frontend lucx_naive_split_7_{port}\n    bind {address.authority} ssl', haproxy)
            section = haproxy.split(f'frontend lucx_naive_split_7_{port}\n', 1)[1].split('\nfrontend ', 1)[0]
            host_line = next(line for line in section.splitlines() if 'acl site_host ' in line)
            self.assertNotIn(str(address.port), host_line)
        self.assertNotIn(source, haproxy + nginx)
        with self.assertRaises(ValueError):
            renderers.render_nginx_decoys(manifest, runtime=runtime)

    def test_source_identity_and_cached_route_drift_are_rejected(self):
        original, _, original_material = common_fixture()
        mutations = [lambda m, s: s[7].update(naive_caddyfile_text=SOURCE + '# changed'),
                     lambda m, s: m['decoys']['extended_routes'][0].update(status='ready'),
                     lambda m, s: m['decoys']['extended_routes'].pop(),
                     lambda m, s: m['decoys']['extended_routes'].append(copy.deepcopy(m['decoys']['extended_routes'][0])),
                     lambda m, s: m['protocols'][0]['public_endpoints'][1].update(port=9443),
                     lambda m, s: m['protocols'][0].update(backend_tls_policy={'ca_file': '/cert/changed.pem'})]
        for field, value in (('kind', 'symlink'), ('mode', 0o644), ('uid', 1), ('gid', 1),
                             ('path', '/etc/example/naive-8.caddyfile')):
            mutations.append(lambda m, s, f=field, v=value: s[7]['naive_source_metadata'].update({f: v}))
        for mutate in mutations:
            manifest, material = copy.deepcopy(original), copy.deepcopy(original_material)
            mutate(manifest, material)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                renderers.render_haproxy(manifest, material)

    def test_empty_cached_routes_still_require_source_and_derive_candidate(self):
        manifest, _, material = common_fixture()
        manifest['decoys']['extended_routes'] = []
        self.assertIn('frontend lucx_naive_split_7_443', renderers.render_haproxy(manifest, material))
        with self.assertRaises(ValueError):
            renderers.render_haproxy(manifest)

    def test_unknown_third_participant_cannot_be_filtered_out_of_runtime(self):
        manifest, audit, material = common_fixture()
        unknown = copy.deepcopy(manifest['protocols'][1])
        unknown.update(inbound_id=9, protocol='unknown', domain='unknown.example.test',
                       sni_names=['unknown.example.test'], internal_port=20443)
        manifest['protocols'].append(unknown)
        manifest['decoys']['extended_routes'] = extended_decoys.classify_extended_decoy_routes(manifest, audit)
        with self.assertRaises(ValueError):
            renderers.frontend_listener_inventory(manifest, routing_material=material)

    def test_original_source_cannot_be_a_copied_material_or_runtime_destination(self):
        manifest, audit, material = common_fixture()
        source = material[7]['naive_source_metadata']['path']
        keys = renderers.frontend_listener_inventory(manifest, routing_material=material)
        runtime = RenderRuntime({key: SocketAddress('127.0.0.1', 31000 + index) for index, key in enumerate(keys)},
                                {manifest['certificates']['cert_path']: source})
        with self.assertRaises(ValueError):
            renderers.render_haproxy(manifest, material, runtime=runtime)
        manifest['protocols'][0]['backend_tls_policy'] = {'ca_file': source}
        manifest['decoys']['extended_routes'] = extended_decoys.classify_extended_decoy_routes(manifest, audit)
        with self.assertRaises(ValueError):
            renderers.frontend_material_inventory(manifest, routing_material=material)
        with self.assertRaises(ValueError):
            renderers.render_haproxy(manifest, material)


class NaiveConnectCandidateTests(unittest.TestCase):
    def test_general_classifier_exposes_exact_candidate_without_claiming_ready(self):
        manifest, audit, _ = candidate_fixture()
        expected = extended_decoys.classify_naive_connect_candidate(manifest, audit, 7)
        actual = extended_decoys.classify_extended_decoy_routes(manifest, audit)
        self.assertEqual(actual, [expected])
        self.assertEqual(actual[0]['status'], 'rendered_candidate')
        self.assertFalse(actual[0]['managed'])

    def apis(self):
        classifier = getattr(extended_decoys, "classify_naive_connect_candidate", None)
        renderer = getattr(renderers, "render_naive_connect_candidate", None)
        self.assertTrue(callable(classifier), "Нет явного классификатора кандидата Naive CONNECT")
        self.assertTrue(callable(renderer), "Нет изолированного renderer Naive CONNECT")
        return classifier, renderer

    def runtime_fixture(self, candidate):
        self.assertIn("runtime", inspect.signature(renderers.render_naive_connect_candidate).parameters,
            "Нужна явная типизированная подстановка Naive candidate")
        return RenderRuntime({ListenerKey("public", 443): SocketAddress("127.0.0.2", 31001),
            ListenerKey("public", 8443): SocketAddress("::1", 31002),
            ListenerKey("decoy_h2c"): SocketAddress("::1", 31100)},
            paths={"/etc/lucx-post-configurator/tls/certificate.pem": "/private/staging/frontend.pem",
                candidate["backend_tls_policy"]["ca_file"]: "/private/staging/backend-ca.pem"},
            foreground=True, suppress_system_log=True)

    def test_legacy_listen_ports_preserve_pre_runtime_bytes(self):
        classifier, renderer = self.apis()
        manifest, audit, material = candidate_fixture()
        candidate = classifier(manifest, audit, 7)
        text = renderer(manifest, candidate, material, listen_ports={443: 25443, 8443: 26443})
        # Снято с прежнего candidate renderer до изменения API/helper.
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),
            "6f03133d53c38113e5bba9cdf6ec6798d50dbccb7800e475670f0d96f80395c3")

    def test_runtime_moves_only_frontend_site_and_exact_materials_without_mutating_inputs(self):
        classifier, renderer = self.apis()
        manifest, audit, material = candidate_fixture()
        candidate = classifier(manifest, audit, 7)
        runtime = self.runtime_fixture(candidate)
        before = copy.deepcopy((manifest, candidate, material))
        listeners, paths = dict(runtime.listeners), dict(runtime.paths)
        text = renderer(manifest, candidate, material, runtime=runtime)
        self.assertIn("bind 127.0.0.2:31001 ssl crt /private/staging/frontend.pem", text)
        self.assertIn("bind [::1]:31002 ssl crt /private/staging/frontend.pem", text)
        self.assertIn("backend naive_site\n    mode http\n    server existing [::1]:31100 proto h2", text)
        self.assertIn("server existing 127.0.0.1:18443 ssl verify required ca-file /private/staging/backend-ca.pem "
            "verifyhost vpn.example.test sni str(vpn.example.test) alpn h2 proto h2", text)
        for value in ("synthetic-user", "synthetic-secret", "basic_auth", material["naive_source_metadata"]["path"]):
            self.assertNotIn(value, text)
        self.assertEqual((manifest, candidate, material), before)
        self.assertEqual((dict(runtime.listeners), dict(runtime.paths)), (listeners, paths))

    def test_runtime_http_authorities_keep_original_ports_and_connect_destination_guards(self):
        classifier, renderer = self.apis()
        manifest, audit, material = candidate_fixture()
        candidate = classifier(manifest, audit, 7)
        text = renderer(manifest, candidate, material, runtime=self.runtime_fixture(candidate))
        for public, staging, names in ((443, 31001, ["alias.example.test", "vpn.example.test"]),
                                      (8443, 31002, ["alias.example.test"])):
            frontend = text.split(f"frontend naive_candidate_{public}\n", 1)[1].split("\nfrontend ", 1)[0]
            host_lines = "\n".join(line for line in frontend.splitlines() if " hdr(host) " in line)
            for name in names:
                self.assertIn(f"{name} {name}:{public}", host_lines)
                self.assertNotIn(f"{name}:{staging}", host_lines)
            self.assertIn("deny deny_status 400 if { method CONNECT } !{ ssl_fc_alpn -m str h2 }", frontend)
            self.assertIn("deny deny_status 421 if { method CONNECT } !vpn_sni", frontend)
            self.assertIn("deny deny_status 421 if !{ method CONNECT } !site_host", frontend)
            self.assertIn("deny deny_status 400 if !{ method CONNECT } !{ hdr_cnt(host) eq 1 }", frontend)
            self.assertIn("use_backend naive_existing if { method CONNECT } vpn_sni", frontend)

    def test_runtime_requires_one_mechanism_exact_roles_and_exact_private_material_paths(self):
        classifier, renderer = self.apis()
        manifest, audit, material = candidate_fixture()
        candidate = classifier(manifest, audit, 7)
        runtime = self.runtime_fixture(candidate)
        for options in ({}, {"runtime": runtime, "listen_ports": {443: 25443, 8443: 26443}},
                        {"runtime": {}}, {"runtime": False}):
            with self.subTest(options=tuple(options)), self.assertRaises(ValueError):
                renderer(manifest, candidate, material, **options)
        for role in (ListenerKey("public", 8443), ListenerKey("decoy_h2c")):
            listeners = dict(runtime.listeners); del listeners[role]
            with self.subTest(missing=role), self.assertRaises(ValueError):
                renderer(manifest, candidate, material, runtime=RenderRuntime(listeners, runtime.paths))
        for role in (ListenerKey("split", 7), ListenerKey("decoy_tls"), ListenerKey("public", 9443)):
            listeners = {**runtime.listeners, role: SocketAddress("127.0.0.1", 31200)}
            with self.subTest(extra=role), self.assertRaises(ValueError):
                renderer(manifest, candidate, material, runtime=RenderRuntime(listeners, runtime.paths))
        certificate = "/etc/lucx-post-configurator/tls/certificate.pem"
        source_path = material["naive_source_metadata"]["path"]
        paths_cases = [{}, {certificate: "/private/staging/frontend.pem"},
            {**runtime.paths, source_path: "/private/staging/source"},
            {**runtime.paths, "/etc/example/auth.json": "/private/staging/auth"},
            {**runtime.paths, certificate + ".key": "/private/staging/frontend.pem.key"},
            {**runtime.paths, certificate: certificate}, {**runtime.paths, certificate: source_path}]
        for paths in paths_cases:
            with self.subTest(paths=tuple(paths)), self.assertRaises(ValueError):
                renderer(manifest, candidate, material, runtime=RenderRuntime(runtime.listeners, paths))

    def test_runtime_all_listener_roles_avoid_original_reserved_ports(self):
        classifier, renderer = self.apis()
        manifest, audit, material = candidate_fixture()
        candidate = classifier(manifest, audit, 7)
        runtime = self.runtime_fixture(candidate)
        for role in runtime.listeners:
            for port in sorted(reserved_listener_ports(manifest)):
                listeners = {**runtime.listeners, role: SocketAddress("127.0.0.1", port)}
                with self.subTest(role=role, reserved_port=port), self.assertRaises(ValueError):
                    renderer(manifest, candidate, material, runtime=RenderRuntime(listeners, runtime.paths))
        listeners = {**runtime.listeners, ListenerKey("decoy_h2c"): SocketAddress("::1", 31001)}
        with self.assertRaises(ValueError):
            renderer(manifest, candidate, material, runtime=RenderRuntime(listeners, runtime.paths))

    def test_runtime_ca_mapping_is_bound_to_the_fresh_candidate(self):
        classifier, renderer = self.apis()
        manifest, audit, material = candidate_fixture()
        original = classifier(manifest, audit, 7)
        runtime = self.runtime_fixture(original)
        manifest["protocols"][0]["backend_tls_policy"] = {"ca_file": "/cert/existing-naive-ca.pem"}
        candidate = classifier(manifest, audit, 7)
        with self.assertRaises(ValueError):
            renderer(manifest, candidate, material, runtime=runtime)
        text = renderer(manifest, candidate, material, runtime=self.runtime_fixture(candidate))
        self.assertIn("ca-file /private/staging/backend-ca.pem", text)
        with self.assertRaises(ValueError):
            renderer(manifest, original, material, runtime=runtime)

    def test_runtime_does_not_treat_original_naive_source_as_ca_material(self):
        classifier, renderer = self.apis()
        manifest, audit, material = candidate_fixture()
        manifest["protocols"][0]["backend_tls_policy"] = {
            "ca_file": material["naive_source_metadata"]["path"]}
        candidate = classifier(manifest, audit, 7)
        with self.assertRaises(ValueError):
            renderer(manifest, candidate, material, runtime=self.runtime_fixture(candidate))

    def test_candidate_never_becomes_ready_or_managed_from_source_or_version(self):
        classifier, _ = self.apis()
        manifest, audit, _ = candidate_fixture()
        manifest["haproxy_version"] = "3.0.26"
        candidate = classifier(manifest, audit, 7)
        self.assertEqual(candidate["status"], "rendered_candidate")
        self.assertEqual(candidate["strategy"], "naive_connect_h2")
        self.assertFalse(candidate["managed"])
        self.assertTrue(candidate["preflight_required"])
        self.assertEqual({item[0] for item in candidate["public_ingresses"]}, {443, 8443})
        records = classify_decoy_capabilities(manifest, audit)
        self.assertTrue(all(not row["managed"] for row in records if row["domain"] != "example.test"))

    def test_staging_renderer_has_fixed_backend_and_never_exports_source_auth(self):
        classifier, renderer = self.apis()
        manifest, audit, material = candidate_fixture()
        candidate = classifier(manifest, audit, 7)
        text = renderer(manifest, candidate, material, listen_ports={443: 25443, 8443: 26443})
        self.assertIn("bind 127.0.0.1:25443 ssl", text)
        self.assertIn("bind 127.0.0.1:26443 ssl", text)
        self.assertIn("server existing 127.0.0.1:18443 ssl verify required", text)
        self.assertIn("verifyhost vpn.example.test sni str(vpn.example.test) alpn h2 proto h2", text)
        self.assertNotIn("synthetic-user", text)
        self.assertNotIn("synthetic-secret", text)
        self.assertNotIn("basic_auth", text)
        self.assertNotIn("set-dst", text)
        self.assertIn("use_backend naive_existing if { method CONNECT }", text)
        self.assertIn("default_backend naive_site", text)

    def test_each_changed_endpoint_transport_source_or_metadata_invalidates_candidate(self):
        classifier, renderer = self.apis()
        original, audit, material = candidate_fixture()
        candidate = classifier(original, audit, 7)
        mutations = [
            lambda m, s: m["protocols"][0]["public_endpoints"][1].update(port=9443),
            lambda m, s: m["protocols"][0].update(transport="ws"),
            lambda m, s: m["protocols"][0].update(internal_port=19443),
            lambda m, s: s.update(naive_caddyfile_text=SOURCE + "# drift"),
            lambda m, s: s["naive_source_metadata"].update(mode=0o644),
            lambda m, s: s["naive_source_metadata"].update(uid=1),
        ]
        for mutate in mutations:
            manifest, changed_material = copy.deepcopy(original), copy.deepcopy(material)
            mutate(manifest, changed_material)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                renderer(manifest, candidate, changed_material, listen_ports={443: 25443, 8443: 26443})

    def test_unverified_topology_or_source_never_renders_candidate(self):
        classifier, _ = self.apis()
        for field, value in (("protocol", "vless"), ("transport", "ws"), ("network", "udp"),
                             ("internal_host", "192.0.2.10"), ("alpn", ["h3"])):
            manifest, audit, _ = candidate_fixture()
            manifest["protocols"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                classifier(manifest, audit, 7)
        manifest, audit, _ = candidate_fixture()
        for field, value in (("path", "/etc/example/naive-8.caddyfile"), ("kind", "symlink"),
                             ("sha256", "missing"), ("capabilities", {})):
            changed = copy.deepcopy(audit)
            changed.naive_caddyfile["files"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                classifier(manifest, changed, 7)

    def test_candidate_requires_all_disjoint_staging_ports_and_strict_tls(self):
        classifier, renderer = self.apis()
        manifest, audit, material = candidate_fixture()
        candidate = classifier(manifest, audit, 7)
        for mapping in ({443: 25443}, {443: 25443, 8443: 25443}, {443: 443, 8443: 26443},
                        {443: 18443, 8443: 26443}, {443: True, 8443: 26443}):
            with self.subTest(mapping=mapping), self.assertRaises(ValueError):
                renderer(manifest, candidate, material, listen_ports=mapping)
        manifest["protocols"][0]["backend_tls_policy"] = {"verify": "none"}
        with self.assertRaises(ValueError):
            classifier(manifest, audit, 7)

    def test_existing_native_fallback_is_not_replaced_by_candidate(self):
        classifier, _ = self.apis()
        manifest, audit, _ = candidate_fixture()
        audit.naive_caddyfile["files"][0]["capabilities"]["native_decoy"] = True
        self.assertEqual(extended_decoys.classify_extended_decoy_routes(manifest, audit)[0]["strategy"], "naive_native")
        with self.assertRaises(ValueError):
            classifier(manifest, audit, 7)

    def test_verified_candidate_can_render_but_forged_ready_is_rejected(self):
        classifier, renderer = self.apis()
        for status in ("rendered_candidate", "ready"):
            manifest, audit, material = candidate_fixture()
            candidate = classifier(manifest, audit, 7)
            candidate.update(status=status, managed=status == "ready")
            manifest["decoys"]["extended_routes"] = [candidate]
            if status == 'rendered_candidate':
                self.assertIn('frontend lucx_naive_split_7_443', renderers.render_haproxy(manifest, {7: material}))
            else:
                with self.assertRaises(ValueError):
                    renderers.render_haproxy(manifest, {7: material})
            records = classify_decoy_capabilities(manifest, audit)
            self.assertTrue(all(not row["managed"] for row in records if row["domain"] != "example.test"))
            if status == "ready":
                with self.assertRaises(ValueError):
                    renderer(manifest, candidate, material, listen_ports={443: 25443, 8443: 26443})

    def test_certificate_site_listener_and_full_transport_fingerprint_are_bound(self):
        classifier, renderer = self.apis()
        original, audit, material = candidate_fixture()
        candidate = classifier(original, audit, 7)
        for change in (
            lambda m: m["certificates"].update(cert_path="/cert/changed.pem"),
            lambda m: m["decoys"].update(listen_port=25000),
            lambda m: m["protocols"][0].update(transport_details={"stream_fingerprint": "sha256:" + "a" * 64}),
        ):
            manifest = copy.deepcopy(original)
            change(manifest)
            self.assertNotEqual(candidate["candidate_fingerprint"], classifier(manifest, audit, 7)["candidate_fingerprint"])
            with self.assertRaises(ValueError):
                renderer(manifest, candidate, material, listen_ports={443: 25443, 8443: 26443})

    def test_unknown_or_contradictory_wrapper_is_not_guessed_from_review_flag(self):
        classifier, _ = self.apis()
        for details in (
            {"new_wrapper": {}}, {"requires_adapter_review": False, "masks": {"present": True}},
            {"extra": {"present": False, "keys": ["downloadSettings"]}},
            {"masks": {"present": False, "tcp_types": ["unknown"]}},
            {"settings_keys": ["header"]}, {"unsupported_settings": ["header"]},
            {"unknown_stream_fields": ["future"]}, {"conflicting_settings_alias": True},
        ):
            manifest, audit, _ = candidate_fixture()
            manifest["protocols"][0]["transport_details"] = details
            with self.subTest(details=details), self.assertRaises(ValueError):
                classifier(manifest, audit, 7)
        for field, value in (("transport_path", "/unverified"), ("transport_mode", "future"),
                             ("transport_hosts", ["vpn.example.test"])):
            manifest, audit, _ = candidate_fixture()
            manifest["protocols"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                classifier(manifest, audit, 7)


if __name__ == "__main__":
    unittest.main()
