"""Штатно сгенерированные HAProxy/Nginx и настоящий synthetic existing Xray."""
from __future__ import annotations

import json
import unittest

import staging_frontend_fixture as fixture

from lucx_post_configurator.render_runtime import (
    ListenerKey,
    RenderRuntime,
    SocketAddress,
)
from lucx_post_configurator.renderers import (
    frontend_listener_inventory,
    render_haproxy,
    render_nginx_decoys,
)
from lucx_post_configurator.vpn_probes import _simple_profile


class FrontendFixtureContractTests(unittest.TestCase):
    def test_declared_matrix_contains_every_requested_protocol_transport_mode_and_root(self):
        actual = {(case['protocol'], case['transport'], case['mode'], case['path']) for case in fixture.cases()}
        expected = {(protocol, transport, '', path) for protocol in ('vless', 'vmess')
                    for transport, path in (('ws', '/vpn'), ('httpupgrade', '/vpn'), ('grpc', 'FixtureService'),
                                            ('ws', '/'), ('httpupgrade', '/'))}
        expected.update((protocol, 'xhttp', mode, '/vpn') for protocol in ('vless', 'vmess')
                        for mode in ('auto', 'packet-up', 'stream-up', 'stream-one'))
        self.assertEqual(actual, expected)
        self.assertEqual(len(fixture.cases()), 18)

    def test_every_fixture_is_supported_and_preserves_original_endpoint_and_backend(self):
        for case in fixture.cases():
            with self.subTest(case=case['name']):
                manifest = fixture.make_manifest(case, 18443)
                original = json.dumps(manifest, sort_keys=True)
                self.assertTrue(_simple_profile(manifest['protocols'][0]))
                keys = frontend_listener_inventory(manifest)
                self.assertEqual(set(keys), {ListenerKey('public', 443), ListenerKey('public', 8443),
                    ListenerKey('split', 7), ListenerKey('decoy_tls'), ListenerKey('decoy_h2c'), ListenerKey('decoy_plain')})
                runtime = RenderRuntime({key: SocketAddress('127.0.0.1', 41000 + index) for index, key in enumerate(keys)},
                                        foreground=True, suppress_system_log=True)
                haproxy = render_haproxy(manifest, runtime=runtime)
                render_nginx_decoys(manifest, runtime=runtime)
                self.assertIn('127.0.0.1:18443', haproxy)
                self.assertIn('verify required ca-file /cert/ca.pem', haproxy)
                self.assertEqual(json.dumps(manifest, sort_keys=True), original)

    def test_safe_failure_does_not_serialize_exception_payload(self):
        payload = 'arbitrary-private-fixture-data'
        result = fixture._safe_failure(ValueError(payload))
        self.assertNotIn(payload, json.dumps(result))
        self.assertEqual(result['kind'], 'ValueError')

    def test_distinct_http_host_override_remains_explicitly_outside_supported_matrix(self):
        manifest = fixture.make_manifest(fixture.cases()[0], 18443)
        manifest['protocols'][0]['public_endpoints'][0]['http_host'] = 'host.example.test'
        manifest['decoys']['extended_routes'] = fixture.classify_extended_decoy_routes(manifest)
        with self.assertRaises(ValueError):
            frontend_listener_inventory(manifest)


class RealStagingFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reason = fixture.prerequisites()
        if reason:
            raise unittest.SkipTest(reason + '; вся матрица 18 cases не проверена')


def _real_test(case):
    def run(self):
        result = fixture.run_case(case)
        self.assertTrue(result.get('passed'), json.dumps(result, ensure_ascii=True, sort_keys=True))
        self.assertEqual(result['browser_rows'], 34)
        self.assertEqual(result['vpn_rows'], 2)
        self.assertEqual(result['summary']['verified_sites'], 3)
        self.assertEqual(result['summary']['verified_endpoints'], 2)
        self.assertFalse(result['summary']['public'])
        self.assertTrue(result['existing_backend_preserved'])
    return run


for _case in fixture.cases():
    setattr(RealStagingFrontendTests, 'test_' + _case['name'], _real_test(_case))


if __name__ == '__main__':
    unittest.main()
