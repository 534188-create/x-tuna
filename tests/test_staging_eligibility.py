"""Область первой функциональной staging-пробы: до любых операций."""
from __future__ import annotations

import copy
import importlib
import json
import unittest
from unittest import mock

from test_endpoint_routing import aliased_topology

from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes


def candidate_manifest():
    manifest = aliased_topology(8443)
    manifest['components']['install_packages'] = False
    manifest['decoys']['require_full_acceptance'] = True
    protocol = manifest['protocols'][0]
    protocol.update(alpn=['http/1.1'], transport_mode='', transport_details={})
    for endpoint in protocol['public_endpoints']:
        endpoint.update(sni_source='explicit', keep_sni_blank=False, http_host='')
    manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(manifest)
    return manifest


def two_profile_manifest():
    manifest = candidate_manifest()
    other = copy.deepcopy(manifest['protocols'][0])
    other.update(inbound_id=8, domain='second.example.test', internal_port=19443,
                 sni_names=['second.example.test'],
                 transport_hosts=['second.example.test', 'second-alias.example.test'],
                 port_bindings=[{'port': 19443, 'protocol': 'TCP'}])
    for index, endpoint in enumerate(other['public_endpoints']):
        domain = ('second.example.test', 'second-alias.example.test')[index]
        endpoint.update(host_id=20 + index, address=domain, sni=domain)
        manifest['decoys']['sites'].append({'domain': domain, 'root': '/var/www/lucx-decoys/' + domain})
    manifest['protocols'].append(other)
    manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(manifest)
    return manifest


class StagingEligibilityTests(unittest.TestCase):
    def test_mixed_naive_requires_complete_ephemeral_source_without_io(self):
        from test_naive_connect_frontend import common_fixture
        manifest, _, material = common_fixture()
        manifest['components']['install_packages'] = False
        manifest['decoys']['require_full_acceptance'] = True
        self.assertTrue(self.api.staging_eligibility_errors(manifest))
        before = copy.deepcopy((manifest, material))
        with mock.patch('builtins.open', side_effect=AssertionError('No FS')):
            self.assertEqual(self.api.staging_eligibility_errors(manifest, routing_material=material), ())
        self.assertEqual((manifest, material), before)
        for change in ({'transport': 'raw'}, {'alpn': ['h3']}, {'security': 'reality'}):
            changed = copy.deepcopy(manifest)
            changed['protocols'][0].update(change)
            self.assertTrue(self.api.staging_eligibility_errors(changed, routing_material=material))

    def setUp(self):
        self.api = importlib.import_module('lucx_post_configurator.staging_eligibility')
        self.manifest = candidate_manifest()

    def errors(self, **options):
        return self.api.staging_eligibility_errors(self.manifest, **options)

    def test_simple_complete_profiles_and_aliases_without_io(self):
        for kind in ('vless', 'vmess'):
            for transport, path, alpn in (('ws', '/', ['http/1.1']), ('httpupgrade', '/', ['http/1.1']),
                                          ('grpc', 'VpnService', ['h2']), ('xhttp', '/vpn', ['h2'])):
                for mode in (('',) if transport != 'xhttp' else ('', 'auto', 'packet-up', 'stream-up', 'stream-one')):
                    with self.subTest(kind=kind, transport=transport, mode=mode):
                        self.manifest = candidate_manifest()
                        self.manifest['protocols'][0].update(protocol=kind, transport=transport,
                            transport_path=path, alpn=alpn, transport_mode=mode)
                        self.manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(self.manifest)
                        before = copy.deepcopy(self.manifest)
                        with mock.patch('builtins.open', side_effect=AssertionError('Не читать FS')), \
                                mock.patch('subprocess.Popen', side_effect=AssertionError('Не запускать процесс')):
                            self.assertEqual(self.errors(), ())
                        self.assertEqual(self.manifest, before)

    def test_any_active_unsupported_profile_blocks_the_whole_candidate(self):
        for change in ({'protocol': 'trojan'}, {'protocol': 'naive'}, {'protocol': 'trusttunnel'},
                       {'security': 'reality'}, {'transport': 'raw'}, {'transport': 'tcp'},
                       {'network': 'udp'}, {'transport_mode': 'future'},
                       {'transport_details': {'extra': {'present': True}}}, {'flow': 'future'},
                       {'alpn': ['h2', 'http/1.1']}):
            self.manifest = two_profile_manifest()
            self.assertEqual(self.errors(), (), 'Положительный контроль не должен иметь коллизий')
            self.manifest['protocols'][1].update(change)
            self.manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(self.manifest)
            with self.subTest(change=change):
                self.assertTrue(self.errors())

    def test_missing_duplicate_and_ambiguous_endpoints_are_not_silently_removed(self):
        for change in ('missing', 'duplicate', 'blank_sni', 'unknown_source', 'host_conflict'):
            self.manifest = candidate_manifest()
            protocol = self.manifest['protocols'][0]
            if change == 'missing':
                protocol['public_endpoints'] = []
            elif change == 'duplicate':
                protocol['public_endpoints'].append(copy.deepcopy(protocol['public_endpoints'][0]))
            elif change == 'blank_sni':
                protocol['public_endpoints'][0]['sni'] = ''
            elif change == 'unknown_source':
                protocol['public_endpoints'][0]['sni_source'] = 'ambiguous'
            else:
                protocol['public_endpoints'][0]['http_host'] = 'other.example.test'
            with self.subTest(change=change):
                self.assertTrue(self.errors())

    def test_backend_mutation_flags_block_before_backup(self):
        for field in ('sync_domains', 'sync_panel_path', 'sync_subscription_urls', 'sync_naive_share_addr',
                      'sync_public_endpoints', 'sync_certificate_paths', 'sync_naive_endpoint',
                      'allow_inbound_changes', 'sync_future_setting'):
            self.manifest = candidate_manifest()
            self.manifest['lucx']['settings_management'][field] = True
            with self.subTest(field=field):
                self.assertTrue(self.errors())
        for field in ('sync_public_endpoint', 'sync_naive_endpoint', 'sync_share_addr'):
            self.manifest = candidate_manifest()
            self.manifest['protocols'][0][field] = True
            with self.subTest(field=field):
                self.assertTrue(self.errors())
        self.manifest = candidate_manifest()
        self.manifest['lucx']['inbound_changes'] = [{'inbound_id': 7, 'transport_path': '/changed'}]
        self.assertTrue(self.errors())

    def test_new_services_or_prerequisite_changes_require_a_later_scope(self):
        for field in ('sidecar', 'naive_frontend', 'trusttunnel_backend', 'tls_hook'):
            self.manifest = candidate_manifest()
            self.manifest['components'][field] = True
            with self.subTest(field=field):
                self.assertTrue(self.errors())
        self.manifest = candidate_manifest()
        self.manifest['components']['install_packages'] = True
        self.assertTrue(self.errors())
        self.assertEqual(self.errors(packages_ready=True), ())
        self.assertTrue(self.errors(packages_ready=1))

    def test_disabled_required_components_legacy_mode_and_stale_routes_are_rejected(self):
        for field in ('haproxy', 'nginx', 'extended_tls_split'):
            self.manifest = candidate_manifest()
            self.manifest['components'][field] = False
            with self.subTest(field=field):
                self.assertTrue(self.errors())
        for field, value in (('enabled', False), ('require_full_acceptance', False), ('routing_mode', 'strict'),
                             ('extended_routes', []), ('sites', [])):
            self.manifest = candidate_manifest()
            self.manifest['decoys'][field] = value
            with self.subTest(field=field):
                self.assertTrue(self.errors())

    def test_empty_and_malformed_candidates_fail_without_raw_input(self):
        for candidate in ({}, {'protocols': []}, {'protocols': 'sensitive-sentinel'}, None):
            self.manifest = candidate
            errors = self.errors()
            self.assertTrue(errors)
            self.assertNotIn('sensitive-sentinel', json.dumps(errors))
        self.manifest = candidate_manifest()
        self.manifest['network']['public_tcp_port'] = 'sensitive-sentinel'
        self.assertNotIn('sensitive-sentinel', json.dumps(self.errors()))


if __name__ == '__main__':
    unittest.main()
