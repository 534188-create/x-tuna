from __future__ import annotations
import copy
import json
import unittest
from unittest import mock
from lucx_post_configurator import decoy_health as health
from lucx_post_configurator.models import default_manifest
from lucx_post_configurator.runner import Runner


def strict_manifest():
    manifest = default_manifest()
    manifest['decoys'].update(enabled=True, require_full_acceptance=True,
                             sites=[{'domain':'site.example.test'}])
    manifest['protocols'] = [{
        'inbound_id':7, 'protocol':'vless', 'exposure':'tcp_sni', 'transport':'ws',
        'security':'tls', 'transport_path':'/vpn', 'transport_mode':'', 'alpn':['http/1.1'],
        'public_endpoints':[
            {'host_id':1, 'address':'one.example.test', 'port':443, 'sni':'one.example.test',
             'sni_source':'address', 'keep_sni_blank':False, 'http_host':'', 'valid':True},
            {'host_id':2, 'address':'two.example.test', 'port':8443, 'sni':'two.example.test',
             'sni_source':'explicit', 'keep_sni_blank':False, 'http_host':'', 'valid':True},
        ],
    }]
    return manifest


def functional_result(protocol, runner):
    return {**protocol['acceptance_target'], 'state':'healthy', 'functional':True,
            'phase':protocol.get('acceptance_phase', 'public'),
            'public':True, 'authenticated':True, 'bytes_sent':16, 'bytes_received':32}


class RequiredAcceptanceTests(unittest.TestCase):
    def test_endpoint_bound_support_is_consistent_before_and_after_commit(self):
        class EndpointObserver:
            def supports(self, protocol):
                return (protocol.get('acceptance_endpoint', {}).get('host_id') in (1, 2)
                        and protocol.get('acceptance_phase') == 'public')

            def __call__(self, protocol, runner):
                return functional_result(protocol, runner)

        manifest, runner = strict_manifest(), Runner()
        runner.vpn_observers = {'vless':EndpointObserver()}
        self.assertEqual(health.required_vpn_probe_errors(manifest, runner), [])
        rows = health.observe_vpn_capabilities(manifest, runner)
        self.assertTrue(health.vpn_acceptance_summary(manifest, rows)['complete'])

    def test_missing_adapter_prerequisites_block_before_commands(self):
        seen = []

        class UnavailableObserver:
            def supports(self, protocol):
                return True

            def preflight(self, protocol, runner):
                seen.append((protocol['acceptance_endpoint']['host_id'], protocol['acceptance_phase']))
                return False

            def __call__(self, protocol, runner):
                raise AssertionError('Проверка доступности не запускает VPN')

        runner = Runner()
        runner.vpn_observers = {'vless':UnavailableObserver()}
        self.assertTrue(health.required_vpn_probe_errors(strict_manifest(), runner))
        self.assertEqual(seen, [(1, 'public'), (2, 'public')])
        self.assertEqual(runner.history, [])

    def test_staging_receipt_cannot_satisfy_public_acceptance(self):
        def observer(protocol, runner):
            return {**functional_result(protocol, runner), 'phase':'staging'}
        rows = health.observe_vpn_capabilities(strict_manifest(), Runner(),
                                               observers={'vless':observer})
        self.assertEqual({row['state'] for row in rows}, {'not_tested'})
        self.assertFalse(health.vpn_acceptance_summary(strict_manifest(), rows)['complete'])

    def test_missing_phase_cannot_satisfy_public_acceptance(self):
        def observer(protocol, runner):
            row = functional_result(protocol, runner)
            row.pop('phase')
            return row
        rows = health.observe_vpn_capabilities(strict_manifest(), Runner(),
                                               observers={'vless':observer})
        self.assertEqual({row['state'] for row in rows}, {'not_tested'})

    def test_unsupported_profile_blocks_precommit_and_does_not_run_observer(self):
        class WebSocketObserver:
            def supports(self, protocol):
                return protocol.get('transport') == 'ws'

            def __call__(self, protocol, runner):
                raise AssertionError('Неподдержанный транспорт не должен запускаться')

        manifest, runner = strict_manifest(), Runner()
        runner.vpn_observers = {'vless':WebSocketObserver()}
        self.assertEqual(health.required_vpn_probe_errors(manifest, runner), [])
        manifest['protocols'][0]['transport'] = 'xhttp'
        self.assertTrue(health.required_vpn_probe_errors(manifest, runner))
        rows = health.observe_vpn_capabilities(manifest, runner)
        self.assertEqual({row['state'] for row in rows}, {'not_tested'})
        self.assertEqual(runner.history, [])

    def test_missing_observers_block_precommit_without_executing_commands(self):
        manifest, runner = strict_manifest(), Runner(dry_run=True)
        self.assertTrue(health.required_vpn_probe_errors(manifest, runner))
        self.assertEqual(runner.history, [])
        observer = mock.Mock(spec=functional_result, side_effect=AssertionError('precommit must not execute probe'))
        runner.vpn_observers = {'vless':observer}
        self.assertEqual(health.required_vpn_probe_errors(manifest, runner), [])
        observer.assert_not_called()

    def test_legacy_manifest_does_not_require_observer_registration(self):
        manifest = strict_manifest()
        manifest['decoys']['require_full_acceptance'] = False
        self.assertEqual(health.required_vpn_probe_errors(manifest, Runner()), [])

    def test_every_public_endpoint_is_observed_and_profile_bound(self):
        manifest, runner, seen = strict_manifest(), Runner(), []
        def observer(protocol, command_runner):
            seen.append(protocol['acceptance_endpoint']['host_id'])
            result = functional_result(protocol, command_runner)
            protocol['public_endpoints'][0]['address'] = 'changed.example.test'
            return result
        runner.vpn_observers = {'vless':observer}
        observations = health.observe_vpn_capabilities(manifest, runner)
        self.assertEqual(seen, [1, 2])
        self.assertEqual(manifest['protocols'][0]['public_endpoints'][0]['address'], 'one.example.test')
        summary = health.vpn_acceptance_summary(manifest, observations)
        self.assertTrue(summary['complete'], summary)
        self.assertEqual(summary['required_endpoints'], 2)
        self.assertEqual(summary['verified_endpoints'], 2)
        self.assertEqual(len({row['endpoint_fingerprint'] for row in observations}), 2)

    def test_missing_duplicate_and_wrong_inbound_receipts_are_not_complete(self):
        manifest = strict_manifest()
        rows = health.observe_vpn_capabilities(manifest, Runner(), observers={'vless':functional_result})
        wrong = copy.deepcopy(rows)
        wrong[0]['inbound_id'] = 8
        for observations in (rows[:1], rows + [copy.deepcopy(rows[0])], wrong):
            with self.subTest(count=len(observations)):
                self.assertFalse(health.vpn_acceptance_summary(manifest, observations)['complete'])

    def test_stale_transport_and_endpoint_receipts_fail(self):
        manifest = strict_manifest()
        rows = health.observe_vpn_capabilities(manifest, Runner(), observers={'vless':functional_result})
        for change in ('mode', 'alpn', 'path', 'port', 'sni', 'address', 'http_host'):
            updated = copy.deepcopy(manifest)
            protocol = updated['protocols'][0]
            if change == 'mode': protocol['transport_mode'] = 'stream-one'
            elif change == 'alpn': protocol['alpn'] = ['h2']
            elif change == 'path': protocol['transport_path'] = '/new-vpn'
            else: protocol['public_endpoints'][0][change] = 9443 if change == 'port' else 'changed.example.test'
            with self.subTest(change=change):
                self.assertFalse(health.vpn_acceptance_summary(updated, rows)['complete'])

    def test_claimed_health_without_functional_public_identity_and_exchange_is_not_tested(self):
        manifest = strict_manifest()
        for field in ('profile_fingerprint', 'endpoint_fingerprint', 'functional', 'public',
                      'authenticated', 'bytes_sent', 'bytes_received'):
            def observer(protocol, runner):
                row = functional_result(protocol, runner)
                row.pop(field)
                return row
            with self.subTest(field=field):
                rows = health.observe_vpn_capabilities(manifest, Runner(), observers={'vless':observer})
                self.assertEqual({row['state'] for row in rows}, {'not_tested'})
                self.assertFalse(health.vpn_acceptance_summary(manifest, rows)['complete'])

    def test_no_adapter_is_not_tested_and_error_details_are_not_exposed(self):
        manifest = strict_manifest()
        rows = health.observe_vpn_capabilities(manifest, Runner())
        self.assertEqual(len(rows), 2)
        self.assertEqual({row['state'] for row in rows}, {'not_tested'})
        def failed(protocol, runner):
            raise RuntimeError('sensitive-sentinel one.example.test /private-token')
        rows = health.observe_vpn_capabilities(manifest, Runner(), observers={'vless':failed})
        rendered = json.dumps(rows) + json.dumps(health.vpn_acceptance_summary(manifest, rows))
        for forbidden in ('sensitive-sentinel','one.example.test','private-token'):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual({row['state'] for row in rows}, {'failed'})

    def test_strict_dry_run_does_not_call_adapter_or_claim_live_success(self):
        observer = mock.Mock(side_effect=functional_result)
        rows = health.observe_vpn_capabilities(strict_manifest(), Runner(dry_run=True),
                                               observers={'vless':observer})
        self.assertEqual({row['state'] for row in rows}, {'not_tested'})
        observer.assert_not_called()

    def test_adapter_result_is_allowlisted_and_non_mapping_is_not_tested(self):
        manifest = strict_manifest()
        def observer(protocol, runner):
            return {**functional_result(protocol, runner), 'credentials':'sensitive-sentinel',
                    'detail':'one.example.test /private-token'}
        rows = health.observe_vpn_capabilities(manifest, Runner(), observers={'vless':observer})
        self.assertTrue(health.vpn_acceptance_summary(manifest, rows)['complete'])
        self.assertNotIn('sensitive-sentinel', json.dumps(rows))
        self.assertNotIn('one.example.test', json.dumps(rows))
        rows = health.observe_vpn_capabilities(manifest, Runner(), observers={'vless':lambda *args: ['healthy']})
        self.assertEqual({row['state'] for row in rows}, {'not_tested'})

    def test_duplicate_host_id_and_non_callable_registration_are_rejected(self):
        manifest, runner = strict_manifest(), Runner()
        runner.vpn_observers = {'vless':'manifest-command-is-not-an-adapter'}
        self.assertTrue(health.required_vpn_probe_errors(manifest, runner))
        runner.vpn_observers = {'vless':functional_result}
        manifest['protocols'][0]['public_endpoints'][1]['host_id'] = 1
        self.assertTrue(health.required_vpn_probe_errors(manifest, runner))

    def test_invalid_duplicate_or_missing_endpoints_block_precommit_and_summary(self):
        for shape in ('missing','invalid','duplicate'):
            manifest, runner = strict_manifest(), Runner()
            endpoints = manifest['protocols'][0]['public_endpoints']
            if shape == 'missing': endpoints.clear()
            elif shape == 'invalid': endpoints[0]['valid'] = False
            else: endpoints.append(copy.deepcopy(endpoints[0]))
            runner.vpn_observers = {'vless':functional_result}
            with self.subTest(shape=shape):
                self.assertTrue(health.required_vpn_probe_errors(manifest, runner))
                self.assertFalse(health.vpn_acceptance_summary(manifest, [])['complete'])

    def test_extra_receipts_and_boolean_byte_counts_cannot_claim_success(self):
        manifest = strict_manifest()
        rows = health.observe_vpn_capabilities(manifest, Runner(), observers={'vless':functional_result})
        extra = copy.deepcopy(rows[0])
        extra['endpoint_fingerprint'] = 'sha256:' + '0' * 64
        self.assertFalse(health.vpn_acceptance_summary(manifest, rows + [extra])['complete'])
        rows[0]['bytes_sent'] = True
        self.assertFalse(health.vpn_acceptance_summary(manifest, rows)['complete'])

    def test_duplicate_and_stale_browser_receipts_do_not_complete_acceptance(self):
        manifest = default_manifest()
        manifest['decoys'].update(enabled=True, require_full_acceptance=True,
                                 sites=[{'domain':'site.example.test'}])
        with mock.patch.object(health, 'observe_decoy', return_value={'state':'healthy', 'status':200, 'detail':'ok',
                'content_verified':True,'body_absence_verified':True,'resources_complete':True,'resource_count':0,'verified_resources':0}):
            rows = health.observe_decoy_capabilities(manifest, '192.0.2.1')
        self.assertTrue(health.decoy_acceptance_summary(manifest, rows)['complete'])
        self.assertFalse(health.decoy_acceptance_summary(manifest, rows + [copy.deepcopy(rows[0])])['complete'])
        manifest['network']['public_tcp_port'] = 8443
        self.assertFalse(health.decoy_acceptance_summary(manifest, rows)['complete'])


if __name__ == '__main__':
    unittest.main()
