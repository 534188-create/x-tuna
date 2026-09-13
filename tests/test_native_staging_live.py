"""Общий coordinator: исходный LucX Naive bridge, VLESS/WS и все сайты."""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import os
import sys
import tempfile
import unittest
import uuid
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import staging_frontend_fixture as frontend
import test_naive_native as native_fixture
from test_naive_candidate_live import BACKEND_CA, DOCUMENTATION_ECHO, HAPROXY
from test_naive_probes_live import CADDY, CADDY_HASH, NAIVE, NAIVE_HASH

from lucx_post_configurator.decoy_capabilities import classify_decoy_capabilities
from lucx_post_configurator.discovery import read_lucx_database
from lucx_post_configurator.engine import _ephemeral_routing_material
from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
from lucx_post_configurator.integrity import capture_integrity
from lucx_post_configurator.naive_probes import NaiveProbeCredential
from lucx_post_configurator.renderers import render_files
from lucx_post_configurator.routing_profiles import (
    inbound_routing_metadata,
    routing_fingerprint,
)
from lucx_post_configurator.runner import Runner
from lucx_post_configurator.staging_integrity import capture_staged_candidate
from lucx_post_configurator.staging_native import NativeStagingSet
from lucx_post_configurator.staging_probes import (
    StagingCredentialSet,
    StagingPreflight,
    StagingTools,
    prepare_functional_staging,
    run_functional_staging,
)
from lucx_post_configurator.staging_processes import ServiceIdentity
from lucx_post_configurator.vpn_probes import XrayProbeCredential


class NativeStagingCoordinatorLiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (sys.platform != 'linux' or os.environ.get('XTUNA_TEST_CADDY') != str(CADDY)
                or os.environ.get('XTUNA_TEST_NAIVE_BRIDGE') != '1'
                or os.environ.get('XTUNA_TEST_DOCUMENTATION_ECHO') != DOCUMENTATION_ECHO):
            raise unittest.SkipTest('Нужен отдельный Debian native staging fixture')
        for path, digest in ((CADDY, CADDY_HASH), (NAIVE, NAIVE_HASH),
                             (frontend.XRAY, frontend.XRAY_SHA256)):
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise AssertionError('Не подтверждён тестовый binary')

    def exercise(self, *, wrong_native_ca=False, genuine_preflight=False):
        import pwd
        helper = native_fixture.NativeSourceLiveTests()
        self.addCleanup(helper.doCleanups)
        domains = (*frontend.DOMAINS, 'xray.example.test')
        with tempfile.TemporaryDirectory(prefix='native-coordinator-') as directory, ExitStack() as stack:
            root = Path(directory)
            root.chmod(0o711)
            fs = frontend.create_sources(root, domains=domains)
            with frontend.reservations(2) as ports:
                bridge_port, xray_port = ports
            password = 'abcdefghijklmnopqrstuvwx'
            bridge_config = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1',
                'port': bridge_port, 'protocol': 'socks', 'settings': {'auth': 'password',
                    'accounts': [{'user': 'lucx', 'pass': password}], 'udp': False}}],
                'outbounds': [{'protocol': 'freedom', 'settings': {}}]}
            bridge, bridge_fd, bridge_digest = stack.enter_context(frontend.existing_backend(bridge_config))
            actual, _, caddy, native_ca = stack.enter_context(helper.fixture(
                f'socks5://lucx:{password}@127.0.0.1:{bridge_port}', resistance=True))
            # Fixture создаёт именно Host LucX: alias не подставляется в protocol вручную.
            actual.sql("INSERT INTO hosts VALUES (2,7,'alias.example.test',8443,'',1,0,'',0,'same')")
            user_id = str(uuid.uuid4())
            case = {'protocol': 'vless', 'transport': 'ws', 'path': '/vpn', 'mode': ''}
            xray_config = frontend.backend_config(case, user_id, xray_port, fs)
            client = {'id': user_id, 'email': 'synthetic-xray-client', 'enable': True,
                      'totalGB': 0, 'expiryTime': 0, 'limitIp': 0, 'flow': '', 'security': 'auto'}
            settings = {'clients': [client], 'decryption': 'none', 'encryption': 'none'}
            stream = xray_config['inbounds'][0]['streamSettings']
            stream['tlsSettings'].update(serverName='xray.example.test', settings={},
                certificates=[{'certificateFile': str(fs.path(frontend.CERT)),
                               'keyFile': str(fs.path(frontend.KEY))}])
            xray_config['inbounds'][0]['settings'] = settings
            actual.sql('INSERT INTO inbounds (id,protocol,enable,listen,port,settings,stream_settings,'
                'share_addr,total,expiry_time,node_id,origin_node_guid,traffic_reset,traffic_reset_day,up,down,tag) '
                "VALUES (8,'vless',1,'127.0.0.1',?,?,?,'xray.example.test',0,0,NULL,'','never',1,0,0,'synthetic-xray')",
                (xray_port, json.dumps(settings), json.dumps(stream)))
            actual.sql("INSERT INTO hosts VALUES (3,8,'xray.example.test',443,'',1,0,'',0,'same')")
            actual.sql("INSERT INTO clients VALUES (3,'synthetic-xray-client',?,1,0,0,'','auto',0,0,0,0,0,'never',1,0,'',0,0)",
                       (user_id,))
            actual.sql("INSERT INTO client_inbounds VALUES (3,8,'',0)")
            actual.sql("INSERT INTO client_traffics VALUES (3,8,'synthetic-xray-client',1,0,0,0,0,0,0,0,0,0)")
            actual.refresh_manifest()
            actual.audit.naive_caddyfile['files'][0]['path'] = str(actual.caddy_path)
            actual.audit.public_addresses = [DOCUMENTATION_ECHO]
            native_protocol = actual.protocol
            native_protocol['backend_tls_policy'] = {'ca_file': BACKEND_CA}
            manifest = frontend.make_manifest(case, xray_port)
            _, inbounds, supported, warnings = read_lucx_database(actual.fs, actual.db_path)
            self.assertTrue(supported)
            self.assertEqual(warnings, [])
            item = next(value for value in inbounds if value.id == 8)
            xray_protocol = dict(inbound_id=item.id, protocol=item.protocol, network=item.network,
                security=item.security, exposure='tcp_sni', domain=item.share_addr,
                internal_host=item.listen, internal_port=item.port, public_port=item.suggested_public_port,
                sni_names=item.server_names, port_bindings=item.port_bindings,
                backend_tls_policy={'ca_file': frontend.CA}, **inbound_routing_metadata(item))
            manifest['protocols'] = [native_protocol, xray_protocol]
            manifest['lucx']['db_path'] = actual.db_path
            manifest['decoys']['sites'].append({'domain': 'xray.example.test',
                                               'root': '/var/www/lucx-decoys/xray.example.test'})
            manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(manifest, actual.audit)
            manifest['decoys']['capabilities'] = classify_decoy_capabilities(manifest, actual.audit)
            routing_material = _ephemeral_routing_material(actual.fs, actual.audit, manifest)
            frontend._write(fs, BACKEND_CA,
                fs.path(frontend.CA).read_bytes() if wrong_native_ca else native_ca.encode())
            xray, xray_fd, xray_digest = stack.enter_context(frontend.existing_backend(xray_config))
            originals = frontend.source_snapshot(fs, domains=domains)
            original_native = actual.snapshot()
            original_configs = copy.deepcopy((manifest, routing_material, bridge_config, xray_config))
            native = NativeStagingSet.capture(actual.fs, manifest, actual.audit)
            generated = render_files(manifest, routing_material=routing_material)
            for site in manifest['decoys']['sites']:
                generated.pop(site['root'] + '/index.html', None)
            run_id = 'native-coordinator-' + uuid.uuid4().hex
            staged = frontend.stage_files(fs, generated, run_id)
            seal = capture_staged_candidate(fs, manifest, generated, staged, run_id)
            snapshot = {str(p['inbound_id']): routing_fingerprint(p, 443) for p in manifest['protocols']}
            account = pwd.getpwnam('haproxy')
            paths = {**frontend.FRONTENDS, 'haproxy': HAPROXY, 'xray': frontend.XRAY,
                     'curl': Path('/usr/bin/curl'), 'naive': NAIVE}
            tools = StagingTools({role: (path, hashlib.sha256(path.read_bytes()).hexdigest())
                                  for role, path in paths.items()}, ServiceIdentity(account.pw_uid, account.pw_gid))

            def credential(protocol):
                if protocol['protocol'] == 'naive':
                    value = native.credential(protocol)
                    return dataclasses.replace(value, ca_pem=fs.path(frontend.CA).read_text()) if value else None
                return XrayProbeCredential(user_id, routing_fingerprint(protocol, 443),
                    fs.path(frontend.CA).read_text(), 'sha256:' + 'a' * 64)

            class ObservedRunner(Runner):
                calls = 0

                def __init__(self):
                    super().__init__()
                    self.summaries = []

                def run_bounded(self, args, **options):
                    self.calls += 1
                    result = super().run_bounded(args, **options)
                    value = json.loads(result.stdout) if result.stdout else {}
                    summary = {'returncode': result.returncode, 'ok': value.get('ok') is True}
                    for key in ('direct_rows', 'vpn_rows', 'browser_rows'):
                        rows = value.get(key, [])
                        summary[key] = [(index, row.get('inbound_id'),
                                         row.get('state') if row.get('state') in {'healthy', 'failed', 'not_tested', 'skipped'} else 'unknown',
                                         row.get('authenticated') is True, row.get('content_verified') is True)
                                        for index, row in enumerate(rows)]
                    self.summaries.append(summary)
                    return result

            runner = ObservedRunner()
            options = {'staged_seal': seal, 'routing_snapshot': snapshot, 'routing_material': routing_material,
                'tools': tools, 'credential_source': credential, 'native_sources': native,
                'temporary_parent': root, 'browser_ca_source': frontend.CA}
            if genuine_preflight:
                tools.verify()
                with mock.patch('lucx_post_configurator.staging_probes.installed_staging_tools',
                                return_value=tools) as installed:
                    preflight = prepare_functional_staging(actual.fs, runner, manifest,
                        audit=actual.audit, routing_material=routing_material)
                installed.assert_called_once_with(include_naive=True)
                self.assertIs(type(preflight), StagingPreflight)
                self.assertIs(type(preflight.credentials), StagingCredentialSet)
                self.assertIs(type(preflight.native_sources), NativeStagingSet)
                self.assertEqual(set(preflight.native_sources.bindings), {7})
                values = list(preflight.credentials.entries.values())
                self.assertEqual(len(values), 3)
                self.assertEqual(sum(type(value) is NaiveProbeCredential for value in values), 2)
                self.assertEqual(sum(type(value) is XrayProbeCredential for value in values), 1)
                selected = next(value for value in values if type(value) is XrayProbeCredential)
                self.assertEqual(selected.user_id, user_id)
                self.assertTrue(all(value.ca_pem == '' for value in values))
                for value in values:
                    self.assertRegex(value.policy_fingerprint, r'^sha256:[0-9a-f]{64}$')
                preflight.verify(manifest, routing_material=routing_material)
                with_integrity = copy.deepcopy(manifest)
                with_integrity['integrity'] = capture_integrity(actual.fs, actual.db_path, actual.audit.naive_caddyfile)
                preflight.verify(with_integrity, routing_material=routing_material)
                self.assertEqual(runner.calls, 0, 'Preflight не должен запускать coordinator')
            elif wrong_native_ca:
                with self.assertRaises(ValueError):
                    run_functional_staging(fs, runner, manifest, generated, staged, run_id, **options)
                self.assertGreater(runner.calls, 0, 'Отрицательный тест обязан дойти до общего child coordinator')
                receipt = runner.summaries[-1]
                self.assertTrue(receipt['ok'])
                self.assertEqual(len(receipt['direct_rows']), 3)
                self.assertTrue(all(row[2] == 'healthy' for row in receipt['direct_rows']))
                self.assertEqual(len(receipt['vpn_rows']), 3)
                self.assertTrue(all(row[2] != 'healthy' for row in receipt['vpn_rows'] if row[1] == 7))
                self.assertTrue(all(row[2] == 'healthy' for row in receipt['vpn_rows'] if row[1] == 8))
                self.assertEqual(len(receipt['browser_rows']), 44)
                self.assertTrue(all(row[2] == 'healthy' and row[4] for row in receipt['browser_rows']))
            else:
                try:
                    proof = run_functional_staging(fs, runner, manifest, generated, staged, run_id, **options)
                except ValueError:
                    self.fail('Общий coordinator отказал: ' + json.dumps(runner.summaries))
                self.assertIs(proof.summary.get('candidate_verified'), True)
                self.assertIs(proof.summary.get('public'), False)
                self.assertIs(proof.summary.get('direct_verified'), True)
                self.assertEqual(proof.summary.get('verified_sites'), 4)
                self.assertEqual(proof.summary.get('verified_endpoints'), 3)
                self.assertEqual(len(runner.summaries[-1]['browser_rows']), 44)
                proof.verify(fs, manifest, generated, staged, staged_seal=seal,
                             routing_snapshot=snapshot, routing_material=routing_material)
            self.assertEqual((manifest, routing_material, bridge_config, xray_config), original_configs)
            self.assertEqual(frontend.source_snapshot(fs, domains=domains), originals)
            self.assertEqual(actual.snapshot(), original_native)
            for process in (bridge, xray, caddy):
                self.assertIsNone(process.poll(), 'Исходный backend был завершён')
            for descriptor, config, digest in ((bridge_fd, bridge_config, bridge_digest),
                                                (xray_fd, xray_config, xray_digest)):
                self.assertEqual(hashlib.sha256(os.pread(descriptor, len(frontend._encoded(config)) + 1, 0)).hexdigest(), digest)
            self.assertEqual({path.name for path in root.iterdir()}, {'source'}, 'Private staging не очищен')

    def test_whole_native_xray_candidate_and_all_sites_are_verified(self):
        self.exercise()

    def test_genuine_preflight_reads_whole_db_cohort_and_survives_integrity_capture(self):
        self.exercise(genuine_preflight=True)

    def test_wrong_native_ca_blocks_whole_candidate_without_subset_pass(self):
        self.exercise(wrong_native_ca=True)


if __name__ == '__main__':
    unittest.main()
