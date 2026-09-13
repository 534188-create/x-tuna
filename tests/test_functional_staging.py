"""Настоящий production coordinator на synthetic existing backend Debian 12/13."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path

import staging_frontend_fixture as fixture

from lucx_post_configurator.runner import Runner
from lucx_post_configurator.staging_integrity import capture_staged_candidate
from lucx_post_configurator.staging_probes import (
    StagingCredentialSet,
    StagingPreflight,
    StagingTools,
    run_functional_staging,
)
from lucx_post_configurator.staging_processes import ServiceIdentity
from lucx_post_configurator.vpn_probes import XRAY_SHA256, XrayProbeCredential


class RealFunctionalStagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reason = fixture.prerequisites()
        if reason:
            raise unittest.SkipTest(reason + '; production coordinator не проверен')

    def execute(self, case, *, tamper=None, prepared=False, own_echo=False):
        import pwd
        with tempfile.TemporaryDirectory(prefix='xtuna-coordinator-') as temporary:
            root = Path(temporary)
            root.chmod(0o711)
            fs = fixture.create_sources(root)
            with fixture.reservations(1) as ports:
                port = ports[0]
            manifest = fixture.make_manifest(case, port)
            manifest['components']['install_packages'] = prepared
            generated = fixture.render_files(manifest)
            for site in manifest['decoys']['sites']:
                generated.pop(site['root'] + '/index.html', None)
            run_id = 'coordinator-' + uuid.uuid4().hex
            staged = fixture.stage_files(fs, generated, run_id)
            seal = capture_staged_candidate(fs, manifest, generated, staged, run_id)
            snapshot = {'profile': fixture.routing_fingerprint(manifest['protocols'][0], 443)}
            account = pwd.getpwnam('haproxy')
            paths = {**fixture.FRONTENDS, 'xray': fixture.XRAY, 'curl': Path('/usr/bin/curl')}
            tools = StagingTools({role: (path, hashlib.sha256(path.read_bytes()).hexdigest())
                                  for role, path in paths.items()}, ServiceIdentity(account.pw_uid, account.pw_gid))
            self.assertEqual(tools.binaries['xray'][1], XRAY_SHA256)
            selected = {'id': str(uuid.uuid4()), 'policy': 'sha256:' + 'a' * 64}

            def source(protocol):
                return XrayProbeCredential(selected['id'], fixture.routing_fingerprint(protocol, 443),
                                            fs.path(fixture.CA).read_text(), selected['policy'])

            class ControlledRunner(Runner):
                def run_bounded(self, args, **options):
                    result = super().run_bounded(args, **options)
                    if tamper == 'policy':
                        selected['policy'] = 'sha256:' + 'b' * 64
                    elif tamper == 'site':
                        fs.path(manifest['decoys']['sites'][0]['root'] + '/a.css').write_bytes(b'changed')
                    elif tamper == 'ipc':
                        value = json.loads(result.stdout)
                        value['binding'] = 'sha256:' + '0' * 64
                        result.stdout = json.dumps(value)
                    return result

            config = fixture.backend_config(case, selected['id'], port, fs)
            if own_echo:
                config['outbounds'].append({'tag': 'deny-private', 'protocol': 'blackhole'})
                config['routing'] = {'rules': [{'type': 'field', 'ip': ['127.0.0.0/8'],
                                                'outboundTag': 'deny-private'}]}
            originals = fixture.source_snapshot(fs)
            with fixture.existing_backend(config) as (backend, descriptor, digest):
                if tamper:
                    with self.assertRaises(ValueError):
                        run_functional_staging(fs, ControlledRunner(), manifest, generated, staged, run_id,
                            staged_seal=seal, routing_snapshot=snapshot, tools=tools, credential_source=source,
                            temporary_parent=root, browser_ca_source=fixture.CA)
                else:
                    options = ({'preflight': StagingPreflight(tools,
                                StagingCredentialSet.capture(manifest, source), packages_ready=True)} if prepared else
                               {'tools': tools, 'credential_source': source})
                    if own_echo:
                        options['echo_address'] = os.environ['XTUNA_TEST_DOCUMENTATION_ECHO']
                    proof = run_functional_staging(fs, Runner(), manifest, generated, staged, run_id,
                        staged_seal=seal, routing_snapshot=snapshot,
                        temporary_parent=root, browser_ca_source=fixture.CA, **options)
                    self.assertTrue(proof.summary['candidate_verified'])
                    self.assertFalse(proof.summary['public'])
                    if own_echo:
                        self.assertIs(proof.summary['direct_verified'], True)
                    self.assertEqual(proof.summary['verified_sites'], 3)
                    self.assertEqual(proof.summary['verified_endpoints'], 2)
                    proof.verify(fs, manifest, generated, staged, staged_seal=seal, routing_snapshot=snapshot)
                    selected['policy'] = 'sha256:' + 'b' * 64
                    with self.assertRaises(ValueError):
                        proof.verify(fs, manifest, generated, staged, staged_seal=seal, routing_snapshot=snapshot)
                fixture._wait_backend(backend, port)
                self.assertIsNone(backend.poll())
                self.assertEqual(hashlib.sha256(os.pread(descriptor, len(fixture._encoded(config)) + 1, 0)).hexdigest(), digest)
                if tamper != 'site':
                    self.assertEqual(fixture.source_snapshot(fs), originals)
                self.assertEqual({path.name for path in root.iterdir()}, {'source'}, 'Временный workspace не очищен')

    def test_changed_policy_blocks_receipt_and_cleans_private_files(self):
        self.execute(fixture.cases()[0], tamper='policy')

    def test_changed_source_content_blocks_receipt_and_cleans_private_files(self):
        self.execute(fixture.cases()[0], tamper='site')

    def test_wrong_candidate_binding_blocks_receipt_and_cleans_private_files(self):
        self.execute(fixture.cases()[0], tamper='ipc')

    def test_code_owned_preflight_retains_clients_and_accepts_already_installed_packages(self):
        self.execute(fixture.cases()[0], prepared=True)

    def test_own_echo_checks_complete_direct_and_staged_xray_cohort(self):
        if not os.environ.get('XTUNA_TEST_DOCUMENTATION_ECHO'):
            self.skipTest('Нужен RFC5737 адрес в изолированном namespace')
        self.execute(fixture.cases()[0], own_echo=True)


def _real_test(case):
    def run(self):
        self.execute(case)
    return run


for _case in fixture.cases():
    setattr(RealFunctionalStagingTests, 'test_' + _case['name'], _real_test(_case))


if __name__ == '__main__':
    unittest.main()
