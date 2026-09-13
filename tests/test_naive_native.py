"""Read-only native source: действительная LucX policy и удерживаемый TLS socket."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import test_naive_lucx_source as lucx_fixture
from test_naive_probes_live import CADDY, CADDY_HASH, NAIVE, NAIVE_HASH, _backend

from lucx_post_configurator import naive_native
from lucx_post_configurator.targetfs import TargetFS

CURRENT_XRAY = Path('/tmp/completion/native-current-xray')
CURRENT_XRAY_SHA256 = '64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d'


@contextmanager
def current_xray_backend(configuration):
    """Отдельный release binary; неизменный общий Xray fixture не подменяется."""
    import fcntl

    from staging_frontend_fixture import _wait_backend
    if (CURRENT_XRAY.is_symlink() or not CURRENT_XRAY.is_file()
            or hashlib.sha256(CURRENT_XRAY.read_bytes()).hexdigest() != CURRENT_XRAY_SHA256):
        raise AssertionError('Не подтверждён отдельный Xray 26.7.28')
    payload = json.dumps(configuration, separators=(',', ':'), allow_nan=False).encode('utf-8')
    descriptor = os.memfd_create('synthetic-current-xray', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    process = None
    try:
        os.write(descriptor, payload)
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        process = subprocess.Popen([str(CURRENT_XRAY), 'run', '-format', 'json', '-config',
            f'/proc/self/fd/{descriptor}'], pass_fds=(descriptor,), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        _wait_backend(process, configuration['inbounds'][0]['port'])
        yield process
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        os.close(descriptor)


class NativeSourceUnitTests(unittest.TestCase):
    def test_synthetic_filesystem_never_becomes_native_source(self):
        with self.assertRaisesRegex(ValueError, '^Исходный backend Naive не подтверждён$'):
            naive_native.NativeNaiveSource(TargetFS('/synthetic'), {}, None, None)

    def test_actor_state_is_not_part_of_stable_identity(self):
        from lucx_post_configurator.staging_processes import ProcessIdentity
        first = ProcessIdentity(42, 1, 42, 42, 777, 'R'), (1, 2), (3, 4)
        second = ProcessIdentity(42, 1, 42, 42, 777, 'S'), (1, 2), (3, 4)
        self.assertEqual(naive_native._stable(first), naive_native._stable(second))


class NativeSourceLiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (sys.platform != 'linux' or os.environ.get('XTUNA_TEST_CADDY') != str(CADDY)):
            raise unittest.SkipTest('Нужен изолированный Debian с закреплённым Caddy')
        if hashlib.sha256(CADDY.read_bytes()).hexdigest() != CADDY_HASH:
            raise AssertionError('Не подтверждён тестовый Caddy')

    @contextmanager
    def fixture(self, upstream='', *, resistance=False, wildcard=False):
        fixture = lucx_fixture.LucXNaiveSourceTests()
        fixture.setUp()
        try:
            with tempfile.TemporaryDirectory(prefix='native-original-') as directory:
                root = Path(directory)
                fixture.settings.update(useAcme=False, certFile=str(root / 'cert.pem'),
                                        keyFile=str(root / 'key.pem'), probeResistance=resistance)
                if upstream:
                    fixture.settings.update(routeThroughXray=True, routeXrayPort=int(upstream.rsplit(':', 1)[1]))
                    fixture.sql("ALTER TABLE inbounds ADD COLUMN tag TEXT DEFAULT 'synthetic-naive'")
                pairs = [(fixture.settings['authUser'], fixture.settings['authPass'])]
                pairs += [fixture.auth(c['email']) for c in fixture.clients]
                processes = []
                write_text = Path.write_text
                def original_source(path, text, *args, **kwargs):
                    if wildcard and path == root / 'naive-7.caddyfile':
                        text = text.replace('    bind 127.0.0.1\n', '')
                    return write_text(path, text, *args, **kwargs)
                with mock.patch.object(Path, 'write_text', original_source), _backend(
                              root, *pairs[0], 1, canonical_source=True, auth_pairs=pairs,
                              processes=processes, upstream=upstream,
                              probe_resistance=resistance) as (port, pem):
                    fixture.write_settings()
                    fixture.sql('UPDATE inbounds SET port=? WHERE id=7', (port,))
                    if wildcard:
                        fixture.sql("UPDATE inbounds SET listen='0.0.0.0' WHERE id=7")
                    fixture.fs = TargetFS('/')
                    fixture.db_path = str(fixture.path)
                    fixture.caddy_path = root / 'naive-7.caddyfile'
                    fixture.refresh_manifest()
                    if wildcard:
                        fixture.protocol['internal_host'] = '127.0.0.1'
                    fixture.audit.naive_caddyfile['files'][0]['path'] = str(fixture.caddy_path)
                    yield fixture, root, processes[0], pem
        finally:
            fixture.doCleanups()

    def provider(self, fixture):
        return naive_native.NativeNaiveSource(fixture.fs, fixture.manifest, fixture.audit,
                                             fixture.source())

    def observer_exchange(self, fixture):
        from test_naive_probes import accepted

        from lucx_post_configurator.naive_probes import (
            NaiveProbeContext,
            NaiveVPNObserver,
        )
        from lucx_post_configurator.runner import Runner
        auth = fixture.source()
        source = naive_native.NativeNaiveSource(fixture.fs, fixture.manifest, fixture.audit, auth)
        context = NaiveProbeContext(binary_path=NAIVE, binary_sha256=NAIVE_HASH,
            credential_provider=auth, echo_address='192.0.2.10', echo_port=0, timeout=30,
            native_binding_provider=source)
        observer = NaiveVPNObserver(context)
        protocol = accepted(fixture.protocol, phase='direct')
        self.assertTrue(observer.preflight(protocol, Runner()))
        result = observer(protocol, Runner())
        self.assertEqual(result.get('state'), 'healthy', 'Native observer не подтвердил настоящий обмен')
        self.assertIs(result.get('authenticated'), True)
        self.assertIs(result.get('functional'), True)
        self.assertEqual((result.get('bytes_sent'), result.get('bytes_received')), (16384, 16384))
        for secret in ('vpn.example.test', '192.0.2.10', fixture.panel_secret, fixture.settings['authPass']):
            self.assertNotIn(secret, json.dumps(result))

    def test_native_observer_worker_direct_with_hidden_denial(self):
        with self.fixture(resistance=True) as (fixture, _, _, _):
            before = fixture.snapshot()
            self.observer_exchange(fixture)
            self.assertEqual(before, fixture.snapshot())

    def test_installed_registry_uses_genuine_native_source_and_restores_runner(self):
        from test_naive_probes import accepted
        from lucx_post_configurator import vpn_probe_registry as registry
        from lucx_post_configurator.runner import Runner
        with self.fixture(resistance=True) as (fixture, _, _, _):
            fixture.audit.public_addresses = ['192.0.2.10']
            fixture.manifest['lucx']['db_path'] = fixture.db_path
            before = fixture.snapshot()
            runner = Runner()
            with mock.patch.object(registry, 'NAIVE_PROBE_PATH', str(NAIVE)):
                with registry.installed_vpn_probes(fixture.fs, runner, fixture.manifest, audit=fixture.audit):
                    observer = runner.vpn_observers['naive']
                    result = observer(accepted(fixture.protocol, phase='direct'), runner)
                    self.assertEqual(result['state'], 'healthy')
                    self.assertEqual((result['bytes_sent'], result['bytes_received']), (16384, 16384))
                self.assertFalse(hasattr(runner, 'vpn_observers'))
            self.assertEqual(before, fixture.snapshot())

    def test_genuine_cohort_tls_and_caddy_owner_are_stable(self):
        with self.fixture() as (fixture, root, process, pem):
            before = fixture.snapshot()
            source = self.provider(fixture)
            binding = source(fixture.protocol)
            self.assertIsNotNone(binding)
            self.assertEqual(source(fixture.protocol), binding)
            self.assertEqual(binding.caddy_pid, process.pid)
            self.assertEqual(binding.caddy_sha256, CADDY_HASH)
            self.assertEqual(binding.backend_ca_pem, pem)
            self.assertEqual((binding.xray_pid, binding.xray_sha256, binding.bridge_port), (0, '', 0))
            self.assertRegex(binding.binding_fingerprint, '^sha256:[0-9a-f]{64}$')
            self.assertEqual(before, fixture.snapshot())
            for secret in (pem, fixture.panel_secret, str(root), fixture.settings['authPass']):
                self.assertNotIn(secret, repr(source) + repr(binding))

    def test_unselected_client_drift_permanently_closes_provider(self):
        with self.fixture() as (fixture, _, _, _):
            source = self.provider(fixture)
            fixture.sql('UPDATE clients SET limit_ip=1 WHERE id=2')
            self.assertIsNone(source(fixture.protocol))
            fixture.sql('UPDATE clients SET limit_ip=0 WHERE id=2')
            self.assertIsNone(source(fixture.protocol))

    def test_default_wildcard_caddy_listener_has_exact_reverse_socket_owner(self):
        with self.fixture(wildcard=True) as (fixture, _, caddy, _):
            binding = self.provider(fixture)(fixture.protocol)
            self.assertIsNotNone(binding)
            self.assertEqual(binding.caddy_pid, caddy.pid)
            self.assertEqual(binding.backend_address, '127.0.0.1')

    def test_settings_tls_paths_must_match_native_source(self):
        with self.fixture() as (fixture, _, _, _):
            fixture.settings['certFile'] = '/synthetic/wrong.pem'
            fixture.write_settings()
            fixture.refresh_manifest()
            fixture.audit.naive_caddyfile['files'][0]['path'] = str(fixture.caddy_path)
            with self.assertRaisesRegex(ValueError, '^Исходный backend Naive не подтверждён$'):
                self.provider(fixture)

    def test_source_port_must_match_database_profile(self):
        with self.fixture() as (fixture, _, _, _):
            fixture.sql('UPDATE inbounds SET port=1 WHERE id=7')
            fixture.refresh_manifest()
            fixture.audit.naive_caddyfile['files'][0]['path'] = str(fixture.caddy_path)
            with self.assertRaisesRegex(ValueError, '^Исходный backend Naive не подтверждён$'):
                self.provider(fixture)

    def test_wrong_tls_leaf_fails_despite_valid_ca(self):
        with self.fixture() as (fixture, _, _, pem):
            deadline = naive_native.time.monotonic() + 10
            with self.assertRaisesRegex(ValueError, '^Исходный backend Naive не подтверждён$'):
                naive_native._tls('127.0.0.1', fixture.protocol['internal_port'], 'vpn.example.test',
                                  pem, b'not-the-leaf', deadline)

    def test_source_and_cert_capture_drift_close_provider(self):
        for filename in ('naive-7.caddyfile', 'cert.pem', 'key.pem'):
            with self.subTest(filename=filename), self.fixture() as (fixture, root, _, _):
                source = self.provider(fixture)
                original = naive_native._capture
                target = root / filename
                def changed(path, original=original, target=target):
                    result = original(path)
                    if path == target:
                        return result[0], (*result[1], 'changed'), result[2]
                    return result
                with mock.patch.object(naive_native, '_capture', side_effect=changed):
                    self.assertIsNone(source(fixture.protocol))
                self.assertIsNone(source(fixture.protocol))

    def test_actor_replacement_is_not_rebaselined(self):
        with self.fixture() as (fixture, _, _, _):
            source = self.provider(fixture)
            original = naive_native._pin_actor
            def replaced(pid, digest, deadline):
                actor = original(pid, digest, deadline)
                from dataclasses import replace
                return replace(actor[0], starttime=actor[0].starttime + 1), *actor[1:]
            with mock.patch.object(naive_native, '_pin_actor', side_effect=replaced):
                self.assertIsNone(source(fixture.protocol))
            self.assertIsNone(source(fixture.protocol))

    def test_real_routed_source_pins_running_xray_and_resistance(self):
        from staging_frontend_fixture import XRAY_SHA256, existing_backend, reservations
        with reservations(1) as ports:
            port = ports[0]
        password = 'abcdefghijklmnopqrstuvwx'
        configuration = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1',
            'port': port, 'protocol': 'socks', 'settings': {'auth': 'password',
                'accounts': [{'user': 'lucx', 'pass': password}], 'udp': False}}],
            'outbounds': [{'protocol': 'freedom', 'settings': {}}]}
        with existing_backend(configuration) as (xray, _, _), self.fixture(
                f'socks5://lucx:{password}@127.0.0.1:{port}', resistance=True) as (fixture, _, caddy, _):
            before = fixture.snapshot()
            source = self.provider(fixture)
            binding = source(fixture.protocol)
            self.assertIsNotNone(binding)
            self.assertEqual((binding.xray_pid, binding.xray_sha256, binding.bridge_port),
                             (xray.pid, XRAY_SHA256, port))
            self.assertEqual(binding.caddy_pid, caddy.pid)
            self.assertTrue(binding.probe_resistance)
            self.assertEqual(source(fixture.protocol), binding)
            self.assertEqual(before, fixture.snapshot())
            self.observer_exchange(fixture)
            self.assertEqual(before, fixture.snapshot())
            with mock.patch.object(naive_native, '_bridge_owner', return_value=caddy.pid):
                self.assertIsNone(source(fixture.protocol))
            self.assertIsNone(source(fixture.protocol))

    def test_unavailable_bridge_never_yields_binding(self):
        from staging_frontend_fixture import reservations
        with reservations(1) as ports:
            port = ports[0]
        with (self.fixture('socks5://lucx:abcdefghijklmnopqrstuvwx@127.0.0.1:' + str(port)) as (fixture, _, _, _),
              self.assertRaisesRegex(ValueError, '^Исходный backend Naive не подтверждён$')):
            self.provider(fixture)

    def test_root_python_listener_is_not_trusted_xray_bridge(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            upstream = 'socks5://lucx:abcdefghijklmnopqrstuvwx@127.0.0.1:' + str(port)
            with (self.fixture(upstream) as (fixture, _, _, _),
                  self.assertRaisesRegex(ValueError, '^Исходный backend Naive не подтверждён$')):
                self.provider(fixture)

    @unittest.skipUnless(os.environ.get('XTUNA_TEST_NATIVE_XRAY') == str(CURRENT_XRAY),
                         'Нужен отдельный закреплённый Xray 26.7.28')
    def test_current_xray_26_7_28_routed_observer_worker(self):
        from staging_frontend_fixture import reservations
        with reservations(1) as ports:
            port = ports[0]
        password = 'abcdefghijklmnopqrstuvwx'
        configuration = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1',
            'port': port, 'protocol': 'socks', 'settings': {'auth': 'password',
                'accounts': [{'user': 'lucx', 'pass': password}], 'udp': False}}],
            'outbounds': [{'protocol': 'freedom', 'settings': {}}]}
        with current_xray_backend(configuration) as xray, self.fixture(
                f'socks5://lucx:{password}@127.0.0.1:{port}', resistance=True) as (fixture, _, caddy, _):
            before = fixture.snapshot()
            source = self.provider(fixture)
            binding = source(fixture.protocol)
            self.assertIsNotNone(binding)
            self.assertEqual((binding.xray_pid, binding.xray_sha256, binding.bridge_port),
                             (xray.pid, CURRENT_XRAY_SHA256, port))
            self.assertEqual(binding.caddy_pid, caddy.pid)
            self.assertEqual(source(fixture.protocol), binding)
            self.observer_exchange(fixture)
            self.assertEqual(before, fixture.snapshot())

    def test_caddy_executable_hash_mismatch_fails_closed(self):
        with (self.fixture() as (fixture, _, _, _),
              mock.patch.object(naive_native, '_CADDY_SHA256', '0' * 64),
              self.assertRaisesRegex(ValueError, '^Исходный backend Naive не подтверждён$')):
            self.provider(fixture)


if __name__ == '__main__':
    unittest.main()
