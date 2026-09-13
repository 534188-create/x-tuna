"""Naive observer и candidate renderer вместе; это ещё не общий Engine staging."""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from pathlib import Path

from staging_frontend_fixture import (
    CA,
    CERT,
    DOMAINS,
    HTML,
    KEY,
    _nginx_wrapper,
    create_sources,
    reservations,
    source_snapshot,
)
from test_naive_connect_frontend import candidate_fixture
from test_naive_probes_live import CADDY, CADDY_HASH, NAIVE, NAIVE_HASH, _backend

from lucx_post_configurator.decoy_health import (
    BrowserDialAddress,
    observe_decoy,
    observe_vpn_capabilities,
)
from lucx_post_configurator.extended_decoys import classify_naive_connect_candidate
from lucx_post_configurator.models import Audit
from lucx_post_configurator.naive_probe_source import NaiveCaddyCredentialSource
from lucx_post_configurator.naive_probes import (
    NaiveProbeContext,
    NaiveProbeCredential,
    NaiveVPNObserver,
)
from lucx_post_configurator.render_runtime import (
    ListenerKey,
    RenderRuntime,
    SocketAddress,
)
from lucx_post_configurator.renderers import (
    render_naive_connect_candidate,
    render_nginx_decoys,
)
from lucx_post_configurator.routing_profiles import routing_fingerprint
from lucx_post_configurator.runner import Runner
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.vpn_probe_echo import LocalProbeEcho

HAPROXY = Path('/usr/local/bin/haproxy-tested')
HAPROXY_HASHES = {
    'e0c256b68b983bfbd64bf66d4df28d172db4321d04ff25fb34f60e13ac9ea4fa',
    '1b4363b29322221ab97e3296ea38d6f9ee417cac43e79ccfe5a4fed2e78082f3',
}
BUNDLE = '/etc/lucx-post-configurator/tls/certificate.pem'
BACKEND_CA = '/cert/backend-ca.pem'
DOCUMENTATION_ECHO = '192.0.2.10'


class _DocumentationEcho(LocalProbeEcho):
    """Только test namespace: тот же ограниченный echo на RFC5737 вместо loopback."""

    def __enter__(self):
        if (os.environ.get('XTUNA_TEST_DOCUMENTATION_ECHO') != DOCUMENTATION_ECHO
                or not Path('/.dockerenv').is_file()
                or {name for _, name in socket.if_nameindex()} != {'lo'}
                or self._listener is not None or self._stop.is_set()):
            raise RuntimeError('synthetic_echo_namespace')
        listener = socket.socket()
        try:
            listener.bind((DOCUMENTATION_ECHO, 0))
            listener.listen(4)
            listener.setblocking(False)
            self.endpoint = listener.getsockname()
            self._listener = listener
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            return self
        except BaseException:
            listener.close()
            raise


def _site_port():
    for _ in range(32):
        with ExitStack() as stack:
            first = stack.enter_context(socket.socket())
            first.bind(('127.0.0.1', 0))
            port = first.getsockname()[1]
            if port > 65533:
                continue
            try:
                for number in (port + 1, port + 2):
                    stream = stack.enter_context(socket.socket())
                    stream.bind(('127.0.0.1', number))
            except OSError:
                continue
            return port
    raise RuntimeError('synthetic_site_ports_unavailable')


@contextmanager
def _process(command, ports):
    """Только собственный foreground/single-process fixture, без systemd."""
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    try:
        deadline = time.monotonic() + 5
        for port in ports:
            while True:
                if process.poll() is not None:
                    raise RuntimeError('synthetic_frontend_exited')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('synthetic_frontend_listener') from None
                    time.sleep(.02)
        yield
        if process.poll() is not None:
            raise RuntimeError('synthetic_frontend_exited')
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


class NaiveCandidateLiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (sys.platform != 'linux' or os.environ.get('XTUNA_TEST_NAIVE') != str(NAIVE)
                or os.environ.get('XTUNA_TEST_CADDY') != str(CADDY)
                or os.environ.get('XTUNA_TEST_NAIVE_CANDIDATE_HAPROXY') != str(HAPROXY)):
            raise unittest.SkipTest('Нужен отдельный pinned Naive candidate fixture')
        for path, hashes in ((NAIVE, {NAIVE_HASH}), (CADDY, {CADDY_HASH}), (HAPROXY, HAPROXY_HASHES)):
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() not in hashes:
                raise RuntimeError('synthetic_native_tool_identity')

    def exercise(self, *, wrong_backend_ca=False, source_auth=False):
        with tempfile.TemporaryDirectory(prefix='xtuna-naive-candidate-') as directory, ExitStack() as stack:
            root = Path(directory)
            sources = create_sources(root)
            original = source_snapshot(sources)
            echo = stack.enter_context(_DocumentationEcho() if source_auth else LocalProbeEcho())
            backend_root = root / 'existing'
            backend_root.mkdir()
            username, password = 'synthetic', secrets.token_hex(18)
            backend_options = {'canonical_source': True} if source_auth else {}
            backend_port, backend_ca = stack.enter_context(_backend(
                backend_root, username, password, echo.endpoint[1], **backend_options))
            manifest, _, _ = candidate_fixture()
            manifest['decoys'].update(require_full_acceptance=True,
                sites=[{'domain': domain, 'root': '/var/www/lucx-decoys/' + domain} for domain in DOMAINS])
            protocol = manifest['protocols'][0]
            protocol.update(internal_port=backend_port,
                port_bindings=[{'port': backend_port, 'protocol': 'TCP'}],
                backend_tls_policy={'ca_file': BACKEND_CA})
            source = backend_root / 'naive-7.caddyfile'
            info = source.lstat()
            metadata = {'path': str(source), 'kind': 'file', 'mode': info.st_mode & 0o7777,
                'uid': info.st_uid, 'gid': info.st_gid, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'capabilities': {'forward_proxy': True, 'native_decoy': False}}
            audit = Audit(naive_caddyfile={'files': [metadata]})
            candidate = classify_naive_connect_candidate(manifest, audit, 7)
            auth_source = NaiveCaddyCredentialSource(TargetFS('/'), manifest, audit) if source_auth else None
            auth_before = auth_source(protocol) if auth_source is not None else None
            if source_auth:
                self.assertIsNotNone(auth_before, 'Исходная auth не подтверждена до пробы')
            site_ingresses = {(port, domain) for port, domain, kind in candidate['public_ingresses'] if kind == 'site'}
            self.assertEqual(site_ingresses, {(443, DOMAINS[0]), (443, DOMAINS[1]), (8443, DOMAINS[1])})
            material = {'naive_caddyfile_text': source.read_text(), 'naive_source_metadata': metadata}
            public_ports = sorted({port for port, _, _ in candidate['public_ingresses']})
            site_port = _site_port()
            with reservations(len(public_ports)) as ports:
                addresses = {ListenerKey('public', public): SocketAddress('127.0.0.1', actual)
                             for public, actual in zip(public_ports, ports)}
            addresses[ListenerKey('decoy_h2c')] = SocketAddress('127.0.0.1', site_port + 1)
            bundle, backend_ca_path = root / 'bundle.pem', root / 'backend-ca.pem'
            bundle.write_bytes(sources.path(CERT).read_bytes() + sources.path(KEY).read_bytes())
            backend_ca_path.write_text(sources.path(CA).read_text() if wrong_backend_ca else backend_ca)
            for path in (bundle, backend_ca_path):
                path.chmod(0o600)
            runtime = RenderRuntime(addresses, paths={BUNDLE: str(bundle), BACKEND_CA: str(backend_ca_path)},
                                    foreground=True, suppress_system_log=True)
            expected = copy.deepcopy((manifest, candidate, material))
            config = render_naive_connect_candidate(manifest, candidate, material, runtime=runtime)
            self.assertEqual((manifest, candidate, material), expected)
            self.assertNotIn(password, config)
            haproxy = root / 'haproxy.cfg'
            haproxy.write_text(config)
            site_manifest = copy.deepcopy(manifest)
            site_manifest['certificates'].update(cert_path=str(sources.path(CERT)), key_path=str(sources.path(KEY)))
            site_manifest['decoys'].update(listen_port=site_port,
                sites=[{'domain': domain, 'root': str(sources.path('/var/www/lucx-decoys/' + domain))}
                       for domain in DOMAINS])
            writable = root / 'nginx-runtime'
            writable.mkdir()
            for name in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'):
                (writable / name).mkdir()
            nginx = root / 'nginx.conf'
            nginx.write_bytes(_nginx_wrapper(render_nginx_decoys(site_manifest),
                                             sources.path('/etc/nginx/mime.types'), writable))
            stack.enter_context(_process(['/usr/sbin/nginx', '-c', str(nginx), '-p', str(root),
                '-g', 'daemon off; master_process off;'], (site_port, site_port + 1, site_port + 2)))
            stack.enter_context(_process([str(HAPROXY), '-db', '-f', str(haproxy)], ports))

            def credential(value):
                if auth_source is not None:
                    observed = auth_source(value)
                    if observed is None:
                        return None
                    if (observed.username != username or observed.password != password or observed.ca_pem
                            or not observed.policy_fingerprint):
                        raise RuntimeError('synthetic_source_auth_mismatch')
                    # Меняется только доверенная CA frontend; auth и обе привязки исходные.
                    return dataclasses.replace(observed, ca_pem=sources.path(CA).read_text())
                return NaiveProbeCredential(username, password, routing_fingerprint(value, 443),
                                            sources.path(CA).read_text(), 'sha256:' + 'a' * 64)

            def dial(value, _phase):
                address = runtime.listeners[ListenerKey('public', value['acceptance_endpoint']['port'])]
                return address.host, address.port

            observer = NaiveVPNObserver(NaiveProbeContext(NAIVE, NAIVE_HASH, credential,
                echo.endpoint[0], echo.endpoint[1], dial_target_provider=dial))
            with ThreadPoolExecutor(max_workers=1) as pool:
                vpn = pool.submit(observe_vpn_capabilities, manifest, Runner(),
                                  phase='staging', observers={'naive': observer})
                for public, domain in sorted(site_ingresses):
                    actual = runtime.listeners[ListenerKey('public', public)]
                    for version in ('h1', 'h2'):
                        for method in ('GET', 'HEAD'):
                            result = observe_decoy(domain, '127.0.0.1', public, 'X-LucX-Decoy: ' + domain,
                                method=method, http_version=version, strict_content=True, phase='staging',
                                dial_address=BrowserDialAddress(actual.host, actual.port),
                                ca_file=str(sources.path(CA)), runner=Runner(), timeout=5)
                            self.assertEqual(result['state'], 'healthy', 'Браузерный ingress не подтверждён')
                            self.assertIs(result.get('content_verified'), True)
                    self.check_http_boundaries(actual.port, domain, sources.path(CA))
                rows = vpn.result(timeout=45)
            self.assertEqual(len(rows), len(protocol['public_endpoints']))
            for row in rows:
                if wrong_backend_ca:
                    self.assertNotEqual(row['state'], 'healthy', 'Неверная backend CA дала VPN PASS')
                else:
                    self.assertEqual(row['state'], 'healthy', 'Naive не прошёл frontend endpoint')
                    self.assertEqual((row['bytes_sent'], row['bytes_received']), (16384, 16384))
                    self.assertIs(row['authenticated'], True)
                    self.assertIs(row['public'], False)
                self.assertEqual(row['phase'], 'staging')
                self.assertNotIn(password, json.dumps(row))
            self.assertEqual(source_snapshot(sources), original)
            self.assertEqual((manifest, candidate, material), expected)
            if auth_source is not None:
                self.assertTrue(auth_source(protocol) == auth_before, 'Исходная auth изменилась во время пробы')

    def check_http_boundaries(self, port, domain, ca):
        context = ssl.create_default_context(cafile=str(ca))
        context.set_alpn_protocols(['http/1.1'])
        alternate = DOMAINS[1] if domain == DOMAINS[0] else DOMAINS[0]
        for case_index, (host, method, extra, connection, expected) in enumerate((
                (domain + ':' + str(port), 'GET', '', 'close', 421),
                ('unowned.example.test', 'GET', '', 'close', 421), (alternate, 'GET', '', 'close', 421),
                (domain, 'POST', '', 'close', 405), (domain, 'CONNECT', '', 'close', 400),
                # HAProxy удаляет одиночные Upgrade/Connection upgrade до HTTP ACL.
                # Обычный GET должен вернуть именно сайт, без переключения протокола.
                (domain, 'GET', 'Upgrade: websocket\r\n', 'close', 200),
                (domain, 'GET', 'Upgrade: websocket\r\n', 'upgrade', 400),
                (domain, 'GET', '', 'upgrade', 200))):
            with self.subTest(case=case_index), socket.create_connection(('127.0.0.1', port), timeout=3) as raw:  # noqa: SIM117
                with context.wrap_socket(raw, server_hostname=domain) as stream:
                    target = 'echo.example.test:80' if method == 'CONNECT' else '/'
                    stream.sendall((f'{method} {target} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: {connection}\r\n\r\n').encode())
                    with http.client.HTTPResponse(stream, method=method) as response:
                        response.begin()
                        self.assertEqual(response.status, expected, 'synthetic_browser_boundary_' + str(case_index))
                        if expected == 200:
                            self.assertEqual(response.getheader('X-LucX-Decoy'), domain)
                            self.assertIsNone(response.getheader('Upgrade'))
                            self.assertEqual(response.read(len(HTML) + 1), HTML)

    def test_runtime_candidate_keeps_sites_and_naive_on_every_ingress(self):
        self.exercise()

    def test_sites_alone_cannot_hide_wrong_backend_ca(self):
        self.exercise(wrong_backend_ca=True)

    @unittest.skipUnless(os.environ.get('XTUNA_TEST_DOCUMENTATION_ECHO') == DOCUMENTATION_ECHO,
                         'Нужен отдельный network-none fixture с RFC5737 echo')
    def test_original_caddyfile_auth_crosses_every_frontend_endpoint(self):
        self.exercise(source_auth=True)

    @unittest.skipUnless(os.environ.get('XTUNA_TEST_DOCUMENTATION_ECHO') == DOCUMENTATION_ECHO,
                         'Нужен отдельный network-none fixture с RFC5737 echo')
    def test_original_source_auth_does_not_hide_wrong_backend_ca(self):
        self.exercise(source_auth=True, wrong_backend_ca=True)


if __name__ == '__main__':
    unittest.main()
