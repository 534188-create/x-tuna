"""Настоящий общий L4 frontend; fixture PASS не снимает запрет Engine."""
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
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path

import test_naive_candidate_live as candidate_live
from staging_frontend_fixture import (
    CA,
    CERT,
    DOMAINS,
    KEY,
    XRAY,
    XRAY_SHA256,
    _nginx_wrapper,
    backend_config,
    create_sources,
    existing_backend,
    reservations,
    source_snapshot,
)
from test_naive_candidate_live import (
    BACKEND_CA,
    BUNDLE,
    DOCUMENTATION_ECHO,
    HAPROXY,
    _DocumentationEcho,
    _process,
)
from test_naive_connect_frontend import common_fixture
from test_naive_probes_live import NAIVE, NAIVE_HASH, _backend

from lucx_post_configurator.decoy_health import (
    BrowserDialAddress,
    observe_decoy,
    observe_vpn_capabilities,
)
from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
from lucx_post_configurator.models import Audit
from lucx_post_configurator.naive_probe_source import NaiveCaddyCredentialSource
from lucx_post_configurator.naive_probes import NaiveProbeContext, NaiveVPNObserver
from lucx_post_configurator.render_runtime import (
    ListenerKey,
    RenderRuntime,
    SocketAddress,
)
from lucx_post_configurator.renderers import (
    frontend_listener_inventory,
    frontend_material_inventory,
    render_haproxy,
    render_nginx_decoys,
)
from lucx_post_configurator.routing_profiles import (
    reserved_listener_ports,
    routing_fingerprint,
)
from lucx_post_configurator.runner import Runner
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.vpn_probes import (
    XrayProbeContext,
    XrayProbeCredential,
    XrayVPNObserver,
)


class NaiveCommonLiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidate_live.NaiveCandidateLiveTests.setUpClass()
        if os.environ.get('XTUNA_TEST_DOCUMENTATION_ECHO') != DOCUMENTATION_ECHO:
            raise unittest.SkipTest('Нужен отдельный network-none fixture с RFC5737 echo')
        if not XRAY.is_file() or hashlib.sha256(XRAY.read_bytes()).hexdigest() != XRAY_SHA256:
            raise RuntimeError('synthetic_xray_identity')

    def exercise(self, *, wrong_backend_ca=False, wrong_backend_name=False):
        domains = (*DOMAINS, 'xray.example.test')
        with tempfile.TemporaryDirectory(prefix='xtuna-naive-common-') as directory, ExitStack() as stack:
            root = Path(directory)
            sources = create_sources(root, domains=domains)
            original_sources = source_snapshot(sources, domains=domains)
            echo = stack.enter_context(_DocumentationEcho())
            backend_root = root / 'existing'
            backend_root.mkdir()
            username, password = 'synthetic', secrets.token_hex(18)
            naive_port, naive_ca = stack.enter_context(_backend(
                backend_root, username, password, echo.endpoint[1], canonical_source=True))
            with reservations(1) as ports:
                xray_port = ports[0]
            user_id = str(uuid.uuid4())
            case = {'protocol': 'vless', 'transport': 'ws', 'path': '/vpn', 'mode': ''}
            original_backend = backend_config(case, user_id, xray_port, sources)
            original_backend_snapshot = copy.deepcopy(original_backend)
            xray_process, xray_fd, xray_hash = stack.enter_context(existing_backend(original_backend))
            manifest, _, _ = common_fixture()
            manifest['decoys']['require_full_acceptance'] = True
            manifest['protocols'][0].update(internal_port=naive_port, backend_tls_policy={'ca_file': BACKEND_CA})
            if wrong_backend_name:
                manifest['protocols'][0].update(domain='alias.example.test', sni_names=['alias.example.test'])
            manifest['protocols'][1].update(internal_port=xray_port, backend_tls_policy={'ca_file': CA})
            source = backend_root / 'naive-7.caddyfile'
            info = source.lstat()
            metadata = {'path': str(source), 'kind': 'file', 'mode': info.st_mode & 0o7777,
                'uid': info.st_uid, 'gid': info.st_gid, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'capabilities': {'forward_proxy': True, 'native_decoy': False}}
            audit = Audit(naive_caddyfile={'files': [metadata]})
            manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(manifest, audit)
            material = {7: {'naive_caddyfile_text': source.read_text(), 'naive_source_metadata': metadata}}
            provider = NaiveCaddyCredentialSource(TargetFS('/'), manifest, audit)
            original_auth = provider(manifest['protocols'][0])
            self.assertIsNotNone(original_auth)
            keys = frontend_listener_inventory(manifest, routing_material=material)
            inventory = frontend_material_inventory(manifest, routing_material=material)
            with reservations(len(keys)) as ports:
                self.assertFalse(set(ports) & (reserved_listener_ports(manifest) | {24443, 24444, 24445}))
                addresses = {key: SocketAddress('127.0.0.1', port) for key, port in zip(keys, ports)}
            bundle = root / 'bundle.pem'
            bundle.write_bytes(sources.path(CERT).read_bytes() + sources.path(KEY).read_bytes())
            Path(str(bundle) + '.key').write_bytes(sources.path(KEY).read_bytes())
            backend_ca = root / 'backend-ca.pem'
            backend_ca.write_text(sources.path(CA).read_text() if wrong_backend_ca else naive_ca)
            paths = {path: str(sources.path(path)) for path in inventory}
            paths.update({BUNDLE: str(bundle), BUNDLE + '.key': str(bundle) + '.key', BACKEND_CA: str(backend_ca)})
            runtime = RenderRuntime(addresses, paths, foreground=True, suppress_system_log=True)
            original = copy.deepcopy((manifest, material))
            haproxy_text = render_haproxy(manifest, material, runtime=runtime)
            nginx_text = render_nginx_decoys(manifest, runtime=runtime, routing_material=material)
            self.assertNotIn(password, haproxy_text + nginx_text)
            haproxy = root / 'haproxy.cfg'
            haproxy.write_text(haproxy_text)
            writable = root / 'nginx-runtime'
            writable.mkdir()
            for name in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'):
                (writable / name).mkdir()
            nginx = root / 'nginx.conf'
            nginx.write_bytes(_nginx_wrapper(nginx_text, sources.path('/etc/nginx/mime.types'), writable))
            stack.enter_context(_process(['/usr/sbin/nginx', '-c', str(nginx), '-p', str(root),
                '-g', 'daemon off; master_process off;'],
                tuple(address.port for key, address in addresses.items() if key.role.startswith('decoy_'))))
            stack.enter_context(_process([str(HAPROXY), '-db', '-f', str(haproxy)],
                tuple(address.port for key, address in addresses.items() if key.role in {'public', 'split'})))

            def dial(value, phase):
                self.assertEqual(phase, 'staging')
                address = addresses[ListenerKey('public', value['acceptance_endpoint']['port'])]
                return address.host, address.port

            def naive_credential(value):
                credential = provider(value)
                return dataclasses.replace(credential, ca_pem=sources.path(CA).read_text()) if credential else None

            naive = NaiveVPNObserver(NaiveProbeContext(NAIVE, NAIVE_HASH, naive_credential,
                echo.endpoint[0], echo.endpoint[1], dial_target_provider=dial))
            xray = XrayVPNObserver(XrayProbeContext(XRAY, XRAY_SHA256,
                lambda value: XrayProbeCredential(user_id, routing_fingerprint(value, 443), sources.path(CA).read_text()),
                echo_address='127.0.0.1', echo_port=0, dial_target_provider=dial))
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = []
                for protocol, observer in ((manifest['protocols'][0], naive), (manifest['protocols'][1], xray)):
                    selection = copy.deepcopy(manifest)
                    selection['protocols'] = [protocol]
                    futures.append(pool.submit(observe_vpn_capabilities, selection, Runner(), phase='staging',
                                               observers={protocol['protocol']: observer}))
                sites = {(443, domain) for domain in domains} | {(8443, 'alias.example.test')}
                for public, domain in sorted(sites):
                    address = addresses[ListenerKey('public', public)]
                    for version in ('h1', 'h2'):
                        for method in ('GET', 'HEAD'):
                            row = observe_decoy(domain, '127.0.0.1', public, 'X-LucX-Decoy: ' + domain,
                                method=method, http_version=version, strict_content=True, phase='staging',
                                dial_address=BrowserDialAddress(address.host, address.port),
                                ca_file=str(sources.path(CA)), runner=Runner(), timeout=5)
                            self.assertEqual(row['state'], 'healthy', f'Браузер {domain}:{public}/{version}/{method}')
                            self.assertIs(row.get('content_verified'), True)
                    if domain in DOMAINS[:2]:
                        candidate_live.NaiveCandidateLiveTests.check_http_boundaries(self, address.port, domain, sources.path(CA))
                        self.check_cross_port(address.port, domain, public, sources.path(CA))
                naive_rows, xray_rows = [future.result(timeout=45) for future in futures]
            self.assertEqual((len(naive_rows), len(xray_rows)), (2, 1))
            for row in naive_rows:
                self.assertEqual(row['state'], 'failed' if wrong_backend_ca or wrong_backend_name else 'healthy')
                if not wrong_backend_ca and not wrong_backend_name:
                    self.assertEqual((row['bytes_sent'], row['bytes_received']), (16384, 16384))
                    self.assertIs(row['authenticated'], True)
            self.assertTrue(all(row['state'] == 'healthy' for row in xray_rows), 'Xray не прошёл общий frontend')
            # Настоящий клиент с правильной исходной auth не получает CONNECT на site-only apex.
            denied = copy.deepcopy(manifest)
            negative = copy.deepcopy(manifest['protocols'][0])
            negative.update(domain='example.test', sni_names=['example.test'],
                public_endpoints=[{**negative['public_endpoints'][0], 'address': 'example.test', 'sni': 'example.test'}])
            denied['protocols'] = [negative]
            negative_observer = NaiveVPNObserver(NaiveProbeContext(NAIVE, NAIVE_HASH,
                lambda value: dataclasses.replace(original_auth, profile_fingerprint=routing_fingerprint(value, 443),
                                                  ca_pem=sources.path(CA).read_text()),
                echo.endpoint[0], echo.endpoint[1], dial_target_provider=dial))
            denied_rows = observe_vpn_capabilities(denied, Runner(), phase='staging', observers={'naive': negative_observer})
            self.assertEqual(len(denied_rows), 1)
            self.assertEqual(denied_rows[0]['state'], 'failed', 'Site-only apex стал CONNECT proxy')
            self.assertNotIn(password, json.dumps(naive_rows + xray_rows))
            self.assertEqual(source_snapshot(sources, domains=domains), original_sources)
            self.assertEqual((manifest, material), original)
            self.assertEqual(provider(manifest['protocols'][0]), original_auth)
            self.assertIsNone(xray_process.poll())
            os.lseek(xray_fd, 0, os.SEEK_SET)
            self.assertEqual(hashlib.sha256(os.read(xray_fd, 1024 * 1024)).hexdigest(), xray_hash)
            self.assertEqual(original_backend, original_backend_snapshot)

    def check_cross_port(self, actual, domain, public, ca):
        context = ssl.create_default_context(cafile=str(ca))
        context.set_alpn_protocols(['http/1.1'])
        for port, expected in ((public, 200), (8443 if public == 443 else 443, 421)):
            with socket.create_connection(('127.0.0.1', actual), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname=domain) as stream:
                    stream.sendall(f'GET / HTTP/1.1\r\nHost: {domain}:{port}\r\nConnection: close\r\n\r\n'.encode())
                    with http.client.HTTPResponse(stream) as response:
                        response.begin()
                        self.assertEqual(response.status, expected, 'Исходный ingress port потерян')

    def test_mixed_vpn_and_all_sites_cross_shared_l4_with_original_source_auth(self):
        self.exercise()

    def test_wrong_naive_ca_fails_vpn_even_when_xray_and_every_site_are_healthy(self):
        self.exercise(wrong_backend_ca=True)

    def test_wrong_original_backend_name_fails_vpn_even_when_sites_are_healthy(self):
        self.exercise(wrong_backend_name=True)


if __name__ == '__main__':
    unittest.main()
