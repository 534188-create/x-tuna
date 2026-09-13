"""Настоящие Naive/Caddy в изолированном Debian; исходный backend принадлежит тесту."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from test_vpn_probes import with_acceptance

from lucx_post_configurator.routing_profiles import routing_fingerprint
from lucx_post_configurator.runner import Runner
from lucx_post_configurator.vpn_probe_echo import LocalProbeEcho

NAIVE = Path('/usr/local/bin/naive')
CADDY = Path('/usr/local/bin/caddy')
NAIVE_HASH = 'baea1e9b9f8dd879a6374110bd7bdca80c2ecbdca8debc4f84f784a8739eaea7'
CADDY_HASH = '9a8a4d2cf9dd14040086cf5f1762eb8b4304f1dbc0c85784d8bdf27c2587956b'
DOMAIN = 'vpn.example.test'


def _snapshot(path):
    info = path.lstat()
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest())


def _profile(port):
    return {'inbound_id': 7, 'protocol': 'naive', 'network': 'tcp', 'security': 'tls',
        'transport': 'tcp', 'exposure': 'tcp_sni', 'transport_details': {},
        'transport_path': '', 'transport_mode': '', 'transport_hosts': [], 'alpn': ['h2'],
        'domain': DOMAIN, 'internal_host': '127.0.0.1', 'internal_port': port, 'public_port': 443,
        'sni_names': [DOMAIN], 'port_bindings': [{'port': port, 'protocol': 'TCP'}],
        'public_endpoints': [{'host_id': 1, 'address': DOMAIN, 'port': 443, 'sni': DOMAIN,
            'http_host': '', 'valid': True, 'sni_source': 'address', 'keep_sni_blank': False}]}


@contextmanager
def _backend(root, username, password, echo_port, *, unauthenticated=False, h1_only=False,
             canonical_source=False, probe_resistance=False, upstream='', processes=None, auth_pairs=None):
    """Создаёт один исходный backend для изолированной синтетической проверки."""
    if canonical_source and (unauthenticated or h1_only):
        raise ValueError('unsupported_canonical_backend_options')
    cert, key = root / 'cert.pem', root / 'key.pem'
    completed = subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-nodes', '-days', '1', '-subj', '/CN=' + DOMAIN, '-addext', 'subjectAltName=DNS:' + DOMAIN,
        '-keyout', str(key), '-out', str(cert)], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
    if completed.returncode:
        raise RuntimeError('synthetic_certificate_generation')
    cert.chmod(0o600)
    key.chmod(0o600)
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    auth = '' if unauthenticated else '        basic_auth ' + username + ' ' + password + '\n'
    source = root / 'naive-7.caddyfile'
    if canonical_source:
        source_text = '''{
    admin off
    auto_https off
    servers {
        protocols h1 h2
    }
}
:''' + str(port) + ''' {
    bind 127.0.0.1
    tls ''' + str(cert) + ' ' + str(key) + '''
    route {
        forward_proxy {
            basic_auth ''' + username + ' ' + password + '''
            hide_ip
            hide_via
        }
    }
}
'''
    else:
        source_text = '''{
    admin off
    auto_https off
    order forward_proxy first
    servers {
        protocols ''' + ('h1' if h1_only else 'h1 h2') + '''
    }
}
:''' + str(port) + ''' {
    bind 127.0.0.1
    tls ''' + str(cert) + ' ' + str(key) + '''
    forward_proxy {
''' + auth + '''        hide_ip
        hide_via
        ports ''' + str(echo_port) + '''
        acl {
            allow 127.0.0.1
            deny all
        }
    }
    respond "original synthetic backend" 404
}
'''
    if auth_pairs is not None:
        if not canonical_source or not auth_pairs:
            raise ValueError('unsupported_synthetic_auth_pairs')
        original = '            basic_auth ' + username + ' ' + password + '\n'
        source_text = source_text.replace(original, ''.join(
            '            basic_auth ' + user + ' ' + secret + '\n' for user, secret in auth_pairs))
    if probe_resistance:
        indent = '            ' if canonical_source else '        '
        directive = indent + 'hide_via\n'
        if source_text.count(directive) != 1 or unauthenticated:
            raise ValueError('unsupported_resistance_backend_options')
        source_text = source_text.replace(directive, directive + indent + 'probe_resistance\n')
    if upstream:
        if not canonical_source or not upstream.startswith('socks5://lucx:'):
            raise ValueError('unsupported_synthetic_upstream')
        source_text = source_text.replace('            hide_via\n',
            '            hide_via\n            upstream ' + upstream + '\n')
    source.write_text(source_text, encoding='utf-8')
    source.chmod(0o400)
    originals = {path: _snapshot(path) for path in (source, cert, key)}
    process = subprocess.Popen([str(CADDY), 'run', '--config', str(source), '--adapter', 'caddyfile'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(root),
             'XDG_DATA_HOME': str(root / 'data'), 'XDG_CONFIG_HOME': str(root / 'config')})
    if processes is not None:
        processes.append(process)
    try:
        deadline = time.monotonic() + 8
        while True:
            if process.poll() is not None:
                raise RuntimeError('synthetic_backend_exited')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('synthetic_backend_listener')
                time.sleep(.02)
        yield port, cert.read_text(encoding='utf-8')
        if process.poll() is not None or any(_snapshot(path) != value for path, value in originals.items()):
            raise RuntimeError('original_backend_was_changed')
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


class RealNaiveProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (sys.platform != 'linux' or os.environ.get('XTUNA_TEST_NAIVE') != str(NAIVE)
                or os.environ.get('XTUNA_TEST_CADDY') != str(CADDY)):
            raise unittest.SkipTest('Нужен изолированный Debian Naive fixture; соединение не проверено')
        for path, expected in ((NAIVE, NAIVE_HASH), (CADDY, CADDY_HASH)):
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise RuntimeError('synthetic_native_tool_identity')

    def exercise(self, *, tamper=None, unauthenticated=False):
        from lucx_post_configurator.naive_probes import (
            NaiveProbeContext,
            NaiveProbeCredential,
            NaiveVPNObserver,
        )
        username, password = 'synthetic', secrets.token_hex(18)
        with tempfile.TemporaryDirectory(prefix='xtuna-naive-live-') as temporary, LocalProbeEcho() as echo:  # noqa: SIM117
            with _backend(Path(temporary), username, password, echo.endpoint[1],
                          unauthenticated=unauthenticated, h1_only=tamper == 'h1') as (port, ca):
                value = _profile(port)
                if tamper == 'sni':
                    value['public_endpoints'][0].update(address='wrong.example.test', sni='wrong.example.test')
                    value['domain'] = 'wrong.example.test'
                    value['sni_names'] = ['wrong.example.test']
                supplied_password = secrets.token_hex(18) if tamper == 'password' else password
                supplied_ca = '' if tamper == 'ca' else ca
                fingerprint = routing_fingerprint(value, 443)
                provider = lambda _: NaiveProbeCredential(username, supplied_password, fingerprint,
                                                           supplied_ca, 'sha256:' + 'a' * 64)
                context = NaiveProbeContext(binary_path=NAIVE, binary_sha256=NAIVE_HASH,
                    credential_provider=provider, echo_address=echo.endpoint[0], echo_port=echo.endpoint[1],
                    timeout=20, dial_target_provider=lambda _p, _phase: ('127.0.0.1', port))
                observer = NaiveVPNObserver(context)
                protocol = with_acceptance(value, phase='direct')
                self.assertTrue(observer.preflight(protocol, Runner()), 'Известный профиль должен пройти read-only preflight')
                original = copy.deepcopy(protocol)
                result = observer(protocol, Runner())
                self.assertEqual(protocol, original, 'Проба изменила исходный профиль')
                if tamper or unauthenticated:
                    self.assertIsNot(result.get('functional'), True, 'Неверная auth/TLS либо открытый proxy дали PASS')
                    self.assertNotEqual(result.get('state'), 'healthy')
                else:
                    self.assertEqual(result.get('state'), 'healthy', 'Настоящий Naive обмен не подтверждён')
                    self.assertIs(result.get('authenticated'), True)
                    self.assertIs(result.get('functional'), True)
                    self.assertEqual(result.get('bytes_sent'), 16384)
                    self.assertEqual(result.get('bytes_received'), 16384)
                encoded = json.dumps(result)
                for secret in (password, supplied_password, ca, DOMAIN):
                    self.assertNotIn(secret, encoded, 'Результат содержит исходные данные')

    def test_real_naive_padding_auth_and_reconnect_keep_existing_backend(self):
        self.exercise()

    def test_wrong_existing_password_does_not_pass(self):
        self.exercise(tamper='password')

    def test_missing_ca_does_not_pass(self):
        self.exercise(tamper='ca')

    def test_wrong_tls_name_does_not_pass(self):
        self.exercise(tamper='sni')

    def test_open_proxy_does_not_count_as_authenticated_vpn(self):
        self.exercise(unauthenticated=True)

    def test_h1_only_backend_does_not_prove_h2_profile(self):
        self.exercise(tamper='h1')

    def test_hidden_denial_shape_matches_real_caddy_and_rejects_authenticated_dial_failure(self):
        from lucx_post_configurator import naive_probes as module
        for canonical, resistance, correct in ((False, False, False), (False, True, False),
                                               (True, True, False), (True, True, True)):
            with self.subTest(canonical=canonical, resistance=resistance, correct=correct), \
                 tempfile.TemporaryDirectory(prefix='xtuna-naive-denial-') as temporary, \
                 LocalProbeEcho() as echo:
                username, password = 'synthetic', secrets.token_hex(18)
                with _backend(Path(temporary), username, password, echo.endpoint[1],
                              canonical_source=canonical, probe_resistance=resistance) as (port, ca):
                    request = {'username': username, 'password': password, 'ca_pem': ca, 'sni': DOMAIN,
                        'address': '127.0.0.1', 'port': port, 'echo_address': echo.endpoint[0],
                        'echo_port': echo.endpoint[1]}
                    descriptor = os.memfd_create('synthetic-denial-netlog', os.MFD_CLOEXEC)
                    binary = module._binary(NAIVE, NAIVE_HASH)
                    build, start, exchange = module._client_config, module.subprocess.Popen, module._roundtrip
                    snapshots = []
                    def config(*args, **kwargs):
                        return dict(build(*args, **kwargs), **{'log-net-log': f'/proc/self/fd/{descriptor}'})
                    def spawn(args, **kwargs):
                        kwargs['pass_fds'] = (*kwargs.get('pass_fds', ()), descriptor)
                        return start(args, **kwargs)
                    def capture_before_stop(local_port, auth, target, deadline):
                        try:
                            return exchange(local_port, auth, target, deadline)
                        finally:
                            # Только fixture: дождаться завершения текущей записи до
                            # SIGTERM. Дополнительные SOCKS accepts запрещены: Naive
                            # запускает для них служебные remote preconnect GET.
                            previous, stable = None, 0
                            for _ in range(25):
                                module._remaining(deadline)
                                time.sleep(.02)
                                data = module._netlog_bytes(descriptor)
                                stable = stable + 1 if data == previous and data.endswith(b'\n') else 0
                                previous = data
                                if stable >= 2:
                                    snapshots[:] = [data]
                                    break
                    try:
                        with patch.object(module, '_client_config', side_effect=config), \
                             patch.object(module.subprocess, 'Popen', side_effect=spawn), \
                             patch.object(module, '_roundtrip', side_effect=capture_before_stop):
                            try:
                                module._attempt(request, binary, password if correct else secrets.token_hex(18),
                                                time.monotonic() + 5, negative=True)
                            except OSError:
                                pass  # Проверяем bytes формы, а не ещё закрытый observer mode.
                        self.assertTrue(snapshots, 'Не получен целый синтетический NetLog до остановки')
                        evidence = snapshots[0]
                        self.assertEqual(module._netlog_hidden_auth_denial(evidence, request),
                                         canonical and resistance and not correct,
                                         'Форма отказа перепутана с auth/ACL/dial результатом')
                    finally:
                        os.close(binary)
                        os.close(descriptor)

    def test_independent_netlog_channel_adds_no_backend_get_or_outbound(self):
        from lucx_post_configurator import naive_probes as module
        with tempfile.TemporaryDirectory(prefix='xtuna-naive-flush-') as temporary, LocalProbeEcho() as echo:
            root = Path(temporary)
            username, password = 'synthetic', secrets.token_hex(18)
            with _backend(root, username, password, echo.endpoint[1],
                          canonical_source=True, probe_resistance=True) as (port, ca):
                request = {'username': username, 'password': password, 'ca_pem': ca, 'sni': DOMAIN,
                    'address': '127.0.0.1', 'port': port, 'echo_address': echo.endpoint[0],
                    'echo_port': echo.endpoint[1]}
                before = _snapshot(root / 'naive-7.caddyfile')
                binary = module._binary(NAIVE, NAIVE_HASH)
                try:
                    module._attempt(request, binary, secrets.token_hex(18), time.monotonic() + 5,
                                    negative=True, hidden_denial=True)
                    with self.assertRaises(OSError):
                        module._attempt(request, binary, password, time.monotonic() + 5,
                                        negative=True, hidden_denial=True)
                    with self.assertRaises(OSError):
                        module._attempt(dict(request, sni='wrong.example.test'), binary,
                            secrets.token_hex(18), time.monotonic() + 5, negative=True, hidden_denial=True)
                finally:
                    os.close(binary)
                self.assertEqual(_snapshot(root / 'naive-7.caddyfile'), before)

    def test_hidden_attempt_rejects_late_job_after_collector_marker(self):
        from lucx_post_configurator import naive_probes as module
        with tempfile.TemporaryDirectory(prefix='xtuna-naive-late-') as temporary, LocalProbeEcho() as echo:
            username, password = 'synthetic', secrets.token_hex(18)
            with _backend(Path(temporary), username, password, echo.endpoint[1],
                          canonical_source=True, probe_resistance=True) as (port, ca):
                request = {'username': username, 'password': password, 'ca_pem': ca, 'sni': DOMAIN,
                    'address': '127.0.0.1', 'port': port, 'echo_address': echo.endpoint[0],
                    'echo_port': echo.endpoint[1]}
                binary = module._binary(NAIVE, NAIVE_HASH)
                collect, read = module._collect_hidden_denial, module._netlog_bytes
                returned, injected = [], []
                def capture(*args):
                    result = collect(*args)
                    returned.append(result)
                    return result
                def late_job(fd):
                    data = read(fd)
                    if returned:
                        prefix = returned[0][0] if isinstance(returned[0], tuple) else returned[0]
                        constants = json.loads(prefix.splitlines()[0][len(b'{"constants":'):-1])
                        job = {'type': constants['logEventTypes']['CONNECT_JOB'],
                            'source': {'id': 999999, 'type': constants['logSourceType']['HTTP_PROXY_CONNECT_JOB']},
                            'phase': constants['logEventPhase']['PHASE_BEGIN']}
                        injected.append(True)
                        return prefix + json.dumps(job).encode() + b',\n'
                    return data
                try:
                    with patch.object(module, '_collect_hidden_denial', side_effect=capture), \
                         patch.object(module, '_netlog_bytes', side_effect=late_job):
                        with self.assertRaises(OSError):
                            module._attempt(request, binary, secrets.token_hex(18), time.monotonic() + 5,
                                            negative=True, hidden_denial=True)
                    self.assertTrue(injected, 'Нужно проверить sealed evidence после настоящего collector')
                finally:
                    os.close(binary)

    def test_native_manual_tls_shape_matches_real_backend_and_adapter(self):
        from lucx_post_configurator.naive_frontend import parse_naive_native_source
        for resistance in (False, True):
            with self.subTest(resistance=resistance), \
                 tempfile.TemporaryDirectory(prefix='xtuna-naive-native-') as temporary:
                root = Path(temporary)
                with _backend(root, 'synthetic', secrets.token_hex(18), 9,
                              canonical_source=True, probe_resistance=resistance) as (port, _):
                    text = (root / 'naive-7.caddyfile').read_text(encoding='utf-8')
                    parsed = parse_naive_native_source(text)
                    self.assertEqual((parsed.port, parsed.bind_host, parsed.probe_resistance),
                                     (port, '127.0.0.1', resistance))
                    completed = subprocess.run([str(CADDY), 'adapt', '--adapter', 'caddyfile', '--config', '-'],
                        input=text.encode(), capture_output=True, timeout=5, check=False,
                        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
                    self.assertEqual(completed.returncode, 0, 'Canonical source не прошёл Caddy adapter')
                    document = json.loads(completed.stdout)
                    servers = list(document['apps']['http']['servers'].values())
                    self.assertEqual(len(servers), 1)
                    self.assertTrue(servers[0]['listen'] == ['127.0.0.1:' + str(port)])
                    self.assertTrue(servers[0].get('protocols') == ['h1', 'h2'])
                    certificates = document['apps']['tls']['certificates']['load_files']
                    self.assertTrue(len(certificates) == 1 and
                        certificates[0]['certificate'] == parsed.cert_path and
                        certificates[0]['key'] == parsed.key_path)
                    self.assertTrue(document['admin']['disabled'])
                    self.assertTrue(servers[0]['automatic_https']['disable'])
                    routes = servers[0]['routes']
                    self.assertTrue(len(routes) == 1)
                    handlers = routes[0]['handle']
                    if handlers[0].get('handler') == 'subroute':
                        handlers = handlers[0]['routes'][0]['handle']
                    self.assertTrue(len(handlers) == 1 and handlers[0]['handler'] == 'forward_proxy')
                    # В Go это *ProbeResistance: включённое пустое значение — {}.
                    self.assertEqual('probe_resistance' in handlers[0], resistance)
                    if resistance:
                        self.assertTrue(handlers[0]['probe_resistance'] == {})

    def test_source_auth_lexing_matches_actual_caddy_adapter(self):
        from lucx_post_configurator.naive_probe_source import _parse_source
        for token in ('synthetic#suffix', '`synthetic "quoted"#suffix`', "'synthetic-literal'",
                      r'"synthetic\"quoted#suffix"', r'synthetic\suffix', r'"synthetic\\suffix"'):
            source = 'vpn.example.test {\n route {\n forward_proxy {\n basic_auth synthetic ' + token + '\n }\n }\n}\n'
            parsed = _parse_source(source)
            completed = subprocess.run([str(CADDY), 'adapt', '--adapter', 'caddyfile', '--config', '-'],
                input=source.encode('utf-8'), capture_output=True, timeout=5, check=False,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
            self.assertEqual(completed.returncode, 0, 'Синтетическая auth не прошла настоящий Caddy adapter')
            document = json.loads(completed.stdout)
            handlers = []
            def collect(node, found):
                if isinstance(node, dict):
                    if node.get('handler') == 'forward_proxy':
                        found.append(node)
                    for value in node.values():
                        collect(value, found)
                elif isinstance(node, list):
                    for value in node:
                        collect(value, found)
            collect(document, handlers)
            self.assertEqual(len(handlers), 1)
            # Go сериализует [][]byte как base64; внутри лежит HTTP Basic base64.
            actual = handlers[0].get('auth_credentials')
            self.assertTrue(isinstance(actual, list) and len(actual) == 1
                            and isinstance(actual[0], str), 'Неизвестная форма auth Caddy')
            expected = base64.b64encode(':'.join(parsed.auth_pairs[0]).encode())
            self.assertTrue(base64.b64decode(actual[0], validate=True) == expected,
                            'Auth provider расходится с настоящим Caddy adapter')


if __name__ == '__main__':
    unittest.main()
