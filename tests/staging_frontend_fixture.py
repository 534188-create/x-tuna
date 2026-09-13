"""Настоящий Linux frontend fixture; credentials существуют только во время теста.

Это test-only orchestration production API, не Engine и не production executor.
Existing Xray принадлежит parent-тесту; coordinator владеет только candidate.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from lucx_post_configurator.decoy_health import (
    BrowserDialAddress,
    decoy_acceptance_summary,
    observe_decoy,
    observe_decoy_capabilities,
    observe_vpn_capabilities,
    vpn_acceptance_summary,
)
from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
from lucx_post_configurator.models import default_manifest
from lucx_post_configurator.render_runtime import (
    ListenerKey,
    RenderRuntime,
    SocketAddress,
)
from lucx_post_configurator.renderers import (
    frontend_listener_inventory,
    frontend_material_inventory,
    render_files,
    render_haproxy,
    render_nginx_decoys,
)
from lucx_post_configurator.routing_profiles import routing_fingerprint
from lucx_post_configurator.runner import Runner
from lucx_post_configurator.staging_binding import (
    StagingReceipt,
    create_candidate_binding,
    staging_acceptance_summary,
)
from lucx_post_configurator.staging_integrity import capture_staged_candidate
from lucx_post_configurator.staging_materials import create_staging_materials
from lucx_post_configurator.staging_processes import (
    ForegroundSession,
    FrontendSpec,
    ServiceIdentity,
)
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import stage_files
from lucx_post_configurator.vpn_probes import (
    XRAY_SHA256,
    XrayProbeContext,
    XrayProbeCredential,
    XrayVPNObserver,
)

XRAY = Path('/usr/local/bin/xray')
FRONTENDS = {'haproxy': Path('/usr/sbin/haproxy'), 'nginx': Path('/usr/sbin/nginx')}
DOMAINS = ('vpn.example.test', 'alias.example.test', 'example.test')
CERT, KEY = '/cert/fullchain.pem', '/cert/key.pem'
CA = '/cert/ca.pem'
HTML = b'<!doctype html><html><head><link rel="stylesheet" href="/a.css"></head><body>retained fixture</body></html>\n'
CSS = b'body { color: #27313a; }\n'


def cases():
    """Матрица не сокращается при отсутствии инструментов или ошибке транспорта."""
    result = []
    for protocol in ('vless', 'vmess'):
        for transport in ('ws', 'httpupgrade', 'grpc'):
            result.append({'name': f'{protocol}_{transport}', 'protocol': protocol,
                           'transport': transport, 'path': 'FixtureService' if transport == 'grpc' else '/vpn', 'mode': ''})
        for mode in ('auto', 'packet-up', 'stream-up', 'stream-one'):
            result.append({'name': f'{protocol}_xhttp_{mode.replace("-", "_")}', 'protocol': protocol,
                           'transport': 'xhttp', 'path': '/vpn', 'mode': mode})
        for transport in ('ws', 'httpupgrade'):
            result.append({'name': f'{protocol}_{transport}_root', 'protocol': protocol,
                           'transport': transport, 'path': '/', 'mode': ''})
    return tuple(result)


def make_manifest(case, backend_port):
    manifest = default_manifest()
    manifest['dns'].update(enabled=False, servers=[])
    manifest['network'].update(public_tcp_port=443, public_bind_address='127.0.0.1')
    manifest['lucx']['panel'].update(domain='panel.example.test', public_port=443)
    manifest['lucx']['subscription'].update(domain='sub.example.test', public_port=443)
    manifest['certificates'].update(cert_path=CERT, key_path=KEY)
    manifest['components'].update(install_packages=False, firewall=False, logrotate=False,
                                  extended_tls_split=True, haproxy=True, nginx=True)
    manifest['decoys'].update(enabled=True, routing_mode='extended', extended_user_confirmed=True,
        require_full_acceptance=True, listen_port=17444, zone_apex=DOMAINS[2],
        sites=[{'domain': domain, 'root': '/var/www/lucx-decoys/' + domain} for domain in DOMAINS])
    manifest['protocols'] = [{'inbound_id': 7, 'protocol': case['protocol'], 'domain': DOMAINS[0],
        'network': 'tcp', 'exposure': 'tcp_sni', 'security': 'tls', 'transport': case['transport'],
        'transport_path': case['path'], 'transport_mode': case['mode'], 'transport_details': {},
        'transport_hosts': list(DOMAINS[:2]), 'sni_names': [DOMAINS[0]],
        'internal_host': '127.0.0.1', 'internal_port': backend_port, 'public_port': 443,
        'alpn': ['http/1.1'] if case['transport'] in {'ws', 'httpupgrade'} else ['h2'],
        'backend_tls_policy': {'ca_file': CA}, 'port_bindings': [{'port': backend_port, 'protocol': 'TCP'}],
        'public_endpoints': [{'host_id': index + 1, 'address': domain, 'port': port, 'sni': domain,
            'http_host': host, 'valid': True, 'sni_source': 'address', 'keep_sni_blank': False}
            for index, (domain, port, host) in enumerate(((DOMAINS[0], 443, ''), (DOMAINS[1], 8443, '')))]}]
    manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(manifest)
    return manifest


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _write(fs, target, payload):
    path = fs.path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def source_snapshot(fs, *, domains=DOMAINS):
    """Только original files: inode/type/owner/mode/content, без volatile atime."""
    result = []
    for target in (CERT, KEY, CA, '/etc/nginx/mime.types', '/etc/caddy/Caddyfile',
                   *(f'/var/www/lucx-decoys/{domain}/{name}' for domain in domains for name in ('index.html', 'a.css'))):
        path = fs.path(target)
        info = path.lstat()
        result.append((target, info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                       info.st_size, info.st_mtime_ns, info.st_ctime_ns, _sha(path.read_bytes())))
    return result


def create_sources(root, *, domains=DOMAINS):
    fs = TargetFS(root / 'source')
    fs.root.mkdir(mode=0o700)
    config = _write(fs, '/cert/request.cnf', (
        '[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n'
        '[dn]\nCN=vpn.example.test\n[ext]\nbasicConstraints=critical,CA:TRUE\n'
        'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n'
        'extendedKeyUsage=serverAuth\nsubjectAltName=' + ','.join('DNS:' + value for value in domains) + '\n').encode())
    completed = subprocess.run(['/usr/bin/openssl', 'req', '-new', '-x509', '-nodes', '-newkey', 'rsa:2048',
        '-days', '1', '-config', str(config), '-keyout', str(fs.path(KEY)), '-out', str(fs.path(CERT))],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=15, check=False, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    if completed.returncode:
        raise RuntimeError('certificate_generation')
    fs.path(KEY).chmod(0o600)
    fs.path(CERT).chmod(0o600)
    _write(fs, CA, fs.path(CERT).read_bytes())
    _write(fs, '/etc/nginx/mime.types', Path('/etc/nginx/mime.types').read_bytes())
    _write(fs, '/etc/caddy/Caddyfile', b'# retained synthetic Naive source\n')
    for domain in domains:
        _write(fs, '/var/www/lucx-decoys/' + domain + '/index.html', HTML)
        _write(fs, '/var/www/lucx-decoys/' + domain + '/a.css', CSS)
    return fs


@contextmanager
def reservations(count):
    sockets = []
    try:
        for _ in range(count):
            stream = socket.socket()
            sockets.append(stream)
            stream.bind(('127.0.0.1', 0))
        yield tuple(stream.getsockname()[1] for stream in sockets)
    finally:
        for stream in sockets:
            stream.close()


def backend_config(case, user_id, port, fs):
    settings = {'clients': [{'id': user_id}]}
    if case['protocol'] == 'vless':
        settings['decryption'] = 'none'
    transport = case['transport']
    stream = {'network': transport, 'security': 'tls', 'tlsSettings': {
        'alpn': ['http/1.1'] if transport in {'ws', 'httpupgrade'} else ['h2'],
        'certificates': [{'certificate': fs.path(CERT).read_text().splitlines(),
                          'key': fs.path(KEY).read_text().splitlines()}]}}
    key = {'ws': 'wsSettings', 'httpupgrade': 'httpupgradeSettings', 'grpc': 'grpcSettings', 'xhttp': 'xhttpSettings'}[transport]
    stream[key] = {'serviceName' if transport == 'grpc' else 'path': case['path']}
    if transport == 'xhttp':
        stream[key]['mode'] = case['mode']
    return {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port,
        'protocol': case['protocol'], 'settings': settings, 'streamSettings': stream}],
        'outbounds': [{'protocol': 'freedom', 'settings': {}}]}


def _wait_backend(process, port):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('backend_exited')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return
        except OSError:
            time.sleep(.02)
    raise TimeoutError('backend_listener')


@contextmanager
def existing_backend(config):
    """Запускается parent вне coordinator, config только в sealed memfd."""
    import fcntl
    payload = _encoded(config)
    fd = os.memfd_create('synthetic-existing-xray', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    process = None
    try:
        os.write(fd, payload)
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        process = subprocess.Popen([str(XRAY), 'run', '-format', 'json', '-config', f'/proc/self/fd/{fd}'],
            pass_fds=(fd,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        port = config['inbounds'][0]['port']
        _wait_backend(process, port)
        yield process, fd, _sha(payload)
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        os.close(fd)


def prerequisites():
    """Только установленный test image; скачивания, пакетов и PATH discovery нет."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        return 'Нужен изолированный Linux root fixture'
    if os.environ.get('XTUNA_TEST_XRAY') != str(XRAY):
        return 'Нужен явный XTUNA_TEST_XRAY=/usr/local/bin/xray'
    for path in (XRAY, *FRONTENDS.values(), Path('/usr/bin/openssl'), Path('/usr/bin/curl'), Path('/etc/nginx/mime.types')):
        if not path.is_file():
            return 'Test image не содержит обязательный frontend/TLS/HTTP2 инструмент'
    if _sha(XRAY.read_bytes()) != XRAY_SHA256:
        return 'SHA-256 тестового Xray не совпал с закреплённым'
    result = subprocess.run(['/usr/bin/curl', '--disable', '--version'], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, timeout=5, check=False)
    if result.returncode or not any(line.startswith('Features:') and 'HTTP2' in line.split() for line in result.stdout.splitlines()):
        return 'Test image требует curl с HTTP2'
    import pwd
    try:
        account = pwd.getpwnam('haproxy')
    except KeyError:
        return 'Нужна существующая ненулевая service identity haproxy'
    if not account.pw_uid or not account.pw_gid:
        return 'Нужна существующая ненулевая service identity haproxy'
    return ''


def _nginx_wrapper(fragment, mime, runtime_root):
    lines = ['error_log stderr warn;', f'pid {runtime_root}/nginx.pid;', 'events {}', 'http {',
             f'include {mime};', 'access_log off;']
    for directive in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'):
        lines.append(f'{directive}_temp_path {runtime_root}/{directive};')
    return ('\n'.join(lines) + '\n' + fragment + '\n}\n').encode()


def _safe_failure(error):
    reasons = {'Ожидаемый listener принадлежит другому процессу': 'foreign_listener',
        'Frontend завершился до проверки listeners': 'frontend_exited',
        'Не удалось запустить staging frontend': 'frontend_start',
        'Лишний owned listener': 'extra_owned_listener',
        'Не подтверждён полный набор staging listeners': 'listeners_incomplete'}
    result = {'kind': type(error).__name__ if type(error).__name__ in {
        'ValueError', 'RuntimeError', 'StagingProcessError', 'PermissionError', 'TimeoutError',
        'FileNotFoundError', 'ProcessLookupError', 'AssertionError', 'OSError'} else 'unknown',
        'reason': reasons.get(str(error), 'unclassified')}
    trace = error.__traceback__
    while trace is not None:
        if trace.tb_frame.f_code.co_name in {'coordinator', 'start', 'wait_for_listeners', '_checked_config',
                '_verified_binary', 'prepare_read_access', 'verify_copies', 'verify_sources', 'cleanup'}:
            result.update(at=trace.tb_frame.f_code.co_name, line=trace.tb_lineno)
        trace = trace.tb_next
    return result


def coordinator(request):
    """Запускает реальные штатные frontend/probes без production Engine."""
    import pwd
    result = {'stage': 'setup', 'passed': False, 'cleanup_complete': False}
    try:
        root = Path(request['root'])
        fs = TargetFS(root / 'source')
        manifest = request['manifest']
        original_manifest = _encoded(manifest)
        account = pwd.getpwnam('haproxy')
        identity = ServiceIdentity(account.pw_uid, account.pw_gid)
        config_root, writable = root / 'configs', root / 'runtime'
        config_root.mkdir(mode=0o710)
        os.chown(config_root, 0, identity.gid)
        config_root.chmod(0o710)
        writable.mkdir(mode=0o700)
        os.chown(writable, identity.uid, identity.gid)
        for name in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'):
            directory = writable / name
            directory.mkdir(mode=0o700)
            os.chown(directory, identity.uid, identity.gid)
        generated = render_files(manifest)
        for site in manifest['decoys']['sites']:
            generated.pop(site['root'] + '/index.html', None)
        original_haproxy, original_nginx = render_haproxy(manifest), render_nginx_decoys(manifest)
        run_id = 'frontend-' + uuid.uuid4().hex
        staged = stage_files(fs, generated, run_id)
        seal = capture_staged_candidate(fs, manifest, generated, staged, run_id)
        result['stage'] = 'materials'
        with create_staging_materials(fs, manifest, generated, temporary_parent=root) as materials:
            material_root = materials.root
            materials.prepare_read_access(identity.uid, identity.gid)
            inventory = frontend_listener_inventory(manifest)
            if set(materials.paths) != set(frontend_material_inventory(manifest)):
                raise AssertionError('material_inventory')
            with reservations(len(inventory)) as ports:
                runtime = RenderRuntime({key: SocketAddress('127.0.0.1', port) for key, port in zip(inventory, ports)},
                                        paths=materials.paths, foreground=True, suppress_system_log=True)
            configs = {'haproxy': render_haproxy(manifest, runtime=runtime).encode(),
                       'nginx': _nginx_wrapper(render_nginx_decoys(manifest, runtime=runtime), materials.mime_path, writable)}
            paths = {}
            for role, payload in configs.items():
                path = config_root / (role + '.conf')
                path.write_bytes(payload)
                os.chown(path, 0, identity.gid)
                path.chmod(0o640)
                paths[role] = path
            binding = create_candidate_binding(manifest, run_id=run_id, staged_seal=seal,
                routing_snapshot={'profile': routing_fingerprint(manifest['protocols'][0], 443)},
                runtime_configs=configs, runtime=runtime, material_snapshot_digest=materials.snapshot_digest,
                toolchain=request['toolchain'])
            expected = {'haproxy': [value for key, value in runtime.listeners.items() if key.role in {'public', 'split'}],
                        'nginx': [value for key, value in runtime.listeners.items() if key.role.startswith('decoy_')]}
            session = ForegroundSession(timeout=110)
            result['stage'] = 'frontends'
            with session:
                for role, binary in FRONTENDS.items():
                    session.start(FrontendSpec(role, binary, request['toolchain'][role]['sha256'],
                                               paths[role], config_root, identity))
                session.wait_for_listeners(expected, timeout=10)
                result['stage'] = 'browser'

                def browser_dial(target, phase):
                    if phase != 'staging':
                        raise ValueError('phase')
                    key = (ListenerKey('public', target['port']) if target['path'] == 'public_tls' else
                           ListenerKey('decoy_tls' if target['path'] == 'internal_tls' else 'decoy_h2c'))
                    address = runtime.listeners[key]
                    return BrowserDialAddress(address.host, address.port)

                runner = Runner()
                browser_rows = observe_decoy_capabilities(manifest, '127.0.0.1', timeout=5, runner=runner,
                    phase='staging', dial_target_provider=browser_dial, ca_file=materials.paths[CA])
                plain = runtime.listeners[ListenerKey('decoy_plain')]
                plain_rows = [observe_decoy(DOMAINS[2], '127.0.0.1', manifest['decoys']['listen_port'] + 2,
                    'X-LucX-Decoy: ' + DOMAINS[2], use_tls=False, method=method, strict_content=True,
                    phase='staging', dial_address=BrowserDialAddress(plain.host, plain.port), runner=runner)
                    for method in ('GET', 'HEAD')]
                result['stage'] = 'vpn'

                def vpn_dial(value, phase):
                    if phase != 'staging':
                        raise ValueError('phase')
                    target = runtime.listeners[ListenerKey('public', value['acceptance_endpoint']['port'])]
                    return target.host, target.port

                observer = XrayVPNObserver(XrayProbeContext(binary_path=XRAY, binary_sha256=XRAY_SHA256,
                    credential_provider=lambda value: XrayProbeCredential(request['user_id'],
                        routing_fingerprint(value, 443), fs.path(CA).read_text()),
                    echo_address='127.0.0.1', echo_port=0, timeout=20, coordinator_pid=os.getpid(),
                    dial_target_provider=vpn_dial))
                vpn_rows = observe_vpn_capabilities(manifest, runner, phase='staging',
                                                   observers={request['case']['protocol']: observer})
                result['stage'] = 'recheck'
                session.wait_for_listeners(expected, timeout=3)
                materials.verify_sources()
                materials.verify_copies()
                seal.verify(fs, manifest, generated, staged, run_id)
                unchanged = (_encoded(manifest) == original_manifest and render_haproxy(manifest) == original_haproxy
                    and render_nginx_decoys(manifest) == original_nginx
                    and all(path.read_bytes() == configs[role] for role, path in paths.items()))
                if not unchanged:
                    raise AssertionError('candidate_changed')
            result['cleanup_complete'] = session.cleanup_complete
            # Binding добавляется лишь к реально полученным rows; state не подменяется.
            for row in (*browser_rows, *vpn_rows):
                row['candidate_fingerprint'] = binding.fingerprint
            receipt = StagingReceipt(binding, browser_rows, vpn_rows, session.cleanup_complete, True, True, unchanged)
            summary = staging_acceptance_summary(manifest, receipt, expected_binding=binding)
            result.update(summary=summary, browser_rows=len(browser_rows), vpn_rows=len(vpn_rows),
                browser_failed=sum(row['state'] != 'healthy' for row in browser_rows),
                vpn_failed=sum(row['state'] != 'healthy' for row in vpn_rows),
                plain_verified=all(row['state'] == 'healthy' and row.get('content_verified') is True for row in plain_rows),
                public_rejected=not decoy_acceptance_summary(manifest, browser_rows)['complete']
                    and not vpn_acceptance_summary(manifest, vpn_rows)['complete'],
                nonroot_verified=identity.uid > 0 and identity.gid > 0,
                vpn_exchange_verified=all(row.get('authenticated') is True and row.get('bytes_sent') == 16384
                    and row.get('bytes_received') == 16384 and row.get('public') is False for row in vpn_rows),
                css_verified=all(row.get('resource_count') == 1 and row.get('verified_resources') == 1
                                 for row in browser_rows if row.get('method') == 'GET'))
        result.update(materials_removed=not material_root.exists(), stage='complete')
        result['passed'] = (result['summary']['candidate_verified'] and result['cleanup_complete']
            and all(result[key] for key in ('plain_verified', 'public_rejected', 'nonroot_verified',
                                           'vpn_exchange_verified', 'css_verified', 'materials_removed')))
    except Exception as error:  # noqa: BLE001 — наружу только безопасные коды, без payload.
        result['failure'] = _safe_failure(error)
    return result


def run_case(case):
    """Parent owns synthetic sources/backend until outer Runner has stopped."""
    with tempfile.TemporaryDirectory(prefix='xtuna-frontend-') as temporary:
        root = Path(temporary)
        root.chmod(0o711)
        fs = create_sources(root)
        with reservations(1) as ports:
            backend_port = ports[0]
        manifest = make_manifest(case, backend_port)
        user_id = str(uuid.uuid4())
        config = backend_config(case, user_id, backend_port, fs)
        originals = source_snapshot(fs)
        logical_snapshot = _encoded(manifest)
        toolchain = {role: {'path': str(path), 'sha256': _sha(path.read_bytes())} for role, path in FRONTENDS.items()}
        toolchain['xray'] = {'path': str(XRAY), 'sha256': XRAY_SHA256}
        request = {'root': str(root), 'manifest': manifest, 'case': case, 'user_id': user_id, 'toolchain': toolchain}
        with existing_backend(config) as (backend, descriptor, digest):
            bootstrap = ('import sys,runpy;sys.path[:0]=sys.argv[1:3];'
                'sys.argv=["staging_frontend_fixture","--coordinator"];'
                'runpy.run_module("staging_frontend_fixture",run_name="__main__")')
            completed = Runner().run_bounded([sys.executable, '-I', '-S', '-c', bootstrap,
                str(Path(__file__).absolute().parents[1] / 'src'), str(Path(__file__).absolute().parent)],
                input_text=_encoded(request).decode(), timeout=120, max_output_bytes=4096,
                isolate_process_group=True, inherit_env=False, check=False)
            if completed.returncode:
                return {'passed': False, 'stage': 'outer_worker', 'returncode': completed.returncode}
            result = json.loads(completed.stdout)
            _wait_backend(backend, backend_port)
            result['existing_backend_preserved'] = (
                _sha(os.pread(descriptor, len(_encoded(config)) + 1, 0)) == digest
                and _encoded(manifest) == logical_snapshot and source_snapshot(fs) == originals
                and backend.poll() is None and os.getpgid(backend.pid) == os.getpgrp())
            result['passed'] = result['passed'] and result['existing_backend_preserved']
            return result


if __name__ == '__main__':
    if sys.argv[1:] != ['--coordinator']:
        raise SystemExit(2)
    print(json.dumps(coordinator(json.loads(sys.stdin.read(256 * 1024))), separators=(',', ':')))
