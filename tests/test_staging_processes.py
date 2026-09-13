"""Проверки владения процессами; эти фикстуры не являются VPN evidence."""
from __future__ import annotations

import importlib
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import time
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from lucx_post_configurator.render_runtime import SocketAddress
from lucx_post_configurator.runner import Runner

HEADER = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
TCP4 = ' 0: 0100007F:A029 00000000:0000 0A 00000000:00000000 00:00000000 00000000 65534 0 12345 1 0 100 0 0 10 0\n'
TCP6 = ' 1: 00000000000000000000000001000000:A02A 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 65534 0 12346 1 0 100 0 0 10 0\n'


class ProcessContracts(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('lucx_post_configurator.staging_processes'),
                             'Отсутствует supervisor staging-процессов')
        self.module = importlib.import_module('lucx_post_configurator.staging_processes')

    def test_literal_ipv4_and_ipv6_listen_rows(self):
        rows = self.module.parse_tcp_listeners(HEADER + TCP4, ipv6=False, byteorder='little')
        self.assertEqual([(x.host, x.port, x.inode) for x in rows], [('127.0.0.1', 41001, 12345)])
        rows = self.module.parse_tcp_listeners(HEADER + TCP6, ipv6=True, byteorder='little')
        self.assertEqual([(x.host, x.port, x.inode) for x in rows], [('::1', 41002, 12346)])

    def test_big_endian_words_and_non_listeners(self):
        data = TCP4.replace('0100007F', '7F000001')
        rows = self.module.parse_tcp_listeners(HEADER + data, ipv6=False, byteorder='big')
        self.assertEqual(rows[0].host, '127.0.0.1')
        self.assertEqual(self.module.parse_tcp_listeners(HEADER + TCP4.replace(' 0A ', ' 01 '), ipv6=False), ())

    def test_public_and_wildcard_rows_are_retained_for_rejection(self):
        rows = self.module.parse_tcp_listeners(HEADER + TCP4.replace('0100007F', '00000000'), ipv6=False)
        self.assertEqual(rows[0].host, '0.0.0.0')

    def test_malformed_proc_rows_fail_closed_without_raw_text(self):
        for value in ('secret-sentinel', HEADER + 'secret-sentinel\n',
                      HEADER + TCP4.replace('12345', '-2'), HEADER + TCP4.replace('0100007F', 'XYZ'),
                      HEADER + TCP4.replace(' 0A ', ' XX '), HEADER + TCP4 + TCP4):
            with self.subTest(value=len(value)), self.assertRaises(ValueError) as caught:
                self.module.parse_tcp_listeners(value, ipv6=False)
            self.assertNotIn('secret-sentinel', str(caught.exception))

    def test_proc_table_and_row_limits(self):
        with self.assertRaises(ValueError):
            self.module.parse_tcp_listeners(HEADER + TCP4, ipv6=False, max_rows=0)
        with self.assertRaises(ValueError):
            self.module.parse_tcp_listeners(HEADER + TCP4, ipv6=False, max_bytes=32)

    def test_proc_short_read_does_not_mean_end_of_table(self):
        data = (HEADER + TCP4).encode('ascii')

        class ShortStream(io.BytesIO):
            def read(self, count=-1):
                return super().read(min(17, count))

        with mock.patch.object(Path, 'open', return_value=ShortStream(data)):
            self.assertEqual(self.module._read(Path('/proc/net/tcp'), 8192,
                             time.monotonic() + 2), data.decode('ascii'))
        with mock.patch.object(Path, 'open', return_value=ShortStream(data)):
            with self.assertRaises(ValueError):
                self.module._read(Path('/proc/net/tcp'), 32, time.monotonic() + 2)

    def test_stat_comm_parentheses_do_not_shift_starttime(self):
        # После comm: поля 3..22. Значение поля 22 задано вручную.
        row = '321 (name ) with spaces) S 99 321 321 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 987654 0 0'
        identity = self.module.parse_process_stat(row)
        self.assertEqual((identity.pid, identity.ppid, identity.pgrp, identity.session, identity.starttime),
                         (321, 99, 321, 321, 987654))

    def test_bad_stat_is_private_failure(self):
        for row in ('sensitive-process', '321 (bad) S 0 0', '0 (bad) S ' + '0 ' * 30):
            with self.assertRaises(ValueError) as caught:
                self.module.parse_process_stat(row)
            self.assertNotIn('sensitive-process', str(caught.exception))

    def test_nonroot_identity_and_finite_budget_required(self):
        for uid, gid in ((0, 1), (1, 0), (-1, 1), (True, 1)):
            with self.assertRaises(ValueError):
                self.module.ServiceIdentity(uid, gid)
        for timeout in (0, -1, .12, 2.9, float('nan'), float('inf'), 301, True):
            with self.assertRaises(ValueError):
                self.module.ForegroundSession(timeout=timeout)

    def test_spec_does_not_accept_commands_or_publish_private_paths(self):
        identity = self.module.ServiceIdentity(65534, 65534)
        root = Path(tempfile.gettempdir()) / 'private-sentinel'
        spec = self.module.FrontendSpec('nginx', root / 'bin', 'a' * 64,
                                       root / 'config', root, identity)
        self.assertNotIn('private-sentinel', repr(spec))
        for role in ('sh', '', '--daemon'):
            with self.assertRaises(ValueError):
                self.module.FrontendSpec(role, Path('/bin/safe'), 'a' * 64,
                                         Path('/tmp/c'), Path('/tmp'), identity)

    def test_expected_roles_and_collisions_are_exact(self):
        fn = self.module.normalize_expected
        a, b = SocketAddress('127.0.0.1', 41001), SocketAddress('127.0.0.1', 41002)
        self.assertEqual(fn({'nginx': [a], 'haproxy': [b]}, {'nginx', 'haproxy'}),
                         {'nginx': frozenset({a}), 'haproxy': frozenset({b})})
        for expected in ({'nginx': []}, {'nginx': [a, a]}, {'nginx': [a], 'haproxy': [a]},
                         {'nginx': [a]}, {'nginx': [('127.0.0.1', 41001)]}):
            with self.assertRaises(ValueError):
                fn(expected, {'nginx', 'haproxy'})

    def test_process_identity_guards_pid_reuse(self):
        identity = self.module.ProcessIdentity(11, 10, 10, 10, 100, 'S')
        for pid, pgrp, session, started in ((12, 10, 10, 100), (11, 10, 10, 101),
                                           (11, 11, 10, 100), (11, 10, 11, 100)):
            self.assertFalse(identity.same_process(self.module.ProcessIdentity(
                pid, 10, pgrp, session, started, 'S')))

    def test_fixture_diagnostics_do_not_publish_exception_payload(self):
        self.assertTrue(callable(globals().get('_safe_failure')), 'Нужна безопасная fixture диагностика')
        error = self.module.StagingProcessError('private-sentinel')
        error.__context__ = PermissionError(13, 'private-sentinel', '/private-sentinel')
        diagnostics = _safe_failure(error)
        self.assertEqual(diagnostics['kind'], 'PermissionError')
        self.assertEqual(diagnostics['errno'], 13)
        self.assertNotIn('private-sentinel', json.dumps(diagnostics))

    def _snapshot_session(self):
        # Контролируем только границу proc/OS; настоящий wait_for_listeners не заменён.
        owner = self.module.ProcessIdentity(42, 41, 41, 41, 100, 'S')
        coordinator = self.module.ProcessIdentity(41, 1, 41, 41, 99, 'S')
        session = self.module.ForegroundSession(timeout=3)
        session._entered = True
        session._pid = 41
        session._deadline = time.monotonic() + 1
        session._frontends = [self.module._Frontend('nginx', SimpleNamespace(poll=lambda: None), owner)]
        return session, owner, {41: coordinator, 42: owner}

    def test_owned_socket_born_between_proc_snapshots_is_not_foreign(self):
        session, owner, members = self._snapshot_session()
        born = False

        def sockets(info, _deadline):
            return {12345} if info.pid == owner.pid and born else set()

        def listeners(_deadline):
            nonlocal born
            # Сокет появился после предыдущего чтения /proc/PID/fd и до tcp table.
            born = True
            return (self.module.TCPListener('127.0.0.1', 41001, 12345),)

        with mock.patch.object(session, '_members', return_value=members), \
                mock.patch.object(session, '_socket_inodes', side_effect=sockets), \
                mock.patch.object(session, '_listeners', side_effect=listeners), \
                mock.patch.object(self.module, '_process', return_value=owner):
            try:
                session.wait_for_listeners({'nginx': [SocketAddress('127.0.0.1', 41001)]}, timeout=.3)
            except self.module.StagingProcessError as exc:
                self.fail('Новый owned socket ошибочно отвергнут: ' + json.dumps(_safe_failure(exc)))

    def test_stable_foreign_socket_remains_fatal(self):
        session, owner, members = self._snapshot_session()
        with mock.patch.object(session, '_members', return_value=members), \
                mock.patch.object(session, '_socket_inodes', return_value=set()), \
                mock.patch.object(session, '_listeners', return_value=(
                    self.module.TCPListener('127.0.0.1', 41001, 12345),)), \
                mock.patch.object(self.module, '_process', return_value=owner), \
                self.assertRaises(self.module.StagingProcessError) as caught:
            session.wait_for_listeners({'nginx': [SocketAddress('127.0.0.1', 41001)]}, timeout=.3)
        self.assertEqual(_safe_failure(caught.exception)['reason'], 'foreign_listener')

    def test_listener_added_during_ready_check_forces_full_recheck(self):
        session, owner, members = self._snapshot_session()
        calls = 0

        def listeners(_deadline):
            nonlocal calls
            calls += 1
            expected = self.module.TCPListener('127.0.0.1', 41001, 12345)
            extra = self.module.TCPListener('127.0.0.1', 41002, 12346)
            return (expected,) if calls == 1 else (expected, extra)

        def sockets(info, _deadline):
            return {12345, 12346} if info.pid == owner.pid else set()

        with mock.patch.object(session, '_members', return_value=members), \
                mock.patch.object(session, '_socket_inodes', side_effect=sockets), \
                mock.patch.object(session, '_listeners', side_effect=listeners), \
                mock.patch.object(self.module, '_process', return_value=owner), \
                self.assertRaises(self.module.StagingProcessError) as caught:
            session.wait_for_listeners({'nginx': [SocketAddress('127.0.0.1', 41001)]}, timeout=.3)
        self.assertEqual(_safe_failure(caught.exception)['reason'], 'extra_owned_listener')

    def test_platform_and_session_guard_run_before_spawn(self):
        with mock.patch.object(self.module.sys, 'platform', 'win32'), \
                mock.patch.object(self.module.subprocess, 'Popen') as spawn:
            with self.assertRaises(self.module.StagingProcessError), self.module.ForegroundSession():
                self.fail('Supervisor допущен вне Linux')
            spawn.assert_not_called()
        with mock.patch.object(self.module.sys, 'platform', 'linux'), \
                mock.patch.object(self.module.os, 'geteuid', return_value=0, create=True), \
                mock.patch.object(self.module.os, 'getpid', return_value=321), \
                mock.patch.object(self.module.os, 'getpgrp', return_value=99, create=True), \
                mock.patch.object(self.module.os, 'getsid', return_value=99, create=True), \
                self.assertRaises(self.module.StagingProcessError), self.module.ForegroundSession():
            self.fail('Supervisor допущен в чужой группе')


# Фиксированная программа синтетического frontend. Данные не содержат команд.
FIXTURE = '''#!/usr/bin/python3
import json, os, signal, socket, sys, time
flag = '-f' if '-f' in sys.argv else '-c'
with open(sys.argv[sys.argv.index(flag)+1]) as stream:
    config = json.load(stream)
assert os.getuid() != 0 and os.getgid() != 0 and os.getgroups() == []
assert 'STAGING_PRIVATE_SENTINEL' not in os.environ
assert os.getpgrp() == os.getsid(0) and os.getpgrp() != os.getpid()
if config['mode'] == 'exit':
    sys.exit(4)
sockets = []
for host, port in config['binds']:
    sock = socket.socket()
    sock.bind((host, port))
    sock.listen()
    sockets.append(sock)
if config['mode'] == 'orphan':
    child = os.fork()
    if child:
        time.sleep(.05)
        os._exit(0)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if config['mode'] in ('ignore', 'noise'):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if config['mode'] == 'noise':
    child = os.fork()
    if not child:
        for i in range(128):
            os.write(1, b'x' * 65536)
            os.write(2, b'y' * 65536)
while True:
    time.sleep(.05)
'''


def _safe_failure(error):
    """Только коды fixture: raw исключения/argv/proc строки не сериализуются."""
    reasons = {
        'Ожидаемый listener принадлежит другому процессу': 'foreign_listener',
        'Лишний либо неоднозначный owned listener': 'ambiguous_owned_listener',
        'Лишний owned listener': 'extra_owned_listener',
        'Frontend завершился до проверки listeners': 'frontend_exited',
        'Frontend завершился до старта': 'frontend_exited_early',
        'Владелец listener изменился': 'listener_identity_changed',
        'Исчерпан бюджет staging процессов': 'deadline',
        'Некорректная таблица TCP listeners': 'proc_table_invalid',
        'Некорректная identity процесса': 'process_identity_invalid',
    }
    kinds = {'OSError', 'PermissionError', 'FileNotFoundError', 'ProcessLookupError',
             'StagingProcessError', 'ValueError', 'TypeError', 'RuntimeError', 'TimeoutError'}
    functions = {'_read', '_process', '_members', '_socket_inodes', '_listeners', '_signal',
                 '_verified_binary', '_checked_config', '_open_regular', 'start', 'wait_for_listeners',
                 'parse_tcp_listeners', 'parse_process_stat', 'cleanup', '__enter__'}
    result = {'kind': 'unknown', 'reason': 'unclassified', 'errno': 0, 'at': 'unknown', 'line': 0}
    seen = set()
    for _ in range(8):
        if error is None or id(error) in seen:
            break
        seen.add(id(error))
        kind = type(error).__name__
        if kind in kinds:
            result['kind'] = kind
        if kind == 'StagingProcessError' and error.args and error.args[0] in reasons:
            result['reason'] = reasons[error.args[0]]
        number = getattr(error, 'errno', None)
        if type(number) is int and 0 < number < 4096:
            result['errno'] = number
        trace = error.__traceback__
        while trace is not None:
            if (trace.tb_frame.f_globals.get('__name__') == 'lucx_post_configurator.staging_processes'
                    and trace.tb_frame.f_code.co_name in functions):
                result.update(at=trace.tb_frame.f_code.co_name, line=trace.tb_lineno)
            trace = trace.tb_next
        error = error.__context__
    return result


def _worker(scenario, foreign_port=0):
    import hashlib
    import pwd
    import signal

    from lucx_post_configurator import staging_processes as module
    from lucx_post_configurator.staging_processes import (
        ForegroundSession,
        FrontendSpec,
        ServiceIdentity,
        StagingProcessError,
    )
    account = pwd.getpwnam('nobody')
    identity = ServiceIdentity(account.pw_uid, account.pw_gid)
    # Только owned synthetic root; сервис получает traverse и config group-read.
    with tempfile.TemporaryDirectory(prefix='x-tuna-process-test-') as folder:
        root = Path(folder)
        os.chown(root, 0, identity.gid)
        root.chmod(0o710)
        binary = root / 'fixture'
        binary.write_text(FIXTURE, encoding='utf-8')
        binary.chmod(0o755)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        reservations = []
        ports = []
        for _ in range(3):
            reservation = socket.socket()
            reservation.bind(('127.0.0.1', 0))
            reservations.append(reservation)
            ports.append(reservation.getsockname()[1])
        for reservation in reservations:
            reservation.close()
        mode = scenario if scenario in {'exit', 'orphan', 'noise', 'ignore'} else 'normal'
        binds = [('127.0.0.1', foreign_port or ports[0])]
        if scenario in {'missing', 'budget'}:
            binds = []
        if scenario == 'extra':
            binds.append(('127.0.0.1', ports[2]))
        if scenario == 'public':
            binds = [('0.0.0.0', ports[0])]
        config = root / 'nginx.config'
        config.write_text(json.dumps({'mode': mode, 'binds': binds}), encoding='utf-8')
        os.chown(config, 0, identity.gid)
        config.chmod(0o640)
        config2 = root / 'haproxy.config'
        config2.write_text(json.dumps({'mode': 'normal', 'binds': [('127.0.0.1', ports[1])]}))
        os.chown(config2, 0, identity.gid)
        config2.chmod(0o640)
        if scenario == 'bad_hash':
            digest = '0' * 64
        elif scenario == 'binary_symlink':
            link = root / 'fixture.link'
            link.symlink_to(binary)
            binary = link
        elif scenario == 'binary_writable':
            binary.chmod(0o775)
        elif scenario == 'binary_setuid':
            binary.chmod(0o4755)
        elif scenario == 'binary_fifo':
            binary = root / 'fixture.fifo'
            os.mkfifo(binary)
        elif scenario == 'config_symlink':
            link = root / 'config.link'
            link.symlink_to(config)
            config = link
        elif scenario == 'config_writable':
            config.chmod(0o660)
        elif scenario == 'config_world_readable':
            config.chmod(0o644)
        expected = {'nginx': [SocketAddress('127.0.0.1', foreign_port or ports[0])]}
        if scenario == 'partial':
            expected['nginx'].append(SocketAddress('127.0.0.1', ports[1]))
        session = ForegroundSession(timeout=3 if scenario == 'budget' else 4)
        outcome = 'unknown'
        stage = 'enter'
        failure = {}
        began = time.monotonic()
        original_popen = module.subprocess.Popen

        def swapped_binary(args, **options):
            replacement = root / 'replacement'
            replacement.write_text('#!/usr/bin/python3\nraise SystemExit(7)\n', encoding='utf-8')
            replacement.chmod(0o755)
            os.replace(replacement, binary)
            return original_popen(args, **options)

        spawn_context = (mock.patch.object(module.subprocess, 'Popen', side_effect=swapped_binary)
                         if scenario == 'binary_swap' else nullcontext())
        try:
            with session, spawn_context:
                stage = 'start_nginx'
                session.start(FrontendSpec('nginx', binary, digest, config, root, identity))
                if scenario == 'normal':
                    stage = 'start_haproxy'
                    session.start(FrontendSpec('haproxy', binary, digest, config2, root, identity))
                    expected['haproxy'] = [SocketAddress('127.0.0.1', ports[1])]
                if scenario == 'orphan':
                    time.sleep(.15)
                if scenario == 'budget':
                    time.sleep(.7)
                stage = 'listeners'
                session.wait_for_listeners(expected, timeout=.6)
                stage = 'scenario'
                if scenario == 'interrupt':
                    raise KeyboardInterrupt()
                if scenario == 'signal_interrupt':
                    os.kill(os.getpid(), signal.SIGINT)
                if scenario == 'signal_term':
                    os.kill(os.getpid(), signal.SIGTERM)
                if scenario == 'exception':
                    raise RuntimeError('private-sentinel')
                if scenario == 'cleanup_error':
                    # Сбой финального чтения proc блокирует receipt после смерти детей.
                    def failed_check(_deadline):
                        raise OSError('private-sentinel')
                    session._listeners = failed_check
                outcome = 'ready'
                stage = 'cleanup'
        except StagingProcessError as exc:
            outcome = 'rejected'
            failure = _safe_failure(exc)
        except KeyboardInterrupt:
            outcome = 'interrupted'
        except RuntimeError:
            outcome = 'exception'
        remaining = []
        # Независимая проверка исчезновения группы, включая зомби потомков.
        for entry in Path('/proc').iterdir():
            if entry.name.isdigit() and int(entry.name) != os.getpid():
                try:
                    fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
                    if int(fields[2]) == os.getpgrp():
                        remaining.append(int(entry.name))
                except FileNotFoundError:
                    pass
        return {'outcome': outcome, 'cleanup': session.cleanup_complete,
                'remaining': len(remaining), 'elapsed': time.monotonic() - began,
                'stage': stage, 'failure': failure}


@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'Нужен изолированный Linux root с SETUID/SETGID/SYS_PTRACE')
class LinuxProcesses(unittest.TestCase):
    def run_worker(self, scenario, foreign_port=0):
        bootstrap = ("import sys,runpy;sys.path[:0]=sys.argv[1:3];"
                     "sys.argv=['test_staging_processes','--worker'];"
                     "runpy.run_module('test_staging_processes',run_name='__main__')")
        result = Runner().run_bounded([sys.executable, '-I', '-S', '-c', bootstrap,
            str(Path(__file__).resolve().parents[1] / 'src'), str(Path(__file__).resolve().parent)],
            input_text=json.dumps({'scenario': scenario, 'foreign_port': foreign_port}),
            timeout=8, max_output_bytes=1024, isolate_process_group=True, inherit_env=False,
            env={'STAGING_PRIVATE_SENTINEL': 'private-sentinel'}, check=False)
        self.assertEqual(result.returncode, 0, 'Синтетический coordinator завершился с ошибкой')
        self.assertEqual(result.stderr, '')
        data = json.loads(result.stdout)
        self.assertEqual(data['cleanup'], scenario != 'cleanup_error', data)
        self.assertEqual(data['remaining'], 0)
        self.assertLess(data['elapsed'], 6)
        if scenario in {'normal', 'ignore', 'noise', 'binary_swap'}:
            self.assertEqual(data['outcome'], 'ready', data)
        return data

    def test_two_owned_frontends(self):
        self.assertEqual(self.run_worker('normal')['outcome'], 'ready')

    def test_exit_before_startup(self):
        self.assertEqual(self.run_worker('exit')['outcome'], 'rejected')

    def test_missing_and_partial_listeners(self):
        for scenario in ('missing', 'partial'):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.run_worker(scenario)['outcome'], 'rejected')

    def test_extra_and_public_listeners(self):
        for scenario in ('extra', 'public'):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.run_worker(scenario)['outcome'], 'rejected')

    def test_foreign_listener_survives_rejection(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            port = listener.getsockname()[1]
            self.assertEqual(self.run_worker('foreign', port)['outcome'], 'rejected')
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                connection, _ = listener.accept()
                connection.close()

    def test_orphan_ignoring_term_is_reaped(self):
        self.assertEqual(self.run_worker('orphan')['outcome'], 'rejected')

    def test_term_ignored_and_descendant_output_are_bounded(self):
        for scenario in ('ignore', 'noise'):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.run_worker(scenario)['outcome'], 'ready')

    def test_exception_and_keyboard_interrupt_cleanup(self):
        for scenario, outcome in (('exception', 'exception'), ('interrupt', 'interrupted')):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.run_worker(scenario)['outcome'], outcome)

    def test_real_abort_signals_trigger_cleanup(self):
        for scenario, outcome in (('signal_interrupt', 'interrupted'), ('signal_term', 'rejected')):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.run_worker(scenario)['outcome'], outcome)

    def test_binary_and_config_preflight_refuse_unsafe_files(self):
        for scenario in ('bad_hash', 'binary_symlink', 'binary_writable', 'binary_setuid',
                         'binary_fifo', 'config_symlink', 'config_writable', 'config_world_readable'):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.run_worker(scenario)['outcome'], 'rejected')

    def test_binary_path_replacement_cannot_change_executed_fd(self):
        self.assertEqual(self.run_worker('binary_swap')['outcome'], 'ready')

    def test_total_deadline_is_not_reset_by_listener_wait(self):
        data = self.run_worker('budget')
        self.assertEqual(data['outcome'], 'rejected')
        self.assertLess(data['elapsed'], 1.2)

    def test_cleanup_failure_cannot_issue_complete_receipt(self):
        self.assertEqual(self.run_worker('cleanup_error')['outcome'], 'rejected')

    def test_binary_hash_detects_metadata_drift_during_fd_read(self):
        import hashlib

        from lucx_post_configurator import staging_processes as module
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'fixture'
            binary.write_bytes(b'bounded-native-fixture')
            binary.chmod(0o755)
            expected = hashlib.sha256(binary.read_bytes()).hexdigest()
            original_read = os.read
            changed = False

            def changing_read(fd, amount):
                nonlocal changed
                data = original_read(fd, amount)
                if not changed:
                    binary.chmod(0o700)
                    changed = True
                return data

            with mock.patch.object(module.os, 'read', side_effect=changing_read), \
                    self.assertRaises(module.StagingProcessError):
                module._verified_binary(binary, expected, time.monotonic() + 1)


if __name__ == '__main__':
    if sys.argv[1:] == ['--worker']:
        try:
            request = json.loads(sys.stdin.buffer.read(1024))
            print(json.dumps(_worker(**request), separators=(',', ':')))
        except BaseException:  # noqa: BLE001 — даже ошибка fixture не публикует raw output.
            raise SystemExit(1) from None
    else:
        unittest.main()
