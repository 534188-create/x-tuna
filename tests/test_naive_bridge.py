"""Kernel filter не выпускает пароль или данные стороннего SOCKS-туннеля."""
from __future__ import annotations

import importlib.util
import os
import secrets
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


def packet(payload=b'', *, reverse=False, seq=100, ack=200, flags=0x18, options=12):
    source, destination = (19443, 31000) if reverse else (31000, 19443)
    tcp = struct.pack('!HHIIBBHHH', source, destination, seq, ack,
                      ((20 + options) // 4) << 4, flags, 32768, 0, 0) + b'\x01' * options
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0x4000,
                     64, 6, 0, socket.inet_aton('127.0.0.1'), socket.inet_aton('127.0.0.1'))
    return ip + tcp + payload


CONNECT = b'\x05\x01\x00\x01' + socket.inet_aton('192.0.2.10') + struct.pack('!H', 19600)
AUTH = b'\x01\x04lucx\x18' + b'abcdefghijklmnopqrstuvwx'


class BridgeSocketTableTests(unittest.TestCase):
    def test_ipv4_mapped_tcp6_and_cross_table_ambiguity(self):
        from lucx_post_configurator import naive_bridge as module
        def address(host, port, mapped=False):
            raw = socket.inet_aton(host)
            if mapped:
                raw = bytes(10) + b'\xff\xff' + raw
            return ''.join(f'{int.from_bytes(raw[i:i + 4], sys.byteorder):08X}'
                           for i in range(0, len(raw), 4)) + f':{port:04X}'
        local, remote = ('127.0.0.1', 19443), ('127.0.0.1', 31000)
        header = ' sl local_address rem_address st\n'
        def table(mapped):
            return header + f'0: {address(*local, mapped)} {address(*remote, mapped)} 01 0 0 0 0 0 777\n'
        with mock.patch.object(module, '_read', side_effect=lambda path, *args:
                               table(True) if path.name == 'tcp6' else header):
            self.assertEqual(module._tcp_inode(local, remote, time.monotonic() + 2), 777)
        with mock.patch.object(module, '_read', side_effect=lambda path, *args:
                               table(path.name == 'tcp6')):
            with self.assertRaises(ValueError):
                module._tcp_inode(local, remote, time.monotonic() + 2)


class BridgeSequenceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('lucx_post_configurator.naive_bridge'),
                             'Нужен ограниченный свидетель handshake SOCKS bridge')
        from lucx_post_configurator.naive_bridge import BridgeSequence
        self.sequence = BridgeSequence('192.0.2.10', 19600, 19443)

    def events(self):
        return [packet(seq=100, ack=0, flags=2),
            packet(reverse=True, seq=200, ack=101, flags=0x12),
            packet(b'\x05\x02\x00\x02', seq=101, ack=201),
            packet(b'\x05\x02', reverse=True, seq=201, ack=105),
            packet(AUTH, seq=105, ack=203)[:-29],
            packet(b'\x01\x00', reverse=True, seq=203, ack=136),
            packet(CONNECT, seq=136, ack=205)]

    def test_fresh_authenticated_connect_has_exact_tcp_sequence(self):
        events = self.events()
        for event in events[:-1]:
            self.assertIsNone(self.sequence.observe(event))
        self.assertEqual(self.sequence.observe(events[-1]), (31000, 100, 200))

    def test_existing_tunnel_payload_and_missing_handshake_do_not_count(self):
        events = self.events()
        for missing in range(6):
            self.setUp()
            results = [self.sequence.observe(event) for i, event in enumerate(events) if i != missing]
            self.assertFalse(any(result is not None for result in results))
        self.setUp()
        for event in events[:-1]:
            self.sequence.observe(event)
        self.assertIsNone(self.sequence.observe(packet(CONNECT, seq=146, ack=215)))


class BridgeCaptureStateTests(unittest.TestCase):
    def setUp(self):
        from lucx_post_configurator import naive_bridge
        self.module = naive_bridge
        self.capture = naive_bridge.BridgeCapture('192.0.2.10', 19600, 19443,
            caddy_pid=100, caddy_sha256='a' * 64, xray_pid=101, xray_sha256='b' * 64)
        self.capture._deadline = time.monotonic() + 5
        self.capture._actors = ((SimpleNamespace(pid=100),), (SimpleNamespace(pid=101),))
        self.stream = self.capture._socket = mock.Mock()
        self.stream.getsockopt.return_value = struct.pack('II', 10, 0)
        self.peer = mock.Mock(family=socket.AF_INET)
        self.peer.getsockname.return_value = ('192.0.2.10', 19600)
        self.peer.getpeername.return_value = ('192.0.2.10', 31001)
        self.peer.fileno.return_value = 77
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(naive_bridge.os, 'fstat',
            return_value=SimpleNamespace(st_ino=10000)))
        self.stack.enter_context(mock.patch.object(naive_bridge, '_actor', return_value=None))
        self.stack.enter_context(mock.patch.object(naive_bridge, '_same_actor', return_value=True))
        self.owner = self.stack.enter_context(mock.patch.object(naive_bridge, '_owned'))
        self.stack.enter_context(mock.patch.object(naive_bridge, '_tcp_inode',
            side_effect=lambda local, remote, deadline: 10001 if local[0] == '192.0.2.10'
                        else 10002 if remote[1] == 19443 else 10003))

    def queue(self, values):
        iterator = iter(values)

        def receive(*args):
            try:
                return next(iterator), [], 0, ('lo', 0x0800, 0)
            except StopIteration:
                raise BlockingIOError from None
        self.stream.recvmsg.side_effect = receive

    def events(self, peer=31000):
        source = BridgeSequenceTests()
        result = source.events()
        return [value[:20] + (value[20:22] + struct.pack('!H', peer) if value[20:22] == struct.pack('!H', 19443)
                else struct.pack('!H', peer) + value[22:24]) + value[24:] for value in result]

    def test_old_connect_followed_by_reset_and_new_syn_cannot_bind_new_inode(self):
        self.queue(self.events() + [packet(seq=146, ack=205, flags=0x14),
                                   packet(seq=1000, ack=0, flags=2)])
        self.assertFalse(self.capture.prove(self.peer))

    def test_packet_drop_poison_persists_for_next_otherwise_valid_attempt(self):
        self.queue(self.events())
        self.stream.getsockopt.return_value = struct.pack('II', 10, 1)
        self.assertFalse(self.capture.prove(self.peer))
        self.queue(self.events(peer=31002))
        self.stream.getsockopt.return_value = struct.pack('II', 10, 0)
        self.assertFalse(self.capture.prove(self.peer))

    def test_owner_failure_poison_persists_for_next_otherwise_valid_attempt(self):
        self.queue(self.events())
        self.owner.side_effect = ValueError('synthetic-owner-drift')
        self.assertFalse(self.capture.prove(self.peer))
        self.owner.side_effect = None
        self.assertFalse(self.capture.prove(self.peer))

class BridgeSequenceGenerationTests(unittest.TestCase):
    setUp = BridgeSequenceTests.setUp
    events = BridgeSequenceTests.events

    def test_retransmission_does_not_advance_handshake_twice(self):
        events = self.events()
        for event in events[:-1]:
            self.assertIsNone(self.sequence.observe(event))
            self.assertIsNone(self.sequence.observe(event))
        self.assertEqual(self.sequence.observe(events[-1]), (31000, 100, 200))
        self.assertIsNone(self.sequence.observe(events[-1]))

    def test_wrong_generation_target_ack_and_reset_never_prove_route(self):
        for change in ('target', 'ack', 'reset', 'generation'):
            self.setUp()
            events = self.events()
            for event in events[:-1]:
                self.sequence.observe(event)
            if change == 'reset':
                self.sequence.observe(packet(seq=136, ack=205, flags=0x14))
            if change == 'generation':
                self.sequence.observe(packet(seq=1000, ack=0, flags=2))
            final = (packet(CONNECT[:-1] + b'\x00', seq=136, ack=205) if change == 'target' else
                     packet(CONNECT, seq=136, ack=206) if change == 'ack' else events[-1])
            self.assertIsNone(self.sequence.observe(final))

    def test_second_connect_bytes_inside_established_foreign_tunnel_are_rejected(self):
        for event in self.events()[:-1]:
            self.sequence.observe(event)
        # Первый CONNECT к чужой цели не проходит kernel filter. Его 10 bytes
        # всё равно занимают TCP sequence space; payload-двойник уже не handshake.
        self.assertIsNone(self.sequence.observe(packet(CONNECT, seq=146, ack=215)))


@unittest.skipUnless(sys.platform == 'linux', 'Нужен настоящий Linux socket filter')
class BridgeKernelFilterTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('lucx_post_configurator.naive_bridge'))
        from lucx_post_configurator.naive_bridge import _attach_filter, _bridge_filter
        self.sender, self.receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(self.sender.close)
        self.addCleanup(self.receiver.close)
        _attach_filter(self.receiver, _bridge_filter('192.0.2.10', 19600, 19443))
        self.receiver.settimeout(.02)

    def filtered(self, data):
        self.sender.send(data)
        try:
            return self.receiver.recv(1024)
        except TimeoutError:
            return None

    def test_kernel_retains_only_safe_handshake_bytes(self):
        self.assertEqual(len(AUTH), 31)
        for options in (0, 12, 40):
            header = 40 + options
            for payload, reverse, retained in ((AUTH, False, 2), (CONNECT, False, 10),
                    (b'\x05\x02\x00\x02', False, 4), (b'\x05\x01\x02', False, 3),
                    (b'\x05\x02', True, 2), (b'\x01\x00', True, 2)):
                with self.subTest(options=options, size=len(payload)):
                    data = packet(payload, reverse=reverse, options=options)
                    self.assertEqual(self.filtered(data), data[:header + retained])
            syn = packet(seq=100, ack=0, flags=2, options=options)
            self.assertEqual(self.filtered(syn), syn)

    def test_kernel_drops_unrelated_payload_fragments_and_malformed_lengths(self):
        valid = packet(CONNECT)
        for data in (packet(b'synthetic-secret-data'), packet(CONNECT + b'synthetic-extra'),
                     packet(CONNECT[:5]), packet(CONNECT[5:]), valid[:-1], valid + b'x',
                     packet(CONNECT, reverse=True), packet(CONNECT[:-1] + b'x'),
                     valid[:6] + b'\x20\x00' + valid[8:],
                     valid[:22] + struct.pack('!H', 19444) + valid[24:],
                     valid[:9] + b'\x11' + valid[10:],
                     packet(AUTH[:6] + b'\x17' + AUTH[7:])):
            with self.subTest(length=len(data)):
                self.assertIsNone(self.filtered(data))

    def test_filter_cannot_be_detached_after_lock(self):
        with self.assertRaises(OSError):
            self.receiver.setsockopt(socket.SOL_SOCKET, 27, 0)  # SO_DETACH_FILTER
        self.assertIsNone(self.filtered(packet(b'synthetic-private-payload')))


@unittest.skipUnless(sys.platform == 'linux' and os.environ.get('XTUNA_TEST_NAIVE_BRIDGE') == '1',
                     'Нужен изолированный Naive/Xray стенд с NET_RAW')
class BridgeLiveTests(unittest.TestCase):
    def exercise(self, routed, foreign=False):
        from lucx_post_configurator import naive_bridge, naive_probes
        cls = getattr(naive_bridge, 'BridgeCapture', None)
        self.assertIsNotNone(cls, 'Нужна привязка CONNECT к живым sockets Caddy/Xray/echo')
        from staging_frontend_fixture import existing_backend, reservations, XRAY_SHA256
        from test_naive_candidate_live import DOCUMENTATION_ECHO
        from test_naive_probes_live import _backend, CADDY_HASH, NAIVE, NAIVE_HASH
        self.assertEqual(os.environ.get('XTUNA_TEST_DOCUMENTATION_ECHO'), DOCUMENTATION_ECHO)
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            listener = stack.enter_context(socket.socket())
            listener.bind((DOCUMENTATION_ECHO, 0))
            listener.listen(4)
            listener.settimeout(8)
            host, port = listener.getsockname()
            with reservations(1) as ports:
                bridge_port = ports[0]
            password = 'abcdefghijklmnopqrstuvwx'
            xray, _, _ = stack.enter_context(existing_backend({'log': {'loglevel': 'none'},
                'inbounds': [{'listen': '127.0.0.1', 'port': bridge_port, 'protocol': 'socks',
                    'settings': {'auth': 'password', 'accounts': [{'user': 'lucx', 'pass': password}],
                                 'udp': False}}], 'outbounds': [{'protocol': 'freedom', 'settings': {}}]}))
            processes = []
            naive_password = secrets.token_hex(18)
            backend_port, ca = stack.enter_context(_backend(root, 'synthetic', naive_password, port,
                canonical_source=True, probe_resistance=True, processes=processes,
                upstream=f'socks5://lucx:{password}@127.0.0.1:{bridge_port}' if routed else ''))
            capture = stack.enter_context(cls(host, port, bridge_port, caddy_pid=processes[0].pid,
                caddy_sha256=CADDY_HASH, xray_pid=xray.pid, xray_sha256=XRAY_SHA256))
            if foreign:
                from lucx_post_configurator.vpn_probes import _receive
                sink = stack.enter_context(socket.socket())
                sink.bind((DOCUMENTATION_ECHO, 0))
                sink.listen(1)
                sink.settimeout(3)
                decoy_connection = stack.enter_context(socket.create_connection(('127.0.0.1', bridge_port)))
                deadline = time.monotonic() + 3
                decoy_connection.sendall(b'\x05\x02\x00\x02')
                self.assertEqual(_receive(decoy_connection, 2, deadline), b'\x05\x02')
                decoy_connection.sendall(AUTH)
                self.assertEqual(_receive(decoy_connection, 2, deadline), b'\x01\x00')
                decoy_connection.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(DOCUMENTATION_ECHO)
                                         + struct.pack('!H', sink.getsockname()[1]))
                self.assertEqual(_receive(decoy_connection, 4, deadline), b'\x05\x00\x00\x01')
                _receive(decoy_connection, 6, deadline)
                sink_peer = stack.enter_context(sink.accept()[0])
                sink_peer.settimeout(3)
                misleading = b'\x05\x01\x00\x01' + socket.inet_aton(host) + struct.pack('!H', port)
                decoy_connection.sendall(misleading)
                self.assertEqual(_receive(sink_peer, len(misleading), deadline), misleading)
            findings, failures, evidence_errors = [], [], []

            def trace(frame, event, arg):
                if (event == 'exception' and frame.f_code.co_filename.endswith('/naive_bridge.py')
                        and len(evidence_errors) < 32):
                    evidence_errors.append((frame.f_code.co_name, frame.f_lineno, arg[0].__name__))
                    if frame.f_code.co_name == '_tcp_inode':
                        wanted = frame.f_locals.get('wanted', ())
                        lines = frame.f_locals.get('lines', [])
                        evidence_errors.append(('tcp_shape', wanted,
                            [line.split()[1:4] for line in lines[1:] if len(line.split()) >= 4
                             and any(line.split()[index].endswith(wanted[index - 1][-5:])
                                     for index in (1, 2))][:8]))
                return trace

            def serve():
                try:
                    for _ in range(2):
                        with listener.accept()[0] as peer:
                            peer.settimeout(5)
                            first = peer.recv(8192)
                            sys.settrace(trace)
                            try:
                                findings.append(capture.prove(peer, timeout=1))
                            finally:
                                sys.settrace(None)
                            peer.sendall(first)
                            count = len(first)
                            while count < 8192:
                                data = peer.recv(8192 - count)
                                if not data:
                                    raise OSError('synthetic_echo_incomplete')
                                peer.sendall(data)
                                count += len(data)
                except Exception as error:
                    failures.append(type(error).__name__)

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            binary = naive_probes._binary(NAIVE, NAIVE_HASH)
            try:
                request = dict(username='synthetic', password=naive_password, ca_pem=ca,
                    sni='vpn.example.test', address='127.0.0.1', port=backend_port,
                    echo_address=host, echo_port=port)
                naive_probes._attempt(request, binary, naive_password,
                                      time.monotonic() + 18, negative=False)
            finally:
                os.close(binary)
                thread.join(timeout=9)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(findings, [routed, routed],
                f'events={capture._sequence._events}, stages={[v.stage for v in capture._sequence._flows.values()]}, '
                f'errors={evidence_errors}')

    def test_real_naive_xray_echo_is_correlated_twice(self):
        self.exercise(True)

    def test_direct_naive_echo_is_not_mistaken_for_bridge(self):
        self.exercise(False)

    def test_foreign_open_bridge_with_connect_shaped_payload_is_not_our_route(self):
        self.exercise(False, foreign=True)

    def test_repeated_live_bridge_generations(self):
        for number in range(10):
            with self.subTest(number=number):
                self.exercise(True)


if __name__ == '__main__':
    unittest.main()
