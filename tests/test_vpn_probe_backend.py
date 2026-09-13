"""Владелец backend и обеих echo-сессий проверяется до передачи nonce."""
from __future__ import annotations

import os
import socket
import sys
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

from lucx_post_configurator import vpn_probe_backend as backend
from lucx_post_configurator.staging_processes import ProcessIdentity

HOST, PORT, ENDPOINT = '127.0.0.1', 18443, ('192.0.2.10', 18080)
HASH = '8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed'


class XrayEchoWitnessTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.actor = ProcessIdentity(123, 1, 123, 123, 100, 'R'), (1, 2), (3, 4)
        for name, value in (('_listener_identity', (123, 77)), ('_executable_hash', HASH),
                            ('_pin_actor', self.actor), ('_actor', self.actor), ('_owner', 123),
                            ('_owned', None)):
            setattr(self, name, self.stack.enter_context(mock.patch.object(backend, name, return_value=value)))
        self.inode = self.stack.enter_context(mock.patch.object(backend, '_tcp_inode',
            side_effect=lambda remote, _local, _deadline: remote[1]))
        self.stack.enter_context(mock.patch.object(backend.sys, 'platform', 'linux'))

    def peer(self, number=40001, *, family=socket.AF_INET, endpoint=ENDPOINT):
        return SimpleNamespace(family=family, getsockname=lambda: endpoint,
                               getpeername=lambda: ('192.0.2.10', number))

    def test_two_distinct_owned_sockets_and_post_context_verify(self):
        with backend.XrayEchoWitness(HOST, PORT, ENDPOINT) as witness:
            self.assertTrue(witness.prove(self.peer()))
            self.assertTrue(witness.prove(self.peer(40002)))
        self.assertIsNone(witness.verify())
        self.assertGreaterEqual(self._listener_identity.call_count, 4)
        self.assertGreaterEqual(self._pin_actor.call_count, 2)

    def test_peer_family_and_exact_echo_endpoint_are_required(self):
        for peer in (self.peer(family=socket.AF_INET6), self.peer(endpoint=('192.0.2.11', 18080)),
                     self.peer(endpoint=('192.0.2.10', 18081))):
            with self.subTest(family=peer.family), backend.XrayEchoWitness(HOST, PORT, ENDPOINT) as witness:
                self.assertFalse(witness.prove(peer))
                self.assertFalse(witness.prove(self.peer()))
                with self.assertRaises(ValueError):
                    witness.verify()

    def test_untrusted_binary_or_failed_pin_rejects_enter_without_details(self):
        for digest, error in (('a' * 64, None), (HASH, ValueError('private-source-value'))):
            self._executable_hash.return_value = digest
            self._pin_actor.side_effect = error
            with (self.subTest(known=digest == HASH), self.assertRaises(ValueError) as caught,
                  backend.XrayEchoWitness(HOST, PORT, ENDPOINT)):
                self.fail('Неподтверждённый executable принят')
            self.assertNotIn('private-source-value', str(caught.exception))

    def test_listener_inode_or_owner_drift_closes_witness(self):
        for identity in ((123, 78), (124, 77)):
            self._listener_identity.return_value = (123, 77)
            with backend.XrayEchoWitness(HOST, PORT, ENDPOINT) as witness:
                self._listener_identity.return_value = identity
                self.assertFalse(witness.prove(self.peer()))
                self._listener_identity.return_value = (123, 77)
                self.assertFalse(witness.prove(self.peer(40002)))
                with self.assertRaises(ValueError):
                    witness.verify()

    def test_actor_drift_and_foreign_reverse_owner_are_rejected(self):
        replacement = ProcessIdentity(123, 1, 123, 123, 101, 'S'), (1, 2), (3, 4)
        for name, changed in (('_actor', replacement), ('_owner', 124)):
            with self.subTest(check=name), backend.XrayEchoWitness(HOST, PORT, ENDPOINT) as witness:
                selected = getattr(self, name)
                original = selected.return_value
                selected.return_value = changed
                self.assertFalse(witness.prove(self.peer()))
                selected.return_value = original
                self.assertFalse(witness.prove(self.peer()))

    def test_duplicate_inode_or_drift_between_reads_is_rejected(self):
        with backend.XrayEchoWitness(HOST, PORT, ENDPOINT) as witness:
            self.assertTrue(witness.prove(self.peer()))
            self.assertFalse(witness.prove(self.peer()))
            with self.assertRaises(ValueError):
                witness.verify()
        with backend.XrayEchoWitness(HOST, PORT, ENDPOINT) as witness:
            self.inode.side_effect = [40001, 40002]
            self.assertFalse(witness.prove(self.peer()))

    def test_verify_requires_exactly_two_sessions_and_rechecks_actor_and_listener(self):
        for count, drift in ((1, None), (2, 'actor'), (2, 'listener'), (3, None)):
            self._listener_identity.return_value = (123, 77)
            self._pin_actor.side_effect = None
            with self.subTest(count=count, drift=drift), backend.XrayEchoWitness(HOST, PORT, ENDPOINT) as witness:
                for index in range(count):
                    witness.prove(self.peer(40001 + index))
                if drift == 'actor':
                    self._pin_actor.side_effect = ValueError('private-source-value')
                elif drift == 'listener':
                    self._listener_identity.return_value = (123, 78)
                with self.assertRaises(ValueError):
                    witness.verify()


class EchoAddressTests(unittest.TestCase):
    def test_only_canonical_controlled_ipv4_is_accepted(self):
        for address in ('192.0.2.10', '198.51.100.20', '203.0.113.30', '10.1.2.3'):
            self.assertTrue(backend.valid_echo_address(address))
        for address in ('127.0.0.1', '169.254.1.1', '224.0.0.1', '0.0.0.0', '255.255.255.255',
                        '::1', '::ffff:192.0.2.10', 'example.test', '192.0.2.010', ' 192.0.2.10', None, 1):
            self.assertFalse(backend.valid_echo_address(address))


class ListenerIdentityTests(unittest.TestCase):
    def test_wildcard_dualstack_and_mapped_listener_identity(self):
        from test_staging_processes import HEADER, TCP4, TCP6
        port = int('A029', 16)
        forms = ((TCP4, ''), (TCP4.replace('0100007F', '00000000'), ''),
                 ('', TCP6.replace('00000000000000000000000001000000', '00000000000000000000000000000000')
                  .replace('A02A', 'A029')),
                 ('', TCP6.replace('00000000000000000000000001000000', '0000000000000000FFFF00000100007F')
                  .replace('A02A', 'A029')))
        for tcp4, tcp6 in forms:
            with (self.subTest(ipv6=bool(tcp6)), mock.patch.object(backend, '_owner', return_value=123),
                  mock.patch.object(backend, '_read', side_effect=[HEADER + tcp4, HEADER + tcp6])):
                self.assertEqual(backend._listener_identity(HOST, port, float('inf')),
                                 (123, 12346 if tcp6 else 12345))
        with (mock.patch.object(backend, '_owner', return_value=123),
              mock.patch.object(backend, '_read', side_effect=[HEADER + TCP4 * 2, HEADER]),
              self.assertRaises(ValueError)):
            backend._listener_identity(HOST, port, float('inf'))
        with (mock.patch.object(backend, '_owner', return_value=123),
              mock.patch.object(backend, '_read', side_effect=[HEADER + TCP4.replace('0100007F', '00000000'), HEADER]),
              self.assertRaises(ValueError)):
            backend._listener_identity(HOST, port, float('inf'), bridge=True)


class XrayEchoWitnessLiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != 'linux' or os.environ.get('XTUNA_TEST_DOCUMENTATION_ECHO') != ENDPOINT[0]:
            raise unittest.SkipTest('Нужен изолированный Linux с собственным documentation IPv4')

    def exercise(self, *, foreign_peer=False):
        import staging_frontend_fixture as frontend
        with frontend.reservations(1) as reserved:
            port = reserved[0]
        config = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': HOST, 'port': port,
            'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}],
            'outbounds': [{'protocol': 'freedom', 'settings': {}}]}
        with frontend.existing_backend(config) as (process, _fd, _digest), ExitStack() as stack:
            listener = stack.enter_context(socket.socket())
            listener.bind((ENDPOINT[0], 0))
            listener.listen(2)
            listener.settimeout(3)
            endpoint = listener.getsockname()
            with backend.XrayEchoWitness(HOST, port, endpoint) as witness:
                for _number in range(1 if foreign_peer else 2):
                    client = stack.enter_context(socket.create_connection(endpoint if foreign_peer else (HOST, port), timeout=3))
                    if not foreign_peer:
                        client.sendall(b'\x05\x01\x00')
                        self.assertEqual(client.recv(2), b'\x05\x00')
                        client.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(endpoint[0]) + endpoint[1].to_bytes(2, 'big'))
                        self.assertEqual(client.recv(10)[:2], b'\x05\x00')
                    peer, _address = listener.accept()
                    stack.enter_context(peer)
                    self.assertEqual(witness.prove(peer), not foreign_peer)
                stack.close()
            if foreign_peer:
                with self.assertRaises(ValueError):
                    witness.verify()
            else:
                self.assertIsNone(witness.verify())
            self.assertIsNone(process.poll(), 'Witness не должен управлять исходным backend')

    def test_real_xray_owns_both_echo_sessions(self):
        self.exercise()

    def test_direct_python_peer_cannot_impersonate_xray_backend(self):
        self.exercise(foreign_peer=True)


if __name__ == '__main__':
    unittest.main()
