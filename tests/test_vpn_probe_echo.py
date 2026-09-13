from __future__ import annotations

import importlib.util
import socket
import time
import unittest


class ProbeEchoTests(unittest.TestCase):
    def test_route_proof_precedes_first_echo_and_failure_is_sticky(self):
        from lucx_post_configurator.vpn_probe_echo import LocalProbeEcho
        calls = []
        def verify(peer):
            calls.append(peer.getpeername())
            return len(calls) == 1
        with LocalProbeEcho(verify_peer=verify) as echo:
            with socket.create_connection(echo.endpoint, timeout=1) as client:
                client.sendall(b'first')
                self.assertEqual(client.recv(100), b'first')
                client.sendall(b'same-connection')
                self.assertEqual(client.recv(100), b'same-connection')
            self.assertEqual(echo.verified_connections, 1)
            with socket.create_connection(echo.endpoint, timeout=1) as client:
                client.sendall(b'must-not-echo')
                self.assertEqual(client.recv(100), b'')
            self.assertTrue(echo.verification_failed)
            self.assertEqual(echo.verified_connections, 1)
        self.assertEqual(len(calls), 2)

    def test_public_bind_requires_owned_route_verifier(self):
        from lucx_post_configurator.vpn_probe_echo import LocalProbeEcho
        with self.assertRaises(ValueError):
            LocalProbeEcho(bind_address='192.0.2.10')
        for address in ('0.0.0.0', '255.255.255.255', '224.0.0.1', '::1', 'echo.example.test'):
            with self.assertRaises(ValueError):
                LocalProbeEcho(bind_address=address, verify_peer=lambda peer: True)

    def echo(self):
        self.assertIsNotNone(importlib.util.find_spec('lucx_post_configurator.vpn_probe_echo'),
                             'Нужен ограниченный временный echo-listener')
        from lucx_post_configurator.vpn_probe_echo import LocalProbeEcho
        return LocalProbeEcho()

    def test_echo_is_loopback_only_and_closes_with_the_context(self):
        with self.echo() as echo:
            endpoint = echo.endpoint
            self.assertEqual(endpoint[0], '127.0.0.1')
            with socket.create_connection(endpoint, timeout=1) as client:
                client.sendall(b'probe-payload')
                self.assertEqual(client.recv(256), b'probe-payload')
        with self.assertRaises(OSError):
            socket.create_connection(endpoint, timeout=.2)

    def test_eof_after_echo_preserves_half_closed_client_response(self):
        with self.echo() as echo, socket.create_connection(echo.endpoint, timeout=1) as client:
            client.sendall(b'last-payload')
            client.shutdown(socket.SHUT_WR)
            received = b''
            while chunk := client.recv(256):
                received += chunk
            self.assertEqual(received, b'last-payload')

    def test_per_connection_byte_limit_closes_oversized_exchange(self):
        with self.echo() as echo, socket.create_connection(echo.endpoint, timeout=1) as client:
            client.sendall(b'x' * 32768)
            received = b''
            try:
                while chunk := client.recv(8192):
                    received += chunk
            except ConnectionResetError:
                pass
            self.assertLessEqual(len(received), 16384)

    def test_idle_peer_does_not_prevent_other_probe_or_context_cleanup(self):
        started = time.monotonic()
        with self.echo() as echo, socket.create_connection(echo.endpoint, timeout=1) as idle:
            with socket.create_connection(echo.endpoint, timeout=1) as active:
                active.sendall(b'active')
                self.assertEqual(active.recv(100), b'active')
            self.assertGreaterEqual(idle.fileno(), 0)
        self.assertLess(time.monotonic() - started, 2)


if __name__ == '__main__':
    unittest.main()
