from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from helpers import make_target

from lucx_post_configurator.discovery import read_lucx_database
from lucx_post_configurator.routing_profiles import source_routing_fingerprint
from lucx_post_configurator.targetfs import TargetFS


class HostOverrideTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fs = TargetFS(self.temp.name)
        self.database = make_target(Path(self.temp.name))
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute('CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, '
                'address TEXT, port INTEGER, sni TEXT, host_header TEXT, path TEXT, security TEXT, alpn TEXT)')
            connection.execute('INSERT INTO hosts VALUES (1,1,?,?,?,?,?,?,?)',
                ('vpn.example.test', 443, 'vpn.example.test', '', '', 'same', '[]'))

    def inbound(self):
        return read_lucx_database(self.fs, '/etc/x-ui/x-ui.db')[1][0]

    def test_modern_host_header_is_preserved_as_client_authority(self):
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute('UPDATE hosts SET host_header=?', ('http.example.test',))
        endpoint = self.inbound().public_endpoints[0]
        self.assertEqual(endpoint['http_host'], 'http.example.test')

    def test_active_unimplemented_override_is_not_a_valid_route(self):
        for field, value in (('path', '/alternate'), ('security', 'none'), ('alpn', '["h3"]')):
            with self.subTest(field=field):
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    connection.execute('UPDATE hosts SET path=?, security=?, alpn=?', ('', 'same', '[]'))
                    connection.execute('UPDATE hosts SET ' + field + '=?', (value,))
                endpoint = self.inbound().public_endpoints[0]
                self.assertFalse(endpoint['valid'])
                self.assertIn(field, endpoint['unsupported_overrides'])

    def test_override_change_invalidates_source_snapshot_without_exposing_value(self):
        first = source_routing_fingerprint(self.inbound())
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute('UPDATE hosts SET path=?', ('/sensitive-test-sentinel',))
        inbound = self.inbound()
        self.assertNotEqual(first, source_routing_fingerprint(inbound))
        self.assertNotIn('sensitive-test-sentinel', json.dumps(inbound.as_dict()))

    def test_conflicting_legacy_and_modern_http_host_are_not_guessed(self):
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute('ALTER TABLE hosts ADD COLUMN host TEXT')
            connection.execute('UPDATE hosts SET host=?, host_header=?',
                               ('legacy.example.test', 'modern.example.test'))
        self.assertFalse(self.inbound().public_endpoints[0]['valid'])

    def test_neutral_overrides_do_not_block_supported_endpoint(self):
        self.assertTrue(self.inbound().public_endpoints[0]['valid'])

    def test_unknown_column_zero_is_not_assumed_to_be_neutral(self):
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute('ALTER TABLE hosts ADD COLUMN future_transport_mode INTEGER')
            connection.execute('UPDATE hosts SET future_transport_mode=0')
        endpoint = self.inbound().public_endpoints[0]
        self.assertFalse(endpoint['valid'])
        self.assertIn('unknown_host_fields', endpoint['unsupported_overrides'])

    def test_http_authority_port_is_not_silently_discarded(self):
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute('UPDATE hosts SET host_header=?', ('http.example.test:8443',))
        self.assertFalse(self.inbound().public_endpoints[0]['valid'])


if __name__ == '__main__':
    unittest.main()
