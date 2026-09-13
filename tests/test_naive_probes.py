from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import socket
import tempfile
import threading
import time
import types
import unittest
import urllib.parse
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest import mock

from lucx_post_configurator.routing_profiles import routing_fingerprint
from lucx_post_configurator.runner import CommandResult, Runner


def profile():
    return {"inbound_id": 7, "protocol": "naive", "transport": "tcp", "network": "tcp",
        "security": "tls", "exposure": "tcp_sni", "alpn": ["h2"],
        "internal_host": "127.0.0.1", "internal_port": 19443,
        "transport_details": {}, "transport_path": "", "transport_mode": "",
        "transport_hosts": [], "public_endpoints": [{"host_id": 1,
            "address": "vpn.example.test", "port": 443, "sni": "vpn.example.test",
            "http_host": "", "sni_source": "address", "keep_sni_blank": False, "valid": True}]}


def accepted(value=None, phase="public"):
    value = copy.deepcopy(value or profile())
    endpoint = value["public_endpoints"][0]
    fields = {key: endpoint.get(key) for key in (
        "host_id", "address", "port", "sni", "sni_source", "keep_sni_blank", "http_host")}
    value.update(acceptance_endpoint=copy.deepcopy(endpoint), acceptance_phase=phase,
        acceptance_target={"inbound_id": value["inbound_id"],
            "profile_fingerprint": routing_fingerprint(value, 443),
            "endpoint_fingerprint": "sha256:" + hashlib.sha256(json.dumps(fields,
                sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()})
    return value


class HiddenNaiveAuthEvidenceTests(unittest.TestCase):
    """Форма h2-отказа — лишь часть proof, без разрешения runtime source."""

    def setUp(self):
        from lucx_post_configurator import naive_probes
        self.parse = getattr(naive_probes, '_netlog_hidden_auth_denial', None)
        self.assertTrue(callable(self.parse), 'Нужен строгий разбор скрытого h2 auth denial')
        self.request = {'echo_address': '127.0.0.1', 'echo_port': 19600,
                        'sni': 'vpn.example.test', 'port': 25443}
        names = ['HTTP2_SESSION_SEND_HEADERS', 'HTTP2_SESSION_RECV_HEADERS',
                 'HTTP2_SESSION_SEND_DATA', 'HTTP2_SESSION_RECV_DATA',
                 'HTTP2_SESSION_SEND_RST_STREAM', 'HTTP2_SESSION_RECV_RST_STREAM']
        self.constants = {'logEventTypes': dict(zip(names, range(1, 7))),
                          'logSourceType': {'HTTP2_SESSION': 9}}

    def rows(self, count=3):
        result = []
        for index in range(count):
            result.extend([
                {'type': 1, 'source': {'type': 9, 'id': 11}, 'params': {'stream_id': 2 * index + 1,
                    'fin': False, 'headers': [':method: CONNECT', ':authority: 127.0.0.1:19600',
                                              'proxy-authorization: Basic synthetic']}},
                {'type': 2, 'source': {'type': 9, 'id': 11}, 'params': {'stream_id': 2 * index + 1,
                    'fin': True, 'headers': [':status: 200', 'content-length: 0']}}])
        return result

    def payload(self, rows):
        return (b'{"constants":' + json.dumps(self.constants).encode() + b',\n"events": [\n'
                + b''.join(json.dumps(row).encode() + b',\n' for row in rows))

    def test_complete_retries_are_bound_to_target_session_and_stream(self):
        for count in (1, 2, 3):
            self.assertTrue(self.parse(self.payload(self.rows(count)), self.request))
        self.assertFalse(self.parse(self.payload([]), self.request))
        self.assertFalse(self.parse(self.payload(self.rows(4)), self.request))
        for change in ('target', 'session', 'stream', 'source_type'):
            rows = self.rows()
            if change == 'target':
                rows[0]['params']['headers'][1] = ':authority: 192.0.2.9:19600'
            elif change == 'session':
                rows[1]['source']['id'] = 12
            elif change == 'stream':
                rows[1]['params']['stream_id'] = 7
            else:
                rows[1]['source']['type'] = 10
            with self.subTest(change=change):
                self.assertFalse(self.parse(self.payload(rows), self.request))

    def test_status_fin_length_and_absent_padding_are_all_required(self):
        for headers, fin in (([':status: 407', 'content-length: 0'], True),
                ([':status: 404', 'content-length: 0'], True),
                ([':status: 200'], True), ([':status: 200', 'content-length: 1'], True),
                ([':status: 200', 'content-length: 0', 'content-length: 0'], True),
                ([':status: 200', ':status: 200', 'content-length: 0'], True),
                ([':status: 200', 'content-length: 0', 'padding: synthetic'], True),
                ([':status: 200', 'content-length: 0', 'Padding: synthetic'], True),
                ([':status: 200', 'content-length: 0'], False),
                ([':status: 200', 'content-length: 0'], 1)):
            rows = self.rows()
            rows[1]['params'].update(headers=headers, fin=fin)
            with self.subTest(headers=headers, fin=fin):
                self.assertFalse(self.parse(self.payload(rows), self.request))

    def test_two_setup_gets_are_checked_but_never_count_as_auth_denial(self):
        setup = self.rows(2)
        for row in setup:
            row['source']['id'] = 12
            if row['type'] == 1:
                row['params'].update(fin=True, headers=[':method: GET', ':scheme: https',
                    ':path: /', ':authority: vpn.example.test:25443'])
        self.assertTrue(self.parse(self.payload(setup + self.rows()), self.request))
        self.assertFalse(self.parse(self.payload(setup), self.request))
        self.assertFalse(self.parse(self.payload(setup[:-1] + self.rows()), self.request))
        for changed in (':method: HEAD', ':scheme: http', ':path: /other',
                        ':authority: wrong.example.test:25443', 'proxy-authorization: Basic synthetic'):
            bad = copy.deepcopy(setup)
            name = changed.split(': ', 1)[0] + ': '
            bad[0]['params']['headers'] = [h for h in bad[0]['params']['headers'] if not h.startswith(name)] + [changed]
            self.assertFalse(self.parse(self.payload(bad + self.rows()), self.request))
        bad = copy.deepcopy(setup)
        bad[0]['params']['fin'] = False
        self.assertFalse(self.parse(self.payload(bad + self.rows()), self.request))
        extra = copy.deepcopy(setup[:2])
        for row in extra:
            row['params']['stream_id'] = 9
        self.assertFalse(self.parse(self.payload(setup + extra + self.rows()), self.request))

    def test_explicit_root_minimum_cannot_be_replaced_by_resources(self):
        self.assertFalse(self.parse(self.payload(self.rows()), self.request, minimum_roots=2))
        rows = self.rows(2)
        for row in rows:
            row['source']['id'] = 12
            if row['type'] == 1:
                row['params'].update(fin=True, headers=[':method: GET', ':scheme: https',
                    ':path: /', ':authority: vpn.example.test:25443'])
        self.assertTrue(self.parse(self.payload(rows + self.rows()), self.request, minimum_roots=2))
        self.assertFalse(self.parse(self.payload(rows[:2] + self.rows()), self.request, minimum_roots=2))

    def test_connect_requires_its_own_single_authorization_header(self):
        for auth_headers in ([], ['proxy-authorization: Basic synthetic'] * 2):
            rows = self.rows()
            rows[0]['params']['headers'] = rows[0]['params']['headers'][:2] + auth_headers
            self.assertFalse(self.parse(self.payload(rows), self.request))

    def test_same_origin_resources_require_completed_root_and_are_not_auth_proof(self):
        roots = self.rows(2)
        for row in roots:
            row['source']['id'] = 12
            if row['type'] == 1:
                row['params'].update(fin=True, headers=[':method: GET', ':scheme: https',
                    ':path: /', ':authority: vpn.example.test:25443'])
        resource = copy.deepcopy(roots[:2])
        for row in resource:
            row['params']['stream_id'] = 5
        resource[0]['params']['headers'][2] = ':path: /a.css'
        all_rows = roots + resource + self.rows()
        self.assertTrue(self.parse(self.payload(all_rows), self.request, minimum_roots=2))
        self.assertFalse(self.parse(self.payload(roots + resource), self.request, minimum_roots=2))
        self.assertFalse(self.parse(self.payload(resource + roots + self.rows()), self.request, minimum_roots=2))
        for change in ('foreign_session', 'foreign_authority', 'auth', 'absolute', 'no_end'):
            bad = copy.deepcopy(resource)
            if change == 'foreign_session':
                for row in bad:
                    row['source']['id'] = 15
            elif change == 'foreign_authority':
                bad[0]['params']['headers'][3] = ':authority: other.example.test:25443'
            elif change == 'auth':
                bad[0]['params']['headers'].append('proxy-authorization: Basic synthetic')
            elif change == 'absolute':
                bad[0]['params']['headers'][2] = ':path: https://vpn.example.test/a.css'
            else:
                bad = bad[:1]
            self.assertFalse(self.parse(self.payload(roots + bad + self.rows()), self.request, minimum_roots=2))

    def test_setup_site_body_requires_exact_length_and_end_stream(self):
        setup = self.rows(1)
        for row in setup:
            row['source']['id'] = 12
        setup[0]['params'].update(fin=True, headers=[':method: GET', ':scheme: https',
            ':path: /', ':authority: vpn.example.test:25443'])
        setup[1]['params'].update(fin=False, headers=[':status: 200', 'content-length: 12'])
        body = {'type': 4, 'source': {'type': 9, 'id': 12},
                'params': {'stream_id': 1, 'size': 12, 'fin': True}}
        complete = setup + [body] + self.rows()
        self.assertTrue(self.parse(self.payload(complete), self.request, minimum_roots=1))
        first, last = copy.deepcopy(body), copy.deepcopy(body)
        first['params'].update(size=5, fin=False)
        last['params'].update(size=7)
        self.assertTrue(self.parse(self.payload(setup + [first, last] + self.rows()), self.request))
        last['params'].update(size=6)
        self.assertFalse(self.parse(self.payload(setup + [first, last] + self.rows()), self.request))
        self.assertFalse(self.parse(self.payload(setup + [body]), self.request))
        for params in ({'size': 11}, {'size': 13}, {'size': True}, {'size': -1},
                       {'fin': False}, {'fin': 1}, {'stream_id': 9}):
            bad = copy.deepcopy(body)
            bad['params'].update(params)
            self.assertFalse(self.parse(self.payload(setup + [bad] + self.rows()), self.request))
        for rows in (setup + self.rows(), [body] + setup + self.rows(),
                     setup + [body, body] + self.rows(), setup + [setup[1], body] + self.rows()):
            self.assertFalse(self.parse(self.payload(rows), self.request))
        for value in ('1048577', '-1', '012', '12x'):
            bad = copy.deepcopy(complete)
            bad[1]['params']['headers'][1] = 'content-length: ' + value
            self.assertFalse(self.parse(self.payload(bad), self.request))
        # Даже завершённый GET не разрешает DATA в CONNECT.
        bad = copy.deepcopy(body)
        bad['source']['id'] = 11
        self.assertFalse(self.parse(self.payload(complete + [bad]), self.request))

    def test_second_preamble_may_repeat_css_instead_of_root(self):
        root = self.rows(1)
        for row in root:
            row['source']['id'] = 12
        root[0]['params'].update(fin=True, headers=[':method: GET', ':scheme: https',
            ':path: /', ':authority: vpn.example.test:25443'])
        resources = []
        for stream in (3, 5):
            pair = copy.deepcopy(root)
            for row in pair:
                row['params']['stream_id'] = stream
            pair[0]['params']['headers'][2] = ':path: /a.css'
            resources.extend(pair)
        self.assertTrue(self.parse(self.payload(root + resources + self.rows()), self.request, minimum_roots=1))
        self.assertFalse(self.parse(self.payload(root + resources[:-1] + self.rows()), self.request, minimum_roots=1))

    def test_resource_head_has_no_body_and_root_must_eventually_complete(self):
        root = self.rows(1)
        for row in root:
            row['source']['id'] = 12
        root[0]['params'].update(fin=True, headers=[':method: GET', ':scheme: https',
            ':path: /', ':authority: vpn.example.test:25443'])
        root[1]['params'].update(fin=False, headers=[':status: 200', 'content-length: 12'])
        first = {'type': 4, 'source': {'type': 9, 'id': 12},
                 'params': {'stream_id': 1, 'size': 6, 'fin': False}}
        resource = copy.deepcopy(root)
        for row in resource:
            row['params']['stream_id'] = 3
        resource[0]['params']['headers'][0] = ':method: HEAD'
        resource[0]['params']['headers'][2] = ':path: /a.png'
        resource[1]['params'].update(fin=True, headers=[':status: 200', 'content-length: 128'])
        last = copy.deepcopy(first)
        last['params']['fin'] = True
        rows = root + [first] + resource + [last] + self.rows()
        self.assertTrue(self.parse(self.payload(rows), self.request, minimum_roots=1))
        self.assertFalse(self.parse(self.payload(root + [first] + resource + self.rows()), self.request, minimum_roots=1))
        body = copy.deepcopy(last)
        body['params'].update(stream_id=3, size=1)
        self.assertFalse(self.parse(self.payload(rows + [body]), self.request, minimum_roots=1))

    def test_no_retry_may_be_missing_duplicated_or_precede_its_request(self):
        rows = self.rows()
        for altered in (rows[:-1], rows[1:], [rows[1], rows[0], *rows[2:]],
                        [*rows, rows[-1]], [rows[0], *rows]):
            self.assertFalse(self.parse(self.payload(altered), self.request))

    def test_data_and_resets_never_prove_hidden_auth_denial(self):
        for event_type in (3, 4, 5, 6):
            rows = self.rows()
            rows.append({'type': event_type, 'source': {'type': 9, 'id': 11},
                         'params': {'stream_id': 1, 'size': 0}})
            self.assertFalse(self.parse(self.payload(rows), self.request))

    def test_no_error_reset_only_closes_an_already_complete_connect_response(self):
        reset = {'type': 6, 'source': {'type': 9, 'id': 11},
                 'params': {'stream_id': 1, 'error_code': '0 (NO_ERROR)'}}
        rows = self.rows()
        self.assertTrue(self.parse(self.payload(rows + [reset]), self.request))
        for altered in ([rows[0], reset, *rows[1:]], rows + [reset, reset],
                        [reset, *rows], rows[:-1] + [reset]):
            self.assertFalse(self.parse(self.payload(altered), self.request))
        for code in ('8 (CANCEL)', '0', 0, False, None):
            bad = copy.deepcopy(reset)
            bad['params']['error_code'] = code
            self.assertFalse(self.parse(self.payload(rows + [bad]), self.request))
        bad = copy.deepcopy(reset)
        bad['type'] = 5
        self.assertFalse(self.parse(self.payload(rows + [bad]), self.request))

    def test_proxy_may_end_zero_length_connect_in_one_empty_data_frame(self):
        rows = self.rows(1)
        rows[1]['params']['fin'] = False
        end = {'type': 4, 'source': {'type': 9, 'id': 11},
               'params': {'stream_id': 1, 'size': 0, 'fin': True}}
        self.assertTrue(self.parse(self.payload(rows + [end]), self.request))
        for changes in ({'size': 1}, {'size': True}, {'fin': False}, {'fin': 1}):
            bad = copy.deepcopy(end)
            bad['params'].update(changes)
            self.assertFalse(self.parse(self.payload(rows + [bad]), self.request))
        self.assertFalse(self.parse(self.payload(rows + [end, end]), self.request))

    def test_invalid_types_schema_duplicate_keys_and_truncation_fail_closed(self):
        data = self.payload(self.rows())
        for altered in (data[:-1], data + b'{"incomplete":', data + b'{bad}\n',
                data.replace(b'"stream_id": 1', b'"stream_id": true', 1),
                data.replace(b'"fin": true', b'"fin": false, "fin": true', 1),
                data.replace(b'HTTP2_SESSION_RECV_HEADERS', b'UNKNOWN_RECV_HEADERS', 1),
                data + b'x' * (2 * 1024 * 1024), None, 'text'):
            self.assertFalse(self.parse(altered, self.request))
        self.assertFalse(self.parse(data, dict(self.request, echo_port=True)))
        self.assertFalse(self.parse(data, dict(self.request, echo_address='echo.example.test')))


class NaiveTerminalEvidenceTests(unittest.TestCase):
    """Незавершённая попытка и чужие маркеры не подтверждают auth denial."""

    def setUp(self):
        from lucx_post_configurator import naive_probes
        parse = getattr(naive_probes, '_netlog_terminal', None)
        self.assertTrue(callable(parse), 'Нужна проверка окончания основной попытки')
        self.parse = lambda data, peers: parse(data, peers, (31000, 31001))
        self.constants = {'logEventTypes': {'SOCKET_ALIVE': 1, 'TCP_ACCEPT': 2,
            'SOCKS5_CONNECT': 3, 'HTTP2_SESSION_SEND_HEADERS': 4,
            'HTTP2_SESSION_RECV_HEADERS': 5, 'SOCKS5_HANDSHAKE_READ': 6,
            'SOCKS5_HANDSHAKE_WRITE': 7, 'CONNECT_JOB': 8},
            'logSourceType': {'SOCKET': 8, 'HTTP2_SESSION': 9, 'HTTP_PROXY_CONNECT_JOB': 10},
            'logEventPhase': {'PHASE_BEGIN': 1, 'PHASE_END': 2, 'PHASE_NONE': 0}}
        self.peers = (30001, 30002)

    @staticmethod
    def event(kind, source, phase, **params):
        return {'type': kind, 'source': {'type': 8, 'id': source}, 'phase': phase, 'params': params}

    def rows(self):
        e = self.event
        dep = lambda parent: {'id': parent, 'type': 8}
        return [e(1, 10, 1), e(1, 11, 1), e(2, 10, 1),
            e(1, 20, 1, source_dependency=dep(10)), e(2, 10, 2, address='127.0.0.1:31000'),
            e(3, 20, 1), e(3, 20, 2, net_error=-120), e(1, 20, 2),
            e(2, 10, 1), e(1, 21, 1, source_dependency=dep(10)),
            e(2, 10, 2, address='127.0.0.1:31001'), e(3, 21, 1), e(3, 21, 2),
            {'type': 4, 'source': {'type': 9, 'id': 40}, 'phase': 0, 'params': {}},
            {'type': 5, 'source': {'type': 9, 'id': 40}, 'phase': 0, 'params': {}},
            e(1, 21, 2), e(2, 10, 1), e(2, 11, 1),
            e(1, 30, 1, source_dependency=dep(11)), e(2, 11, 2, address='127.0.0.1:30001'),
            e(3, 30, 1), e(3, 30, 2, net_error=-120), e(1, 30, 2), e(2, 11, 1)]

    def payload(self, rows):
        jobs = [{'type': 8, 'source': {'type': 10, 'id': 50}, 'phase': phase} for phase in (1, 2)]
        rows = [jobs[0], *rows[:13], jobs[1], *rows[13:]]
        return (b'{"constants":' + json.dumps(self.constants).encode() + b',\n"events": [\n'
                + b''.join(json.dumps(row).encode() + b',\n' for row in rows))

    def test_own_control_marker_after_primary_lifetime_proves_terminal_prefix(self):
        self.assertTrue(self.parse(self.payload(self.rows()), self.peers))

    def test_preamble_pool_balances_and_second_accept_interval_are_required(self):
        from lucx_post_configurator.naive_probes import _netlog_terminal
        self.constants['logEventTypes']['SOCKET_POOL'] = 9
        self.constants['logSourceType']['NONE'] = 11
        def pool(phase):
            return {'type': 9, 'source': {'type': 11, 'id': 60}, 'phase': phase, 'params': {}}
        root_begin, root_end, repeat_begin = pool(1), pool(2), pool(1)
        echo_begin, echo_end, repeat_end = pool(1), pool(2), pool(2)
        rows = self.rows()
        complete = (rows[:5] + [root_begin, root_end] + rows[5:11] + [repeat_begin]
                    + rows[11:15] + [echo_begin, echo_end, repeat_end] + rows[15:])
        parse = lambda values: _netlog_terminal(self.payload(values), self.peers,
                                                (31000, 31001), require_preambles=True)
        self.assertTrue(parse(complete))
        self.assertFalse(parse(rows))
        self.assertFalse(parse([row for row in complete if row is not repeat_end]))
        self.assertFalse(parse([row for row in complete if row is not repeat_begin]))
        self.assertFalse(parse(complete + [pool(2)]))
        self.assertFalse(parse(complete + [pool(1)]))
        # Нормальная отмена pending CSS завершается END без ошибки; другой
        # request может получить его job. FIFO/LIFO pairing здесь неверен.
        self.assertTrue(parse(rows[:5] + [root_begin, pool(1), pool(2), root_end]
                              + rows[5:11] + [repeat_begin] + rows[11:15]
                              + [echo_begin, echo_end, repeat_end] + rows[15:]))
        for change in ('late_end', 'late_repeat', 'foreign_owner', 'error', 'two_repeats'):
            bad = copy.deepcopy(complete)
            position = complete.index(repeat_begin, 8)
            if change == 'late_end':
                index = len(rows[:5]) + 2 + len(rows[5:11]) + 1 + len(rows[11:15]) + 2
                bad.append(bad.pop(index))
            elif change == 'late_repeat':
                bad[position], bad[position + 1] = bad[position + 1], bad[position]
            elif change == 'foreign_owner':
                bad[position]['source']['id'] = 61
            elif change == 'error':
                bad[position]['params']['net_error'] = -3
            else:
                bad[position:position] = [pool(1), pool(2)]
            with self.subTest(change=change):
                self.assertFalse(parse(bad))

    def test_missing_lifetime_handshake_or_owned_marker_is_not_terminal(self):
        rows = self.rows()
        for index in (0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 15, 18, 19, 20, 21, 22):
            with self.subTest(removed=index):
                self.assertFalse(self.parse(self.payload(rows[:index] + rows[index + 1:]), self.peers))
        self.assertFalse(self.parse(self.payload(rows), (30003, 30004)))

    def test_marker_before_primary_end_or_late_primary_activity_is_rejected(self):
        rows = self.rows()
        self.assertFalse(self.parse(self.payload(rows[:15] + rows[16:] + [rows[15]]), self.peers))
        for extra in (self.event(1, 22, 1, source_dependency={'id': 10, 'type': 8}),
                      self.event(3, 21, 2), rows[14], rows[15]):
            self.assertFalse(self.parse(self.payload(rows + [extra]), self.peers))

    def test_foreign_or_successful_control_connection_is_rejected(self):
        for index, params in ((19, {'address': '127.0.0.1:30003'}),
                              (19, {'address': '192.0.2.10:30001'}), (21, {'net_error': -1}),
                              (12, {'net_error': -120})):
            rows = self.rows()
            rows[index]['params'] = params
            self.assertFalse(self.parse(self.payload(rows), self.peers))
        rows = self.rows()
        self.assertFalse(self.parse(self.payload(rows[:21] + [self.event(7, 30, 1)] + rows[21:]), self.peers))

    def test_async_control_end_without_error_still_requires_owned_noauth_exchange(self):
        # Закреплённый Socks5ServerSocket::OnIOComplete пишет END без net_error
        # даже после отказа. 05ff уже проверен caller на каждом private peer.
        rows = self.rows()
        rows[21]['params'] = {}
        self.assertTrue(self.parse(self.payload(rows), self.peers))
        self.assertFalse(self.parse(self.payload(rows), (30003,)))

    def test_detached_connect_job_must_end_before_control_marker(self):
        data = self.payload(self.rows())
        end = json.dumps({'type': 8, 'source': {'type': 10, 'id': 50}, 'phase': 2}).encode() + b',\n'
        begin = json.dumps({'type': 8, 'source': {'type': 10, 'id': 51}, 'phase': 1}).encode() + b',\n'
        self.assertFalse(self.parse(data.replace(end, b''), self.peers))
        self.assertFalse(self.parse(data.replace(end, b'') + end, self.peers))
        self.assertFalse(self.parse(data + begin, self.peers))
        self.assertFalse(self.parse(data + end, self.peers))

    def test_terminal_requires_own_primary_peer_pair(self):
        from lucx_post_configurator import naive_probes
        data = self.payload(self.rows())
        self.assertTrue(naive_probes._netlog_terminal(data, self.peers, (31000, 31001)))
        for primary in ((31000, 31002), (31001, 31000), (31000,), (31000, 31000), (True, 31001)):
            self.assertFalse(naive_probes._netlog_terminal(data, self.peers, primary))

    def test_same_ephemeral_port_on_different_listeners_is_not_foreign(self):
        rows = self.rows()
        rows[19]['params']['address'] = '127.0.0.1:31000'
        self.assertTrue(self.parse(self.payload(rows), (31000, 30002)))

    def test_roundtrip_preserves_local_peer_even_when_remote_socks_rejects(self):
        from lucx_post_configurator import vpn_probes
        local_peers, server_peers = [], []
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(2)
            def reject():
                with listener.accept()[0] as conn:
                    server_peers.append(conn.getpeername()[1])
                    conn.settimeout(2)
                    conn.recv(3)
                    conn.sendall(b'\x05\xff')
            worker = threading.Thread(target=reject, daemon=True)
            worker.start()
            try:
                with self.assertRaises(OSError):
                    vpn_probes._roundtrip(listener.getsockname()[1], (b'u', b'p'), {},
                        time.monotonic() + 2, local_peers=local_peers)
            finally:
                worker.join(timeout=3)
            self.assertEqual(len(local_peers), 1)
            self.assertEqual(local_peers, server_peers)

    def test_duplicate_ids_parents_types_and_partial_json_fail_closed(self):
        original = self.payload(self.rows())
        for peers in ((), (True,), (30001, 30001), (30001, '30002'), list(self.peers)):
            self.assertFalse(self.parse(original, peers))
        for data in (original[:-1], original + b'{bad}\n', original + b'{"partial":',
                     original.replace(b'"phase": 2', b'"phase": true', 1),
                     original.replace(b'"phase": 2', b'"phase": 1, "phase": 2', 1)):
            self.assertFalse(self.parse(data, self.peers))
        for index, key, value in ((9, 'source', {'type': 8, 'id': 20}),
                (18, 'params', {'source_dependency': {'id': 12, 'type': 8}}),
                (19, 'source', {'type': 9, 'id': 11})):
            rows = self.rows()
            rows[index][key] = value
            self.assertFalse(self.parse(self.payload(rows), self.peers))


class NaiveNetLogFlushTests(unittest.TestCase):
    def factory(self, main_port=19600):
        from lucx_post_configurator.naive_probes import _NaiveNetLogFlush
        return _NaiveNetLogFlush(main_port)

    def test_second_listener_preserves_primary_config_and_uses_private_local_auth(self):
        config = {'listen': 'socks://synthetic-user:synthetic-local@127.0.0.1:19600',
                  'proxy': 'https://synthetic:synthetic-pass@vpn.example.test:443', 'log': ''}
        with self.factory() as control:
            result = control.configure(config)
            self.assertEqual(result['listen'][0], config['listen'])
            self.assertEqual(result['proxy'][0], config['proxy'])
            self.assertIsInstance(config['listen'], str)
            local = urllib.parse.urlsplit(result['listen'][1])
            guard = urllib.parse.urlsplit(result['proxy'][1])
            self.assertEqual((local.scheme, local.hostname, guard.scheme, guard.hostname),
                             ('socks', '127.0.0.1', 'http', '127.0.0.1'))
            self.assertEqual(len({19600, local.port, guard.port}), 3)
            self.assertTrue(local.username and local.password)
            self.assertNotIn(local.password, repr(control))
            control.verify_idle()
        with self.assertRaises(ValueError):
            control.configure(config)

    def test_guard_detects_unexpected_outbound_and_closes_on_failure(self):
        import socket
        config = {'listen': 'socks://synthetic-user:synthetic-local@127.0.0.1:19600',
                  'proxy': 'https://synthetic:synthetic-pass@vpn.example.test:443'}
        with self.factory() as control:
            guard = urllib.parse.urlsplit(control.configure(config)['proxy'][1])
            with socket.create_connection((guard.hostname, guard.port), timeout=.5):
                with self.assertRaises(OSError):
                    control.verify_idle()
        with socket.socket() as check:
            self.assertNotEqual(check.connect_ex(('127.0.0.1', guard.port)), 0)

    def test_rejects_bad_port_lifecycle_and_nonlocal_primary_listener(self):
        for port in (0, True, -1, 65536, '19600'):
            with self.subTest(port=port), self.assertRaises(ValueError):
                self.factory(port)
        with self.factory() as control:
            for listen in ('socks://synthetic:synthetic@0.0.0.0:19600',
                           'socks://127.0.0.1:19600',
                           'socks://synthetic:synthetic@127.0.0.1:19601', []):
                with self.subTest(listen=listen), self.assertRaises(ValueError):
                    control.configure({'listen': listen, 'proxy': 'https://vpn.example.test'})
            with self.assertRaises(ValueError):
                control.__enter__()

    def test_flush_requires_method_rejection_and_shared_deadline(self):
        from lucx_post_configurator import naive_probes as module
        with self.factory() as control:
            with mock.patch.object(module.socket, 'create_connection') as connect, \
                 mock.patch.object(module, '_receive', return_value=b'\x05\x00'):
                with self.assertRaises(OSError):
                    control.flush(module.time.monotonic() + 1)
                connect.assert_called_once()
            with self.assertRaises(OSError):
                control.verify_idle()
        with self.factory() as control, mock.patch.object(module.socket, 'create_connection') as connect:
            with self.assertRaises(OSError):
                control.flush(module.time.monotonic() - 1)
            connect.assert_not_called()


class NativeNaiveObserverTests(unittest.TestCase):
    def setUp(self):
        NaiveProbeTests.setUp(self)
        self.value.update(security='', alpn=[])
        self.value['transport_details']['support_status'] = 'unverified'
        self.credential = replace(self.credential,
            profile_fingerprint=routing_fingerprint(self.value, 443),
            policy_fingerprint='sha256:' + '1' * 64)
        self.binding = self.module.NativeBackendBinding(
            self.credential.profile_fingerprint, self.credential.policy_fingerprint,
            'sha256:' + '2' * 64, 123,
            '9a8a4d2cf9dd14040086cf5f1762eb8b4304f1dbc0c85784d8bdf27c2587956b',
            0, '', 0, True, '127.0.0.1', 19443, 'origin.example.test', 'synthetic-ca')
        self.native = mock.Mock(side_effect=lambda value: self.binding)
        self.context = replace(self.context, echo_address='192.0.2.10', echo_port=0,
                               native_binding_provider=self.native)
        self.observer = self.module.NaiveVPNObserver(self.context)

    def test_native_source_proves_implicit_tls_without_changing_protocol(self):
        before = copy.deepcopy(self.value)
        self.assertTrue(self.observer.supports(self.value))
        self.assertEqual(self.value, before)
        self.assertTrue(self.observer.preflight(accepted(self.value, 'direct'), Runner()))
        for changes in ({'security': 'reality'}, {'alpn': ['h3']}, {'transport': 'raw'}):
            self.assertFalse(self.observer.supports({**self.value, **changes}))

    def test_binding_requires_same_policy_profile_backend_and_pinned_caddy(self):
        for change in ({'auth_policy_fingerprint': 'sha256:' + '3' * 64},
                       {'profile_fingerprint': 'sha256:' + '3' * 64},
                       {'backend_port': 19444}, {'caddy_pid': True},
                       {'caddy_sha256': 'a' * 64}, {'backend_address': '192.0.2.10'},
                       {'probe_resistance': 1}, {'xray_pid': 456}, {'bridge_port': 1080},
                       {'xray_pid': 456, 'bridge_port': 1080, 'xray_sha256': 'a' * 64}):
            with self.subTest(fields=list(change)):
                self.native.side_effect = None
                self.native.return_value = replace(self.binding, **change)
                self.assertFalse(self.observer.supports(self.value))

    def test_worker_uses_backend_tls_and_private_binding_then_checks_freshness(self):
        good = {'authenticated': True, 'negative_auth': True, 'reconnect': True,
                'bytes_sent': 16384, 'bytes_received': 16384}
        for changed, healthy in ((self.binding, True), (None, False),
                (replace(self.binding, binding_fingerprint='sha256:' + '3' * 64), False)):
            self.native.side_effect = [self.binding, changed]
            runner = Runner()
            with mock.patch.object(runner, 'run_bounded', return_value=CommandResult(
                    [], 0, json.dumps(good), '')) as run:
                result = self.observer(accepted(self.value, 'direct'), runner)
            request = json.loads(run.call_args.kwargs['input_text'])
            self.assertEqual((request['address'], request['port'], request['sni']),
                             ('127.0.0.1', 19443, 'origin.example.test'))
            self.assertEqual(request['ca_pem'], self.binding.backend_ca_pem)
            self.assertEqual(request['native']['caddy_pid'], 123)
            self.assertEqual(result['state'], 'healthy' if healthy else 'failed')
            self.assertNotIn('synthetic-ca', json.dumps(result))

    def test_native_hidden_denial_is_enabled_only_for_verified_policy(self):
        from dataclasses import asdict
        request = {'binary': str(self.binary), 'sha256': self.module.NAIVE_SHA256,
                   'password': self.secret, 'timeout': 10, 'native': asdict(self.binding)}
        with mock.patch.object(self.module, '_attempt') as attempt:
            self.module._worker_exchange(request)
        self.assertTrue(attempt.call_args_list[0].kwargs.get('hidden_denial', False))
        with mock.patch.object(self.module, '_attempt') as attempt:
            self.module._worker_exchange({**request, 'native': {**request['native'], 'probe_resistance': False}})
        self.assertFalse(attempt.call_args_list[0].kwargs.get('hidden_denial', False))


class NaiveProbeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("lucx_post_configurator.naive_probes"),
            "Нужен штатный observer настоящего Naive")
        from lucx_post_configurator import naive_probes as module
        self.module = module
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.binary = Path(self.temp.name) / "naive"
        self.binary.write_bytes(b"synthetic-only-client")
        self.value = profile()
        self.secret = "synthetic-password+/:@"
        self.credential = module.NaiveProbeCredential("synthetic-user", self.secret,
            routing_fingerprint(self.value, 443))
        self.provider = mock.Mock(side_effect=lambda value: self.credential)
        self.context = module.NaiveProbeContext(self.binary, module.NAIVE_SHA256,
            self.provider, "127.0.0.1", 19600)
        self.observer = module.NaiveVPNObserver(self.context)
        platform = mock.patch.object(module.sys, "platform", "linux")
        platform.start()
        self.addCleanup(platform.stop)
        binary = mock.patch.object(module, "_open_binary",
            side_effect=lambda path, digest: os.open(self.binary, os.O_RDONLY))
        binary.start()
        self.addCleanup(binary.stop)

    def test_api_is_immutable_and_hides_credentials(self):
        self.assertEqual(self.context.timeout, 20)
        self.assertEqual(self.credential.policy_fingerprint, "")
        with self.assertRaises(FrozenInstanceError):
            self.credential.password = "changed"
        self.assertNotIn(self.secret, repr(self.credential))
        self.assertTrue(self.observer.supports(self.value))

    def test_pin_cannot_be_replaced_with_arbitrary_client_hash(self):
        context = replace(self.context, binary_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertFalse(self.module.NaiveVPNObserver(context).supports(self.value))

    def test_strict_transport_and_wrapper_allowlist(self):
        changes = [{"protocol": "anytls"}, {"transport": "raw"}, {"security": ""},
            {"network": "udp"}, {"flow": "custom"}, {"udp_over_tcp": True},
            {"alpn": []}, {"alpn": ["h3"]}, {"alpn": ["h2", "h2"]},
            {"transport_path": "/vpn"}, {"transport_mode": "auto"},
            {"transport_hosts": ["vpn.example.test"]}, {"enable": False},
            {"transport_details": {"future": False}},
            {"transport_details": {"settings_keys": ["path"]}},
            {"transport_details": {"extra": {"keys": ["opaque"]}}},
            {"transport_details": {"masks": {"tcp_types": ["opaque"]}}},
            {"transport_details": {"unknown_stream_fields": ["wrapper"]}},
            {"transport_details": {"settings_fingerprint": "invalid"}},
            {"transport_details": {"support_status": "unsupported"}}]
        for change in changes:
            value = {**self.value, **change}
            self.credential = replace(self.credential, profile_fingerprint=routing_fingerprint(value, 443))
            with self.subTest(change=change):
                self.assertFalse(self.observer.supports(value))

    def test_h2_with_optional_h1_and_fresh_profile(self):
        for alpn in (["h2"], ["h2", "http/1.1"], ["http/1.1", "h2"]):
            value = {**self.value, "alpn": alpn}
            self.credential = replace(self.credential, profile_fingerprint=routing_fingerprint(value, 443))
            self.assertTrue(self.observer.supports(value))
        self.credential = replace(self.credential, profile_fingerprint="sha256:" + "0" * 64)
        self.assertFalse(self.observer.supports(self.value))

    def test_different_sni_authority_and_host_override_are_closed(self):
        for change in ({"sni": "other.example.test"}, {"address": "192.0.2.9"},
                       {"http_host": "vpn.example.test"}, {"keep_sni_blank": True}):
            value = profile()
            value["public_endpoints"][0].update(change)
            self.credential = replace(self.credential, profile_fingerprint=routing_fingerprint(value, 443))
            with self.subTest(change=change):
                self.assertFalse(self.observer.supports(value))

    def test_dry_run_and_wrong_phase_never_read_source_or_run(self):
        for phase, dry_run in (("public", True), ([], False), ("future", False)):
            runner = Runner(dry_run=dry_run)
            self.provider.reset_mock()
            with mock.patch.object(runner, "run_bounded") as run:
                self.assertEqual(self.observer(accepted(phase=phase), runner)["state"], "not_tested")
                self.provider.assert_not_called()
                run.assert_not_called()

    def test_identity_and_direct_staging_dial_require_explicit_binding(self):
        for field, value in (("profile_fingerprint", "sha256:" + "0" * 64),
                             ("endpoint_fingerprint", "sha256:" + "0" * 64), ("inbound_id", 8)):
            item = accepted()
            item["acceptance_target"][field] = value
            self.assertFalse(self.observer.preflight(item, Runner()))
        for phase in ("direct", "staging"):
            self.assertFalse(self.observer.preflight(accepted(phase=phase), Runner()))
        provider = mock.Mock(return_value=("127.0.0.1", 25443))
        observer = self.module.NaiveVPNObserver(replace(self.context, dial_target_provider=provider))
        self.assertTrue(observer.preflight(accepted(phase="staging"), Runner()))
        provider.reset_mock()
        self.assertTrue(observer.preflight(accepted(), Runner()))
        provider.assert_not_called()

    def test_echo_and_timeout_are_code_owned_bounded_values(self):
        for changes in ({"echo_port": 0}, {"echo_port": 0, "echo_address": "192.0.2.9"},
                        {"echo_address": "echo.example.test"}, {"timeout": float("nan")},
                        {"timeout": 61}, {"timeout": True}):
            observer = self.module.NaiveVPNObserver(replace(self.context, **changes))
            self.assertEqual(observer.supports(self.value), changes == {"echo_port": 0})

    def test_worker_receipt_requires_explicit_auth_denial_and_reconnect(self):
        good = {"authenticated": True, "negative_auth": True, "reconnect": True,
            "bytes_sent": 16384, "bytes_received": 16384}
        responses = [good, {**good, "negative_auth": False}, {**good, "reconnect": False},
            {**good, "bytes_sent": True}, {**good, "bytes_received": 0},
            {"authenticated": True, "bytes_sent": 16384, "bytes_received": 16384}]
        for index, response in enumerate(responses):
            runner = Runner()
            with mock.patch.object(runner, "run_bounded", return_value=CommandResult([], 0,
                json.dumps({**response, "payload": self.secret}), self.secret)) as run:
                result = self.observer(accepted(), runner)
            self.assertEqual(result["state"], "healthy" if index == 0 else "failed")
            self.assertNotIn(self.secret, json.dumps(result))
            self.assertNotIn(self.secret, repr(run.call_args.args))
            self.assertIn(self.secret, run.call_args.kwargs["input_text"])
            self.assertFalse(run.call_args.kwargs["inherit_env"])
            self.assertTrue(run.call_args.kwargs["isolate_process_group"])

    def test_auth_denial_is_not_a_generic_socks_failure(self):
        for text, expected in ((b"ERR_PROXY_AUTH_UNSUPPORTED", True),
                (b"ERR_PROXY_AUTH_REQUESTED", True), (b"ERR_SOCKS_CONNECTION_FAILED", False),
                (b"peer_closed", False), (b"XERR_PROXY_AUTH_REQUESTED", False),
                (b"ERR_PROXY_AUTH_REQUESTED_suffix", False)):
            self.assertEqual(self.module._auth_denied(text), expected)

    def test_successful_worker_cannot_accept_source_drift_during_exchange(self):
        good = {"authenticated": True, "negative_auth": True, "reconnect": True,
                "bytes_sent": 16384, "bytes_received": 16384}
        for changed in (None, replace(self.credential, password="synthetic-changed"),
                        replace(self.credential, ca_pem="synthetic-changed-ca"),
                        replace(self.credential, policy_fingerprint="sha256:" + "a" * 64)):
            with self.subTest(kind=type(changed).__name__):
                self.provider.side_effect = [self.credential, changed]
                runner = Runner()
                with mock.patch.object(runner, "run_bounded", return_value=CommandResult(
                        [], 0, json.dumps(good), "")):
                    result = self.observer(accepted(), runner)
                self.assertEqual(result["state"], "failed")
                self.assertFalse(result["authenticated"])
                self.assertEqual((result["bytes_sent"], result["bytes_received"]), (0, 0))
                self.assertNotIn(self.secret, json.dumps(result))

    def test_successful_worker_cannot_accept_changed_staging_target(self):
        good = {"authenticated": True, "negative_auth": True, "reconnect": True,
                "bytes_sent": 16384, "bytes_received": 16384}
        dial = mock.Mock(side_effect=[("127.0.0.1", 25443), ("127.0.0.1", 25444)])
        observer = self.module.NaiveVPNObserver(replace(self.context, dial_target_provider=dial))
        runner = Runner()
        with mock.patch.object(runner, "run_bounded", return_value=CommandResult(
                [], 0, json.dumps(good), "")):
            result = observer(accepted(phase="staging"), runner)
        self.assertEqual(result["state"], "failed")
        self.assertFalse(result["functional"])

    def test_client_config_preserves_credentials_uses_socks_auth_and_fixed_dial(self):
        request = {"username": "user +/@", "password": self.secret, "sni": "vpn.example.test",
            "address": "127.0.0.1", "port": 25443}
        config = self.module._client_config(request, self.secret, 19600, (b"local-user", b"local-pass"))
        proxy = urllib.parse.urlsplit(config["proxy"])
        self.assertEqual(urllib.parse.unquote(proxy.username), request["username"])
        self.assertEqual(urllib.parse.unquote(proxy.password), self.secret)
        self.assertEqual((proxy.hostname, proxy.port), (request["sni"], request["port"]))
        self.assertEqual(config["listen"], "socks://local-user:local-pass@127.0.0.1:19600")
        self.assertIn("MAP vpn.example.test 127.0.0.1", config["host-resolver-rules"])
        request['proxy_port'] = 8443
        config = self.module._client_config(request, self.secret, 19600, (b"local-user", b"local-pass"))
        self.assertEqual(urllib.parse.urlsplit(config['proxy']).port, 8443)
        self.assertEqual(config['host-resolver-rules'], 'MAP vpn.example.test 127.0.0.1:25443')

    def test_source_exception_does_not_escape(self):
        self.provider.side_effect = ValueError(self.secret)
        self.assertFalse(self.observer.supports(self.value))
        result = self.observer(accepted(), Runner())
        self.assertEqual(result["state"], "failed")
        self.assertNotIn(self.secret, json.dumps(result))

    def test_coordinator_group_must_belong_to_this_process(self):
        observer = self.module.NaiveVPNObserver(replace(self.context, coordinator_pid=123))
        with mock.patch.object(self.module.os, "getpid", return_value=123), \
             mock.patch.object(self.module.os, "getpgrp", create=True, return_value=124), \
             mock.patch.object(self.module.os, "getsid", create=True, return_value=123):
            self.assertFalse(observer.supports(accepted(phase="staging")))

    def test_attempt_requires_explicit_denial_and_bounds_stderr(self):
        request = {"username": self.credential.username, "password": self.secret,
            "ca_pem": "synthetic-ca", "sni": "vpn.example.test", "address": "127.0.0.1",
            "port": 25443, "echo_address": "127.0.0.1", "echo_port": 19600}
        cases = [(b"ERR_PROXY_AUTH_REQUESTED", True, True),
            (b"ERR_SOCKS_CONNECTION_FAILED", True, False),
            (b"ERR_PROXY_AUTH_REQUESTED" + b"x" * 65536, True, False),
            (b"ERR_PROXY_AUTH_REQUESTED", False, False)]
        for stderr, fails, accepted_denial in cases:
            process = mock.Mock(stderr=io.BytesIO(stderr))
            process.poll.return_value = None
            process.wait.return_value = -15
            sealed = []
            def seal(data, collected=sealed):
                collected.append(data)
                return os.open(self.binary, os.O_RDONLY)
            with mock.patch.object(self.module, "_sealed", side_effect=seal), \
                 mock.patch.object(self.module.subprocess, "Popen", return_value=process) as popen, \
                 mock.patch.object(self.module.socket, "socket") as reservation, \
                 mock.patch.object(self.module.socket, "create_connection"), \
                 mock.patch.object(self.module, "_roundtrip", side_effect=OSError(self.secret) if fails else None):
                reservation.return_value.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 19600)
                if accepted_denial:
                    self.module._attempt(request, 123, self.secret, self.module.time.monotonic() + 2, negative=True)
                else:
                    with self.assertRaisesRegex(OSError, "Naive"):
                        self.module._attempt(request, 123, self.secret, self.module.time.monotonic() + 2, negative=True)
            self.assertNotIn(self.secret, repr(popen.call_args))
            self.assertEqual(len(popen.call_args.args[0]), 2)
            self.assertTrue(popen.call_args.kwargs["env"]["SSL_CERT_FILE"].startswith("/proc/self/fd/"))
            self.assertEqual(sealed[1], b"synthetic-ca")
            process.terminate.assert_called_once()

    def test_worker_requires_negative_then_two_correct_exchanges(self):
        request = {"binary": str(self.binary), "sha256": self.module.NAIVE_SHA256,
            "password": self.secret, "timeout": 19}
        with mock.patch.object(self.module, "_attempt") as attempt:
            result = self.module._worker_exchange(request)
        self.assertEqual(len(attempt.call_args_list), 2)
        self.assertTrue(attempt.call_args_list[0].kwargs["negative"])
        self.assertNotEqual(attempt.call_args_list[0].args[2], self.secret)
        self.assertFalse(attempt.call_args_list[1].kwargs["negative"])
        self.assertEqual(attempt.call_args_list[1].args[2], self.secret)
        self.assertEqual(result["bytes_sent"], 16384)
        with mock.patch.object(self.module, "_attempt", side_effect=OSError("denial not proven")) as attempt:
            with self.assertRaises(OSError):
                self.module._worker_exchange(request)
            self.assertEqual(attempt.call_count, 1)

    def test_preflight_never_starts_listener_and_nonlinux_never_reads_source(self):
        with mock.patch.object(self.module.socket, "socket", side_effect=AssertionError("Нет listener в preflight")):
            self.assertTrue(self.observer.preflight(accepted(), Runner()))
        self.provider.reset_mock()
        with mock.patch.object(self.module.sys, "platform", "win32"):
            self.assertFalse(self.observer.supports(self.value))
        self.provider.assert_not_called()

    def test_h2_proof_requires_two_correlated_connect_data_streams(self):
        self.assertTrue(callable(getattr(self.module, "_netlog_h2", None)), "Нужен proof реальных h2 streams")
        names = ["HTTP2_SESSION_SEND_HEADERS", "HTTP2_SESSION_RECV_HEADERS",
            "HTTP2_SESSION_SEND_DATA", "HTTP2_SESSION_RECV_DATA"]
        constants = {"logEventTypes": dict(zip(names, range(1, 5))),
            "logSourceType": {"HTTP2_SESSION": 9}}
        rows = []
        for stream in (1, 3):
            params = [{"headers": [":method: CONNECT", ":authority: 127.0.0.1:19600"]},
                {"headers": [":status: 200"]}, {"size": 8300}, {"size": 8300}]
            rows.extend({"type": index, "source": {"id": 11, "type": 9},
                "params": {"stream_id": stream, **value}} for index, value in enumerate(params, 1))
        def payload(events):
            return (b'{"constants":' + json.dumps(constants).encode() + b',\n"events": [\n'
                + b"".join(json.dumps(item).encode() + b",\n" for item in events))
        request = {"echo_address": "127.0.0.1", "echo_port": 19600}
        self.assertTrue(self.module._netlog_h2(payload(rows), request))
        self.assertFalse(self.module._netlog_h2(payload(rows[:-1]), request))
        different = copy.deepcopy(rows)
        different[4]["params"]["headers"][1] = ":authority: 192.0.2.9:19600"
        self.assertFalse(self.module._netlog_h2(payload(different), request))
        different = copy.deepcopy(rows)
        different[-1]["params"]["stream_id"] = 5
        self.assertFalse(self.module._netlog_h2(payload(different), request))
        self.assertFalse(self.module._netlog_h2(payload([]) + b'{"next_proto":"h2"},\n', request))
        self.assertFalse(self.module._netlog_h2(payload(rows[:-1]) + json.dumps(rows[-1]).encode(), request))
        self.assertFalse(self.module._netlog_h2(payload(rows) + b'{"broken":},\n', request))

    def test_netlog_flush_rejects_local_unauthenticated_method_with_short_reads(self):
        local = mock.Mock()
        local.recv.side_effect = [b"\x05", b"\xff"]
        with mock.patch.object(self.module, "_netlog_bytes", return_value=b"evidence"), \
             mock.patch.object(self.module, "_netlog_h2", side_effect=[False, True]), \
             mock.patch.object(self.module.socket, "create_connection") as connect, \
             mock.patch.object(self.module.time, "sleep"):
            connect.return_value.__enter__.return_value = local
            self.module._wait_h2(123, 19600, {}, self.module.time.monotonic() + 2)
        local.sendall.assert_called_once_with(b"\x05\x01\x00")
        self.assertEqual(local.recv.call_count, 2)
        self.assertEqual(connect.call_args.args[0], ("127.0.0.1", 19600))

    def test_positive_attempt_closes_private_descriptors_when_evidence_seal_fails(self):
        descriptors = []
        def descriptor(*args):
            value = os.open(self.binary, os.O_RDONLY)
            descriptors.append(value)
            return value
        request = {"username": self.credential.username, "password": self.secret,
            "ca_pem": "synthetic-ca", "sni": "vpn.example.test", "address": "127.0.0.1",
            "port": 25443, "echo_address": "127.0.0.1", "echo_port": 19600}
        process = mock.Mock(stderr=io.BytesIO(b"negotiated padding type: Variant1\n"))
        process.poll.return_value = None
        fcntl = types.SimpleNamespace(F_ADD_SEALS=1, F_SEAL_WRITE=2, F_SEAL_GROW=4,
            F_SEAL_SHRINK=8, F_SEAL_SEAL=16, fcntl=mock.Mock(side_effect=OSError("seal failure")))
        try:
            with mock.patch.dict(self.module.sys.modules, {"fcntl": fcntl}), \
                 mock.patch.object(self.module.os, "memfd_create", create=True, side_effect=descriptor), \
                 mock.patch.object(self.module.os, "MFD_CLOEXEC", create=True, new=1), \
                 mock.patch.object(self.module.os, "MFD_ALLOW_SEALING", create=True, new=2), \
                 mock.patch.object(self.module, "_sealed", side_effect=descriptor), \
                 mock.patch.object(self.module.subprocess, "Popen", return_value=process), \
                 mock.patch.object(self.module.socket, "socket") as reservation, \
                 mock.patch.object(self.module.socket, "create_connection"), \
                 mock.patch.object(self.module, "_roundtrip"), \
                 mock.patch.object(self.module, "_wait_h2"):
                reservation.return_value.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 19600)
                with self.assertRaises(OSError):
                    self.module._attempt(request, 123, self.secret, self.module.time.monotonic() + 2, negative=False)
            for value in descriptors:
                with self.assertRaises(OSError, msg="Ошибка seal не должна оставлять private fd открытым"):
                    os.fstat(value)
        finally:
            for value in descriptors:
                try:
                    os.close(value)
                except OSError:
                    pass

    def test_positive_attempt_rejects_spontaneous_exit_before_own_cleanup(self):
        names = ["HTTP2_SESSION_SEND_HEADERS", "HTTP2_SESSION_RECV_HEADERS",
            "HTTP2_SESSION_SEND_DATA", "HTTP2_SESSION_RECV_DATA"]
        constants = {"logEventTypes": dict(zip(names, range(1, 5))),
            "logSourceType": {"HTTP2_SESSION": 9}}
        rows = []
        for stream in (1, 3):
            params = [{"headers": [":method: CONNECT", ":authority: 127.0.0.1:19600"]},
                {"headers": [":status: 200"]}, {"size": 8300}, {"size": 8300}]
            rows.extend({"type": index, "source": {"id": 11, "type": 9},
                "params": {"stream_id": stream, **value}} for index, value in enumerate(params, 1))
        evidence = (b'{"constants":' + json.dumps(constants).encode() + b',\n"events": [\n'
            + b"".join(json.dumps(item).encode() + b",\n" for item in rows))
        request = {"username": self.credential.username, "password": self.secret,
            "ca_pem": "", "sni": "vpn.example.test", "address": "127.0.0.1",
            "port": 25443, "echo_address": "127.0.0.1", "echo_port": 19600}
        self.assertTrue(self.module._netlog_h2(evidence, request))
        fcntl = types.SimpleNamespace(F_ADD_SEALS=1, F_SEAL_WRITE=2, F_SEAL_GROW=4,
            F_SEAL_SHRINK=8, F_SEAL_SEAL=16, fcntl=mock.Mock())
        def descriptor(*args):
            return os.open(self.binary, os.O_RDONLY)
        cases = [(None, -15, False), (42, 42, False), (0, 0, False),
            (None, 42, False), (None, 0, False),
            (None, -9, True), (None, 42, True), (None, 0, True)]
        for exit_code, final_code, forced in cases:
            process = mock.Mock(stderr=io.BytesIO(b"negotiated padding type: Variant1\n"))
            process.poll.side_effect = [None, exit_code]
            process.wait.side_effect = ([self.module.subprocess.TimeoutExpired("client", .5), final_code]
                if forced else [final_code])
            accepted_stop = exit_code is None and final_code == (-9 if forced else -15)
            with self.subTest(exit_before_cleanup=exit_code, final_code=final_code, forced=forced), \
                 mock.patch.object(self.module.signal, "SIGKILL", create=True, new=9), \
                 mock.patch.dict(self.module.sys.modules, {"fcntl": fcntl}), \
                 mock.patch.object(self.module.os, "memfd_create", create=True, side_effect=descriptor), \
                 mock.patch.object(self.module.os, "MFD_CLOEXEC", create=True, new=1), \
                 mock.patch.object(self.module.os, "MFD_ALLOW_SEALING", create=True, new=2), \
                 mock.patch.object(self.module, "_sealed", side_effect=descriptor), \
                 mock.patch.object(self.module.subprocess, "Popen", return_value=process), \
                 mock.patch.object(self.module.socket, "socket") as reservation, \
                 mock.patch.object(self.module.socket, "create_connection"), \
                 mock.patch.object(self.module, "_roundtrip") as exchange, \
                 mock.patch.object(self.module, "_wait_h2"), \
                 mock.patch.object(self.module, "_netlog_bytes", return_value=evidence):
                reservation.return_value.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 19600)
                if accepted_stop:
                    self.module._attempt(request, 123, self.secret, self.module.time.monotonic() + 2, negative=False)
                else:
                    with self.assertRaises(OSError, msg="Самостоятельный exit не является healthy Naive"):
                        self.module._attempt(request, 123, self.secret, self.module.time.monotonic() + 2, negative=False)
                if exit_code is None:
                    process.terminate.assert_called_once()
                else:
                    process.terminate.assert_not_called()
                self.assertEqual(process.kill.call_count, 1 if forced else 0)
                self.assertEqual(exchange.call_count, 2)


if __name__ == "__main__":
    unittest.main()
