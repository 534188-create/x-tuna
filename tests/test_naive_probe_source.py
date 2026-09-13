"""Источник Naive читает существующую auth, не создавая frontend или клиентов."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_naive_connect_frontend import candidate_fixture

from lucx_post_configurator.models import Audit
from lucx_post_configurator.routing_profiles import routing_fingerprint
from lucx_post_configurator.targetfs import TargetFS


class NaiveConnectSourceParserTests(unittest.TestCase):
    def parse(self, token, extra=''):
        from lucx_post_configurator.naive_frontend import parse_naive_connect_source
        return parse_naive_connect_source('vpn.example.test {\n route {\n forward_proxy {\n'
            f' basic_auth synthetic-user {token}\n{extra}\n hide_ip\n hide_via\n }}\n }}\n}}\n')

    def test_public_parser_keeps_caddy_quoting_and_compatible_private_alias(self):
        from lucx_post_configurator.naive_frontend import parse_naive_connect_source
        from lucx_post_configurator.naive_probe_source import _parse_source
        self.assertIs(_parse_source, parse_naive_connect_source)
        for token, expected in (
                ('synthetic#suffix', 'synthetic#suffix'),
                ('`synthetic "quoted"#suffix`', 'synthetic "quoted"#suffix'),
                ("'synthetic-literal'", "'synthetic-literal'"),
                (r'"synthetic\"quoted#suffix"', 'synthetic"quoted#suffix'),
                (r'synthetic\suffix', r'synthetic\suffix'),
                (r'"synthetic\\suffix"', r'synthetic\\suffix')):
            with self.subTest(token=token):
                source = self.parse(token + ' # comment')
                self.assertEqual(source.auth_pairs, [('synthetic-user', expected)])
                self.assertTrue(source.hide_ip and source.hide_via)

    def test_public_parser_rejects_substitution_multiline_and_unsupported_lexing(self):
        for token in ('{$SYNTHETIC_PASS}', '{env.SYNTHETIC_PASS}', '`unterminated',
                      '"line\nbreak"', '<<PASS', r'\"synthetic"', 'synthetic\rvalue',
                      '"synthetic"suffix', 'synthetic\x00value', 'synthetic\ufeffvalue'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                self.parse(token)

    def test_public_parser_checks_original_utf8_size_before_normalization(self):
        from lucx_post_configurator.naive_frontend import parse_naive_connect_source
        valid = ('vpn.example.test {\n route {\n forward_proxy {\n'
                 ' basic_auth synthetic-user synthetic-pass\n }\n }\n}\n')
        limit = 1024 * 1024
        boundary = valid + '#' + 'x' * (limit - len(valid.encode('utf-8')) - 1)
        self.assertEqual(len(boundary.encode('utf-8')), limit)
        self.assertEqual(parse_naive_connect_source(boundary).auth_pairs,
                         [('synthetic-user', 'synthetic-pass')])
        for value in (boundary + 'x', valid + '#' + 'я' * (limit // 2), None, b'bytes', ''):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                parse_naive_connect_source(value)

    def test_parser_preserves_options_for_callers_to_restrict(self):
        source = self.parse('synthetic-pass',
                            ' probe_resistance\n upstream https://upstream.example.test')
        self.assertTrue(source.probe_resistance)
        self.assertEqual(source.upstream, 'https://upstream.example.test')


class NaiveNativeSourceShapeTests(unittest.TestCase):
    def setUp(self):
        self.text = '''{
 admin off
 skip_install_trust
 auto_https off
 log {
  level WARN
 }
 servers {
  protocols h1 h2
 }
}
:18443, vpn.example.test:18443 {
 bind 127.0.0.1
 tls "/synthetic/cert.pem" "/synthetic/key.pem"
 log {
  output file /synthetic/access.log
  format json
 }
 route {
  forward_proxy {
   basic_auth synthetic-user synthetic-password
   hide_ip
   hide_via
   probe_resistance
   upstream socks5://lucx:abcdefghijklmnopqrstuvwx@127.0.0.1:19443
  }
 }
}
'''

    def parse(self, text=None):
        from lucx_post_configurator.naive_frontend import parse_naive_native_source
        return parse_naive_native_source(self.text if text is None else text)

    def test_manual_tls_chain_keeps_source_identity_without_auth_in_result(self):
        from dataclasses import FrozenInstanceError, asdict
        result = self.parse()
        self.assertEqual(result.port, 18443)
        self.assertEqual(result.bind_host, '127.0.0.1')
        self.assertEqual(result.server_names, ('vpn.example.test',))
        self.assertEqual((result.cert_path, result.key_path),
                         ('/synthetic/cert.pem', '/synthetic/key.pem'))
        self.assertTrue(result.probe_resistance)
        self.assertEqual(result.source_sha256, hashlib.sha256(self.text.encode()).hexdigest())
        self.assertEqual(result.upstream_sha256, hashlib.sha256(
            b'socks5://lucx:abcdefghijklmnopqrstuvwx@127.0.0.1:19443').hexdigest())
        for value in ('synthetic-password', 'abcdefghijklmnopqrstuvwx'):
            self.assertNotIn(value, repr(result))
            self.assertNotIn(value, repr(asdict(result)))
        with self.assertRaises(FrozenInstanceError):
            result.port = 443

    def test_manual_source_accepts_canonical_optional_forms_and_exact_quoted_paths(self):
        text = self.text.replace(' skip_install_trust\n', '').replace(
            ' log {\n  level WARN\n }\n', '').replace(
            ' servers {\n  protocols h1 h2\n }\n', '').replace(
            ' bind 127.0.0.1\n', '').replace(
            '   probe_resistance\n', '').replace(
            '   upstream socks5://lucx:abcdefghijklmnopqrstuvwx@127.0.0.1:19443\n', '')
        result = self.parse(text.replace(':18443, vpn.example.test:18443', ':443, vpn.example.test'))
        self.assertEqual((result.port, result.bind_host, result.server_names),
                         (443, '', ('vpn.example.test',)))
        self.assertFalse(result.probe_resistance)
        self.assertEqual(result.upstream_sha256, '')
        result = self.parse(self.text.replace('bind 127.0.0.1', 'bind ::1').replace(
            '/synthetic/cert.pem', '/synthetic/cert with spaces.pem'))
        self.assertEqual(result.bind_host, '::1')
        self.assertEqual(result.cert_path, '/synthetic/cert with spaces.pem')
        self.assertEqual(self.parse(self.text.replace(', vpn.example.test:18443', '')).server_names, ())

    def test_rejects_path_aliases_log_tls_collision_and_excessive_structure(self):
        for value in ('/synthetic/./cert.pem', '/synthetic//cert.pem', '//synthetic/cert.pem'):
            with self.subTest(path=value), self.assertRaises(ValueError):
                self.parse(self.text.replace('/synthetic/cert.pem', value))
        for value in ('/synthetic/cert.pem', '/synthetic/key.pem'):
            with self.subTest(log=value), self.assertRaises(ValueError):
                self.parse(self.text.replace('/synthetic/access.log', value))
        for text in (self.text + '# bounded\n' * 4096,
                     self.text.replace('synthetic-password', 'x' * 1025)):
            with self.subTest(size=len(text)), self.assertRaises(ValueError):
                self.parse(text)

    def test_rejects_ambiguous_or_unproved_tls_listener_handler_and_auth_shapes(self):
        changes = (
            ('admin off', 'admin localhost:2019'), ('admin off', 'admin off\n admin off'),
            ('auto_https off', 'auto_https disable_redirects'), ('auto_https off\n', ''),
            ('protocols h1 h2', 'protocols h1'), ('protocols h1 h2', 'protocols h1 h2 h2'),
            (':18443, vpn.example.test:18443', 'vpn.example.test'),
            (':18443, vpn.example.test:18443', ':18443, vpn.example.test:443'),
            (':18443, vpn.example.test:18443', ':18443, *.example.test:18443'),
            (':18443, vpn.example.test:18443', ':18443, vpn.example.test:18443, vpn.example.test:18443'),
            ('bind 127.0.0.1', 'bind proxy.example.test'), ('bind 127.0.0.1', 'bind 127.0.0.1 ::1'),
            ('tls "/synthetic/cert.pem" "/synthetic/key.pem"', 'tls internal'),
            ('/synthetic/cert.pem', 'relative/cert.pem'), ('/synthetic/key.pem', '/synthetic/../key.pem'),
            ('/synthetic/key.pem', '/synthetic/cert.pem'),
            ('   hide_ip', '   hide_ip\n   hide_ip'), ('   hide_via\n', ''),
            ('   probe_resistance', '   probe_resistance secret.example.test'),
            ('   basic_auth synthetic-user synthetic-password',
             '   basic_auth synthetic-user synthetic-password\n   basic_auth synthetic-user second-password'),
            ('socks5://lucx:abcdefghijklmnopqrstuvwx@127.0.0.1:19443',
             'socks5://lucx:abcdefghijklmnopqrstuvwx@192.0.2.10:19443'),
            ('  level WARN', '  level WARN\n  level ERROR'),
            ('  format json', '  format console'),
            (' route {', ' route {\n }\n route {'),
        )
        for old, new in changes:
            with self.subTest(old=old, new=new), self.assertRaises(ValueError) as caught:
                self.parse(self.text.replace(old, new))
            self.assertNotIn('synthetic-password', str(caught.exception))
        for extra in ('\n:19443 {\n tls /synthetic/cert.pem /synthetic/key.pem\n}\n',
                      '\n{\n admin off\n}\n'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.parse(self.text + extra)


class NaiveProbeSourceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('lucx_post_configurator.naive_probe_source'),
                             'Нужен read-only источник существующих Naive credentials')
        from lucx_post_configurator.naive_probe_source import NaiveCaddyCredentialSource
        self.source_type = NaiveCaddyCredentialSource
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fs = TargetFS(Path(self.temporary.name))
        self.manifest, _, _ = candidate_fixture()
        self.path = self.fs.path('/etc/example/naive-7.caddyfile')
        self.path.parent.mkdir(parents=True)
        self.username, self.password = 'synthetic-selected', 'synthetic-pass:with+reserved'
        self.text = ('vpn.example.test {\n route {\n forward_proxy {\n'
            f' basic_auth "{self.username}" "{self.password}"\n'
            ' hide_ip\n hide_via\n }\n }\n}\n')
        self.path.write_text(self.text, encoding='utf-8')
        self.path.chmod(0o600)
        self.audit = self.make_audit()

    def make_audit(self):
        info = self.path.lstat()
        return Audit(naive_caddyfile={'files': [{'path': '/etc/example/naive-7.caddyfile',
            'kind': 'file', 'mode': info.st_mode & 0o7777, 'uid': info.st_uid, 'gid': info.st_gid,
            'sha256': hashlib.sha256(self.path.read_bytes()).hexdigest(),
            'capabilities': {'forward_proxy': True, 'native_decoy': False}}]})

    def capture(self):
        return self.source_type(self.fs, self.manifest, self.audit)

    def test_existing_auth_is_exact_and_source_is_read_only(self):
        before = self.path.stat()
        source = self.capture()
        protocol = self.manifest['protocols'][0]
        credential = source(protocol)
        self.assertIsNotNone(credential)
        self.assertEqual((credential.username, credential.password), (self.username, self.password))
        self.assertEqual(credential.profile_fingerprint, routing_fingerprint(protocol, 443))
        self.assertRegex(credential.policy_fingerprint, r'^sha256:[0-9a-f]{64}$')
        self.assertNotIn(self.password, repr(credential))
        self.assertNotIn(self.password, repr(source))
        self.assertEqual(self.path.read_text(encoding='utf-8'), self.text)
        after = self.path.stat()
        for name in ('st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_mtime_ns', 'st_ctime_ns'):
            self.assertEqual(getattr(before, name), getattr(after, name))

    def test_caddy_auth_tokens_preserve_hash_backticks_quotes_and_backslashes(self):
        cases = (
            ('synthetic#suffix', 'synthetic#suffix'),
            ('`synthetic "quoted"#suffix`', 'synthetic "quoted"#suffix'),
            ("'synthetic-literal'", "'synthetic-literal'"),
            (r'"synthetic\"quoted#suffix"', 'synthetic"quoted#suffix'),
            (r'synthetic\suffix', r'synthetic\suffix'),
            (r'"synthetic\\suffix"', r'synthetic\\suffix'),
        )
        for token, expected in cases:
            self.path.write_text(self.text.replace('"' + self.password + '"', token + ' # trailing comment'),
                                 encoding='utf-8')
            self.audit = self.make_audit()
            with self.subTest(token=token):
                credential = self.capture()(self.manifest['protocols'][0])
                self.assertEqual(credential.password, expected)

    def test_old_provider_rejects_source_change_instead_of_silently_selecting_new_auth(self):
        source = self.capture()
        self.path.write_text(self.text.replace(self.password, 'synthetic-replacement'), encoding='utf-8')
        self.assertIsNone(source(self.manifest['protocols'][0]))
        self.audit = self.make_audit()
        fresh = self.capture()(self.manifest['protocols'][0])
        self.assertEqual(fresh.password, 'synthetic-replacement')

    def test_profile_change_and_unknown_inbound_are_rejected(self):
        source = self.capture()
        for field, value in (('internal_port', 19443), ('protocol', 'trusttunnel'), ('transport', 'ws'),
                             ('inbound_id', 8)):
            protocol = copy.deepcopy(self.manifest['protocols'][0])
            protocol[field] = value
            with self.subTest(field=field):
                self.assertIsNone(source(protocol))
        protocol = copy.deepcopy(self.manifest['protocols'][0])
        protocol['public_endpoints'][0]['port'] = 9443
        self.assertIsNone(source(protocol))

    def test_changed_unselected_client_also_invalidates_the_cohort(self):
        self.path.write_text(self.text.replace(' hide_ip\n',
            ' basic_auth synthetic-second synthetic-other\n hide_ip\n'), encoding='utf-8')
        self.audit = self.make_audit()
        source = self.capture()
        credential = source(self.manifest['protocols'][0])
        self.assertEqual(credential.username, self.username)
        self.path.write_text(self.path.read_text(encoding='utf-8').replace('synthetic-other', 'synthetic-changed'),
                             encoding='utf-8')
        self.assertIsNone(source(self.manifest['protocols'][0]))
        self.audit = self.make_audit()
        fresh = self.capture()(self.manifest['protocols'][0])
        self.assertEqual(fresh.username, credential.username)
        self.assertNotEqual(fresh.policy_fingerprint, credential.policy_fingerprint)

    def test_source_replacement_deletion_or_metadata_drift_is_rejected(self):
        source = self.capture()
        replacement = self.path.with_suffix('.replacement')
        replacement.write_bytes(self.path.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, self.path)
        self.assertIsNone(source(self.manifest['protocols'][0]))
        self.audit = self.make_audit()
        fresh = self.capture()
        self.path.unlink()
        self.assertIsNone(fresh(self.manifest['protocols'][0]))

    def test_bad_audit_parser_and_unreviewed_options_have_safe_errors(self):
        self.audit.naive_caddyfile['files'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, '^Источник Naive не подтверждён$'):
            self.capture()
        for extra in ('unsupported synthetic-hidden-value\n', 'probe_resistance\n',
                      'upstream https://upstream.example.test\n'):
            self.path.write_text(self.text.replace(' hide_ip\n', extra), encoding='utf-8')
            self.audit = self.make_audit()
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, '^Источник Naive не подтверждён$'):
                self.capture()

    def test_unreviewed_multiline_heredoc_and_environment_auth_is_blocked(self):
        for token in ('{$SYNTHETIC_PASS}', '`unterminated', '"line\nbreak"', '<<PASS',
                      r'\"synthetic"', 'synthetic\rvalue'):
            self.path.write_text(self.text.replace('"' + self.password + '"', token), encoding='utf-8')
            self.audit = self.make_audit()
            with self.subTest(token=token), self.assertRaisesRegex(ValueError, '^Источник Naive не подтверждён$'):
                self.capture()

    @unittest.skipUnless(os.name == 'posix', 'POSIX no-follow и права источника')
    def test_mode_hardlink_and_symlink_cannot_become_fresh_source(self):
        source = self.capture()
        self.path.chmod(0o644)
        self.assertIsNone(source(self.manifest['protocols'][0]))
        self.path.chmod(0o600)
        linked = self.path.with_suffix('.link')
        os.link(self.path, linked)
        with self.assertRaises(ValueError):
            self.capture()
        linked.unlink()
        self.path.rename(linked)
        self.path.symlink_to(linked)
        with self.assertRaises(ValueError):
            self.capture()

    def test_unrelated_file_is_never_read(self):
        real_open = os.open
        opened = []
        def checked_open(path, flags, *args, **kwargs):
            opened.append(str(path))
            return real_open(path, flags, *args, **kwargs)
        with patch('os.open', side_effect=checked_open):
            self.capture()(self.manifest['protocols'][0])
        self.assertFalse(any('x-ui.db' in path or 'key.pem' in path for path in opened))


if __name__ == '__main__':
    unittest.main()
