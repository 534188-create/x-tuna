import sys
import unittest
from unittest import mock
from lucx_post_configurator import decoy_health as health, decoy_content as content
from lucx_post_configurator.runner import Runner, CommandResult


class ReviewTests(unittest.TestCase):
    def test_head_nonempty_body_rejected(self):
        raw = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nillegal'
        self.assertNotEqual(content.verify_site(raw, 'HEAD', 'https://example.test/', mock.Mock(), 1)['state'], 'healthy')

    def test_late_head_body_read_before_acceptance(self):
        stream = mock.MagicMock()
        stream.recv.side_effect = [b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n', b'illegal', b'']
        stream.__enter__.return_value = stream
        with mock.patch.object(health.socket, 'create_connection', return_value=stream):
            raw = health._strict_h1_response('example.test', '127.0.0.1', 80, '/', 'HEAD', 1, False, True)
        self.assertTrue(raw.endswith(b'illegal'))

    def test_bounded_latin1_roundtrip(self):
        body = b'\x89PNG\r\n\x00\xff\n'
        result = Runner().run_bounded([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(bytes([137,80,78,71,13,10,0,255,10]))'], max_output_bytes=100, output_encoding='latin-1')
        self.assertEqual(result.stdout.encode('latin-1'), body)

    def test_h2_binary_body_preserved(self):
        body = b'\x89PNG\r\n\x00\xff\n'
        runner = mock.Mock(spec=Runner, dry_run=False)
        runner.available.return_value = True
        runner.run_bounded.side_effect = [CommandResult([], 0, 'Features: HTTP2\n', ''), CommandResult([], 0, 'HTTP/2 200\r\nContent-Type: image/png\r\n\r\n'+body.decode('latin-1')+'\nLUCX_HTTP_VERSION:2', '')]
        row = health._observe_h2('example.test', '192.0.2.1', 443, None, 1, True, 'GET', True, runner, capture_body=True)
        self.assertEqual(row['response'].partition(b'\r\n\r\n')[2], body)
        self.assertEqual(runner.run_bounded.call_args.kwargs['output_encoding'], 'latin-1')

    def test_h2_html_png_resource_keeps_every_byte(self):
        body = b'\x89PNG\r\n\x00\xff\n'
        runner = mock.Mock(spec=Runner, dry_run=False)
        runner.available.return_value = True
        version = CommandResult([], 0, 'Features: HTTP2\n', '')
        runner.run_bounded.side_effect = [version, CommandResult([], 0,
            'HTTP/2 200\r\nContent-Type: text/html\r\nX-LucX-Decoy: example.test\r\n\r\n<html><img src="/logo.png"></html>\nLUCX_HTTP_VERSION:2', ''),
            version, CommandResult([], 0, 'HTTP/2 200\r\nContent-Type: image/png\r\n\r\n'+body.decode('latin-1')+'\nLUCX_HTTP_VERSION:2', '')]
        with mock.patch.object(content, 'response_content', wraps=content.response_content) as parse:
            row = health.observe_decoy('example.test', '192.0.2.1', 443, 'X-LucX-Decoy: example.test', http_version='h2', strict_content=True, runner=runner)
        self.assertEqual(row['state'], 'healthy', row)
        self.assertEqual(row['verified_resources'], 1)
        self.assertEqual(parse.call_args_list[-1].args[0].partition(b'\r\n\r\n')[2], body)
        self.assertNotIn('/logo.png', str(row))

    def test_strict_h2_head_captures_body_without_curl_nobody_mode(self):
        runner = mock.Mock(spec=Runner, dry_run=False)
        runner.available.return_value = True
        runner.run_bounded.side_effect = [CommandResult([], 0, 'Features: HTTP2\n', ''), CommandResult([], 0, 'HTTP/2 200\r\nContent-Type: text/html\r\nX-LucX-Decoy: example.test\r\n\r\n\nLUCX_HTTP_VERSION:2', '')]
        row = health.observe_decoy('example.test', '192.0.2.1', 443, 'X-LucX-Decoy: example.test', method='HEAD', http_version='h2', strict_content=True, runner=runner)
        self.assertEqual(row['state'], 'healthy')
        self.assertTrue(row['body_absence_verified'])
        config = runner.run_bounded.call_args.kwargs['input_text'].splitlines()
        self.assertIn('request = "HEAD"', config)
        self.assertIn('ignore-content-length', config)
        self.assertIn('output = "-"', config)
        self.assertNotIn('head', config)

    def test_root_time_consumes_resource_budget(self):
        now = [0.0]
        def fetch(*args, **kwargs):
            now[0] = 2.0
            return b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-LucX-Decoy: example.test\r\n\r\n<html></html>'
        with mock.patch.object(health.time, 'monotonic', side_effect=lambda: now[0]), mock.patch.object(health, '_strict_h1_response', side_effect=fetch):
            row = health.observe_decoy('example.test', '127.0.0.1', 80, 'X-LucX-Decoy: example.test', timeout=1, use_tls=False, strict_content=True)
        self.assertNotEqual(row['state'], 'healthy')

    def test_h2_version_and_probe_share_budget(self):
        now = [0.0]
        runner = mock.Mock(spec=Runner, dry_run=False)
        runner.available.return_value = True
        def execute(*args, **kwargs):
            now[0] = 2.0
            return CommandResult([], 0, 'Features: HTTP2\n', '')
        runner.run_bounded.side_effect = execute
        with mock.patch.object(health.time, 'monotonic', side_effect=lambda: now[0]):
            row = health._observe_h2('example.test', '192.0.2.1', 443, None, 1, True, 'GET', True, runner, capture_body=True)
        self.assertNotEqual(row.get('state'), 'healthy')
        self.assertEqual(runner.run_bounded.call_count, 1)

    def test_audit_forwarded(self):
        audit = object()
        with mock.patch.object(health, 'classify_decoy_capabilities', return_value=[]) as classify:
            health._capabilities({}, audit=audit)
        classify.assert_called_once_with({}, audit=audit)

    def test_all_public_acceptance_apis_forward_fresh_audit(self):
        audit = object()
        manifest = {'network':{'public_tcp_port':443}, 'decoys':{'enabled':True,'require_full_acceptance':True}}
        with mock.patch.object(health, 'classify_decoy_capabilities', return_value=[]) as classify:
            health.decoy_probe_targets(manifest, '192.0.2.1', audit=audit)
            health.observe_decoy_capabilities(manifest, '192.0.2.1', audit=audit)
            health.decoy_acceptance_summary(manifest, [], audit=audit)
            health.validate_decoy_observations(manifest, [], audit=audit)
        self.assertGreaterEqual(classify.call_count, 4)
        self.assertTrue(all(call.kwargs.get('audit') is audit for call in classify.call_args_list))
        self.assertTrue(all(set(call.kwargs) <= {'audit', 'for_staging'} for call in classify.call_args_list))

    def test_head_receipt_requires_body_absence_evidence(self):
        row = {'method':'HEAD', 'content_verified':True}
        self.assertFalse(health._content_receipt_verified(row))
        row['body_absence_verified'] = True
        self.assertTrue(health._content_receipt_verified(row))

    def test_targets_use_shared_ingress_provider(self):
        manifest={'network':{'public_tcp_port':443}, 'decoys':{'require_full_acceptance':True}, 'protocols':[{}]}
        with mock.patch.object(health,'_capabilities',return_value=[{'domain':'example.test','managed':True,'probe_mode':'http'}]), mock.patch.object(health,'public_ingresses',return_value=[(9443,'example.test','site')]) as ingress:
            targets=health.decoy_probe_targets(manifest,'192.0.2.1')
        self.assertEqual({t['port'] for t in targets},{443,9443})
        ingress.assert_called_once_with({},443)
