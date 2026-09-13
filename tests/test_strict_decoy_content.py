from __future__ import annotations
import copy
import http.server
import json
import threading
import time
import unittest
from unittest import mock
from lucx_post_configurator import decoy_health as health
from lucx_post_configurator.models import default_manifest
from lucx_post_configurator.runner import CommandResult, Runner
from lucx_post_configurator import decoy_content as content
from lucx_post_configurator.runner import OutputLimitExceeded


class ContentAcceptanceTests(unittest.TestCase):
    def start_fixture(self, body, content_type='text/html', status=200, resources=None, head_body=False):
        requests = []
        resources = resources or {}
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_HEAD(self): self.respond(False)
            def do_GET(self): self.respond(True)
            def respond(self, include_body):
                requests.append((self.command, self.path, self.headers.get('Host')))
                code, mime, data = (status, content_type, body) if self.path == '/' else resources.get(self.path, (404,'text/plain',b'absent'))
                self.send_response(code)
                self.send_header('Content-Type',mime)
                self.send_header('Content-Length',str(len(data)))
                self.send_header('X-LucX-Decoy','site.example.test')
                self.end_headers()
                if head_body and not include_body:
                    self.wfile.flush()
                    time.sleep(0.03)
                if include_body or head_body:
                    try: self.wfile.write(data)
                    except (BrokenPipeError, ConnectionResetError): pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        return server.server_address[1], requests

    def probe(self, port, method='GET'):
        return health.observe_decoy('site.example.test','127.0.0.1',port,
            'X-LucX-Decoy: site.example.test',use_tls=False, method=method, strict_content=True)

    def test_real_get_requires_document_and_head_requires_html_headers(self):
        body = b'<!doctype html><html><head></head><body>hello</body></html>'
        port, requests = self.start_fixture(body)
        get = self.probe(port)
        head = self.probe(port,'HEAD')
        self.assertEqual(get['state'],'healthy',get)
        self.assertEqual(head['state'],'healthy',head)
        self.assertTrue(get['content_verified'])
        self.assertTrue(get['resources_complete'])
        self.assertEqual(get['resource_count'],0)
        self.assertTrue(head['content_verified'])
        self.assertEqual([row[0] for row in requests],['GET','HEAD'])
        self.assertTrue(all(row[2] == 'site.example.test:'+str(port) for row in requests))
        self.assertNotIn('hello',json.dumps(get))

    def test_real_empty_json_and_redirect_responses_fail_strict(self):
        for body,mime,status in ((b'','text/html',200),(b'{}','application/json',200),
                                 (b'<html></html>','text/html',302),(b'not a document','text/html',200)):
            with self.subTest(mime=mime,status=status,body_bytes=len(body)):
                port,_=self.start_fixture(body,mime,status)
                self.assertNotEqual(self.probe(port)['state'],'healthy')
        port,_=self.start_fixture(b'{}','application/json')
        self.assertNotEqual(self.probe(port,'HEAD')['state'],'healthy')

    def test_real_head_with_delayed_body_rejected(self):
        port,_=self.start_fixture(b'<html>invalid HEAD body</html>',head_body=True)
        self.assertNotEqual(self.probe(port,'HEAD')['state'],'healthy')

    def test_same_origin_resources_are_checked_deduplicated_and_sanitized(self):
        body=b'<html><head><link rel="stylesheet" href="/style.css?token=synthetic"><link rel="stylesheet" href="/style.css?token=synthetic"></head><body><script src="/app.js"></script><img src="/logo.png"></body></html>'
        resources={'/style.css?token=synthetic':(200,'text/css',b'body{}'),
                   '/app.js':(200,'application/javascript',b'void 0'),
                   '/logo.png':(200,'image/png',b'png-content')}
        port,requests=self.start_fixture(body,resources=resources)
        result=self.probe(port)
        self.assertEqual(result['state'],'healthy',result)
        self.assertEqual(result['resource_count'],3)
        self.assertTrue(result['resources_complete'])
        self.assertEqual(sum(row[1].startswith('/style.css') for row in requests),1)
        self.assertNotIn('synthetic',json.dumps(result))

    def test_missing_or_wrong_resource_blocks_acceptance(self):
        for resources in ({},{'/style.css':(200,'text/html',b'<html>error</html>')}):
            port,_=self.start_fixture(b'<html><link rel="stylesheet" href="/style.css"></html>',resources=resources)
            result=self.probe(port)
            self.assertNotEqual(result['state'],'healthy')
            self.assertFalse(result['resources_complete'])

    def test_external_and_excessive_resources_are_not_fetched_or_accepted(self):
        port,requests=self.start_fixture(b'<html><script src="https://other.example.test/private?x=synthetic"></script></html>')
        result=self.probe(port)
        self.assertFalse(result['resources_complete'])
        self.assertEqual(len(requests),1)
        self.assertNotIn('other.example.test',json.dumps(result))
        body=('<html>'+''.join('<img src="/'+str(n)+'.png">' for n in range(40))+'</html>').encode()
        port,requests=self.start_fixture(body)
        result=self.probe(port)
        self.assertFalse(result['resources_complete'])
        self.assertLessEqual(len(requests),17)

    def test_oversized_document_is_not_accepted(self):
        port,_=self.start_fixture(b'<html>'+b'x'*300000+b'</html>')
        self.assertNotEqual(self.probe(port)['state'],'healthy')

    def test_distinct_public_ports_have_distinct_complete_receipt_matrices(self):
        manifest=default_manifest()
        manifest['decoys'].update(enabled=True,require_full_acceptance=True,routing_mode='extended',
            sites=[{'domain':'site.example.test'}],extended_routes=[])
        manifest['protocols']=[{'inbound_id':7,'protocol':'vless','security':'tls','network':'tcp','exposure':'tcp_sni',
            'transport':'ws','transport_path':'/vpn','public_port':443,'internal_port':10001,
            'domain':'site.example.test','sni_names':['site.example.test'],
            'public_endpoints':[{'address':'site.example.test','port':443,'sni':'site.example.test'},
                                {'address':'site.example.test','port':8443,'sni':'site.example.test'}]}]
        targets=health.decoy_probe_targets(manifest,'192.0.2.1')
        self.assertEqual({r['port'] for r in targets if r['path']=='public_tls'},{443,8443})
        good={'state':'healthy','status':200,'detail':'ok','content_verified':True,'body_absence_verified':True,'resources_complete':True,'resource_count':0,'verified_resources':0}
        with mock.patch.object(health,'observe_decoy',return_value=good):
            rows=health.observe_decoy_capabilities(manifest,'192.0.2.1')
        self.assertTrue(health.decoy_acceptance_summary(manifest,rows)['complete'])
        self.assertEqual(len([r for r in rows if r['path']=='public_tls']),8)
        missing=[r for r in rows if not (r['path']=='public_tls' and r['port']==8443)]
        self.assertFalse(health.decoy_acceptance_summary(manifest,missing)['complete'])
        replaced=copy.deepcopy(rows)
        for row in replaced:
            if row['path']=='public_tls': row['port']=443
        self.assertFalse(health.decoy_acceptance_summary(manifest,replaced)['complete'])

    def test_strict_h2_reads_html_with_bounded_runner_on_debian_curl(self):
        runner=mock.Mock(spec=Runner)
        runner.dry_run=False
        runner.available.return_value=True
        body='<html><body>test</body></html>'
        runner.run_bounded.side_effect=[CommandResult([],0,'curl 7.88.1\nFeatures: SSL HTTP2\n',''),
            CommandResult([],0,'HTTP/2 200\nContent-Type: text/html\nX-LucX-Decoy: site.example.test\n\n'+body+'\nLUCX_HTTP_VERSION:2','')]
        result=health.observe_decoy('site.example.test','192.0.2.1',443,'X-LucX-Decoy: site.example.test',
            strict_content=True,http_version='h2',runner=runner)
        self.assertEqual(result['state'],'healthy',result)
        config=runner.run_bounded.call_args.kwargs['input_text']
        self.assertIn('max-filesize',config)
        self.assertNotIn('devnull',config)

    def test_resource_time_budget_does_not_fetch_or_claim_completion(self):
        body=b'<html><script src="/app.js"></script></html>'
        raw=b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'+body
        fetch=mock.Mock()
        with mock.patch.object(content.time,'monotonic',side_effect=[0,2]):
            result=content.verify_site(raw,'GET','https://site.example.test/',fetch,1)
        self.assertFalse(result['resources_complete'])
        fetch.assert_not_called()

    def test_unconfirmed_content_or_resources_cannot_complete_summary(self):
        manifest=default_manifest()
        manifest['decoys'].update(enabled=True,require_full_acceptance=True,sites=[{'domain':'site.example.test'}])
        good={'state':'healthy','status':200,'detail':'ok','content_verified':True,
              'resources_complete':True,'resource_count':0,'verified_resources':0}
        with mock.patch.object(health,'observe_decoy',return_value=good):
            rows=health.observe_decoy_capabilities(manifest,'192.0.2.1')
        for field in ('content_verified','resources_complete','verified_resources'):
            incomplete=copy.deepcopy(rows)
            for row in incomplete:
                if row['method']=='GET': row.pop(field)
            self.assertFalse(health.decoy_acceptance_summary(manifest,incomplete)['complete'])

    def test_h2_output_limit_failure_does_not_leak_output(self):
        runner=mock.Mock(spec=Runner)
        runner.dry_run=False
        runner.available.return_value=True
        runner.run_bounded.side_effect=OutputLimitExceeded('sensitive-sentinel one.example.test')
        result=health.observe_decoy('site.example.test','192.0.2.1',443,'X-LucX-Decoy: site.example.test',
                                   strict_content=True,http_version='h2',runner=runner)
        self.assertNotEqual(result['state'],'healthy')
        self.assertNotIn('sensitive-sentinel',json.dumps(result))

    def test_backslash_resource_url_is_not_treated_as_safe_relative_resource(self):
        body=b'<html><script src="\\\\other.example.test/app.js"></script></html>'
        raw=b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'+body
        fetch=mock.Mock(return_value=b'HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nvoid 0')
        result=content.verify_site(raw,'GET','https://site.example.test/',fetch,1)
        self.assertFalse(result['resources_complete'])
        fetch.assert_not_called()


if __name__=='__main__': unittest.main()
