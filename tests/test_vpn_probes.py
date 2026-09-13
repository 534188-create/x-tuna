from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from lucx_post_configurator.routing_profiles import routing_fingerprint
from lucx_post_configurator.runner import CommandResult, Runner


def profile():
    return {"inbound_id": 7, "protocol": "vless", "transport": "ws", "network": "tcp",
            "security": "tls", "exposure": "tcp_sni", "transport_path": "/vpn",
            "transport_mode": "", "alpn": ["http/1.1"], "transport_details": {},
            "public_endpoints": [{"host_id": 1, "address": "vpn.example.test", "port": 443,
                "sni": "vpn.example.test", "http_host": "", "sni_source": "address",
                "keep_sni_blank": False, "valid": True}]}


def with_acceptance(value, phase="public", shared_port=443):
    value = copy.deepcopy(value)
    endpoint = value["public_endpoints"][0]
    identity = {key: endpoint.get(key) for key in (
        "host_id", "address", "port", "sni", "sni_source", "keep_sni_blank", "http_host")}
    value["acceptance_target"] = {"inbound_id": value["inbound_id"],
        "profile_fingerprint": routing_fingerprint(value, shared_port),
        "endpoint_fingerprint": "sha256:" + hashlib.sha256(json.dumps(identity,
            sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()}
    value["acceptance_endpoint"] = copy.deepcopy(endpoint)
    value["acceptance_phase"] = phase
    return value


class VPNProbeTests(unittest.TestCase):
    def test_own_echo_checks_terminal_state_after_listener_closes(self):
        from types import SimpleNamespace

        from lucx_post_configurator import vpn_probe_backend, vpn_probe_echo
        for failed, count in ((True, 2), (False, 1), (False, 3), (False, 2)):
            events = []
            class Echo:
                endpoint = ('192.0.2.10', 24444)
                verification_failed = False
                verified_connections = 2
                def __init__(self, **kwargs):
                    pass
                def __enter__(self):
                    return self
                def __exit__(inner, *args, failed=failed, count=count, events=events):
                    inner.verification_failed, inner.verified_connections = failed, count
                    events.append('echo closed')
            witness = mock.MagicMock()
            witness.__enter__.return_value = witness
            def verify(events=events):
                self.assertEqual(events, ['echo closed'])
                raise ValueError('late actor drift')
            witness.verify.side_effect = verify
            resource = SimpleNamespace(setrlimit=lambda *_: None, RLIMIT_CORE=0,
                RLIMIT_NOFILE=1, RLIMIT_AS=2, RLIMIT_DATA=3, RLIMIT_CPU=4)
            with (self.subTest(failed=failed, count=count),
                  mock.patch.dict('sys.modules', {'resource': resource}),
                  mock.patch.object(vpn_probe_echo, 'LocalProbeEcho', Echo),
                  mock.patch.object(vpn_probe_backend, 'XrayEchoWitness', return_value=witness),
                  mock.patch.object(self.module, '_worker_exchange', return_value={'authenticated': True})):
                with self.assertRaises(ValueError):
                    self.module._worker({'echo_address': '192.0.2.10', 'echo_port': 0,
                                         'echo_backend': ['127.0.0.1', 18443]})
            self.assertEqual(witness.verify.call_count, int(not failed and count == 2))

    def test_source_and_dial_drift_after_worker_reject_public_receipt(self):
        from dataclasses import replace
        original = self.provider(self.value)
        for field, changed in (('user_id', str(uuid.uuid4())), ('ca_pem', 'changed CA'),
                               ('policy_fingerprint', 'sha256:' + 'b' * 64)):
            with self.subTest(field=field):
                self.provider = lambda _, value=original: value
                runner = Runner()
                def completed(*args, field=field, changed=changed, **kwargs):
                    self.provider = lambda _: replace(original, **{field: changed})
                    return CommandResult([], 0, json.dumps({'authenticated': True,
                        'bytes_sent': 16384, 'bytes_received': 16384}), '')
                with mock.patch.object(runner, 'run_bounded', side_effect=completed):
                    result = self.observer(with_acceptance(self.value), runner)
                self.assertEqual(result['state'], 'failed')
                self.assertFalse(result['functional'])
                self.assertFalse(result['authenticated'])

    def test_staging_dial_changed_after_worker_rejects_receipt(self):
        from dataclasses import replace
        dial = mock.Mock(side_effect=[('127.0.0.1', 24443), ('127.0.0.1', 24444)])
        observer = self.module.XrayVPNObserver(replace(self.context, dial_target_provider=dial))
        runner = Runner()
        with mock.patch.object(runner, 'run_bounded', return_value=CommandResult([], 0,
                json.dumps({'authenticated': True, 'bytes_sent': 16384, 'bytes_received': 16384}), '')):
            result = observer(with_acceptance(self.value, 'staging'), runner)
        self.assertEqual(result['state'], 'failed')
        self.assertFalse(result['authenticated'])

    def test_own_echo_request_binds_validated_backend_and_rejects_address_drift(self):
        from dataclasses import replace
        self.value.update(internal_host='127.0.0.1', internal_port=18443)
        self.snapshot = routing_fingerprint(self.value, 443)
        current = ['192.0.2.10']
        context = replace(self.context, echo_port=0, echo_address_provider=lambda: current[0])
        observer = self.module.XrayVPNObserver(context)
        runner = Runner()
        def completed(*args, **kwargs):
            request = json.loads(kwargs['input_text'])
            self.assertEqual(request['echo_address'], '192.0.2.10')
            self.assertEqual(request['echo_backend'], ['127.0.0.1', 18443])
            current[0] = '192.0.2.11'
            return CommandResult([], 0, json.dumps({'authenticated': True,
                'bytes_sent': 16384, 'bytes_received': 16384}), '')
        with mock.patch.object(runner, 'run_bounded', side_effect=completed) as run:
            result = observer(with_acceptance(self.value), runner)
        run.assert_called_once()
        self.assertEqual(result['state'], 'failed')

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("lucx_post_configurator.vpn_probes"),
                             "Штатный VPN adapter должен существовать")
        from lucx_post_configurator import vpn_probes
        self.module = vpn_probes
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.binary = Path(self.temp.name) / "xray"
        self.binary.write_bytes(b"synthetic-client-image")
        self.binary.chmod(0o700)
        self.credential = str(uuid.uuid4())
        self.value = profile()
        self.snapshot = routing_fingerprint(self.value, 443)
        self.provider = lambda value: vpn_probes.XrayProbeCredential(
            self.credential, self.snapshot)
        self.context = vpn_probes.XrayProbeContext(binary_path=self.binary,
            binary_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            credential_provider=lambda value: self.provider(value),
            echo_address="127.0.0.1", echo_port=19600)
        self.observer = vpn_probes.XrayVPNObserver(self.context)
        self.platform = mock.patch.object(vpn_probes.sys, "platform", "linux")
        self.platform.start()
        self.addCleanup(self.platform.stop)

    def test_supported_profile_requires_current_credential_and_binary(self):
        self.assertTrue(self.observer.supports(self.value))
        self.binary.write_bytes(b"changed-image")
        self.assertFalse(self.observer.supports(self.value))

    def test_binary_read_access_time_change_is_not_content_drift(self):
        real_stat = os.fstat
        calls = 0
        def stat_with_access_time(fd):
            nonlocal calls
            calls += 1
            value = list(real_stat(fd))
            value[7] += calls
            return os.stat_result(value)
        with mock.patch.object(self.module.os, "fstat", side_effect=stat_with_access_time):
            self.assertTrue(self.observer.supports(self.value))

    def test_unsupported_transport_security_mode_and_details_are_closed(self):
        for change in ({"protocol": "trojan"}, {"transport": "raw"}, {"security": "reality"},
                       {"transport_mode": "future"}, {"flow": "xtls-rprx-vision"},
                       {"alpn": ["h3"]}, {"transport_path": "/vpn?ed=2048"},
                       {"transport_details": {"download": {"present": True}}},
                       {"transport_details": {"extra": {"present": True}}},
                       {"transport_details": {"masks": {"present": True}}},
                       {"transport_details": {"unknown_stream_fields": ["wrapper"]}},
                       {"transport_details": {"inbound_settings_fingerprint": "unverified"}},
                       {"transport_details": {"future_flag": True}}):
            value = {**self.value, **change}
            self.snapshot = routing_fingerprint(value, 443)
            with self.subTest(change=change):
                self.assertFalse(self.observer.supports(value))

    def test_stale_credential_fingerprint_and_missing_provider_are_closed(self):
        self.value["transport_path"] = "/changed"
        self.assertFalse(self.observer.supports(self.value))
        self.provider = lambda value: None
        self.assertFalse(self.observer.supports(profile()))

    def test_empty_or_ambiguous_sni_are_unsupported(self):
        for change in ({"sni": ""}, {"keep_sni_blank": True}, {"sni_source": "ambiguous"}):
            value = profile()
            value["public_endpoints"][0].update(change)
            self.snapshot = routing_fingerprint(value, 443)
            self.assertFalse(self.observer.supports(value))

    def test_transport_host_cannot_be_silently_replaced_by_sni(self):
        for hosts in (["different.example.test"], "vpn.example.test", ["invalid value"]):
            value = {**profile(), "transport_hosts": hosts}
            self.snapshot = routing_fingerprint(value, 443)
            self.assertFalse(self.observer.supports(value))

    def test_malformed_phase_is_safely_not_tested(self):
        value = with_acceptance(self.value)
        value["acceptance_phase"] = []
        try:
            result = self.observer(value, Runner())
        except TypeError:
            self.fail("Некорректная фаза не должна вызывать необработанное исключение")
        self.assertEqual(result["state"], "not_tested")

    def test_dry_run_does_not_launch_or_read_secrets(self):
        self.provider = mock.Mock(side_effect=AssertionError("Не читать секреты"))
        runner = Runner(dry_run=True)
        result = self.observer(with_acceptance(self.value), runner)
        self.assertEqual(result["state"], "not_tested")
        self.assertEqual(runner.history, [])
        self.provider.assert_not_called()

    def test_identity_endpoint_and_phase_are_checked_before_execution(self):
        for change in ("profile", "endpoint", "membership", "phase", "inbound"):
            value = with_acceptance(self.value)
            if change == "profile": value["acceptance_target"]["profile_fingerprint"] = "sha256:" + "0" * 64
            if change == "endpoint": value["acceptance_target"]["endpoint_fingerprint"] = "sha256:" + "0" * 64
            if change == "membership": value["acceptance_endpoint"]["port"] = 444
            if change == "phase": value["acceptance_phase"] = "unknown"
            if change == "inbound": value["acceptance_target"]["inbound_id"] = 8
            runner = Runner()
            with mock.patch.object(runner, "run_bounded") as run:
                self.assertNotEqual(self.observer(value, runner)["state"], "healthy")
                run.assert_not_called()

    def test_allowlisted_receipt_secrets_only_in_stdin(self):
        runner = Runner()
        response = {"authenticated": True, "bytes_sent": 8192, "bytes_received": 8192,
                    "secret": self.credential}
        with mock.patch.object(runner, "run_bounded", return_value=CommandResult([], 0, json.dumps(response), "")) as run:
            result = self.observer(with_acceptance(self.value), runner)
        self.assertEqual(result["state"], "healthy")
        self.assertEqual(result["phase"], "public")
        self.assertTrue(result["public"])
        self.assertNotIn(self.credential, json.dumps(result))
        self.assertNotIn(self.credential, repr(self.context))
        self.assertNotIn(self.credential, repr(self.provider(self.value)))
        self.assertNotIn(self.credential, repr(run.call_args.args))
        self.assertIn(self.credential, run.call_args.kwargs["input_text"])
        self.assertTrue(run.call_args.kwargs["isolate_process_group"])
        self.assertFalse(run.call_args.kwargs["inherit_env"])

    def test_code_owned_ephemeral_echo_is_supported_without_starting_a_listener(self):
        from dataclasses import replace
        self.observer = self.module.XrayVPNObserver(replace(self.context, echo_port=0))
        with mock.patch('socket.socket', side_effect=AssertionError('preflight opened a socket')):
            self.assertTrue(self.observer.preflight(with_acceptance(self.value), Runner()))
        self.observer = self.module.XrayVPNObserver(replace(self.context, echo_port=0,
                                                           echo_address='192.0.2.1'))
        self.assertFalse(self.observer.supports(self.value))

    def test_direct_and_staging_require_explicit_code_owned_dial_target(self):
        for phase in ('direct', 'staging'):
            runner = Runner()
            with mock.patch.object(runner, 'run_bounded') as run:
                value = with_acceptance(self.value, phase)
                self.assertFalse(self.observer.preflight(value, runner))
                self.assertNotEqual(self.observer(value, runner)['state'], 'healthy')
                run.assert_not_called()

    def test_worker_failure_false_auth_and_zero_exchange_cannot_pass(self):
        for response in ({}, {"authenticated": False, "bytes_sent": 8192, "bytes_received": 8192},
                         {"authenticated": True, "bytes_sent": 0, "bytes_received": 8192},
                         {"authenticated": True, "bytes_sent": True, "bytes_received": 8192}):
            runner = Runner()
            with mock.patch.object(runner, "run_bounded", return_value=CommandResult([], 0, json.dumps(response), "")):
                self.assertEqual(self.observer(with_acceptance(self.value), runner)["state"], "failed")

    def test_exception_does_not_disclose_source_data(self):
        self.provider = mock.Mock(side_effect=RuntimeError(self.credential))
        result = self.observer(with_acceptance(self.value), Runner())
        self.assertNotEqual(result["state"], "healthy")
        self.assertNotIn(self.credential, json.dumps(result))

    def test_worker_cannot_be_replaced_by_pythonpath_or_working_directory(self):
        package = Path(self.temp.name) / 'lucx_post_configurator'
        package.mkdir()
        (package / '__init__.py').write_text('', encoding='utf-8')
        marker = Path(self.temp.name) / 'forged-worker-executed'
        (package / 'vpn_probes.py').write_text(
            'import json,pathlib,sys\njson.load(sys.stdin)\n'
            'pathlib.Path(__file__).parent.parent.joinpath("forged-worker-executed").touch()\n'
            'print(json.dumps({"authenticated":True,"bytes_sent":16384,"bytes_received":16384}))\n',
            encoding='utf-8')

        class PortableRunner(Runner):
            def run_bounded(self, *args, **kwargs):
                if os.name != 'posix':
                    kwargs['isolate_process_group'] = False
                return super().run_bounded(*args, **kwargs)

        previous = Path.cwd()
        try:
            os.chdir(self.temp.name)
            with mock.patch.dict(os.environ, {'PYTHONPATH': self.temp.name}):
                result = self.observer(with_acceptance(self.value), PortableRunner())
            self.assertFalse(marker.exists(), 'Нельзя импортировать подменный worker')
            self.assertNotEqual(result['state'], 'healthy')
        finally:
            os.chdir(previous)

    def test_preflight_checks_exact_endpoint_without_processes(self):
        self.assertTrue(callable(getattr(self.observer, "preflight", None)))
        runner = Runner()
        with mock.patch.object(runner, "run_bounded") as run:
            self.assertTrue(self.observer.preflight(with_acceptance(self.value), runner))
            bad = with_acceptance(self.value)
            bad["acceptance_endpoint"]["port"] += 1
            self.assertFalse(self.observer.preflight(bad, runner))
            run.assert_not_called()

    def test_failed_client_start_is_not_an_authentication_negative_control(self):
        request = {"binary": str(self.binary), "sha256": self.context.binary_sha256,
                   "timeout": 5, "user_id": self.credential}
        with mock.patch.dict("sys.modules", {"resource": mock.Mock()}), mock.patch.object(
                self.module, "_attempt", side_effect=[OSError("client_start_failed"), None]), self.assertRaises(OSError):
            self.module._worker(request)

    def test_only_code_owned_direct_staging_override_changes_dial_target(self):
        self.context = self.module.XrayProbeContext(binary_path=self.binary,
            binary_sha256=self.context.binary_sha256, credential_provider=self.provider,
            echo_address="127.0.0.1", echo_port=19600,
            dial_target_provider=lambda protocol, phase: ("127.0.0.1", 19443))
        self.observer = self.module.XrayVPNObserver(self.context)
        for phase in ("direct", "staging", "public", "rollback"):
            value = with_acceptance(self.value, phase)
            value["connect_override"] = {"address": "192.0.2.1", "port": 1}
            runner = Runner()
            with mock.patch.object(runner, "run_bounded", return_value=CommandResult([], 0,
                    '{"authenticated":true,"bytes_sent":16384,"bytes_received":16384}', "")) as run:
                result = self.observer(value, runner)
            self.assertEqual(result["state"], "healthy")
            self.assertEqual(result["public"], phase in {"public", "rollback"})
            sent = json.loads(run.call_args.kwargs["input_text"])
            self.assertEqual(sent["address"], "127.0.0.1" if phase in {"direct", "staging"} else "vpn.example.test")
            self.assertEqual(result["endpoint_fingerprint"], value["acceptance_target"]["endpoint_fingerprint"])


@unittest.skipUnless(os.name == "posix" and os.environ.get("XTUNA_TEST_XRAY"),
                     "Настоящий Xray проверяется в изолированной Linux-среде")
class RealXrayProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import socketserver
        import subprocess
        import threading

        from lucx_post_configurator import vpn_probes
        cls.module = vpn_probes
        cls.temp = tempfile.TemporaryDirectory(prefix="vpn-probe-test-")
        cls.root = Path(cls.temp.name)
        cls.binary = Path(os.environ["XTUNA_TEST_XRAY"])
        if hashlib.sha256(cls.binary.read_bytes()).hexdigest() != vpn_probes.XRAY_SHA256:
            raise AssertionError("Linux-стенд использует незакреплённый Xray")
        cls.cert, cls.key = cls.root / "cert.pem", cls.root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=vpn.example.test", "-addext", "subjectAltName=DNS:vpn.example.test",
            "-keyout", str(cls.key), "-out", str(cls.cert)], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.key.chmod(0o600)

        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(10)
                try:
                    while data := self.request.recv(16384):
                        self.request.sendall(data)
                except OSError:
                    pass

        cls.echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        cls.echo.daemon_threads = True
        cls.thread = threading.Thread(target=cls.echo.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.echo.shutdown()
        cls.echo.server_close()
        cls.thread.join(2)
        cls.temp.cleanup()

    def run_real(self, kind, transport, mode="", path=None, wrong_credential=False, ephemeral_echo=False,
                 own_echo=False, deny_private=False, backend_host='127.0.0.1'):
        import socket
        import subprocess
        import time
        value = profile()
        value.update(protocol=kind, transport=transport, transport_mode=mode,
            transport_path=path or ("probe" if transport == "grpc" else "/vpn"),
            alpn=["http/1.1"] if transport in {"ws", "httpupgrade"} else ["h2"])
        with socket.socket(socket.AF_INET6 if ':' in backend_host else socket.AF_INET) as reservation:
            reservation.bind((backend_host, 0))
            port = reservation.getsockname()[1]
        value["public_endpoints"][0].update(address=backend_host, port=port)
        value.update(internal_host=backend_host, internal_port=port)
        credential = str(uuid.uuid4())
        stream = {"network": transport, "security": "tls", "tlsSettings": {
            "alpn": value["alpn"], "certificates": [{"certificateFile": str(self.cert), "keyFile": str(self.key)}]}}
        setting_key = {"ws": "wsSettings", "httpupgrade": "httpupgradeSettings",
                       "grpc": "grpcSettings", "xhttp": "xhttpSettings"}[transport]
        stream[setting_key] = {"serviceName" if transport == "grpc" else "path": value["transport_path"]}
        if transport == "xhttp": stream[setting_key]["mode"] = mode
        incoming = {"clients": [{"id": credential}]}
        if kind == "vless": incoming["decryption"] = "none"
        config = {"log": {"loglevel": "none"}, "inbounds": [{"listen": backend_host, "port": port,
            "protocol": kind, "settings": incoming, "streamSettings": stream}],
            "outbounds": [{"protocol": "freedom"}]}
        if deny_private:
            config['outbounds'].append({'tag': 'deny-private', 'protocol': 'blackhole'})
            config['routing'] = {'rules': [{'type': 'field',
                'ip': ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
                'outboundTag': 'deny-private'}]}
        fd = os.memfd_create("synthetic-xray-server", os.MFD_CLOEXEC)
        process = None
        try:
            os.write(fd, json.dumps(config).encode())
            os.lseek(fd, 0, os.SEEK_SET)
            process = subprocess.Popen([str(self.binary), "run", "-format", "json", "-config", f"/proc/self/fd/{fd}"],
                pass_fds=(fd,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None or time.monotonic() >= deadline:
                    self.fail("Синтетический Xray-сервер не запустился")
                try:
                    with socket.create_connection((backend_host, port), timeout=.1): break
                except OSError:
                    time.sleep(.02)
            supplied = str(uuid.uuid4()) if wrong_credential else credential
            source = self.module.XrayProbeCredential(supplied, routing_fingerprint(value, 443), self.cert.read_text())
            observer = self.module.XrayVPNObserver(self.module.XrayProbeContext(
                binary_path=self.binary, binary_sha256=self.module.XRAY_SHA256,
                credential_provider=lambda protocol: source,
                echo_address=os.environ['XTUNA_TEST_DOCUMENTATION_ECHO'] if own_echo else "127.0.0.1",
                echo_port=0 if ephemeral_echo else self.echo.server_address[1], timeout=8))
            runner = Runner()
            self.assertTrue(observer.preflight(with_acceptance(value), runner))
            result = observer(with_acceptance(value), runner)
            self.assertNotIn(credential, json.dumps(result) + repr(runner.history))
            self.assertEqual(result["state"], "failed" if wrong_credential else "healthy")
            if not wrong_credential:
                self.assertTrue(result["authenticated"])
                self.assertEqual(result["bytes_sent"], 16384)
                self.assertEqual(result["bytes_received"], 16384)
        finally:
            if process is not None:
                process.kill()
                process.wait(timeout=2)
            os.close(fd)

    def test_authenticated_echo_and_reconnect_for_all_advertised_profiles(self):
        for kind in ("vless", "vmess"):
            for transport in ("ws", "httpupgrade", "grpc", "xhttp"):
                for mode in (("auto", "packet-up", "stream-up", "stream-one") if transport == "xhttp" else ("",)):
                    with self.subTest(protocol=kind, transport=transport, mode=mode):
                        self.run_real(kind, transport, mode)
            for transport in ("ws", "httpupgrade"):
                with self.subTest(protocol=kind, transport=transport, path="/"):
                    self.run_real(kind, transport, path="/")

    def test_wrong_credential_is_failed_without_secret_receipt(self):
        self.run_real("vless", "ws", wrong_credential=True)

    def test_code_owned_echo_with_real_authenticated_tunnel(self):
        self.run_real('vless', 'ws', ephemeral_echo=True)

    def test_own_address_echo_preserves_backend_private_acl(self):
        if not os.environ.get('XTUNA_TEST_DOCUMENTATION_ECHO'):
            self.skipTest('Нужен RFC5737 адрес в изолированном Linux namespace')
        self.run_real('vless', 'ws', ephemeral_echo=True, own_echo=True, deny_private=True)

    def test_ipv6_backend_can_use_owned_ipv4_echo(self):
        if not os.environ.get('XTUNA_TEST_DOCUMENTATION_ECHO'):
            self.skipTest('Нужен RFC5737 адрес в изолированном Linux namespace')
        self.run_real('vless', 'ws', ephemeral_echo=True, own_echo=True, deny_private=True,
                      backend_host='::1')


if __name__ == "__main__":
    unittest.main()
