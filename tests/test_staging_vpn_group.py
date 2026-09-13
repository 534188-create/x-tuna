"""Владение вложенными процессами; synthetic client не доказывает работу VPN."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import test_vpn_probes as fixture

from lucx_post_configurator import vpn_probes
from lucx_post_configurator.runner import CommandResult, Runner


class StagingVPNGroupTests(unittest.TestCase):
    def setUp(self):
        self.helper = fixture.VPNProbeTests()
        self.helper.setUp()
        self.addCleanup(self.helper.doCleanups)

    def observer(self, owner=222):
        context = dataclasses.replace(self.helper.context, coordinator_pid=owner,
                                      dial_target_provider=lambda value, phase: ('127.0.0.1', 41001))
        return vpn_probes.XrayVPNObserver(context)

    def test_default_public_worker_keeps_its_own_session(self):
        runner = Runner()
        with mock.patch.object(runner, 'run_bounded', return_value=CommandResult([], 1, '', '')) as call:
            self.helper.observer(fixture.with_acceptance(self.helper.value), runner)
        self.assertTrue(call.call_args.kwargs['isolate_process_group'])

    def test_inherited_mode_requires_current_dedicated_coordinator_before_secret_read(self):
        for phase, owner, pid, group, session in (
                ('public', 222, 222, 222, 222), ('rollback', 222, 222, 222, 222),
                ('staging', True, 222, 222, 222), ('staging', '222', 222, 222, 222),
                ('staging', 222, 333, 222, 222), ('staging', 222, 222, 333, 222),
                ('staging', 222, 222, 222, 333)):
            with self.subTest(phase=phase, owner=owner, group=group, session=session):
                observer = self.observer(owner)
                protocol = fixture.with_acceptance(self.helper.value, phase)
                provider = mock.Mock(side_effect=AssertionError('Источник не должен читаться'))
                self.helper.provider = provider
                with mock.patch.object(os, 'getpid', return_value=pid), \
                        mock.patch.object(os, 'getpgrp', return_value=group, create=True), \
                        mock.patch.object(os, 'getsid', return_value=session, create=True):
                    self.assertFalse(observer.preflight(protocol, Runner()))
                    runner = Runner()
                    self.assertNotEqual(observer(protocol, runner)['state'], 'healthy')
                    self.assertEqual(runner.history, [])
                provider.assert_not_called()

    def test_code_owned_direct_and_staging_keep_group_and_clean_environment(self):
        with mock.patch.object(os, 'getpid', return_value=222), \
                mock.patch.object(os, 'getpgrp', return_value=222, create=True), \
                mock.patch.object(os, 'getsid', return_value=222, create=True):
            for phase in ('direct', 'staging'):
                runner = Runner()
                with mock.patch.object(runner, 'run_bounded', return_value=CommandResult([], 1, '', '')) as call:
                    self.observer()(fixture.with_acceptance(self.helper.value, phase), runner)
                self.assertFalse(call.call_args.kwargs['isolate_process_group'])
                self.assertFalse(call.call_args.kwargs['inherit_env'])
                self.assertIn('-I', call.call_args.args[0])
                self.assertIn('-S', call.call_args.args[0])


@unittest.skipUnless(sys.platform == 'linux', 'Нужны реальные Linux session/group и subreaper')
class RealNestedGroupTests(unittest.TestCase):
    def test_outer_timeout_removes_nested_worker_client_and_grandchild_listener(self):
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        self.addCleanup(lambda: libc.prctl(36, previous.value, 0, 0, 0))
        with tempfile.TemporaryDirectory() as temporary, socket.socket() as foreign:
            root = Path(temporary)
            client_record, child_record = root / 'client.json', root / 'child.json'
            grandchild = ('import json,os,socket,time,pathlib; s=socket.socket();'
                's.bind(("127.0.0.1",0));s.listen();'
                f'pathlib.Path({str(child_record)!r}).write_text(json.dumps('
                '{"pid":os.getpid(),"group":os.getpgrp(),"session":os.getsid(0),"port":s.getsockname()[1]}));'
                'time.sleep(30)')
            image = ('#!/usr/bin/python3\nimport json,os,pathlib,socket,subprocess,sys,time\n'
                f'child=subprocess.Popen([sys.executable,"-I","-S","-c",{grandchild!r}])\n'
                's=socket.socket();s.bind(("127.0.0.1",0));s.listen()\n'
                f'pathlib.Path({str(client_record)!r}).write_text(json.dumps('
                '{"pid":os.getpid(),"parent":os.getppid(),"group":os.getpgrp(),'
                '"session":os.getsid(0),"port":s.getsockname()[1]}))\ntime.sleep(30)\n')
            binary = root / 'synthetic-client'
            binary.write_text(image, encoding='utf-8')
            binary.chmod(0o700)
            foreign.bind(('127.0.0.1', 0))
            foreign.listen()
            request = {'binary': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
            package_root = str(Path(vpn_probes.__file__).parent.parent)
            test_file = str(Path(__file__).absolute())
            bootstrap = ('import sys,runpy;sys.path[:0]=sys.argv[1:3];'
                         'target=sys.argv[3];sys.argv=[target,"--coordinator"];runpy.run_path(target,run_name="__main__")')
            try:
                try:
                    completed = Runner().run_bounded([sys.executable, '-I', '-S', '-c', bootstrap,
                        package_root, str(Path(__file__).parent), test_file], input_text=json.dumps(request),
                        timeout=1.5, max_output_bytes=2048, isolate_process_group=True, inherit_env=False)
                except subprocess.TimeoutExpired:
                    pass
                else:
                    self.fail('Coordinator завершился до timeout: ' + completed.stdout)
                self.assertTrue(client_record.is_file(), 'Настоящий worker должен запустить synthetic client')
                self.assertTrue(child_record.is_file(), 'Synthetic grandchild должен открыть listener')
                client = json.loads(client_record.read_text())
                child = json.loads(child_record.read_text())
                self.assertEqual(client['group'], client['session'])
                self.assertEqual(child['group'], client['group'])
                self.assertEqual(child['session'], client['group'])
                for port in (client['port'], child['port']):
                    with socket.socket() as probe:
                        probe.settimeout(.3)
                        self.assertNotEqual(probe.connect_ex(('127.0.0.1', port)), 0)
                for pid in (client['parent'], client['pid'], child['pid']):
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        try:
                            reaped, _ = os.waitpid(pid, os.WNOHANG)
                            if reaped:
                                break
                        except ChildProcessError:
                            break
                        time.sleep(.01)
                    self.assertFalse(Path(f'/proc/{pid}').exists(), 'Own descendant должен быть reaped')
                with socket.create_connection(foreign.getsockname(), timeout=.3):
                    pass
            finally:
                # RED-реализация создаёт отдельную nested group; удаляем только её
                # подтверждённый synthetic leader, чтобы тест не оставлял процессов.
                if client_record.is_file():
                    group = json.loads(client_record.read_text())['group']
                    if group != os.getpgrp():
                        try:
                            os.killpg(group, 9)
                        except ProcessLookupError:
                            pass
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    try:
                        pid, _ = os.waitpid(-1, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if pid == 0:
                        time.sleep(.01)


def coordinator():
    request = json.loads(sys.stdin.read())
    value = fixture.profile()
    context = vpn_probes.XrayProbeContext(binary_path=Path(request['binary']), binary_sha256=request['sha256'],
        credential_provider=lambda protocol: vpn_probes.XrayProbeCredential(
            '00000000-0000-4000-8000-000000000007', fixture.routing_fingerprint(value, 443)),
        echo_address='127.0.0.1', echo_port=19600, timeout=30,
        coordinator_pid=os.getpid(), dial_target_provider=lambda value, phase: ('127.0.0.1', 41001))
    observer = vpn_probes.XrayVPNObserver(context)
    observer._credential(fixture.with_acceptance(value, 'staging'))
    print(json.dumps(observer(fixture.with_acceptance(value, 'staging'), Runner())))


if __name__ == '__main__':
    if sys.argv[1:] == ['--coordinator']:
        coordinator()
    else:
        unittest.main()
