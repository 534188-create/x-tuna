from __future__ import annotations

import copy
import importlib
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from lucx_post_configurator.renderers import GeneratedFile
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import STAGING_ROOT, stage_files


class StagingIntegrityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fs = TargetFS(temporary.name)
        self.target = '/etc/haproxy/haproxy.cfg'
        self.manifest = {'network': {'public_tcp_port': 443}, 'protocols': []}
        self.generated = {self.target: GeneratedFile(b'candidate\n', component='haproxy')}
        self.run_id = 'synthetic-candidate'
        self.staged = stage_files(self.fs, self.generated, self.run_id)

    def capture(self):
        module = importlib.import_module('lucx_post_configurator.staging_integrity')
        return module.capture_staged_candidate(self.fs, self.manifest, self.generated,
                                               self.staged, self.run_id)

    def verify(self, seal):
        seal.verify(self.fs, self.manifest, self.generated, self.staged, self.run_id)

    def test_modified_staged_bytes_are_rejected_before_capture(self):
        self.staged[self.target].write_bytes(b'different\n')
        with self.assertRaisesRegex(ValueError, 'staging'):
            self.capture()

    def test_unchanged_candidate_survives_validation_scratch_file(self):
        seal = self.capture()
        self.staged[self.target].with_name('check-wrapper.cfg').write_bytes(b'wrapper\n')
        self.verify(seal)

    def test_changed_content_and_same_bytes_inode_replacement_are_rejected(self):
        for changed in (b'different\n', b'candidate\n'):
            with self.subTest(changed=changed != b'candidate\n'):
                seal = self.capture()
                path = self.staged[self.target]
                replacement = path.with_name('replacement')
                replacement.write_bytes(changed)
                os.replace(replacement, path)
                with self.assertRaises(ValueError):
                    self.verify(seal)
                path.write_bytes(b'candidate\n')

    def test_in_memory_bytes_mode_component_and_manifest_are_bound(self):
        mutations = (
            lambda: self.generated.update({self.target: GeneratedFile(b'new\n', component='haproxy')}),
            lambda: self.generated.update({self.target: GeneratedFile(b'candidate\n', mode=0o600, component='haproxy')}),
            lambda: self.generated.update({self.target: GeneratedFile(b'candidate\n', component='nginx')}),
            lambda: self.manifest['network'].update(public_tcp_port=8443),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                manifest, generated = copy.deepcopy(self.manifest), self.generated.copy()
                seal = self.capture()
                mutation()
                with self.assertRaises(ValueError):
                    self.verify(seal)
                self.manifest, self.generated = manifest, generated

    def test_missing_extra_or_retargeted_path_and_other_run_are_rejected(self):
        original = self.staged.copy()
        seal = self.capture()
        for changed in ({}, {**original, '/etc/extra': original[self.target]},
                        {self.target: original[self.target].with_name('other')}):
            with self.subTest(keys=len(changed)):
                self.staged = changed
                with self.assertRaises(ValueError):
                    self.verify(seal)
        self.staged = original
        self.run_id = 'other-run'
        with self.assertRaises(ValueError):
            self.verify(seal)

    def test_wrong_path_never_opens_external_file(self):
        outside = self.fs.root / 'outside'
        outside.write_bytes(b'candidate\n')
        self.staged[self.target] = outside
        with mock.patch('os.open', side_effect=AssertionError('unexpected open')), self.assertRaises(ValueError):
            self.capture()

    def test_nonfinite_or_non_json_manifest_is_rejected_without_value(self):
        for value in (float('nan'), object()):
            with self.subTest(kind=type(value).__name__):
                self.manifest['invalid'] = value
                with self.assertRaises(ValueError) as caught:
                    self.capture()
                self.assertNotIn(repr(value), str(caught.exception))

    def test_file_and_total_size_limits_fail_before_file_open(self):
        for count, size in ((1, 16 * 1024 * 1024 + 1), (3, 12 * 1024 * 1024)):
            with self.subTest(count=count):
                content = b'x' * size
                self.generated = {f'/etc/candidate-{index}': GeneratedFile(content) for index in range(count)}
                self.staged = {target: self.fs.path(f'{STAGING_ROOT}/{self.run_id}{target}') for target in self.generated}
                with mock.patch('os.open', side_effect=AssertionError('oversized file opened')), self.assertRaises(ValueError):
                    self.capture()

    def test_invalid_target_and_artifact_types_fail_before_file_open(self):
        for target, artifact in (
            ('/etc/../candidate', GeneratedFile(b'x')),
            ('/etc/candidate', GeneratedFile(b'x', mode=True)),
            ('/etc/candidate', GeneratedFile(b'x', symlink_target='/cert/source')),
            ('/etc/candidate', GeneratedFile(symlink_target='/cert/../source')),
        ):
            with self.subTest(target=target):
                self.generated = {target: artifact}
                self.staged = {target: self.fs.path(f'{STAGING_ROOT}/{self.run_id}/etc/candidate')}
                with mock.patch('os.open', side_effect=AssertionError('invalid file opened')), self.assertRaises(ValueError):
                    self.capture()

    def test_change_during_read_is_rejected(self):
        original_read, changed = os.read, False

        def read_and_change(fd, size):
            nonlocal changed
            chunk = original_read(fd, size)
            if not changed:
                changed = True
                self.staged[self.target].write_bytes(b'changed!!\n')
            return chunk

        with mock.patch('os.read', side_effect=read_and_change), self.assertRaises(ValueError):
            self.capture()

    @unittest.skipUnless(os.name == 'posix', 'Нужен POSIX symlink каталога')
    def test_parent_symlink_is_not_followed_even_inside_staging_root(self):
        parent = self.staged[self.target].parent
        other = parent.with_name('other-directory')
        parent.rename(other)
        parent.symlink_to(other, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.capture()

    @unittest.skipUnless(os.name == 'posix', 'Нужны POSIX права staging')
    def test_mode_owner_and_ancestor_drift_are_rejected(self):
        path = self.staged[self.target]
        seal = self.capture()
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            self.verify(seal)
        path.chmod(0o644)
        seal = self.capture()
        path.parent.chmod(0o700)
        with self.assertRaises(ValueError):
            self.verify(seal)
        if os.geteuid() == 0:
            path.parent.chmod(0o755)
            seal = self.capture()
            os.chown(path, 1234, 1234)
            try:
                with self.assertRaises(ValueError):
                    self.verify(seal)
            finally:
                os.chown(path, 0, 0)

    @unittest.skipUnless(os.name == 'posix', 'Нужны POSIX symlink и FIFO')
    def test_symlink_directory_and_fifo_cannot_replace_regular_candidate(self):
        path = self.staged[self.target]
        for replacement in ('symlink', 'directory', 'fifo'):
            seal = self.capture()
            path.unlink()
            if replacement == 'symlink':
                path.symlink_to('/not-opened')
            elif replacement == 'directory':
                path.mkdir()
            else:
                os.mkfifo(path)
            try:
                with self.assertRaises(ValueError):
                    self.verify(seal)
            finally:
                path.rmdir() if replacement == 'directory' else path.unlink()
                path.write_bytes(b'candidate\n')

    @unittest.skipUnless(os.name == 'posix', 'Нужен POSIX symlink')
    def test_expected_symlink_is_bound_without_following_its_referent(self):
        target = '/etc/lucx-post-configurator/tls/certificate.pem'
        self.generated = {target: GeneratedFile(symlink_target='/cert/example.pem')}
        self.run_id = 'synthetic-symlink'
        self.staged = stage_files(self.fs, self.generated, self.run_id)
        seal = self.capture()
        self.verify(seal)
        path = self.staged[target]
        path.unlink()
        path.symlink_to('/cert/other.pem')
        with self.assertRaises(ValueError):
            self.verify(seal)


class EngineStagingIntegrityTests(unittest.TestCase):
    def test_validator_cannot_change_staged_file_commit_buffer_or_manifest(self):
        from helpers import make_target
        from test_transport_routing_regressions import topology

        from lucx_post_configurator.engine import ApplyError, Engine
        from lucx_post_configurator.models import Audit, Inbound
        from lucx_post_configurator.runner import Runner

        for mutation in ('staged', 'generated', 'manifest'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                root = Path(temporary)
                make_target(root)
                engine = Engine(root, runner=Runner(dry_run=True))
                target = '/etc/haproxy/haproxy.cfg'
                engine.fs.atomic_write_text(target, 'previous configuration\n')
                manifest = topology('grpc')
                manifest['components'] = {key: False for key in manifest['components']}
                manifest['components'].update(haproxy=True, nginx=True, extended_tls_split=True)
                manifest['dns']['enabled'] = manifest['cloudflare']['enabled'] = False
                audit = Audit(supported_os=True, db_schema_supported=True,
                    settings={'webDomain': 'panel.example.test', 'webPort': '2083',
                              'subDomain': 'sub.example.test', 'subPort': '2096'},
                    inbounds=[Inbound(id=7, protocol='vless', remark='', enable=True,
                                      listen='127.0.0.1', port=18443, transport='grpc')])
                generated = {target: GeneratedFile(b'new configuration\n', component='haproxy')}

                def change_candidate(fs, files, staged, plan, runner, *, mutation=mutation, target=target):
                    if mutation == 'staged':
                        staged[target].write_bytes(b'other configuration\n')
                    elif mutation == 'generated':
                        files[target] = GeneratedFile(b'other configuration\n', component='haproxy')
                    else:
                        plan['changed_during_validation'] = True
                    return []

                stack.enter_context(mock.patch.object(TargetFS, 'is_live', new_callable=mock.PropertyMock, return_value=True))
                stack.enter_context(mock.patch.object(engine, 'audit', side_effect=lambda *_, audit=audit: copy.deepcopy(audit)))
                stack.enter_context(mock.patch.object(engine, '_activate'))
                restore = stack.enter_context(mock.patch.object(engine, '_reactivate_after_restore', return_value=[]))
                stack.enter_context(mock.patch.object(engine, '_register_acme_hook', side_effect=lambda m, complete=None: (complete() if complete else None) or []))
                stack.enter_context(mock.patch('lucx_post_configurator.engine._managed_decoy_directories', return_value={}))
                for name in ('validate_public_bind_conflicts', 'validate_certificate', 'validate_lucx_tls_coverage', 'validate_live_configuration'):
                    stack.enter_context(mock.patch('lucx_post_configurator.engine.' + name, return_value=[]))
                stack.enter_context(mock.patch('lucx_post_configurator.engine.render_files', return_value=generated))
                stack.enter_context(mock.patch('lucx_post_configurator.engine.validate_generated', side_effect=change_candidate))
                commit = stack.enter_context(mock.patch('lucx_post_configurator.engine.commit_managed_transition',
                                                        side_effect=AssertionError('staging mutation reached commit')))
                with self.assertRaisesRegex(ApplyError, 'staging'):
                    engine._apply_locked(manifest)
                commit.assert_not_called()
                restore.assert_not_called()
                self.assertEqual(engine.fs.read_bytes(target), b'previous configuration\n')


if __name__ == '__main__':
    unittest.main()
