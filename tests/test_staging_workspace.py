"""Владение временными configs/runtime staging, без запуска frontend."""
from __future__ import annotations

import importlib
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lucx_post_configurator.staging_processes import ServiceIdentity


def api():
    return importlib.import_module('lucx_post_configurator.staging_workspace')


class WorkspaceContracts(unittest.TestCase):
    def test_workspace_owner_api_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('lucx_post_configurator.staging_workspace'),
                             'Отсутствует owner runtime workspace')
        self.assertTrue(callable(api().create_staging_workspace))

    def test_non_linux_refuses_before_filesystem_access(self):
        self.assertIsNotNone(importlib.util.find_spec('lucx_post_configurator.staging_workspace'),
                             'Отсутствует owner runtime workspace')
        with patch.object(api().sys, 'platform', 'win32'), patch.object(api().os, 'mkdir') as mkdir:
            with self.assertRaises(ValueError):
                api().create_staging_workspace(ServiceIdentity(65534, 65534))
            mkdir.assert_not_called()

    def test_nonroot_refuses_before_filesystem_access(self):
        self.assertIsNotNone(importlib.util.find_spec('lucx_post_configurator.staging_workspace'),
                             'Отсутствует owner runtime workspace')
        with patch.object(api().sys, 'platform', 'linux'), patch.object(api().os, 'geteuid', return_value=1000, create=True):
            with patch.object(api().os, 'mkdir') as mkdir, self.assertRaises(ValueError):
                api().create_staging_workspace(ServiceIdentity(65534, 65534))
            mkdir.assert_not_called()


@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'Нужны Linux root, tmpfs и настоящие service UID/GID')
class LinuxWorkspaceTests(unittest.TestCase):
    def setUp(self):
        import pwd
        account = pwd.getpwnam('nobody')
        self.identity = ServiceIdentity(account.pw_uid, account.pw_gid)
        self.temporary = tempfile.TemporaryDirectory(prefix='workspace-test-', dir='/dev/shm')
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.parent.chmod(0o711)

    def create(self):
        return api().create_staging_workspace(self.identity, temporary_parent=self.parent)

    def populated(self):
        owner = self.create()
        owner.write_configs({'haproxy': b'global\n', 'nginx': b'events {}\n'})
        return owner

    def test_modes_immutable_paths_and_one_shot_configs(self):
        owner = self.populated()
        self.addCleanup(owner.cleanup)
        for path in (owner.root, owner.config_root):
            info = path.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, self.identity.gid, 0o710))
        for path in (owner.runtime_root, *owner.runtime_root.iterdir()):
            info = path.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                             (self.identity.uid, self.identity.gid, 0o700))
        self.assertEqual(set(owner.config_paths), {'haproxy', 'nginx'})
        for path in owner.config_paths.values():
            info = path.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink), (0, self.identity.gid, 0o640, 1))
        for field in ('root', 'config_root', 'runtime_root', 'config_paths', 'cleanup_complete'):
            with self.assertRaises((AttributeError, TypeError)):
                setattr(owner, field, None)
        with self.assertRaises(TypeError):
            owner.config_paths['other'] = owner.root
        with self.assertRaises(ValueError):
            owner.write_configs({'haproxy': b'changed', 'nginx': b'changed'})
        owner.verify_configs()

    def test_service_can_write_runtime_and_read_but_cannot_replace_configs(self):
        owner = self.populated()
        root = owner.root
        neighbor = self.parent / 'neighbor'
        neighbor.write_bytes(b'retain')
        code = ('import pathlib,sys; r=pathlib.Path(sys.argv[1]);c=pathlib.Path(sys.argv[2]);'
                '(r/"nginx.pid").write_bytes(b"123");(r/"proxy"/"owned").write_bytes(b"temp");'
                'assert c.read_bytes();\ntry:\n c.write_bytes(b"changed")\nexcept PermissionError:\n pass\nelse:\n raise RuntimeError("writable config")')
        completed = subprocess.run([sys.executable, '-I', '-S', '-c', code, str(owner.runtime_root), str(owner.config_paths['nginx'])],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            user=self.identity.uid, group=self.identity.gid, extra_groups=[], timeout=5, check=False)
        self.assertEqual(completed.returncode, 0)
        owner.verify_configs()
        owner.cleanup()
        owner.cleanup()
        self.assertTrue(owner.cleanup_complete)
        self.assertFalse(root.exists())
        self.assertEqual(neighbor.read_bytes(), b'retain')

    def test_config_payload_inventory_and_size_are_strict(self):
        for values in ({}, {'haproxy': b'x'}, {'haproxy': b'x', 'nginx': b'x', 'other': b'x'},
                       {'haproxy': 'x', 'nginx': b'x'}, {'haproxy': b'', 'nginx': b'x'},
                       {'haproxy': b'x' * (16 * 1024 * 1024 + 1), 'nginx': b'x'}):
            owner = self.create()
            with self.assertRaises(ValueError):
                owner.write_configs(values)
            owner.cleanup()
            self.assertTrue(owner.cleanup_complete)

    def test_unwritten_workspace_cleans_without_config_claim(self):
        owner = self.create()
        with self.assertRaises(ValueError):
            owner.verify_configs()
        owner.cleanup()
        self.assertTrue(owner.cleanup_complete)

    def test_config_drift_is_retained_on_cleanup(self):
        owner = self.populated()
        path = owner.config_paths['nginx']
        path.write_bytes(b'changed')
        for action in (owner.verify_configs, owner.cleanup):
            with self.assertRaises(ValueError):
                action()
        self.assertFalse(owner.cleanup_complete)
        self.assertTrue(owner.root.exists())
        self.assertEqual(path.read_bytes(), b'changed')

    def test_root_replacement_and_symlink_never_remove_foreign_entry(self):
        for symlink in (False, True):
            owner = self.populated()
            original = owner.root
            moved = self.parent / ('moved-' + str(symlink))
            original.rename(moved)
            if symlink:
                original.symlink_to(moved, target_is_directory=True)
            else:
                original.mkdir()
                (original / 'foreign').write_bytes(b'retain')
            with self.assertRaises(ValueError):
                owner.cleanup()
            self.assertFalse(owner.cleanup_complete)
            self.assertTrue(moved.is_dir())
            if not symlink:
                self.assertEqual((original / 'foreign').read_bytes(), b'retain')

    def test_symlink_ancestor_and_non_tmpfs_fail_before_creation(self):
        link = self.parent / 'alias'
        link.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            api().create_staging_workspace(self.identity, temporary_parent=link)
        with patch.object(api(), '_confirmed_tmpfs', return_value=False), self.assertRaises(ValueError):
            self.create()
        self.assertEqual({path.name for path in self.parent.iterdir()}, {'alias'})
        with self.assertRaises(ValueError):
            api().create_staging_workspace(self.identity, temporary_parent=Path('/etc'))

    def test_runtime_unsafe_types_and_foreign_owner_are_retained(self):
        for kind in ('symlink', 'fifo', 'hardlink', 'foreign'):
            owner = self.populated()
            unsafe = owner.runtime_root / 'unsafe'
            target = self.parent / ('target-' + kind)
            target.write_bytes(b'retain')
            if kind == 'symlink':
                unsafe.symlink_to(target)
            elif kind == 'fifo':
                os.mkfifo(unsafe)
                os.chown(unsafe, self.identity.uid, self.identity.gid)
            elif kind == 'hardlink':
                os.link(target, unsafe)
                os.chown(target, self.identity.uid, self.identity.gid)
            else:
                unsafe.write_bytes(b'foreign')
            with self.assertRaises(ValueError):
                owner.cleanup()
            self.assertTrue(unsafe.is_symlink() or unsafe.exists())
            self.assertTrue(owner.config_paths['nginx'].exists())
            self.assertFalse(owner.cleanup_complete)
            self.assertEqual(target.read_bytes(), b'retain')

    def test_config_replacement_and_extra_inventory_fail_closed(self):
        for kind in ('replacement', 'extra', 'mode', 'hardlink'):
            owner = self.populated()
            path = owner.config_paths['nginx']
            if kind == 'replacement':
                path.rename(owner.runtime_root / 'old-config')
                path.write_bytes(b'events {}\n')
                os.chown(path, 0, self.identity.gid)
                path.chmod(0o640)
            elif kind == 'extra':
                (owner.config_root / 'extra').write_bytes(b'x')
            elif kind == 'mode':
                path.chmod(0o600)
            else:
                os.link(path, self.parent / 'config-link')
            with self.assertRaises(ValueError):
                owner.verify_configs()
            with self.assertRaises(ValueError):
                owner.cleanup()
            self.assertTrue(owner.root.exists())

    def test_runtime_walk_limits_reject_before_deleting_configs(self):
        for kind in ('depth', 'entries', 'bytes'):
            owner = self.populated()
            if kind == 'depth':
                path = owner.runtime_root
                for _ in range(9):
                    path /= 'nested'
                    path.mkdir(mode=0o700)
                    os.chown(path, self.identity.uid, self.identity.gid)
            elif kind == 'entries':
                for index in range(257):
                    path = owner.runtime_root / str(index)
                    path.touch()
                    os.chown(path, self.identity.uid, self.identity.gid)
            else:
                path = owner.runtime_root / 'large'
                with path.open('wb') as stream:
                    stream.truncate(16 * 1024 * 1024 + 1)
                os.chown(path, self.identity.uid, self.identity.gid)
            with self.assertRaises(ValueError):
                owner.cleanup()
            self.assertTrue(owner.config_paths['haproxy'].is_file())

    def test_runtime_depth_limit_includes_regular_file_entries(self):
        owner = self.populated()
        path = owner.runtime_root
        for _ in range(8):
            path /= 'nested'
            path.mkdir(mode=0o700)
            os.chown(path, self.identity.uid, self.identity.gid)
        leaf = path / 'depth-nine'
        leaf.write_bytes(b'bounded fixture')
        os.chown(leaf, self.identity.uid, self.identity.gid)
        with self.assertRaises(ValueError):
            owner.cleanup()
        self.assertFalse(owner.cleanup_complete)
        self.assertTrue(leaf.exists())
        self.assertTrue(owner.config_paths['haproxy'].is_file())

    def test_partial_directory_creation_failure_removes_only_created_inode(self):
        real = os.fchown
        calls = 0

        def fail_second(fd, uid, gid):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise PermissionError('private-payload-must-not-leak')
            return real(fd, uid, gid)

        with patch.object(api().os, 'fchown', side_effect=fail_second), self.assertRaises(ValueError) as failure:
            self.create()
        self.assertNotIn('private-payload', str(failure.exception))
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_partial_config_write_failure_removes_owned_files_and_root(self):
        owner = self.create()
        root = owner.root
        with patch.object(api().os, 'write', side_effect=OSError('private-payload')), self.assertRaises(ValueError):
            owner.write_configs({'haproxy': b'x', 'nginx': b'x'})
        self.assertTrue(owner.cleanup_complete)
        self.assertFalse(root.exists())


if __name__ == '__main__':
    unittest.main()
