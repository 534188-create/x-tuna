from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from lucx_post_configurator.renderers import GeneratedFile
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import create_backup, restore_backup, commit_managed_transition


class BackupOwnershipTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Нужен Linux root для проверки владельца')
    def test_external_owner_change_after_backup_blocks_commit(self):
        with tempfile.TemporaryDirectory() as root:
            fs = TargetFS(root)
            target = '/etc/managed.conf'
            fs.atomic_write(target, b'original\n', mode=0o640)
            generated = {target: GeneratedFile(b'new\n')}
            backup = create_backup(fs, generated, 'owner-drift')
            os.chown(fs.path(target), 65534, 65534)
            journal = {}
            with self.assertRaisesRegex(RuntimeError, 'изменился после backup'):
                commit_managed_transition(fs, generated, [], {}, baseline=backup, mutation_journal=journal)
            self.assertEqual(journal, {})
            self.assertEqual(fs.read_bytes(target), b'original\n')
            self.assertEqual((fs.path(target).stat().st_uid, fs.path(target).stat().st_gid), (65534, 65534))

    def test_backup_records_original_owner_for_later_process_restore(self):
        with tempfile.TemporaryDirectory() as root:
            fs = TargetFS(root)
            fs.atomic_write('/etc/managed.conf', b'original\n', mode=0o640)
            original = fs.path('/etc/managed.conf').stat()
            backup = create_backup(fs, {'/etc/managed.conf': GeneratedFile(b'new\n')}, 'owner-baseline')
            entry = next(item for item in backup.metadata['entries'] if item['target'] == '/etc/managed.conf')
            self.assertEqual((entry.get('uid'), entry.get('gid')), (original.st_uid, original.st_gid))

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Нужен Linux root для проверки владельца')
    def test_restore_publishes_original_owner_and_mode_atomically(self):
        with tempfile.TemporaryDirectory() as root:
            fs = TargetFS(root)
            target = '/etc/managed.conf'
            fs.atomic_write(target, b'original\n', mode=0o640)
            os.chown(fs.path(target), 65534, 65534)
            backup = create_backup(fs, {target: GeneratedFile(b'new\n')}, 'owner-restore')
            fs.atomic_write(target, b'new\n')
            replace = os.replace
            publications = []

            def inspect_before_publish(source, destination):
                if destination == fs.path(target):
                    info = os.stat(source)
                    publications.append((info.st_uid, info.st_gid, info.st_mode & 0o777))
                return replace(source, destination)

            with mock.patch('lucx_post_configurator.targetfs.os.replace', side_effect=inspect_before_publish):
                self.assertEqual(restore_backup(fs, backup), [])
            self.assertEqual(publications, [(65534, 65534, 0o640)])
            self.assertEqual(fs.read_bytes(target), b'original\n')
            self.assertEqual((fs.path(target).stat().st_uid, fs.path(target).stat().st_gid), (65534, 65534))


if __name__ == '__main__':
    unittest.main()
