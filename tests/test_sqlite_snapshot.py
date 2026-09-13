from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from lucx_post_configurator import sqlite_snapshot as snapshot
from lucx_post_configurator.targetfs import TargetFS


class SQLiteSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='snapshot-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.fs = TargetFS(self.temp.name)
        self.path = self.fs.path('/db.sqlite')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('CREATE TABLE counters(value INTEGER)')
            db.execute('INSERT INTO counters VALUES (1)')

    def writer(self):
        db = sqlite3.connect(self.path)
        self.addCleanup(db.close)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('UPDATE counters SET value=2')
        db.commit()
        return db

    def read(self):
        return snapshot.open_snapshot(self.fs, '/db.sqlite')

    def freeze_wal_fixture(self):
        writer = self.writer()
        files = {path: path.read_bytes() for path in self.path.parent.iterdir()}
        writer.close()
        for path, content in files.items():
            path.write_bytes(content)

    def source_hashes(self):
        return {p.name: hashlib.sha256(p.read_bytes()).digest() for p in self.path.parent.iterdir()}

    def test_native_wal_replay_preserves_sources_and_private_copy_disappears(self):
        self.writer()
        before = self.source_hashes()
        connect = sqlite3.connect
        memory_connections, private_paths = [], []
        def inspect_connect(database, *args, **kwargs):
            connection = connect(database, *args, **kwargs)
            if str(database) == ':memory:':
                memory_connections.append(connection)
            else:
                path = Path(database)
                self.assertNotEqual(path.parent, self.path.parent)
                self.assertTrue(path.is_file())
                private_paths.append(path)
            return connection
        with mock.patch.object(sqlite3, 'connect', side_effect=inspect_connect), closing(self.read()) as db:
            self.assertEqual(db.execute('SELECT value FROM counters').fetchone(), (2,))
            self.assertEqual(memory_connections, [db])
            self.assertTrue(private_paths)
            self.assertTrue(all(not path.parent.exists() for path in private_paths))
            self.assertEqual(db.execute('PRAGMA query_only').fetchone(), (1,))
            with self.assertRaises(sqlite3.OperationalError):
                db.execute('UPDATE counters SET value=3')
        self.assertEqual(self.source_hashes(), before)

    def test_source_descriptors_are_read_only_and_all_open_before_content_read(self):
        self.writer()
        original_open, original_read = os.open, os.read
        opened, first = [], []
        def track_open(path, flags, *args, **kwargs):
            if str(path).startswith(str(self.path)) or str(path) in {self.path.name + s for s in ('', '-wal', '-shm')}:
                self.assertEqual(flags & getattr(os, 'O_ACCMODE', 3), os.O_RDONLY)
                if os.name == 'posix':
                    self.assertTrue(flags & os.O_NOFOLLOW)
                opened.append(str(path))
            return original_open(path, flags, *args, **kwargs)
        def track_read(fd, size):
            if not first:
                first.extend(opened)
            return original_read(fd, size)
        with mock.patch.object(os, 'open', side_effect=track_open), \
                mock.patch.object(os, 'read', side_effect=track_read), closing(self.read()):
            pass
        self.assertEqual(len(first), 3)

    def test_concurrent_wal_append_during_copy_is_rejected(self):
        writer = self.writer()
        original = snapshot._read
        calls = 0
        def append(fd, size, deadline):
            nonlocal calls
            result = original(fd, size, deadline)
            calls += 1
            if calls == 1:
                writer.execute('UPDATE counters SET value=3')
                writer.commit()
            return result
        with mock.patch.object(snapshot, '_read', side_effect=append), self.assertRaises(ValueError):
            self.read()

    def test_checkpoint_reset_reuse_during_copy_is_rejected(self):
        writer = self.writer()
        original = snapshot._read
        calls = 0
        def reset(fd, size, deadline):
            nonlocal calls
            result = original(fd, size, deadline)
            calls += 1
            if calls == 1:
                writer.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                writer.execute('UPDATE counters SET value=3')
                writer.commit()
            return result
        with mock.patch.object(snapshot, '_read', side_effect=reset), self.assertRaises(ValueError):
            self.read()

    def test_equal_size_content_drift_is_rejected_even_when_stat_timestamps_are_hidden(self):
        original, identity = snapshot._digest, snapshot._identity
        changed = False
        def overwrite(fd, size, deadline):
            nonlocal changed
            if not changed:
                changed = True
                with closing(sqlite3.connect(self.path)) as writer, writer:
                    writer.execute('UPDATE counters SET value=2')
                self.assertEqual(self.path.stat().st_size, size)
            return original(fd, size, deadline)
        with mock.patch.object(snapshot, '_identity', side_effect=lambda info: identity(info)[:6]), \
                mock.patch.object(snapshot, '_digest', side_effect=overwrite), self.assertRaises(ValueError):
            self.read()

    def test_sidecar_created_after_fd_capture_is_rejected(self):
        original = snapshot._read
        def create(fd, size, deadline):
            result = original(fd, size, deadline)
            self.path.with_name(self.path.name + '-journal').write_bytes(bytes(512))
            return result
        with mock.patch.object(snapshot, '_read', side_effect=create), self.assertRaises(ValueError):
            self.read()

    def test_transient_sidecar_creation_and_deletion_is_rejected(self):
        original = snapshot._read
        directory = self.path.parent.stat()
        def transient(fd, size, deadline):
            result = original(fd, size, deadline)
            journal = self.path.with_name(self.path.name + '-journal')
            journal.write_bytes(bytes(512))
            journal.unlink()
            # Делаем ABA наблюдаемым независимо от разрешения часов ФС.
            os.utime(self.path.parent, ns=(directory.st_atime_ns, directory.st_mtime_ns + 1_000_000_000))
            return result
        with mock.patch.object(snapshot, '_read', side_effect=transient), self.assertRaises(ValueError):
            self.read()

    def test_present_rollback_journal_is_rejected_without_recovery(self):
        journal = self.path.with_name(self.path.name + '-journal')
        journal.write_bytes(b'\xd9\xd5\x05\xf9\x20\xa1\x63\xd7' + bytes(512))
        before = self.source_hashes()
        with self.assertRaises(ValueError):
            self.read()
        self.assertEqual(self.source_hashes(), before)

    def test_torn_and_corrupt_wal_are_not_silently_ignored(self):
        self.writer()
        wal = self.path.with_name(self.path.name + '-wal')
        valid = wal.read_bytes()
        for alteration in ('truncated', 'checksum', 'header'):
            with self.subTest(alteration=alteration):
                changed = bytearray(valid)
                if alteration == 'truncated':
                    del changed[-1]
                elif alteration == 'checksum':
                    changed[-10] ^= 1
                else:
                    changed[24] ^= 1
                wal.write_bytes(changed)
                try:
                    with self.assertRaises((ValueError, sqlite3.DatabaseError)):
                        self.read()
                finally:
                    wal.write_bytes(valid)

    def test_empty_wal_cannot_ignore_nonempty_committed_wal_index(self):
        self.writer()
        wal = self.path.with_name(self.path.name + '-wal')
        original = wal.read_bytes()
        try:
            wal.write_bytes(b'')
            before = self.source_hashes()
            with self.assertRaises(ValueError):
                self.read()
            self.assertEqual(self.source_hashes(), before)
        finally:
            wal.write_bytes(original)

    def test_missing_wal_cannot_ignore_nonempty_committed_wal_index(self):
        self.freeze_wal_fixture()
        wal = self.path.with_name(self.path.name + '-wal')
        original = wal.read_bytes()
        try:
            wal.unlink()
            before = self.source_hashes()
            with self.assertRaises(ValueError):
                self.read()
            self.assertEqual(self.source_hashes(), before)
        finally:
            wal.write_bytes(original)

    def test_nonempty_wal_without_wal_index_is_not_authoritative(self):
        writer = self.writer()
        raw = self.path.read_bytes()
        wal = self.path.with_name(self.path.name + '-wal').read_bytes()
        writer.close()
        self.path.write_bytes(raw)
        self.path.with_name(self.path.name + '-wal').write_bytes(wal)
        self.assertFalse(self.path.with_name(self.path.name + '-shm').exists())
        before = self.source_hashes()
        with self.assertRaises(ValueError):
            self.read()
        self.assertEqual(self.source_hashes(), before)

    def test_disagreeing_or_corrupt_wal_index_headers_are_rejected(self):
        self.freeze_wal_fixture()
        shm = self.path.with_name(self.path.name + '-shm')
        original = shm.read_bytes()
        for both in (False, True):
            changed = bytearray(original)
            changed[8] ^= 1
            if both:
                changed[56] ^= 1
            try:
                shm.write_bytes(changed)
                before = self.source_hashes()
                with self.assertRaises(ValueError):
                    self.read()
                self.assertEqual(self.source_hashes(), before)
            finally:
                shm.write_bytes(original)

    def test_checksummed_but_wrong_index_horizon_is_rejected_by_native_recovery(self):
        self.freeze_wal_fixture()
        shm = self.path.with_name(self.path.name + '-shm')
        original = shm.read_bytes()
        for offset in (0, 4, 12, 13, 14, 20, 24, 32):
            with self.subTest(field_offset=offset):
                header = bytearray(original[:48])
                header[offset] ^= 1
                first = second = 0
                for index in range(0, 40, 8):
                    first = (first + int.from_bytes(header[index:index + 4], sys.byteorder) + second) & 0xFFFFFFFF
                    second = (second + int.from_bytes(header[index + 4:index + 8], sys.byteorder) + first) & 0xFFFFFFFF
                header[40:44] = first.to_bytes(4, sys.byteorder)
                header[44:48] = second.to_bytes(4, sys.byteorder)
                try:
                    shm.write_bytes(header + header + original[96:])
                    before = self.source_hashes()
                    with self.assertRaises(ValueError):
                        self.read()
                    self.assertEqual(self.source_hashes(), before)
                finally:
                    shm.write_bytes(original)

    def test_wal_index_content_drift_is_rejected_when_timestamps_are_hidden(self):
        self.freeze_wal_fixture()
        shm = self.path.with_name(self.path.name + '-shm')
        initial = shm.read_bytes()
        original, identity = snapshot._digest, snapshot._identity
        changed = False
        def drift(fd, size, deadline):
            nonlocal changed
            result = original(fd, size, deadline)
            if not changed:
                changed = True
                altered = bytearray(initial)
                altered[8] ^= 1
                shm.write_bytes(altered)
            return result
        try:
            with mock.patch.object(snapshot, '_identity', side_effect=lambda info: identity(info)[:6]), \
                    mock.patch.object(snapshot, '_digest', side_effect=drift), self.assertRaises(ValueError):
                self.read()
        finally:
            shm.write_bytes(initial)

    def test_uncommitted_wal_frames_are_not_used_as_old_authorization(self):
        writer = self.writer()
        writer.execute('PRAGMA cache_size=1')
        writer.execute('BEGIN')
        # Движок сам формирует настоящий uncommitted WAL с вытеснением страниц.
        writer.execute('CREATE TABLE pending(payload BLOB)')
        for _ in range(40):
            writer.execute('INSERT INTO pending VALUES (zeroblob(4096))')
        with self.assertRaises(ValueError):
            self.read()
        writer.rollback()

    def test_reused_wal_old_salt_tail_recovers_exact_committed_horizon(self):
        writer = self.writer()
        for value in range(3, 7):
            writer.execute('UPDATE counters SET value=?', (value,))
            writer.commit()
        wal = self.path.with_name(self.path.name + '-wal')
        old_size = wal.stat().st_size
        writer.execute('PRAGMA wal_checkpoint(RESTART)')
        writer.execute('UPDATE counters SET value=7')
        writer.commit()
        self.assertEqual(wal.stat().st_size, old_size)
        self.assertEqual(writer.execute('SELECT value FROM counters').fetchone(), (7,))
        before = self.source_hashes()
        # Источник SHM подтверждает mxFrame/checksum, SQLite независимо
        # восстанавливает тот же последний commit из полного WAL с хвостом.
        with closing(self.read()) as restored:
            self.assertEqual(restored.execute('SELECT value FROM counters').fetchone(), (7,))
        self.assertEqual(self.source_hashes(), before)

    def test_reused_wal_tail_with_current_salt_remains_blocked(self):
        writer = self.writer()
        for value in range(3, 7):
            writer.execute('UPDATE counters SET value=?', (value,))
            writer.commit()
        writer.execute('PRAGMA wal_checkpoint(RESTART)')
        writer.execute('UPDATE counters SET value=7')
        writer.commit()
        wal_path = self.path.with_name(self.path.name + '-wal')
        raw = wal_path.read_bytes()
        shm = self.path.with_name(self.path.name + '-shm').read_bytes()
        mx_frame = int.from_bytes(shm[16:20], sys.byteorder)
        size = int.from_bytes(raw[8:12], 'big')
        changed = bytearray(raw)
        offset = 32 + mx_frame * (size + 24)
        self.assertLess(offset, len(raw))
        changed[offset + 8:offset + 16] = raw[16:24]
        try:
            wal_path.write_bytes(changed)
            before = self.source_hashes()
            with self.assertRaises(ValueError):
                self.read()
            self.assertEqual(self.source_hashes(), before)
        finally:
            wal_path.write_bytes(raw)

    def test_logical_page_limit_is_checked_before_serialize(self):
        connection = sqlite3.connect
        serialized = []
        class Oversized(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql == 'PRAGMA page_count':
                    return super().execute('SELECT 1000000000')
                return super().execute(sql, parameters)
            def serialize(self, **kwargs):
                serialized.append(True)
                return super().serialize(**kwargs)
        def oversized(database, *args, **kwargs):
            return connection(database, *args, factory=Oversized, **kwargs)
        with mock.patch.object(sqlite3, 'connect', side_effect=oversized), self.assertRaises(ValueError):
            self.read()
        self.assertEqual(serialized, [])

    def test_missing_deserialize_fails_before_any_private_sqlite_open(self):
        with mock.patch.object(sqlite3, 'Connection', type('NoDeserialize', (), {'serialize': lambda: None})), \
                mock.patch.object(sqlite3, 'connect') as connect, self.assertRaises(TypeError):
            self.read()
        connect.assert_not_called()

    def test_private_files_are_removed_on_native_sqlite_error(self):
        temporary = tempfile.TemporaryDirectory
        created = []
        def directory(*args, **kwargs):
            result = temporary(*args, **kwargs)
            created.append(Path(result.name))
            return result
        with mock.patch.object(tempfile, 'TemporaryDirectory', side_effect=directory), \
                mock.patch.object(snapshot, '_configure', side_effect=sqlite3.DatabaseError('synthetic failure')), \
                self.assertRaises(sqlite3.DatabaseError):
            self.read()
        self.assertTrue(created)
        self.assertTrue(all(not path.exists() for path in created))

    def test_oversized_raw_source_is_rejected_before_copy(self):
        with self.path.open('r+b') as stream:
            stream.truncate(snapshot._MAX_INPUT + 1)
        with mock.patch.object(snapshot, '_private_directory') as private, self.assertRaises(ValueError):
            self.read()
        private.assert_not_called()

    @unittest.skipIf(sys.platform.startswith('linux'), 'Отдельная проверка Linux tmpfs ниже')
    def test_live_source_has_no_disk_temp_fallback_on_non_linux(self):
        with mock.patch.object(TargetFS, 'is_live', new_callable=mock.PropertyMock, return_value=True), \
                mock.patch.object(tempfile, 'TemporaryDirectory') as temporary, self.assertRaises(ValueError):
            self.read()
        temporary.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Требуется настоящий Linux tmpfs')
    def test_live_tmpfs_and_permissions_are_verified_and_unconfirmed_mount_is_rejected(self):
        with snapshot._private_directory(True) as directory:
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            snapshot._write_private(directory / 'fixture', b'synthetic')
            self.assertEqual(stat.S_IMODE((directory / 'fixture').stat().st_mode), 0o600)
        self.assertFalse(directory.exists())
        with mock.patch.object(snapshot, '_confirmed_tmpfs', return_value=False), \
                self.assertRaises(ValueError), snapshot._private_directory(True):
            self.fail('Неподтверждённый mount принят')

    @unittest.skipUnless(os.name == 'posix', 'Требуется POSIX unlink открытого FD')
    def test_sidecar_replacement_and_aba_are_rejected(self):
        self.writer()
        original = snapshot._read
        directory = self.path.parent.stat()
        wal = self.path.with_name(self.path.name + '-wal')
        calls = 0
        def replace(fd, size, deadline):
            nonlocal calls
            result = original(fd, size, deadline)
            calls += 1
            if calls == 1:
                saved = wal.with_name('saved-wal')
                wal.rename(saved)
                wal.write_bytes(saved.read_bytes())
                wal.unlink()
                saved.rename(wal)
                # В одном tick ядра mtime/ctime могут не измениться сами.
                os.utime(self.path.parent, ns=(directory.st_atime_ns, directory.st_mtime_ns + 1_000_000_000))
            return result
        with mock.patch.object(snapshot, '_read', side_effect=replace), self.assertRaises(ValueError):
            self.read()


if __name__ == '__main__':
    unittest.main()
