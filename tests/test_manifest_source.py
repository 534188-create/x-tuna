"""Исходный manifest читается повторно; подтверждение не разрешает его подмену."""
from __future__ import annotations

import copy
import importlib
import inspect
import json
import os
import tempfile
import unittest
from pathlib import Path

from test_staging_eligibility import candidate_manifest

from lucx_post_configurator.migrations import migrate_manifest
from lucx_post_configurator.models import load_manifest


class ManifestSourceTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('lucx_post_configurator.manifest_source')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / 'план с пробелами.json'
        self.raw = json.dumps(candidate_manifest(), ensure_ascii=False, indent=3).encode('utf-8') + b'\n'
        self.path.write_bytes(self.raw)

    def test_guarded_load_matches_normalization_without_rewriting_the_file(self):
        before = self.path.stat()
        expected = load_manifest(self.path)
        manifest, source = self.api.read_manifest_source(self.path)
        self.assertEqual(manifest, expected)
        source.verify(manifest=manifest)
        self.assertEqual(self.path.read_bytes(), self.raw)
        self.assertEqual(self.path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertNotIn(str(self.path), repr(source))

    def test_changed_bytes_replacement_and_removal_reject_previously_confirmed_source(self):
        for change in ('content', 'replace', 'remove'):
            self.path.write_bytes(self.raw)
            _, source = self.api.read_manifest_source(self.path)
            if change == 'content':
                self.path.write_bytes(self.raw + b' ')
            elif change == 'replace':
                replacement = self.root / 'replacement.json'
                replacement.write_bytes(self.raw)
                replacement.replace(self.path)
            else:
                self.path.unlink()
            with self.subTest(change=change), self.assertRaises(ValueError):
                source.verify()

    def test_different_in_memory_plan_cannot_borrow_a_valid_file_guard(self):
        manifest, source = self.api.read_manifest_source(self.path)
        changed = copy.deepcopy(manifest)
        changed['network']['public_tcp_port'] = 9443
        with self.assertRaises(ValueError):
            source.verify(manifest=changed)
        source.verify(manifest=manifest)

    def test_malformed_duplicate_and_oversized_sources_have_safe_errors(self):
        for data in (b'private-source-sentinel', b'{"schema_version":1,"schema_version":2}',
                     b' ' * (4 * 1024 * 1024 + 1)):
            self.path.write_bytes(data)
            with self.assertRaises(ValueError) as caught:
                self.api.read_manifest_source(self.path)
            self.assertNotIn('private-source-sentinel', str(caught.exception))
            self.assertNotIn(str(self.path), str(caught.exception))

    def read_state(self):
        self.assertIn('envelope', inspect.signature(self.api.read_manifest_source).parameters,
                      'Нужен явный режим envelope без угадывания JSON формы')
        return self.api.read_manifest_source(self.path, envelope='state')

    def test_state_envelope_binds_whole_file_to_nested_normalized_manifest_without_writing(self):
        raw = json.dumps({'schema_version': 1, 'status': 'failed', 'run_id': 'synthetic-run',
                          'manifest': candidate_manifest()}, indent=3).encode() + b'\n\n'
        self.path.write_bytes(raw)
        before = self.path.stat()
        manifest, fence = self.read_state()
        self.assertEqual(manifest, migrate_manifest(candidate_manifest()))
        fence.verify(manifest=manifest)
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertEqual(self.path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertTrue(fence.guards(self.path))
        self.assertFalse(fence.guards(self.root / 'other.json'))
        # Даже неизменный manifest не разрешает использовать новую версию envelope.
        self.path.write_bytes(raw.replace(b'synthetic-run', b'synthetic-new'))
        with self.assertRaises(ValueError):
            fence.verify()

    def test_state_envelope_rejects_missing_invalid_or_duplicate_manifest_and_unknown_mode(self):
        for raw in (b'{}', b'[]', b'{"manifest":null}', b'{"manifest":[]}',
                    b'{"manifest":{},"manifest":{}}', b'{"manifest":{},"extra":NaN}'):
            self.path.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.read_state()
        for envelope in ('auto', None, False):
            with self.subTest(envelope=envelope), self.assertRaises(ValueError):
                self.api.read_manifest_source(self.path, envelope=envelope)

    def test_state_file_replacement_removal_and_in_memory_change_reject_old_guard(self):
        raw = json.dumps({'manifest': candidate_manifest()}).encode()
        for change in ('replace', 'remove', 'manifest'):
            self.path.write_bytes(raw)
            manifest, fence = self.read_state()
            if change == 'replace':
                replacement = self.root / 'new-state.json'
                replacement.write_bytes(raw)
                replacement.replace(self.path)
            elif change == 'remove':
                self.path.unlink()
            else:
                manifest['network']['public_tcp_port'] = 9443
            with self.subTest(change=change), self.assertRaises(ValueError):
                fence.verify(manifest=manifest)

    @unittest.skipUnless(os.name == 'posix', 'Нужны POSIX symlink и FIFO')
    def test_symlink_fifo_and_changed_owner_mode_are_rejected_without_following(self):
        link = self.root / 'alias.json'
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            self.api.read_manifest_source(link)
        fifo = self.root / 'pipe.json'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            self.api.read_manifest_source(fifo)
        _, source = self.api.read_manifest_source(self.path)
        self.path.chmod(0o600)
        with self.assertRaises(ValueError):
            source.verify()


if __name__ == '__main__':
    unittest.main()
