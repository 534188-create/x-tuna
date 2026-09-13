from __future__ import annotations

import importlib
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import PropertyMock, patch

from test_transport_routing_regressions import topology

from lucx_post_configurator import renderers
from lucx_post_configurator.renderers import GeneratedFile, render_files
from lucx_post_configurator.targetfs import TargetFS


class StagingMaterialsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.fs = TargetFS(self.base / 'source')
        self.fs.root.mkdir()
        self.parent = self.base / 'private'
        self.parent.mkdir()
        self.manifest = topology('ws', transport_path='/')
        self.generated = render_files(self.manifest)
        self.site = self.manifest['decoys']['sites'][0]['root']
        self.write('/cert/fullchain.pem', b'certificate-fixture\r\n')
        self.write('/cert/key.pem', b'key-fixture\x00\r\n')
        self.write('/etc/ssl/certs/ca-certificates.crt', b'ca-fixture\n')
        self.write('/etc/nginx/mime.types', b'types { text/html html; }\n')
        for site in self.manifest['decoys']['sites']:
            self.write(site['root'] + '/index.html', b'<link href="a.css">retained\r\n')
            self.write(site['root'] + '/a.css', b'body { color: red }\r\n')
            self.generated.pop(site['root'] + '/index.html', None)

    def write(self, target, payload):
        path = self.fs.path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def api(self):
        self.assertIsNotNone(importlib.util.find_spec('lucx_post_configurator.staging_materials'),
                             'Нет владельца приватных снимков материалов')
        return importlib.import_module('lucx_post_configurator.staging_materials')

    def create(self, **kwargs):
        return self.api().create_staging_materials(
            self.fs, self.manifest, self.generated, temporary_parent=self.parent, **kwargs)

    def test_material_inventory_is_typed_complete_and_excludes_naive(self):
        inventory = getattr(renderers, 'frontend_material_inventory', None)
        self.assertTrue(callable(inventory), 'Нет общего inventory материалов renderer')
        actual = inventory(self.manifest)
        self.assertEqual(actual['/cert/key.pem'], 'file')
        self.assertEqual(actual[self.site], 'directory')
        self.assertIn('/etc/lucx-post-configurator/tls/certificate.pem.key', actual)
        self.assertIn('/etc/ssl/certs/ca-certificates.crt', actual)
        self.assertNotIn('/etc/nginx/mime.types', actual)
        self.assertFalse(any('Caddyfile' in value for value in actual))
        with self.assertRaises(TypeError):
            actual['/new'] = 'file'
        self.manifest['components']['nginx'] = False
        with self.assertRaises(ValueError):
            inventory(self.manifest)

    def test_source_fence_survives_copy_cleanup_and_reads_originals_only(self):
        owner = self.create()
        try:
            fence = owner.source_fence()
        finally:
            owner.cleanup()
        self.assertFalse(owner.root.exists())
        self.assertIsNone(fence.verify(self.manifest, self.generated))
        self.assertFalse(owner.root.exists(), 'Проверка не создаёт удалённые копии')
        self.assertNotIn('key-fixture', repr(fence))
        self.write('/cert/key.pem', b'changed-after-cleanup')
        with self.assertRaises(ValueError):
            fence.verify(self.manifest, self.generated)

    def test_source_fence_rejects_changed_write_set_after_cleanup(self):
        owner = self.create()
        try:
            fence = owner.source_fence()
        finally:
            owner.cleanup()
        self.generated[self.site + '/index.html'] = GeneratedFile(b'late mutation')
        with self.assertRaises(ValueError):
            fence.verify(self.manifest, self.generated)

    def test_private_copies_preserve_bytes_existing_tree_and_alias_pair(self):
        with self.create() as owner:
            root = owner.root
            self.assertEqual(set(owner.paths), set(renderers.frontend_material_inventory(self.manifest)))
            self.assertEqual(Path(owner.paths[self.site], 'a.css').read_bytes(), b'body { color: red }\r\n')
            self.assertIn(b'retained', Path(owner.paths[self.site], 'index.html').read_bytes())
            self.assertEqual(Path(owner.paths['/cert/key.pem']).read_bytes(), b'key-fixture\x00\r\n')
            alias = '/etc/lucx-post-configurator/tls/certificate.pem'
            self.assertEqual(owner.paths[alias] + '.key', owner.paths[alias + '.key'])
            self.assertEqual(Path(owner.paths[alias]).read_bytes(), b'certificate-fixture\r\n')
            self.assertEqual(owner.mime_path.read_bytes(), b'types { text/html html; }\n')
            self.assertEqual(len(owner.snapshot_digest), 64)
            self.assertNotIn('key-fixture', repr(owner))
            owner.verify_sources()
            owner.verify_copies()
            self.assertFalse(hasattr(owner, 'candidate_verified'))
            for item in root.rglob('*'):
                self.assertFalse(item.is_symlink())
                if os.name == 'posix':
                    self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o700 if item.is_dir() else 0o600)
            if os.name == 'posix':
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        self.assertFalse(root.exists())

    def test_generated_site_override_and_acl_use_exact_commit_bytes(self):
        self.manifest['cloudflare']['enabled'] = True
        self.manifest['cloudflare']['user_confirmed'] = True
        self.manifest['components']['firewall'] = True
        self.manifest['network']['public_bind_address'] = '203.0.113.10'
        self.generated[self.site + '/index.html'] = GeneratedFile(b'new\x00\r\n', component='nginx')
        self.generated['/etc/haproxy/cloudflare-ips.lst'] = GeneratedFile(b'192.0.2.0/24\r\n')
        with self.create() as owner:
            self.assertEqual(Path(owner.paths[self.site], 'index.html').read_bytes(), b'new\x00\r\n')
            self.assertTrue(Path(owner.paths[self.site], 'a.css').is_file())
            self.assertEqual(Path(owner.paths['/etc/haproxy/cloudflare-ips.lst']).read_bytes(), b'192.0.2.0/24\r\n')
        self.assertIn(b'retained', self.fs.path(self.site + '/index.html').read_bytes())

    def test_new_site_requires_generated_index_and_records_absence(self):
        import shutil
        shutil.rmtree(self.fs.path(self.site))
        with self.assertRaises(ValueError):
            self.create()
        self.generated[self.site + '/index.html'] = GeneratedFile(b'new site')
        with self.create() as owner:
            self.assertEqual(Path(owner.paths[self.site], 'index.html').read_bytes(), b'new site')
            self.write(self.site + '/surprise', b'late content')
            with self.assertRaises(ValueError):
                owner.verify_sources()

    def test_source_and_generated_drift_rejected(self):
        with self.create() as owner:
            self.write('/cert/key.pem', b'different')
            with self.assertRaises(ValueError):
                owner.verify_sources()
        with self.create() as owner:
            self.generated[self.site + '/index.html'] = GeneratedFile(b'late mutation')
            with self.assertRaises(ValueError):
                owner.verify_sources()

    def test_changed_copy_bytes_detected_before_owner_is_returned(self):
        api = self.api()
        original_write = api._write_copies

        def corrupt(owner, *args):
            original_write(owner, *args)
            Path(owner.paths['/cert/key.pem']).write_bytes(b'corrupted private copy')

        with patch.object(api, '_write_copies', side_effect=corrupt), self.assertRaises(ValueError):
            self.create()
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_copy_hardlink_is_rejected(self):
        with self.create() as owner:
            os.link(Path(owner.paths['/cert/key.pem']), self.base / 'outside-link')
            try:
                with self.assertRaises(ValueError):
                    owner.verify_copies()
            finally:
                (self.base / 'outside-link').unlink()

    def test_runtime_path_mapping_mutation_is_rejected(self):
        owner = self.create()
        paths = owner.paths
        try:
            owner.paths = {'/cert/key.pem': str(self.fs.path('/cert/key.pem'))}
            with self.assertRaises(ValueError):
                owner.verify_copies()
        finally:
            owner.paths = paths
            owner.cleanup()

    def test_cleanup_foreign_child_refuses_before_deleting_owned_files(self):
        owner = self.create()
        foreign = owner.root / 'foreign'
        foreign.write_bytes(b'keep')
        with self.assertRaises(ValueError):
            owner.cleanup()
        self.assertTrue(Path(owner.paths['/cert/key.pem']).is_file())
        self.assertEqual(foreign.read_bytes(), b'keep')
        foreign.unlink()
        owner.cleanup()

    def test_empty_generated_new_site_is_incomplete(self):
        import shutil
        shutil.rmtree(self.fs.path(self.site))
        self.generated[self.site + '/index.html'] = GeneratedFile(b'')
        with self.assertRaises(ValueError):
            self.create()

    def test_permission_rejection_and_original_read_only_open_flags(self):
        api = self.api()
        original_open = os.open
        calls = []

        def monitored_open(path, flags, *args, **kwargs):
            calls.append((str(path), flags))
            return original_open(path, flags, *args, **kwargs)

        with patch.object(api.os, 'open', side_effect=monitored_open), self.create() as owner:
            for path, flags in calls:
                if str(self.fs.root) in path or path in {'fullchain.pem', 'key.pem', 'ca-certificates.crt'}:
                    self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            for uid, gid in ((0, 65534), (65534, 0), (True, 65534), (65534, '65534')):
                with self.subTest(uid=uid, gid=gid), self.assertRaises(ValueError):
                    owner.prepare_read_access(uid, gid)
            owner.verify_sources()
            owner.verify_copies()

    @unittest.skipUnless(os.name == 'posix', 'Нужен Linux tmpfs FD')
    def test_live_requires_confirmed_tmpfs(self):
        api = self.api()
        with (patch.object(TargetFS, 'is_live', new_callable=PropertyMock,
                           return_value=True), patch.object(api, '_confirmed_tmpfs', return_value=False),
              self.assertRaises(ValueError)):
            self.create()
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_missing_material_and_alias_substitution_fail_closed(self):
        self.fs.path('/etc/nginx/mime.types').unlink()
        with self.assertRaises(ValueError):
            self.create()
        self.write('/etc/nginx/mime.types', b'types {}')
        self.generated['/etc/lucx-post-configurator/tls/certificate.pem'] = GeneratedFile(
            symlink_target='/etc/nginx/mime.types')
        with self.assertRaises(ValueError):
            self.create()
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_caps_and_deadline_reject_without_successful_truncation(self):
        api = self.api()
        for limits in (api.MaterialLimits(max_file_bytes=4), api.MaterialLimits(max_total_bytes=20),
                       api.MaterialLimits(max_entries=2), api.MaterialLimits(max_depth=1)):
            self.write(self.site + '/one/two/a.css', b'css')
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                self.create(limits=limits)
            self.assertEqual(list(self.parent.iterdir()), [])
        with (patch('lucx_post_configurator.staging_materials.time.monotonic', side_effect=[0, 100]),
              self.assertRaises(ValueError)):
            self.create(timeout=1)

    def test_copy_drift_and_foreign_root_cleanup_rejected(self):
        owner = self.create()
        original = owner.root
        displaced = original.with_name(original.name + '-displaced')
        original.rename(displaced)
        original.mkdir()
        sentinel = original / 'foreign'
        sentinel.write_bytes(b'keep')
        with self.assertRaises(ValueError):
            owner.verify_copies()
        with self.assertRaises(ValueError):
            owner.cleanup()
        self.assertEqual(sentinel.read_bytes(), b'keep')
        sentinel.unlink()
        original.rmdir()
        displaced.rename(original)
        owner.cleanup()

    @unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: -1)() == 0,
                         'Нужен Linux root для fchown private copies')
    def test_prepare_read_access_changes_only_owned_copy_permissions(self):
        original = self.fs.path('/cert/key.pem').stat()
        with self.create() as owner:
            digest = owner.snapshot_digest
            owner.prepare_read_access(65534, 65534)
            self.assertNotEqual(digest, owner.snapshot_digest)
            for path in (owner.root, *owner.root.rglob('*')):
                actual = path.stat()
                self.assertEqual((actual.st_uid, actual.st_gid), (0, 65534))
                self.assertEqual(stat.S_IMODE(actual.st_mode), 0o710 if path.is_dir() else 0o640)
            owner.verify_sources()
            owner.verify_copies()
        current = self.fs.path('/cert/key.pem').stat()
        self.assertEqual((current.st_uid, current.st_gid, current.st_mode),
                         (original.st_uid, original.st_gid, original.st_mode))

    @unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda: -1)() == 0,
                         'Нужен Linux root для fchown private copies')
    def test_partial_permission_failure_cleans_up_owned_root(self):
        api = self.api()
        owner = self.create()
        original = owner.root
        with patch.object(api.os, 'fchmod', side_effect=OSError('fixture failure')), self.assertRaises(ValueError):
            owner.prepare_read_access(65534, 65534)
        self.assertFalse(original.exists())

    @unittest.skipUnless(os.name == 'posix', 'Нужны POSIX owner/mode')
    def test_mode_owner_and_tree_membership_drift_rejected(self):
        with self.create() as owner:
            os.chmod(self.fs.path('/cert/key.pem'), 0o640)
            with self.assertRaises(ValueError):
                owner.verify_sources()
        with self.create() as owner:
            self.write(self.site + '/late.css', b'css')
            with self.assertRaises(ValueError):
                owner.verify_sources()
        if os.geteuid() == 0:
            with self.create() as owner:
                os.chown(self.fs.path('/cert/key.pem'), 65534, 65534)
                with self.assertRaises(ValueError):
                    owner.verify_sources()

    @unittest.skipUnless(os.name == 'posix', 'Нужны POSIX symlink')
    def test_cert_symlink_loop_and_hop_limit_fail_closed(self):
        source = self.fs.path('/cert/fullchain.pem')
        source.unlink()
        source.symlink_to('fullchain.pem')
        with self.assertRaises(ValueError):
            self.create()
        source.unlink()
        source.symlink_to('/archive/first.pem')
        self.write('/archive/last.pem', b'cert')
        self.fs.path('/archive/first.pem').symlink_to('last.pem')
        with self.assertRaises(ValueError):
            self.create(limits=self.api().MaterialLimits(max_symlink_hops=1))
        with self.create() as owner:
            self.assertEqual(Path(owner.paths['/cert/fullchain.pem']).read_bytes(), b'cert')

    @unittest.skipUnless(os.name == 'posix', 'Нужны POSIX symlink и dir_fd')
    def test_certbot_chain_referent_and_link_drift_are_rejected(self):
        source = self.fs.path('/cert/fullchain.pem')
        source.unlink()
        self.write('/archive/cert-v1.pem', b'certificate-fixture\r\n')
        source.symlink_to('../archive/cert-v1.pem')
        with self.create() as owner:
            self.assertFalse(Path(owner.paths['/cert/fullchain.pem']).is_symlink())
            self.write('/archive/cert-v1.pem', b'changed referent')
            with self.assertRaises(ValueError):
                owner.verify_sources()
        with self.create() as owner:
            source.unlink()
            source.symlink_to('../archive/cert-v1.pem')
            with self.assertRaises(ValueError):
                owner.verify_sources()

    @unittest.skipUnless(os.name == 'posix', 'Нужны POSIX special files')
    def test_site_symlink_fifo_and_ancestor_symlink_are_rejected(self):
        unsafe = self.fs.path(self.site + '/unsafe')
        unsafe.symlink_to(self.fs.path('/cert/key.pem'))
        with self.assertRaises(ValueError):
            self.create()
        unsafe.unlink()
        os.mkfifo(unsafe)
        with self.assertRaises(ValueError):
            self.create()
        unsafe.unlink()
        cert = self.fs.path('/cert')
        moved = self.fs.path('/cert-real')
        cert.rename(moved)
        cert.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.create()

    @unittest.skipUnless(os.name == 'posix', 'Нужен POSIX FD')
    def test_source_changed_during_fd_read_rejected(self):
        self.api()
        original_read = os.read
        changed = False

        def racing_read(fd, size):
            nonlocal changed
            data = original_read(fd, size)
            if data == b'key-fixture\x00\r\n' and not changed:
                changed = True
                self.write('/cert/key.pem', b'race')
            return data

        with (patch('lucx_post_configurator.staging_materials.os.read', side_effect=racing_read),
              self.assertRaises(ValueError)):
            self.create()
        self.assertTrue(changed)
        self.assertEqual(list(self.parent.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
