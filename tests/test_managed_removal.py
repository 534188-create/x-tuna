from __future__ import annotations

import tempfile
import unittest

from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.engine import SIDECAR_MANAGED_TARGETS, _component_removal_targets
from lucx_post_configurator.models import default_manifest
from lucx_post_configurator.transaction import (
    commit_managed_transition,
    create_backup,
    remove_managed_targets,
    restore_backup,
    validated_removal_targets,
)


class ManagedRemovalTests(unittest.TestCase):
    def test_stale_managed_naive_frontend_is_removed_by_hash_when_mode_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            targets = [
                "/etc/lucx-post-configurator/naive/naive-7.caddyfile",
                "/etc/systemd/system/lucx-naive-decoy-7.service",
            ]
            hashes: dict[str, str] = {}
            for target in targets:
                fs.atomic_write_text(target, "managed\n")
                hashes[target] = fs.sha256(target)
            manifest = default_manifest()
            manifest["components"]["naive_frontend"] = False

            self.assertEqual(
                _component_removal_targets(fs, manifest, hashes),
                sorted(targets),
            )

            manifest["components"]["naive_frontend"] = True
            manifest["decoys"]["extended_routes"] = [
                {
                    "inbound_id": 7,
                    "strategy": "naive_managed",
                    "status": "ready",
                }
            ]
            self.assertEqual(_component_removal_targets(fs, manifest, hashes), [])

    def test_component_removal_is_limited_to_disabled_sidecar_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            hashes: dict[str, str] = {}
            for target in SIDECAR_MANAGED_TARGETS:
                fs.atomic_write_text(target, "managed\n")
                hashes[target] = fs.sha256(target)
            manifest = default_manifest()
            manifest["components"]["sidecar"] = False
            self.assertEqual(
                _component_removal_targets(fs, manifest, hashes),
                sorted(SIDECAR_MANAGED_TARGETS),
            )
            manifest["components"]["sidecar"] = True
            self.assertEqual(_component_removal_targets(fs, manifest, hashes), [])

    def test_unchanged_previously_managed_sidecar_files_are_removable_and_restorable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            targets = [
                "/usr/local/libexec/lucx-sub-sidecar.py",
                "/etc/lucx-sub-sidecar/env",
                "/etc/systemd/system/lucx-sub-sidecar.service",
            ]
            hashes: dict[str, str] = {}
            for index, target in enumerate(targets):
                fs.atomic_write_text(target, f"managed-{index}\n")
                hashes[target] = fs.sha256(target)

            removable = validated_removal_targets(fs, hashes, targets)
            self.assertEqual(removable, sorted(targets))
            backup = create_backup(fs, {}, "remove-sidecar", extra_targets=removable)
            remove_managed_targets(fs, removable, hashes)
            self.assertTrue(all(not fs.exists(target) for target in targets))
            restore_backup(fs, backup)
            self.assertTrue(all(fs.exists(target) for target in targets))

    def test_locally_modified_managed_file_blocks_removal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            target = "/etc/lucx-sub-sidecar/env"
            fs.atomic_write_text(target, "old\n")
            installed_hash = fs.sha256(target)
            fs.atomic_write_text(target, "user-change\n")
            with self.assertRaisesRegex(RuntimeError, "changed after the previous apply"):
                validated_removal_targets(fs, {target: installed_hash}, [target])

    def test_never_managed_requested_file_is_not_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            target = "/etc/lucx-sub-sidecar/env"
            fs.atomic_write_text(target, "user-owned\n")
            self.assertEqual(validated_removal_targets(fs, {}, [target]), [])

    def test_commit_transition_writes_new_files_and_removes_disabled_component(self) -> None:
        from lucx_post_configurator.renderers import GeneratedFile

        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            old_target = "/etc/lucx-sub-sidecar/env"
            new_target = "/etc/haproxy/haproxy.cfg"
            fs.atomic_write_text(old_target, "old-sidecar\n")
            hashes = {old_target: fs.sha256(old_target)}
            installed = commit_managed_transition(
                fs,
                {new_target: GeneratedFile(b"new-haproxy\n")},
                [old_target],
                hashes,
            )
            self.assertFalse(fs.exists(old_target))
            self.assertEqual(fs.read_text(new_target), "new-haproxy\n")
            self.assertEqual(installed, {new_target: fs.sha256(new_target)})


if __name__ == "__main__":
    unittest.main()
