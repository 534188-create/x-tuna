from __future__ import annotations

import copy
import unittest

from lucx_post_configurator.migrations import CURRENT_SCHEMA_VERSION, migrate_manifest
from lucx_post_configurator.models import ConfigurationError, default_manifest


class MigrationTests(unittest.TestCase):
    def test_v2_sync_share_addr_migrates_to_public_endpoint_sync(self) -> None:
        source = {
            "schema_version": 2,
            "lucx": {"settings_management": {}},
            "protocols": [{"inbound_id": 7, "sync_share_addr": True}],
        }
        migrated = migrate_manifest(source)
        self.assertTrue(migrated["protocols"][0]["sync_public_endpoint"])
        self.assertTrue(migrated["lucx"]["settings_management"]["sync_public_endpoints"])
        self.assertNotIn("sync_public_endpoint", source["protocols"][0])
    def test_v1_manifest_migrates_without_mutating_source(self) -> None:
        source = default_manifest()
        source["schema_version"] = 1
        source["decoys"].pop("capabilities", None)
        source.pop("integrity", None)
        original = copy.deepcopy(source)

        migrated = migrate_manifest(source)

        self.assertEqual(migrated["schema_version"], CURRENT_SCHEMA_VERSION)
        self.assertEqual(migrated["decoys"]["capabilities"], [])
        self.assertEqual(
            migrated["integrity"],
            {"protected_lucx": {}, "naive_caddyfile": {}},
        )
        self.assertEqual(source, original)

    def test_v2_manifest_migrates_to_strict_extended_defaults(self) -> None:
        source = default_manifest()
        source["schema_version"] = 2
        for key in (
            "routing_mode",
            "extended_user_confirmed",
            "extended_routes",
            "naive_frontends",
        ):
            source["decoys"].pop(key, None)
        source["components"].pop("extended_tls_split", None)
        source["components"].pop("naive_frontend", None)
        original = copy.deepcopy(source)

        migrated = migrate_manifest(source)

        self.assertEqual(migrated["schema_version"], 3)
        self.assertEqual(migrated["decoys"]["routing_mode"], "strict")
        self.assertFalse(migrated["decoys"]["extended_user_confirmed"])
        self.assertEqual(migrated["decoys"]["extended_routes"], [])
        self.assertEqual(migrated["decoys"]["naive_frontends"], [])
        self.assertFalse(migrated["components"]["extended_tls_split"])
        self.assertFalse(migrated["components"]["naive_frontend"])
        self.assertEqual(source, original)

    def test_current_manifest_returns_an_independent_copy(self) -> None:
        source = default_manifest()
        migrated = migrate_manifest(source)
        migrated["dns"]["servers"].append("192.0.2.1")
        self.assertNotIn("192.0.2.1", source["dns"]["servers"])

    def test_unknown_newer_manifest_is_rejected_for_mutation(self) -> None:
        source = default_manifest()
        source["schema_version"] = CURRENT_SCHEMA_VERSION + 1
        with self.assertRaisesRegex(ConfigurationError, "newer manifest schema"):
            migrate_manifest(source)

    def test_invalid_legacy_version_is_rejected(self) -> None:
        source = default_manifest()
        source["schema_version"] = 0
        with self.assertRaisesRegex(ConfigurationError, "unsupported manifest schema"):
            migrate_manifest(source)


if __name__ == "__main__":
    unittest.main()
