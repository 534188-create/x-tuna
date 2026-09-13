from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lucx_post_configurator.certificates import CertificateCandidate
from lucx_post_configurator.discovery import audit_system
from lucx_post_configurator.models import default_manifest, validate_manifest
from lucx_post_configurator.questionnaire import migrate_domain_zone, reconfigure_domains_interactively
from lucx_post_configurator.runner import Runner
from lucx_post_configurator.targetfs import TargetFS

from helpers import make_target


class ReconfigureTests(unittest.TestCase):
    def test_zone_migration_preserves_labels_and_external_sni(self) -> None:
        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.test"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.test"
        manifest["protocols"] = [
            {
                "inbound_id": 1,
                "domain": "test.example.test",
                "sni_names": ["test.example.test", "www.samsung.com"],
                "transport_hosts": ["api.example.test", "cdn.samsung.com"],
                "exposure": "tcp_sni",
            }
        ]
        manifest["decoys"]["sites"] = [
            {"domain": "test.example.test", "root": "/var/www/lucx-decoys/test.example.test"}
        ]
        manifest["decoys"]["extended_routes"] = [
            {
                "inbound_id": 1,
                "domain": "test.example.test",
                "status": "ready",
                "strategy": "naive_managed",
                "sni_names": ["test.example.test"],
            }
        ]
        changed = migrate_domain_zone(manifest, "old.example.test", "new.example.test")
        self.assertEqual(changed["lucx"]["panel"]["domain"], "panel.example.test")
        self.assertEqual(changed["lucx"]["subscription"]["domain"], "sub.example.test")
        self.assertEqual(changed["protocols"][0]["domain"], "test.example.test")
        self.assertEqual(
            changed["protocols"][0]["sni_names"],
            ["test.example.test", "www.samsung.com"],
        )
        self.assertEqual(
            changed["protocols"][0]["transport_hosts"],
            ["api.example.test", "cdn.samsung.com"],
        )
        self.assertEqual(changed["decoys"]["sites"][0]["domain"], "test.example.test")
        self.assertEqual(
            changed["decoys"]["sites"][0]["root"],
            "/var/www/lucx-decoys/test.example.test",
        )
        self.assertEqual(
            changed["decoys"]["extended_routes"][0]["domain"],
            "test.example.test",
        )
        zone_apex = "new.example.test"
        self.assertIn(zone_apex, [item["domain"] for item in changed["decoys"]["sites"]])
        self.assertEqual(
            sorted(item["domain"] for item in changed["decoys"]["capabilities"]),
            sorted(["test.example.test", zone_apex]),
        )
    def test_changes_managed_domains_and_auto_selects_certificate_without_touching_lucx(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            audit = audit_system(root)
            audit.inbounds = audit.inbounds[:1]
            audit.inbounds[0].server_names = ["future-reality-sni.example"]
            for endpoint in audit.inbounds[0].public_endpoints:
                endpoint.update(sni="future-reality-sni.example", sni_source="inherited")
            manifest = default_manifest(audit)
            manifest["protocols"] = [
                {
                    "inbound_id": 1,
                    "protocol": "vless",
                    "remark": "Reality",
                    "domain": "api.example.com",
                    "internal_host": "127.0.0.1",
                    "internal_port": 54703,
                    "public_port": 443,
                    "network": "tcp",
                    "exposure": "tcp_sni",
                    "security": "reality",
                    "sni_names": ["api.example.com"],
                    "port_bindings": [{"port": 54703, "protocol": "TCP"}],
                }
            ]
            manifest["decoys"].update(
                {
                    "enabled": True,
                    "sites": [{"domain": "api.example.com", "root": "/var/www/lucx-decoys/api.example.com"}],
                }
            )
            answers = iter([
                "panel.new.test",
                "",
                "1",
                "sub.new.test",
                "",
                "1",
                "api.new.test",
                "",
            ])
            selected = CertificateCandidate(
                cert_path="/root/.acme.sh/new.test_ecc/fullchain.cer",
                key_path="/root/.acme.sh/new.test_ecc/new.test.key",
                sans=["new.test", "*.new.test"],
                expires_at="2030-01-01T00:00:00+00:00",
                seconds_remaining=1000000,
                wildcard=True,
                key_matches=True,
                source="acme.sh",
            )
            with patch("lucx_post_configurator.questionnaire.select_certificate", return_value=selected):
                changed, warnings = reconfigure_domains_interactively(
                    manifest,
                    audit,
                    TargetFS(root),
                    Runner(dry_run=True),
                    input_fn=lambda _: next(answers),
                    output_fn=lambda _: None,
                )
            validate_manifest(changed)
            self.assertEqual(changed["lucx"]["panel"]["domain"], "panel.new.test")
            self.assertTrue(changed["lucx"]["settings_management"]["sync_domains"])
            self.assertEqual(
                changed["protocols"][0]["sni_names"],
                ["future-reality-sni.example"],
            )
            self.assertEqual(
                changed["decoys"]["sites"],
                [{"domain": "api.new.test", "root": "/var/www/lucx-decoys/api.example.com"}],
            )
            self.assertEqual(changed["certificates"]["cert_path"], selected.cert_path)
            self.assertTrue(any("LucX" in warning for warning in warnings))
            self.assertEqual(audit.settings["webDomain"], "panel.example.com")


    def test_zone_migration_preserves_reality_camouflage_sni(self) -> None:
        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.test"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.test"
        manifest["protocols"] = [{
            "inbound_id": 2,
            "domain": "test1.example.test",
            "security": "reality",
            "sni_names": ["www.samsung.com", "api.example.test"],
        }]
        changed = migrate_domain_zone(manifest, "old.example.test", "new.example.test")
        self.assertEqual(changed["protocols"][0]["domain"], "test1.example.test")
        self.assertEqual(changed["protocols"][0]["sni_names"], ["www.samsung.com", "api.example.test"])


if __name__ == "__main__":
    unittest.main()
