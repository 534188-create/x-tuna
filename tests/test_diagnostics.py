from __future__ import annotations

import json
import tempfile
import unittest

from lucx_post_configurator.diagnostics import redact, stable_fingerprint


class DiagnosticsTests(unittest.TestCase):
    def test_transport_and_download_paths_are_private_in_export_but_resumable(self) -> None:
        marker = "synthetic-private-path-marker"
        source = {"transport_path": "/" + marker,
                  "transport_details": {"download": {"transport_path": "/download?token=" + marker}}}
        self.assertNotIn(marker, json.dumps(redact(source)))
        self.assertEqual(redact(source, network=False), source)

    def test_relative_sensitive_url_is_hidden_inside_diagnostic_error(self) -> None:
        marker = "synthetic-private-path-marker"
        self.assertNotIn(marker, redact("failed GET /download?token=" + marker))

    def test_failed_state_remains_resumable_but_export_hides_network(self) -> None:
        from lucx_post_configurator.targetfs import TargetFS
        from lucx_post_configurator.transaction import save_failed_state, load_failed_state
        from lucx_post_configurator.models import validate_manifest
        from test_transport_routing_regressions import topology
        manifest = topology()
        manifest["lucx"]["db_path"] = "/etc/x-ui/x-ui.db"
        with tempfile.TemporaryDirectory() as directory:
            fs = TargetFS(directory)
            save_failed_state(fs, {"manifest": manifest})
            restored = load_failed_state(fs)["manifest"]
        validate_manifest(restored)
        self.assertEqual(restored["lucx"], manifest["lucx"])
        self.assertNotIn("panel.example.test", json.dumps(redact(restored)))

    def test_ip_before_punctuation_and_subscription_query_are_redacted(self) -> None:
        value = "failed 203.0.113.9. https://sub.example.test/?subId=synthetic-subscription-value"
        result = redact(value)
        self.assertNotIn("203.0.113.9", result)
        self.assertNotIn("synthetic-subscription-value", result)

    def test_network_identifiers_are_fingerprinted_in_keys_urls_and_text(self) -> None:
        domain = "vpn.example.test"
        address = "192.0.2.44"
        ipv6 = "2001:db8::44"
        source = {
            "manifest": {"sites": {domain: {"domain": domain, "address": address}}},
            "error": f"connect {domain}:443 failed at {address} and [{ipv6}]:443",
            "url": f"https://{domain}/status?endpoint={address}",
            "command": ["probe", "--resolve", f"{domain}:443:{address}"],
            "subId": "synthetic-subscription-value",
        }
        serialized = json.dumps(redact(source), ensure_ascii=False)
        for forbidden in (domain, address, ipv6, "synthetic-subscription-value"):
            self.assertNotIn(forbidden, serialized)
        self.assertIn("sha256:", serialized)
        self.assertEqual(redact({"status": "not_tested", "count": 2}),
                         {"status": "not_tested", "count": 2})

    def test_trusttunnel_uri_is_removed_in_error_text(self) -> None:
        value = "failed tt://synthetic-credential@vpn.example.test:443?alpn=h2"
        result = redact(value)
        self.assertNotIn("synthetic-credential", result)
        self.assertNotIn("tt://", result)
        self.assertIn("redacted-uri", result)

    def test_nested_secrets_commands_and_subscription_ids_are_removed(self) -> None:
        source = {
            "private_key": "SECRET-PRIVATE-KEY",
            "nested": {"password": "SECRET-PASSWORD"},
            "url": "https://user:pass@sub.example.com/sub/client-secret?token=SECRET-TOKEN",
            "command": ["tool", "--token", "SECRET-ARGV", "--mode=safe"],
        }

        serialized = json.dumps(redact(source), ensure_ascii=False)

        for forbidden in (
            "SECRET-PRIVATE-KEY",
            "SECRET-PASSWORD",
            "client-secret",
            "SECRET-TOKEN",
            "SECRET-ARGV",
            "user:pass",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertIn("sha256:", serialized)

    def test_connection_uris_and_uuids_inside_error_text_are_removed(self) -> None:
        source = (
            "failed vless://user-secret@example.com:443?security=tls#Name "
            "for 550e8400-e29b-41d4-a716-446655440000"
        )

        redacted = redact(source)

        self.assertNotIn("user-secret", redacted)
        self.assertNotIn("550e8400-e29b-41d4-a716-446655440000", redacted)
        self.assertIn("redacted-uri", redacted)

    def test_oversized_payload_is_replaced_by_fingerprint(self) -> None:
        value = "A" * 5000
        result = redact({"payload": value})
        self.assertNotIn(value, json.dumps(result))
        self.assertIn("redacted-large-value", result["payload"])

    def test_fingerprint_is_short_stable_and_does_not_include_input(self) -> None:
        first = stable_fingerprint("client-secret")
        second = stable_fingerprint("client-secret")
        self.assertEqual(first, second)
        self.assertRegex(first, r"^sha256:[0-9a-f]{12}$")
        self.assertNotIn("client-secret", first)


if __name__ == "__main__":
    unittest.main()
