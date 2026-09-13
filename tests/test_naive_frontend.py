from __future__ import annotations

import hashlib
import unittest

from lucx_post_configurator.naive_frontend import (
    NaiveFrontendError,
    frontend_sync_state,
    parse_naive_caddyfile,
    render_managed_naive_caddyfile,
    render_naive_frontend_unit,
    supports_native_decoy,
)


GENERATED_SOURCE = """{
    admin off
    skip_install_trust
    auto_https off
    log {
        level WARN
    }
    servers {
        protocols h1 h2
    }
}

:47863, naive.example.net:47863 {
    bind 127.0.0.1
    tls /cert/fullchain.pem /cert/privkey.pem
    log {
        output file /var/log/x-ui/naive.json
        format json
    }
    route {
        forward_proxy {
            basic_auth user-one pass-one
            basic_auth "user two" "pass two"
            hide_ip
            hide_via
            probe_resistance
            upstream socks5://bridge:secret@127.0.0.1:1080
        }
    }
}
"""


class NaiveFrontendTests(unittest.TestCase):
    def test_generated_source_is_parsed_without_losing_forward_proxy_options(self) -> None:
        parsed = parse_naive_caddyfile(GENERATED_SOURCE)

        self.assertEqual(parsed.auth_pairs, [("user-one", "pass-one"), ("user two", "pass two")])
        self.assertTrue(parsed.hide_ip)
        self.assertTrue(parsed.hide_via)
        self.assertTrue(parsed.probe_resistance)
        self.assertEqual(parsed.upstream, "socks5://bridge:secret@127.0.0.1:1080")
        self.assertEqual(parsed.source_sha256, hashlib.sha256(GENERATED_SOURCE.encode()).hexdigest())

    def test_unknown_or_ambiguous_directive_blocks_managed_frontend(self) -> None:
        source = GENERATED_SOURCE.replace("            hide_via\n", "            unknown_option enabled\n")
        with self.assertRaisesRegex(NaiveFrontendError, "unknown_option"):
            parse_naive_caddyfile(source)
        with self.assertRaisesRegex(NaiveFrontendError, "unsupported block"):
            parse_naive_caddyfile(GENERATED_SOURCE.replace("forward_proxy", "not_a_proxy"))

    def test_managed_frontend_serves_get_head_and_preserves_connect_auth(self) -> None:
        parsed = parse_naive_caddyfile(GENERATED_SOURCE)

        rendered = render_managed_naive_caddyfile(
            parsed,
            domain="naive.example.net",
            listen_port=26443,
            cert_path="/cert/fullchain.pem",
            key_path="/cert/privkey.pem",
            site_root="/var/www/lucx-decoys/naive.example.net",
        )

        self.assertIn("bind 127.0.0.1", rendered)
        self.assertIn("@browser method GET HEAD", rendered)
        self.assertIn("handle @browser", rendered)
        self.assertIn('header X-LucX-Decoy "naive.example.net"', rendered)
        self.assertIn("file_server", rendered)
        self.assertIn('basic_auth "user two" "pass two"', rendered)
        self.assertIn('upstream "socks5://bridge:secret@127.0.0.1:1080"', rendered)
        self.assertNotIn(":47863", rendered)
        self.assertNotIn("/var/log/x-ui/naive.json", rendered)

    def test_native_mode_requires_forward_proxy_and_file_server_in_same_site(self) -> None:
        native = GENERATED_SOURCE.replace(
            "        forward_proxy {",
            "        @browser method GET HEAD\n        handle @browser {\n            root * /var/www/site\n            file_server\n        }\n        forward_proxy {",
        )
        self.assertTrue(supports_native_decoy(native))
        self.assertFalse(supports_native_decoy(GENERATED_SOURCE))
        self.assertFalse(supports_native_decoy(GENERATED_SOURCE + "\n:9443 { file_server }\n"))

    def test_unit_uses_discovered_binary_and_root_only_managed_config(self) -> None:
        rendered = render_naive_frontend_unit(
            inbound_id=7,
            binary_path="/usr/local/x-ui/bin/caddy-naive-linux-amd64",
        )

        self.assertIn("/usr/local/x-ui/bin/caddy-naive-linux-amd64 run", rendered)
        self.assertIn("/etc/lucx-post-configurator/naive/naive-7.caddyfile", rendered)
        self.assertIn("UMask=0077", rendered)
        self.assertIn("ProtectSystem=strict", rendered)
        self.assertIn("ProtectHome=read-only", rendered)
        self.assertNotIn("ProtectHome=yes", rendered)
        self.assertIn("Environment=HOME=/var/lib/lucx-naive-decoy-7", rendered)
        self.assertIn("XDG_CONFIG_HOME=/var/lib/lucx-naive-decoy-7/config", rendered)
        self.assertIn("StateDirectory=lucx-naive-decoy-7", rendered)
        self.assertIn("StateDirectoryMode=0700", rendered)
        self.assertIn("XDG_DATA_HOME=/var/lib/lucx-naive-decoy-7", rendered)
        self.assertNotIn("ReadWritePaths=", rendered)

    def test_source_hash_drift_requires_transactional_resync(self) -> None:
        expected = hashlib.sha256(GENERATED_SOURCE.encode()).hexdigest()
        self.assertEqual(frontend_sync_state(expected, expected), "ready")
    def test_sync_script_and_units_rendered_properly(self) -> None:
        from lucx_post_configurator.naive_frontend import (
            render_naive_sync_path,
            render_naive_sync_script,
            render_naive_sync_unit,
        )

        script = render_naive_sync_script()
        self.assertIn("[lucx-naive-sync]", script)
        self.assertIn("--sync-naive-inbound", script)
        self.assertNotIn("os.replace", script)
        self.assertNotIn("try-restart", script)

        path_unit = render_naive_sync_path(5)
        self.assertIn("PathModified=/usr/local/x-ui/bin/tunnel/naive-5.caddyfile", path_unit)
        self.assertIn("Unit=lucx-naive-sync-5.service", path_unit)

        sync_unit = render_naive_sync_unit(5)
        self.assertIn("ExecStart=/usr/local/libexec/lucx-naive-sync.py 5", sync_unit)


if __name__ == "__main__":
    unittest.main()
