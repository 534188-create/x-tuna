from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lucx_post_configurator.runner import CommandResult, Runner
from lucx_post_configurator.trusttunnel_backend import (
    BackendProbe,
    probe_backend,
    validate_backend_manifest,
    render_backend_config,
    render_backend_unit,
    pin_backend,
    read_backend_credentials,
    discover_existing_backend_credentials,
)


class TrustTunnelBackendTests(unittest.TestCase):
    def test_unknown_binary_is_not_considered_compatible(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            result = probe_backend(Runner(dry_run=True), binary="/missing/backend", loopback_port=26444)
        self.assertFalse(result.ready)
        self.assertTrue(result.reasons)

    def test_manifest_rejects_backend_without_probe(self) -> None:
        with self.assertRaises(ValueError):
            validate_backend_manifest(
                {"components": {"trusttunnel_backend": True}},
                BackendProbe(binary="backend"),
            )

    def test_manifest_accepts_only_ready_probe(self) -> None:
        validate_backend_manifest(
            {"components": {"trusttunnel_backend": True}},
            BackendProbe(ready=True, protocol_handshake=True),
        )

    def test_manifest_rejects_ready_flag_without_protocol_handshake(self) -> None:
        with self.assertRaises(ValueError):
            validate_backend_manifest(
                {"components": {"trusttunnel_backend": True}},
                BackendProbe(ready=True, protocol_handshake=False),
            )

    def test_manifest_rejects_unconfirmed_backend_configuration(self) -> None:
        from lucx_post_configurator.models import default_manifest, validate_manifest

        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.test"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.test"
        manifest["certificates"]["cert_path"] = "/etc/ssl/cert.pem"
        manifest["certificates"]["key_path"] = "/etc/ssl/key.pem"
        manifest["network"]["public_bind_address"] = "203.0.113.10"
        manifest["components"]["trusttunnel_backend"] = True
        manifest["trusttunnel_backend"].update(
            {
                "user_confirmed": False,
                "listen_port": 26444,
                "public_domain": "tt.example.test",
                "binary_path": "/opt/x-tuna/bin/backend",
                "sha256": "0" * 64,
                "credentials": [{"username": "probe", "password": "secret"}],
            }
        )
        with self.assertRaises(ValueError):
            validate_manifest(manifest)

    def test_manifest_accepts_confirmed_pinned_backend(self) -> None:
        from lucx_post_configurator.models import default_manifest, validate_manifest

        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.test"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.test"
        manifest["certificates"]["cert_path"] = "/etc/ssl/cert.pem"
        manifest["certificates"]["key_path"] = "/etc/ssl/key.pem"
        manifest["network"]["public_bind_address"] = "203.0.113.10"
        manifest["components"]["trusttunnel_backend"] = True
        manifest["trusttunnel_backend"].update(
            {
                "user_confirmed": True,
                "listen_port": 26444,
                "public_domain": "tt.example.test",
                "binary_path": "/opt/x-tuna/bin/backend",
                "sha256": "0" * 64,
                "credentials": [{"username": "probe", "password": "secret"}],
            }
        )
        manifest["decoys"]["sites"].append({"domain": "tt.example.test", "root": "/var/www/lucx-decoys/tt.example.test"})
        validate_manifest(manifest)

    def test_probe_requires_explicit_http2_connect_and_standard_uri(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "backend"
            binary.write_bytes(b"placeholder")
            version = CommandResult([str(binary), "--version"], 0, "compatible 1.0", "")
            help_result = CommandResult(
                [str(binary), "--help"],
                0,
                "tcp http2-connect standard-uri --config",
                "",
            )
            runner = mock.Mock(spec=Runner)
            runner.run.side_effect = [version, help_result]
            with mock.patch(
                "lucx_post_configurator.trusttunnel_backend._probe_port",
                return_value=True,
            ), mock.patch(
                "lucx_post_configurator.trusttunnel_backend.http2_connect_roundtrip",
                return_value=True,
            ):
                result = probe_backend(runner, binary=binary, loopback_port=26444)
        self.assertFalse(result.ready)
        self.assertTrue(result.capability_ready)
        self.assertFalse(result.live_ready)
        self.assertEqual(result.version, "compatible 1.0")
        self.assertFalse(result.protocol_handshake)
        self.assertEqual(result.protocol_probe_state, "not_checked")
        self.assertNotIn("не прошёл реальный", "; ".join(result.reasons))

    def test_occupied_active_endpoint_is_not_a_staging_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "trusttunnel_endpoint"
            binary.write_bytes(b"placeholder")
            runner = mock.Mock(spec=Runner)
            runner.run.side_effect = [
                CommandResult([str(binary), "--version"], 0, "TrustTunnel v1.1.0", ""),
                CommandResult(
                    [str(binary), "--help"],
                    0,
                    "trusttunnel_endpoint vpn.toml hosts.toml",
                    "",
                ),
            ]
            with mock.patch(
                "lucx_post_configurator.trusttunnel_backend._probe_port",
                return_value=False,
            ), mock.patch(
                "lucx_post_configurator.trusttunnel_backend.http2_connect_roundtrip",
                return_value=True,
            ):
                result = probe_backend(
                    runner,
                    binary=binary,
                    loopback_port=26444,
                    protocol_host="127.0.0.1",
                    protocol_username="probe",
                    protocol_password="secret",
                    protocol_target_port=9,
                )

        self.assertTrue(result.ready)
        self.assertTrue(result.live_ready)
        self.assertEqual(result.staging_port_state, "occupied")
        self.assertEqual(result.protocol_probe_state, "observed")
        self.assertNotIn("уже занят", "; ".join(result.reasons))

    def test_missing_optional_candidate_does_not_claim_lucx_vpn_is_dead(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            result = probe_backend(
                Runner(dry_run=True),
                binary="/missing/optional-candidate",
                loopback_port=26444,
            )

        self.assertFalse(result.ready)
        self.assertFalse(result.live_ready)
        self.assertEqual(result.metadata_state, "not_observed")
        self.assertNotIn("VPN", "; ".join(result.reasons))

    def test_official_endpoint_accepts_positional_toml_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "trusttunnel_endpoint"
            binary.write_bytes(b"placeholder")
            version = CommandResult([str(binary), "--version"], 0, "TrustTunnel v1.1.0", "")
            help_result = CommandResult(
                [str(binary), "--help"],
                0,
                "trusttunnel_endpoint vpn.toml hosts.toml -c USER --format deeplink tcp HTTP/2 CONNECT standard-uri throne-uri",
                "",
            )
            runner = mock.Mock(spec=Runner)
            runner.run.side_effect = [version, help_result]
            with mock.patch(
                "lucx_post_configurator.trusttunnel_backend._probe_port",
                return_value=True,
            ), mock.patch(
                "lucx_post_configurator.trusttunnel_backend.http2_connect_roundtrip",
                return_value=True,
            ):
                result = probe_backend(
                    runner,
                    binary=binary,
                    loopback_port=26444,
                    protocol_host="127.0.0.1",
                    protocol_username="probe",
                    protocol_password="secret",
                    protocol_target_port=9,
                )
        self.assertTrue(result.supports_config_file)
        self.assertTrue(result.protocol_handshake)
        self.assertTrue(result.ready)

    def test_official_endpoint_uses_confirmed_positional_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "trusttunnel_endpoint"
            binary.write_bytes(b"placeholder")
            runner = mock.Mock(spec=Runner)
            runner.run.side_effect = [
                CommandResult([str(binary), "--version"], 0, "TrustTunnel v1.1.0", ""),
                CommandResult([str(binary), "--help"], 0, "trusttunnel_endpoint vpn.toml hosts.toml", ""),
            ]
            with mock.patch("lucx_post_configurator.trusttunnel_backend._probe_port", return_value=True), mock.patch(
                "lucx_post_configurator.trusttunnel_backend.http2_connect_roundtrip", return_value=True
            ):
                result = probe_backend(
                    runner,
                    binary=binary,
                    loopback_port=26444,
                    protocol_host="127.0.0.1",
                    protocol_username="probe",
                    protocol_password="secret",
                    protocol_target_port=9,
                )
        self.assertTrue(result.ready)

    def test_endpoint_roundtrip_uses_official_positional_configs(self) -> None:
        from lucx_post_configurator import trusttunnel_backend as backend

        class FakeProcess:
            def __init__(self, args, **kwargs):
                self.args = args
                self.returncode = None

            def poll(self):
                return self.returncode

            def terminate(self):
                self.returncode = 0

            def wait(self, timeout=None):
                return 0

        with mock.patch.object(backend.subprocess, "Popen", FakeProcess), mock.patch.object(
            backend, "_probe_port", side_effect=[True, False]
        ), mock.patch.object(backend, "http2_connect_roundtrip", return_value=True):
            self.assertTrue(
                backend.run_endpoint_roundtrip(
                    "/opt/trusttunnel/trusttunnel_endpoint",
                    "/tmp/vpn.toml",
                    "/tmp/hosts.toml",
                    username="probe",
                    password="secret",
                    listen_port=26444,
                    server_name="tt.example.test",
                )
            )

    def test_rendered_backend_is_loopback_only_and_http2_aware(self) -> None:
        manifest = {
            "trusttunnel_backend": {
                "binary_path": "/opt/x-tuna/bin/backend",
                "listen_host": "127.0.0.1",
                "listen_port": 26444,
                "public_domain": "tt.example.test",
                "public_port": 443,
            }
        }
        config = render_backend_config(manifest).decode("utf-8")
        unit = render_backend_unit(manifest).decode("utf-8")
        self.assertIn('"listen": "127.0.0.1:26444"', config)
        self.assertIn('"http2_connect": true', config)
        self.assertIn("/etc/x-tuna/trusttunnel/vpn.toml /etc/x-tuna/trusttunnel/hosts.toml", unit)
        self.assertIn("User=root", unit)
        self.assertIn("StateDirectory=x-tuna/trusttunnel", unit)
        self.assertNotIn("0.0.0.0", config)

    def test_official_endpoint_routes_http_paths_to_decoy_but_keeps_connect_tunnel(self) -> None:
        from lucx_post_configurator.trusttunnel_backend import render_backend_vpn_toml

        manifest = {
            "trusttunnel_backend": {
                "listen_host": "127.0.0.1",
                "listen_port": 26444,
                "decoy_address": "127.0.0.1:8446",
            }
        }
        config = render_backend_vpn_toml(manifest).decode("utf-8")
        self.assertIn('[reverse_proxy]', config)
        self.assertIn('server_address = "127.0.0.1:8446"', config)
        self.assertIn('path_mask = "/"', config)
        self.assertIn('non_connect_auth_failure_status_code = 404', config)
        self.assertIn('[forward_protocol]', config)

    def test_backend_reverse_proxy_uses_plain_loopback_decoy_port(self) -> None:
        from lucx_post_configurator.trusttunnel_backend import render_backend_vpn_toml

        config = render_backend_vpn_toml({"trusttunnel_backend": {"listen_host": "127.0.0.1", "listen_port": 26444}}).decode()
        self.assertIn('server_address = "127.0.0.1:8446"', config)
        self.assertNotIn('server_address = "127.0.0.1:8444"', config)

    def test_backend_production_config_disallows_private_connect_targets(self) -> None:
        from lucx_post_configurator.trusttunnel_backend import render_backend_vpn_toml

        config = render_backend_vpn_toml(
            {"trusttunnel_backend": {"listen_host": "127.0.0.1", "listen_port": 26454}}
        ).decode()
        self.assertIn("allow_private_network_connections = false", config)
        self.assertIn('non_connect_auth_failure_status_code = 404', config)

    def test_backend_route_is_loopback_and_public_sni_is_not_lucx_listener(self) -> None:
        from lucx_post_configurator.renderers import render_haproxy

        manifest = {
            "network": {"public_bind_address": "203.0.113.10", "public_tcp_port": 443},
            "lucx": {
                "panel": {"domain": "panel.example.test", "internal_host": "127.0.0.1", "internal_port": 2083},
                "subscription": {"domain": "sub.example.test", "internal_host": "127.0.0.1", "internal_port": 2096},
            },
            "components": {"trusttunnel_backend": True},
            "trusttunnel_backend": {
                "public_domain": "tt.example.test",
                "public_port": 443,
                "listen_host": "127.0.0.1",
                "listen_port": 26454,
            },
            "protocols": [
                {"inbound_id": 9, "protocol": "trusttunnel", "domain": "tt.example.test", "public_port": 443, "internal_host": "127.0.0.1", "internal_port": 9443, "network": "tcp", "exposure": "tcp_sni", "security": "tls"},
            ],
            "decoys": {
                "enabled": True,
                "routing_mode": "extended",
                "extended_user_confirmed": True,
                "listen_host": "127.0.0.1",
                "listen_port": 8444,
                "sites": [{"domain": "tt.example.test", "root": "/var/www/tt"}],
                "extended_routes": [{
                    "inbound_id": 9,
                    "domain": "tt.example.test",
                    "public_port": 443,
                    "strategy": "trusttunnel_clienthello_split",
                    "status": "ready",
                    "internal_host": "127.0.0.1",
                    "internal_port": 9443,
                    "sni_names": [],
                }],
            },
            "cloudflare": {"enabled": False},
        }
        # Проверяем назначение backend по текущим фактам, без устаревшего ручного кэша.
        manifest["protocols"][0]["sni_names"] = ["tt.example.test"]
        manifest["decoys"]["extended_routes"] = []
        rendered = render_haproxy(manifest)
        self.assertIn("use_backend be_trusttunnel_compatible", rendered)
        self.assertIn("127.0.0.1:26454", rendered)
        self.assertNotIn("be_inbound_9", rendered)

    def test_backend_config_contains_no_credentials(self) -> None:
        import json

        manifest = {
            "trusttunnel_backend": {
                "binary_path": "/opt/x-tuna/bin/backend",
                "listen_host": "127.0.0.1",
                "listen_port": 26444,
                "public_domain": "tt.example.test",
            "public_port": 443,
            "credentials": [{"username": "probe", "password": "secret"}],
            }
        }
        config = json.loads(render_backend_config(manifest))
        self.assertNotIn("username", config)
        self.assertNotIn("password", config)

    def test_real_trusttunnel_files_are_rendered_with_root_only_credentials(self) -> None:
        from lucx_post_configurator.models import default_manifest
        from lucx_post_configurator.renderers import render_files

        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.test"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.test"
        manifest["certificates"].update({"cert_path": "/etc/ssl/cert.pem", "key_path": "/etc/ssl/key.pem"})
        manifest["network"]["public_bind_address"] = "203.0.113.10"
        manifest["components"]["trusttunnel_backend"] = True
        manifest["trusttunnel_backend"].update({
            "user_confirmed": True,
            "listen_port": 26444,
            "public_domain": "tt.example.test",
            "binary_path": "/opt/x-tuna/bin/backend",
            "sha256": "0" * 64,
            "credentials": [{"username": "alice", "password": "secret"}],
        })
        manifest["decoys"]["sites"].append({"domain": "tt.example.test", "root": "/var/www/lucx-decoys/tt.example.test"})
        files = render_files(manifest)
        self.assertIn("/etc/x-tuna/trusttunnel/vpn.toml", files)
        self.assertEqual(files["/etc/x-tuna/trusttunnel/credentials.toml"].mode, 0o600)
        self.assertIn(b"username = \"alice\"", files["/etc/x-tuna/trusttunnel/credentials.toml"].content)

    def test_backend_credentials_can_be_reloaded_from_toml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.toml"
            path.write_text(
                '[[client]]\nusername = "alice"\npassword = "secret"\n\n',
                encoding="utf-8",
            )
            self.assertEqual(
                read_backend_credentials(path),
                [{"username": "alice", "password": "secret"}],
            )

    def test_existing_backend_credentials_are_discovered_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "usr/local/x-ui/bin/tunnel"
            path.mkdir(parents=True)
            (path / "trusttunnel-9-credentials.toml").write_text(
                '[[client]]\nusername = "alice"\npassword = "secret"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                discover_existing_backend_credentials(directory),
                [{"username": "alice", "password": "secret"}],
            )

    def test_planner_exposes_backend_as_separate_service(self) -> None:
        from lucx_post_configurator.models import default_manifest
        from lucx_post_configurator.planner import build_plan

        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.test"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.test"
        manifest["certificates"]["cert_path"] = "/etc/ssl/cert.pem"
        manifest["certificates"]["key_path"] = "/etc/ssl/key.pem"
        manifest["network"]["public_bind_address"] = "203.0.113.10"
        manifest["components"]["trusttunnel_backend"] = True
        manifest["trusttunnel_backend"].update({
            "user_confirmed": True,
            "listen_port": 26444,
            "public_domain": "tt.example.test",
            "binary_path": "/opt/x-tuna/bin/backend",
            "sha256": "0" * 64,
            "credentials": [{"username": "probe", "password": "secret"}],
        })
        manifest["decoys"]["sites"].append({"domain": "tt.example.test", "root": "/var/www/lucx-decoys/tt.example.test"})
        actions = [item for item in build_plan(manifest)["actions"]
                   if item["component"] == "trusttunnel_backend"]
        self.assertEqual(len(actions), 1)
        self.assertIn("HTTP/2 CONNECT", actions[0]["description"])
        self.assertIn("x-tuna-trusttunnel-backend.service", actions[0]["services"])

    def test_pin_backend_records_sha256_without_exposing_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "backend"
            binary.write_bytes(b"verified backend")
            pinned = pin_backend(binary, source="local-cache")
        self.assertEqual(pinned["source"], "local-cache")
        self.assertEqual(len(pinned["sha256"]), 64)
        self.assertNotIn("verified backend", str(pinned))
