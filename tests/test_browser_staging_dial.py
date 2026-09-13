"""Логический endpoint не меняется вслед за адресом временного listener."""
from __future__ import annotations

import copy
import http.server
import json
import shutil
import ssl
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from lucx_post_configurator import decoy_health as health
from lucx_post_configurator.models import default_manifest
from lucx_post_configurator.runner import CommandResult, Runner
from lucx_post_configurator.validation import validate_required_acceptance


class WireInputRunner(Runner):
    """Проверяет построение stdin curl; это не функциональная HTTP/2-приёмка."""
    def __init__(self):
        super().__init__()
        self.calls = []

    def available(self, command):
        return command == "curl"

    def run_bounded(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if "--version" in args:
            return CommandResult(args, 0, "curl 7.88.1\nFeatures: SSL HTTP2\n", "")
        config = kwargs["input_text"]
        mime, body = "text/html", ('<html><link rel="stylesheet" '
            'href="https://alias.example.test:8443/site.css"></html>')
        if '/site.css"' in config:
            mime, body = "text/css", "body { color: black; }"
        if 'request = "HEAD"' in config:
            body = ""
        return CommandResult(args, 0, f"HTTP/2 200\nContent-Type: {mime}\n"
            f"X-LucX-Decoy: alias.example.test\n\n{body}\nLUCX_HTTP_VERSION:2", "")


def receipt_fixture(phase="public"):
    """Искусственные входы чистого валидатора, без заявления работы транспорта."""
    manifest = default_manifest()
    manifest["network"]["public_tcp_port"] = 8443
    manifest["decoys"].update(enabled=True, require_full_acceptance=True,
                             sites=[{"domain": "alias.example.test"}])
    fingerprint = health._decoy_profile_fingerprint(manifest)
    rows = [{"domain": "alias.example.test", "path": "public_tls", "port": 8443,
        "method": method, "http_version": version, "state": "healthy", "tls_verified": True,
        "content_verified": True, "body_absence_verified": True, "resources_complete": True,
        "resource_count": 0, "verified_resources": 0, "profile_fingerprint": fingerprint,
        "phase": phase} for method, version in (("GET", "h1"), ("GET", "h2"),
                                                ("HEAD", "h1"), ("HEAD", "h2"))]
    return manifest, rows


class BrowserStagingDialTests(unittest.TestCase):
    def test_h2_stdin_keeps_logical_url_for_html_css_and_head(self):
        runner = WireInputRunner()
        dial = health.BrowserDialAddress("127.0.0.1", 41023)
        for method in ("GET", "HEAD"):
            health.observe_decoy("alias.example.test", "192.0.2.1", 8443,
                "X-LucX-Decoy: alias.example.test", method=method, http_version="h2",
                strict_content=True, runner=runner, phase="staging", dial_address=dial)
        calls = [(args, kwargs) for args, kwargs in runner.calls if "--config" in args]
        self.assertEqual(len(calls), 3, "HTML/CSS/HEAD должны пройти через один dial")
        for (args, kwargs), path in zip(calls, ("/", "/site.css", "/")):
            config = kwargs["input_text"]
            self.assertIn(f'url = "https://alias.example.test:8443{path}"', config)
            self.assertIn('connect-to = "alias.example.test:8443:127.0.0.1:41023"', config)
            self.assertNotIn("resolve =", config)
            self.assertNotIn("insecure", config)
            self.assertNotIn("location", config)
            self.assertNotIn("alias.example.test", " ".join(args))
            self.assertNotIn("127.0.0.1", " ".join(args))
            self.assertLessEqual(kwargs["max_output_bytes"], 300000)
            self.assertGreater(kwargs["timeout"], 0)
            self.assertLessEqual(kwargs["timeout"], 10)
        self.assertIn('request = "HEAD"', calls[-1][1]["input_text"])
        self.assertIn("ignore-content-length", calls[-1][1]["input_text"])

    def test_h2_ipv6_dial_is_bracketed_and_public_mapping_is_unchanged(self):
        runner = WireInputRunner()
        health.observe_decoy("alias.example.test", "192.0.2.1", 8443,
            "X-LucX-Decoy: alias.example.test", method="HEAD", http_version="h2",
            strict_content=True, runner=runner, phase="direct",
            dial_address=health.BrowserDialAddress("::1", 41023))
        self.assertIn('connect-to = "alias.example.test:8443:[::1]:41023"',
                      runner.calls[-1][1]["input_text"])
        for phase in ("public", "rollback"):
            health.observe_decoy("alias.example.test", "192.0.2.1", 8443,
                "X-LucX-Decoy: alias.example.test", method="HEAD", http_version="h2",
                strict_content=True, runner=runner, phase=phase)
            config = runner.calls[-1][1]["input_text"]
            self.assertIn('resolve = "alias.example.test:8443:192.0.2.1"', config)
            self.assertNotIn("connect-to", config)

    def test_h2_code_owned_ca_stays_in_escaped_stdin_config(self):
        runner = WireInputRunner()
        ca_file = str(Path.cwd() / 'synthetic "ca".pem')
        health.observe_decoy("alias.example.test", "192.0.2.1", 8443, None,
            method="HEAD", http_version="h2", strict_content=True, runner=runner,
            phase="staging", dial_address=health.BrowserDialAddress("127.0.0.1", 41023), ca_file=ca_file)
        args, kwargs = runner.calls[-1]
        self.assertNotIn(ca_file, " ".join(args))
        config = kwargs["input_text"]
        self.assertIn('\\"ca\\".pem"', config)
        self.assertEqual(sum(line.startswith("cacert = ") for line in config.splitlines()), 1)
        self.assertNotIn("insecure", config)

    def test_dial_validation_rejects_public_wildcard_name_scope_and_noninteger_ports(self):
        for host, port in (("192.0.2.1", 41023), ("0.0.0.0", 41023), ("::", 41023),
                           ("localhost", 41023), ("::1%1", 41023), ("127.0.0.1", True),
                           ("127.0.0.1", "41023"), ("127.0.0.1", 0), ("127.0.0.1", 65536)):
            with self.subTest(host=host, port=port), self.assertRaises(ValueError):
                health.BrowserDialAddress(host, port)

    def test_forbidden_override_and_missing_staging_dial_never_open_connection(self):
        for phase, dial in (("public", health.BrowserDialAddress("127.0.0.1", 41023)),
                            ("rollback", health.BrowserDialAddress("127.0.0.1", 41023)),
                            ("direct", None), ("staging", None),
                            ("staging", ("127.0.0.1", 41023))):
            runner = WireInputRunner()
            with self.subTest(phase=phase, dial=dial), mock.patch.object(
                    health.socket, "create_connection", side_effect=AssertionError("Соединение запрещено")):
                for version in ("h1", "h2"):
                    result = health.observe_decoy("alias.example.test", "192.0.2.1", 8443, None,
                        phase=phase, dial_address=dial, http_version=version, runner=runner)
                    self.assertNotEqual(result["state"], "healthy")
                self.assertEqual(runner.calls, [])

    def test_staging_cannot_disable_tls_and_dry_run_does_not_connect(self):
        dial = health.BrowserDialAddress("127.0.0.1", 41023)
        with mock.patch.object(health.socket, "create_connection",
                               side_effect=AssertionError("Соединение запрещено")):
            for version in ("h1", "h2"):
                result = health.observe_decoy("alias.example.test", "127.0.0.1", 8443, None,
                    phase="staging", dial_address=dial, http_version=version, verify_tls=False)
                self.assertNotEqual(result["state"], "healthy")
            result = health.observe_decoy("alias.example.test", "192.0.2.1", 8443, None,
                phase="staging", dial_address=dial, runner=Runner(dry_run=True))
            self.assertEqual(result["state"], "not_tested")

    def test_real_tls_keeps_sni_and_hostname_with_code_owned_ca(self):
        openssl = shutil.which("openssl") or "C:/Program Files/Git/usr/bin/openssl.exe"
        if not Path(openssl).is_file():
            self.skipTest("Нет openssl для временного тестового сертификата")
        with tempfile.TemporaryDirectory() as temporary:
            cert, key = Path(temporary) / "cert.pem", Path(temporary) / "key.pem"
            Runner().run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=alias.example.test", "-addext", "subjectAltName=DNS:alias.example.test",
                "-keyout", str(key), "-out", str(cert)])
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            sni, requests = [], []
            context.set_servername_callback(lambda stream, name, ctx: sni.append(name))

            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    requests.append(self.headers["Host"])
                    body = b"<html><body>synthetic site</body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("X-LucX-Decoy", "alias.example.test")
                    self.end_headers()
                    self.wfile.write(body)

            with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
                server.socket = context.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    dial = health.BrowserDialAddress("127.0.0.1", server.server_port)
                    for strict in (False, True):
                        result = health.observe_decoy("alias.example.test", "192.0.2.1", 8443,
                            "X-LucX-Decoy: alias.example.test", phase="staging", dial_address=dial,
                            ca_file=str(cert), strict_content=strict)
                        self.assertEqual(result["state"], "healthy", result)
                    for domain, ca_file in (("wrong.example.test", str(cert)), ("alias.example.test", None)):
                        result = health.observe_decoy(domain, "192.0.2.1", 8443, None,
                            phase="staging", dial_address=dial, ca_file=ca_file, strict_content=True)
                        self.assertNotEqual(result["state"], "healthy", result)
                finally:
                    server.shutdown()
                    thread.join(timeout=2)
        self.assertEqual(requests, ["alias.example.test:8443"] * 2)
        self.assertEqual(sni, ["alias.example.test"] * 2 + ["wrong.example.test", "alias.example.test"])

    def test_ca_override_cannot_inject_curl_config_or_change_public_trust(self):
        for phase, ca_file in (("public", "/tmp/test.pem"), ("rollback", "/tmp/test.pem"),
                               ("staging", '/tmp/test.pem\ninsecure\nurl = "https://other.example.test"'),
                               ("direct", "relative.pem")):
            runner = WireInputRunner()
            result = health.observe_decoy("alias.example.test", "192.0.2.1", 8443, None,
                http_version="h2", runner=runner, strict_content=True, phase=phase, ca_file=ca_file,
                dial_address=None if phase in {"public", "rollback"} else health.BrowserDialAddress("127.0.0.1", 41023))
            self.assertNotEqual(result["state"], "healthy")
            self.assertEqual(runner.calls, [])

    def test_h1_logical_8443_and_resources_use_one_ephemeral_dial(self):
        self.assertTrue(hasattr(health, "BrowserDialAddress"), "Нет typed browser dial override")
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                requests.append((self.path, self.headers["Host"]))
                body = (b'<html><link rel="stylesheet" '
                        b'href="http://alias.example.test:8443/site.css"></html>')
                if self.path == "/site.css":
                    body = b"body { color: black; }"
                self.send_response(200)
                self.send_header("Content-Type", "text/css" if self.path == "/site.css" else "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-LucX-Decoy", "alias.example.test")
                self.end_headers()
                self.wfile.write(body)

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                dial = health.BrowserDialAddress("127.0.0.1", server.server_port)
                for strict in (False, True):
                    result = health.observe_decoy("alias.example.test", "192.0.2.1", 8443,
                        "X-LucX-Decoy: alias.example.test", use_tls=False, strict_content=strict,
                        phase="staging", dial_address=dial)
                    self.assertEqual(result["state"], "healthy", result)
                self.assertTrue(result["resources_complete"])
                self.assertEqual(result["verified_resources"], 1)
            finally:
                server.shutdown()
                thread.join(timeout=2)
        self.assertEqual(requests, [("/", "alias.example.test:8443"),
            ("/", "alias.example.test:8443"), ("/site.css", "alias.example.test:8443")])


class BrowserPhaseTests(unittest.TestCase):
    def test_strict_summary_and_validator_reject_wrong_missing_and_stale_phase(self):
        manifest, rows = receipt_fixture()
        self.assertTrue(health.decoy_acceptance_summary(manifest, rows)["complete"])
        self.assertEqual(health.validate_decoy_observations(manifest, rows), [])
        for phase in (None, "direct", "staging", "rollback"):
            invalid = copy.deepcopy(rows)
            for row in invalid:
                if phase is None:
                    row.pop("phase")
                else:
                    row["phase"] = phase
            with self.subTest(phase=phase):
                self.assertFalse(health.decoy_acceptance_summary(manifest, invalid)["complete"])
                self.assertTrue(health.validate_decoy_observations(manifest, invalid))

    def test_strict_acceptance_rejects_missing_duplicate_extra_and_stale_browser_rows(self):
        manifest, rows = receipt_fixture()
        stale = copy.deepcopy(rows)
        stale[0]["profile_fingerprint"] = "sha256:" + "0" * 64
        extra = {**rows[0], "domain": "other.example.test"}
        for invalid in (rows[1:], rows + [rows[0]], rows + [extra], stale):
            with self.subTest(count=len(invalid)):
                self.assertFalse(health.decoy_acceptance_summary(manifest, invalid)["complete"])
                self.assertTrue(health.validate_decoy_observations(manifest, invalid))

    def test_same_domain_extra_unverified_identity_is_rejected_in_every_phase(self):
        for phase in ("public", "rollback", "staging"):
            manifest, rows = receipt_fixture(phase)
            completeness = "matrix_complete" if phase == "staging" else "complete"
            self.assertTrue(health.decoy_acceptance_summary(manifest, rows, phase=phase)[completeness])
            for change in ({"port": 9443, "content_verified": False},
                           {"port": 9443, "tls_verified": False},
                           {"method": "POST", "content_verified": False}):
                invalid = rows + [{**rows[0], **change}]
                with self.subTest(phase=phase, change=change):
                    summary = health.decoy_acceptance_summary(manifest, invalid, phase=phase)
                    self.assertFalse(summary[completeness])
                    self.assertEqual(summary["verified_sites"], 0)
                    self.assertTrue(health.validate_decoy_observations(manifest, invalid, phase=phase))
                    self.assertTrue(validate_required_acceptance(manifest, invalid, [], vpn_phase=phase))

    def test_staging_matrix_without_candidate_binding_is_never_complete(self):
        manifest, rows = receipt_fixture("staging")
        summary = health.decoy_acceptance_summary(manifest, rows, phase="staging")
        self.assertTrue(summary["matrix_complete"])
        self.assertFalse(summary["complete"])
        self.assertFalse(summary["candidate_verified"])
        self.assertTrue(health.validate_decoy_observations(manifest, rows, phase="staging"))

    def test_staging_internal_tls_requires_positive_tls_receipt(self):
        manifest, rows = receipt_fixture("staging")
        manifest["decoys"]["routing_mode"] = "extended"
        internal = [{**row, "path": "internal_tls", "port": 8444} for row in rows]
        h2c = [{**row, "path": "internal_h2c", "port": 8445, "tls_verified": False}
               for row in rows if row["http_version"] == "h2"]
        rows += internal + h2c
        for row in rows:
            row["profile_fingerprint"] = health._decoy_profile_fingerprint(manifest)
        self.assertTrue(health.decoy_acceptance_summary(manifest, rows, phase="staging")["matrix_complete"])
        internal[0]["tls_verified"] = False
        self.assertFalse(health.decoy_acceptance_summary(manifest, rows, phase="staging")["matrix_complete"])

    def test_expected_rollback_phase_reaches_required_acceptance(self):
        manifest, rows = receipt_fixture("rollback")
        self.assertEqual(validate_required_acceptance(manifest, rows, [], vpn_phase="rollback"), [])
        self.assertTrue(validate_required_acceptance(manifest, rows, []))

    def test_non_strict_legacy_rows_can_omit_phase(self):
        manifest, rows = receipt_fixture()
        manifest["decoys"]["require_full_acceptance"] = False
        for row in rows:
            row.pop("phase")
        self.assertTrue(health.decoy_acceptance_summary(manifest, rows)["complete"])
        self.assertEqual(health.validate_decoy_observations(manifest, rows), [])

    def test_new_rows_have_requested_phase_even_when_skipped_or_dry_run(self):
        manifest, _ = receipt_fixture()
        manifest["decoys"]["capabilities"] = [{"domain": "blocked.example.test", "managed": False,
            "probe_mode": "none", "status": "blocked"}]
        rows = health.observe_decoy_capabilities(manifest, "192.0.2.1", runner=Runner(dry_run=True),
                                                phase="rollback")
        self.assertEqual({row["phase"] for row in rows}, {"rollback"})
        self.assertEqual({row["state"] for row in rows}, {"not_tested", "skipped"})

    def test_provider_missing_invalid_or_raising_does_not_fall_back_to_public(self):
        manifest, _ = receipt_fixture()
        manifest["decoys"]["dial_target_provider"] = "ignored-command"
        manifest["decoys"]["ca_file"] = "/ignored/ca.pem"
        manifest["decoys"]["insecure"] = True
        def fail(target, phase):
            raise RuntimeError("private-sentinel")
        for provider in (None, lambda target, phase: None, lambda target, phase: ("127.0.0.1", 41023), fail):
            with self.subTest(provider=provider), mock.patch.object(
                    health, "observe_decoy", side_effect=AssertionError("Не должно быть public fallback")):
                rows = health.observe_decoy_capabilities(manifest, "192.0.2.1", phase="staging",
                                                        dial_target_provider=provider)
                self.assertEqual(len(rows), 4)
                self.assertEqual({row["state"] for row in rows}, {"not_tested"})
                self.assertNotIn("private-sentinel", json.dumps(rows))

    def test_provider_is_exact_immutable_target_and_forbidden_for_public(self):
        manifest, _ = receipt_fixture()
        seen = []
        def provider(target, phase):
            seen.append((copy.deepcopy(target), phase))
            target["domain"] = "changed.example.test"
            return health.BrowserDialAddress("127.0.0.1", 41023)
        runner = Runner(dry_run=True)
        rows = health.observe_decoy_capabilities(manifest, "192.0.2.1", runner=runner,
                                                phase="staging", dial_target_provider=provider)
        self.assertEqual(seen, [({"domain": "alias.example.test", "path": "public_tls",
            "address": "192.0.2.1", "port": 8443, "tls": True}, "staging")])
        self.assertEqual({row["domain"] for row in rows}, {"alias.example.test"})
        self.assertEqual({row["port"] for row in rows}, {8443})
        for phase in ("public", "rollback"):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                health.observe_decoy_capabilities(manifest, "192.0.2.1", phase=phase,
                                                  dial_target_provider=provider)
        self.assertEqual(len(seen), 1)

    def test_missing_one_internal_target_keeps_full_staging_matrix(self):
        manifest, _ = receipt_fixture()
        manifest["decoys"]["routing_mode"] = "extended"
        seen = []
        def provider(target, phase):
            seen.append((target["path"], target["port"]))
            return None if target["path"] == "internal_tls" else health.BrowserDialAddress("127.0.0.1", 41023)
        rows = health.observe_decoy_capabilities(manifest, "192.0.2.1", runner=Runner(dry_run=True),
            phase="staging", dial_target_provider=provider)
        self.assertEqual(seen, [("public_tls", 8443), ("internal_tls", 8444), ("internal_h2c", 8445)])
        self.assertEqual(len(rows), 10)
        self.assertEqual({row["state"] for row in rows}, {"not_tested"})
        self.assertEqual({row["phase"] for row in rows}, {"staging"})


if __name__ == "__main__":
    unittest.main()
