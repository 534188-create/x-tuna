from __future__ import annotations

import unittest

from lucx_post_configurator.models import Audit, Inbound, default_manifest
from lucx_post_configurator.models import ConfigurationError
from lucx_post_configurator.questionnaire import (
    default_public_port_for_inbound,
    _select_numbered_domains,
    _yes_no,
    build_manifest_interactively,
    configure_protocol_decoys_interactively,
    configure_decoy_routing_mode,
    decoy_reachability,
    refresh_manifest_from_audit,
)


def _audit(protocol: str) -> Audit:
    return Audit(
        os_id="debian",
        os_version="12",
        supported_os=True,
        db_path="/etc/x-ui/x-ui.db",
        db_schema_supported=True,
        settings={
            "webDomain": "panel.example.com",
            "webPort": "2083",
            "webCertFile": "/cert/fullchain.pem",
            "webKeyFile": "/cert/privkey.pem",
            "subDomain": "sub.example.com",
            "subPort": "2096",
            "subPath": "/sub/",
        },
        inbounds=[
            Inbound(
                id=1,
                protocol=protocol,
                remark=f"ONLY {protocol}",
                enable=True,
                listen="",
                port=443 if protocol == "vless" else 56712,
                share_addr=f"{protocol}.example.com",
                network="tcp" if protocol == "vless" else "udp",
                security="reality" if protocol == "vless" else "",
                suggested_public_port=443 if protocol == "vless" else 56712,
                server_names=["www.microsoft.com"] if protocol == "vless" else [],
            )
        ],
        ssh_ports=[49283],
        public_addresses=["192.0.2.10"],
    )


class RefreshInboundSetPolicyTests(unittest.TestCase):
    """Post-update refresh must stay strict about the inbound set."""

    def test_refresh_adds_current_endpoint_sites_and_removes_retired_alias(self):
        audit = _audit("vless")
        inbound = audit.inbounds[0]
        inbound.share_addr = "vpn.example.test"
        inbound.security = "tls"
        inbound.transport = "grpc"
        inbound.transport_path = "vpn"
        inbound.port = 18443
        inbound.server_names = ["vpn.example.test"]
        inbound.public_endpoints = [{"host_id": 1, "address": "alias.example.test", "port": 8443,
            "sni": "alias.example.test", "sni_source": "address", "keep_sni_blank": False,
            "http_host": "", "valid": True}]
        manifest = default_manifest(audit)
        manifest["protocols"] = [{"inbound_id": 1, "protocol": "vless", "domain": "vpn.example.test",
            "internal_port": 18443, "public_port": 443, "exposure": "tcp_sni",
            "public_endpoints": [{"address": "retired.example.test"}]}]
        manifest["decoys"].update(enabled=True, sites=[
            {"domain": "vpn.example.test", "root": "/var/www/custom-vpn"},
            {"domain": "retired.example.test", "root": "/var/www/retired"},
            {"domain": "example.test", "root": "/var/www/apex"}])
        refreshed, _ = refresh_manifest_from_audit(manifest, audit)
        sites = {site["domain"]: site["root"] for site in refreshed["decoys"]["sites"]}
        self.assertEqual(set(sites), {"vpn.example.test", "alias.example.test", "example.test"})
        self.assertEqual(sites["vpn.example.test"], "/var/www/custom-vpn")
        self.assertEqual(sites["example.test"], "/var/www/apex")

    def test_added_or_removed_inbounds_stop_the_refresh(self) -> None:
        audit = _audit("vless")
        manifest = {
            "lucx": {
                "panel": {"internal_host": "127.0.0.1", "internal_port": 2083},
                "subscription": {"internal_host": "127.0.0.1", "internal_port": 2096},
            },
            "protocols": [
                {
                    "inbound_id": 1,
                    "protocol": "vless",
                    "domain": "vless.example.com",
                    "internal_port": 443,
                    "public_port": 443,
                },
                {
                    "inbound_id": 2,
                    "protocol": "trojan",
                    "domain": "trojan.example.com",
                    "internal_port": 443,
                    "public_port": 443,
                },
            ],
        }

        with self.assertRaises(ConfigurationError):
            refresh_manifest_from_audit(manifest, audit)


class RenewalNormalizationTests(unittest.TestCase):
    """A pre-existing certificate must still show renewal as configured."""

    def _manifest(self) -> dict:
        audit = _audit("vless")
        manifest = default_manifest(audit)
        return manifest

    def test_refresh_confirms_certbot_renewal_from_certificate_path(self) -> None:
        audit = _audit("vless")
        manifest = default_manifest(audit)
        manifest["protocols"] = [
            {
                "inbound_id": 1,
                "protocol": "vless",
                "domain": "vless.example.com",
                "internal_port": 443,
                "public_port": 443,
            }
        ]
        manifest["certificates"]["cert_path"] = "/etc/letsencrypt/live/example.com/fullchain.pem"
        manifest["certificates"]["key_path"] = "/etc/letsencrypt/live/example.com/privkey.pem"
        manifest["certificates"]["renewal"] = {
            "enabled": False,
            "provider": "auto",
            "primary_domain": "",
        }

        refreshed, warnings = refresh_manifest_from_audit(manifest, audit)

        renewal = refreshed["certificates"]["renewal"]
        self.assertTrue(renewal["enabled"])
        self.assertEqual(renewal["provider"], "certbot")
        self.assertEqual(renewal["primary_domain"], "example.com")
        self.assertTrue(any("Автопродление" in warning for warning in warnings))

    def test_refresh_confirms_acme_sh_renewal_from_certificate_path(self) -> None:
        audit = _audit("vless")
        manifest = default_manifest(audit)
        manifest["protocols"] = [
            {
                "inbound_id": 1,
                "protocol": "vless",
                "domain": "vless.example.com",
                "internal_port": 443,
                "public_port": 443,
            }
        ]
        manifest["certificates"]["cert_path"] = (
            "/root/.acme.sh/example.com_ecc/fullchain.pem"
        )
        manifest["certificates"]["renewal"] = {
            "enabled": False,
            "provider": "auto",
            "primary_domain": "",
        }

        refreshed, _warnings = refresh_manifest_from_audit(manifest, audit)

        renewal = refreshed["certificates"]["renewal"]
        self.assertTrue(renewal["enabled"])
        self.assertEqual(renewal["provider"], "acme.sh")
        self.assertEqual(renewal["primary_domain"], "example.com")

    def test_refresh_keeps_unknown_certificate_renewal_off(self) -> None:
        audit = _audit("vless")
        manifest = default_manifest(audit)
        manifest["protocols"] = [
            {
                "inbound_id": 1,
                "protocol": "vless",
                "domain": "vless.example.com",
                "internal_port": 443,
                "public_port": 443,
            }
        ]
        manifest["certificates"]["cert_path"] = "/root/cert/example.com/fullchain.pem"

        refreshed, _warnings = refresh_manifest_from_audit(manifest, audit)

        self.assertFalse(refreshed["certificates"]["renewal"]["enabled"])


class NumberedDomainSelectionTests(unittest.TestCase):
    def test_selects_sni_by_number_and_offers_select_all(self) -> None:
        output: list[str] = []

        selected = _select_numbered_domains(
            "SNI для маршрутизации",
            ["one.example.com", "two.example.com", "three.example.com"],
            input_fn=lambda _: "2,4",
            output_fn=output.append,
        )

        self.assertEqual(selected, ["one.example.com", "three.example.com"])
        self.assertIn("  1. Выбрать все (по умолчанию)", output)
        self.assertIn("  2. one.example.com", output)
        self.assertIn("  4. three.example.com", output)

    def test_blank_or_one_selects_all_sni(self) -> None:
        domains = ["one.example.com", "two.example.com"]
        for answer in ("", "1"):
            with self.subTest(answer=answer):
                self.assertEqual(
                    _select_numbered_domains(
                        "SNI",
                        domains,
                        input_fn=lambda _prompt, value=answer: value,
                        output_fn=lambda _: None,
                    ),
                    domains,
                )


class QuestionnaireTests(unittest.TestCase):
    def _public_routing_audit(self, protocol: str, transport: str = "tcp") -> Audit:
        audit = _audit(protocol)
        audit.settings["webDomain"] = "panel.example.test"
        audit.settings["subDomain"] = "sub.example.test"
        inbound = audit.inbounds[0]
        inbound.share_addr = f"{protocol}.example.test"
        inbound.network = "tcp"
        inbound.security = "tls"
        inbound.port = 18443
        inbound.suggested_public_port = 18443
        inbound.server_names = [inbound.share_addr]
        inbound.transport = transport
        inbound.transport_path = "/" if transport == "xhttp" else ""
        inbound.port_bindings = [{"port": 18443, "protocol": "TCP"}]
        inbound.public_endpoints = [{
            "host_id": 0, "address": inbound.share_addr, "port": 18443,
            "sni": inbound.share_addr, "sni_source": "address",
            "keep_sni_blank": False, "http_host": "", "valid": True,
        }]
        return audit

    def _run_public_routing_wizard(self, audit: Audit) -> dict:
        output: list[str] = []

        def answer(prompt: str) -> str:
            if "Внешний основной порт" in prompt:
                return "443"
            if prompt == "Номер варианта: ":
                return "1"
            if "Номер варианта [2]" in prompt and len(output) >= 3:
                question = output[-3]
                if question.startswith((
                    "Создать/синхронизировать заглушки",
                    "Записать публичный адрес Naive",
                    "Разрешить изменить только XHTTP path",
                )):
                    return "1"
            return ""

        return build_manifest_interactively(audit, input_fn=answer, output_fn=output.append)

    def test_initial_wizard_keeps_confirmed_public_routes_when_enabling_sites(self) -> None:
        for name in ("vless", "trojan", "naive", "trusttunnel", "anytls"):
            with self.subTest(protocol=name):
                audit = self._public_routing_audit(name)
                manifest = self._run_public_routing_wizard(audit)
                protocol = manifest["protocols"][0]
                self.assertTrue(manifest["decoys"]["enabled"])
                self.assertEqual(protocol["public_port"], 443)
                self.assertEqual(protocol["exposure"], "tcp_sni")
                self.assertEqual(protocol["sni_names"], [f"{name}.example.test"])
                self.assertEqual(protocol["public_endpoints"][0]["port"], 443)
                self.assertEqual(protocol["public_endpoints"][0]["sni"], f"{name}.example.test")
                self.assertTrue(protocol["sync_public_endpoint"])
                self.assertEqual(protocol["sync_share_addr"], name == "naive")
                self.assertEqual(
                    manifest["lucx"]["settings_management"]["sync_naive_share_addr"],
                    name == "naive",
                )
                self.assertEqual(protocol["internal_port"], 18443)
                self.assertEqual(protocol["port_bindings"], [{"port": 18443, "protocol": "TCP"}])
                self.assertEqual(audit.inbounds[0].port, 18443)
                self.assertEqual(audit.inbounds[0].public_endpoints[0]["port"], 18443)
                route = manifest["decoys"]["extended_routes"][0]
                self.assertEqual(route["public_tcp_port"], 443)
                self.assertEqual(route["sni_names"], [f"{name}.example.test"])

    def test_initial_wizard_keeps_public_routes_after_confirming_xhttp_path(self) -> None:
        audit = self._public_routing_audit("vless", "xhttp")
        manifest = self._run_public_routing_wizard(audit)
        self.assertEqual(manifest["lucx"].get("inbound_changes"), [
            {"inbound_id": 1, "field": "transport_path", "value": "/xhttp-1"},
        ])
        protocol = manifest["protocols"][0]
        self.assertEqual(protocol["public_port"], 443)
        self.assertEqual(protocol["exposure"], "tcp_sni")
        self.assertEqual(protocol["public_endpoints"][0]["port"], 443)
        self.assertEqual(protocol["internal_port"], 18443)
        self.assertEqual(audit.inbounds[0].transport_path, "/")

    def test_existing_decoy_mode_still_refreshes_routes_from_audit_by_default(self) -> None:
        audit = self._public_routing_audit("naive")
        manifest = default_manifest(audit)
        manifest["protocols"] = [{
            "inbound_id": 1, "protocol": "naive", "domain": "naive.example.test",
            "internal_port": 18443, "public_port": 443, "exposure": "tcp_sni",
            "sni_names": ["naive.example.test"], "sync_share_addr": True,
        }]
        refreshed, _ = configure_decoy_routing_mode(manifest, audit, "extended")
        protocol = refreshed["protocols"][0]
        self.assertEqual(protocol["public_port"], 18443)
        self.assertEqual(protocol["exposure"], "tcp_direct")
        self.assertEqual(protocol["public_endpoints"][0]["port"], 18443)
        self.assertFalse(protocol["sync_share_addr"])
        self.assertEqual(manifest["protocols"][0]["public_port"], 443)
        self.assertTrue(manifest["protocols"][0]["sync_share_addr"])

    def test_trusttunnel_defaults_to_shared_https_port(self) -> None:
        audit = _audit("trusttunnel")
        inbound = audit.inbounds[0]
        inbound.network = "tcp"
        inbound.port = 8443
        inbound.suggested_public_port = 8443
        inbound.security = "tls"
        self.assertEqual(default_public_port_for_inbound(inbound), 443)

    def test_non_tls_direct_inbound_keeps_its_listener_port(self) -> None:
        audit = _audit("mieru")
        inbound = audit.inbounds[0]
        self.assertEqual(default_public_port_for_inbound(inbound), inbound.port)

    def test_extended_decoy_mode_is_built_from_current_audit_and_can_return_to_strict(self) -> None:
        audit = _audit("vless")
        audit.inbounds[0].security = "tls"
        audit.inbounds[0].server_names = ["vless.example.com"]
        manifest = default_manifest(audit)
        manifest["protocols"] = [
            {
                "inbound_id": 1,
                "protocol": "vless",
                "remark": "ONLY vless",
                "domain": "vless.example.com",
                "internal_host": "127.0.0.1",
                "internal_port": 443,
                "public_port": 443,
                "udp_public_port": 443,
                "network": "tcp",
                "exposure": "tcp_sni",
                "security": "tls",
                "sni_names": ["vless.example.com"],
                "transport": "tcp",
                "transport_path": "",
                "transport_hosts": [],
                "alpn": ["h2", "http/1.1"],
                "port_bindings": [{"port": 443, "protocol": "TCP"}],
            }
        ]
        manifest["decoys"]["enabled"] = True
        manifest["decoys"]["sites"] = [
            {
                "domain": "vless.example.com",
                "root": "/var/www/lucx-decoys/vless.example.com",
            }
        ]

        extended, warnings = configure_decoy_routing_mode(manifest, audit, "extended")

        self.assertEqual(extended["decoys"]["routing_mode"], "extended")
        self.assertTrue(extended["decoys"]["extended_user_confirmed"])
        self.assertFalse(extended["decoys"].get("require_full_acceptance"))
        self.assertFalse(any(extended["lucx"]["settings_management"].values()))
        self.assertFalse(extended["protocols"][0]["sync_public_endpoint"])
        self.assertTrue(extended["components"]["extended_tls_split"])
        self.assertEqual(
            extended["decoys"]["extended_routes"][0]["strategy"],
            "blocked_unknown",
        )
        self.assertTrue(any("RAW" in warning for warning in warnings))

        strict, _ = configure_decoy_routing_mode(extended, audit, "strict")
        self.assertEqual(strict["decoys"]["routing_mode"], "strict")
        self.assertFalse(strict["decoys"]["extended_user_confirmed"])
        self.assertFalse(strict["decoys"].get("require_full_acceptance"))
        self.assertFalse(strict["components"]["extended_tls_split"])
        self.assertFalse(strict["components"]["naive_frontend"])
        self.assertEqual(strict["decoys"]["extended_routes"], [])

    def test_extended_mode_refreshes_trusttunnel_matcher_from_current_audit(self) -> None:
        audit = _audit("trusttunnel")
        audit.inbounds[0].network = "tcp"
        audit.inbounds[0].port = 9443
        audit.inbounds[0].suggested_public_port = 443
        audit.inbounds[0].clienthello_match_fingerprint = "sha256:0123456789ab"
        manifest = default_manifest(audit)
        manifest["protocols"] = [
            {
                "inbound_id": 1,
                "protocol": "trusttunnel",
                "remark": "stale",
                "domain": "trusttunnel.example.com",
                "internal_host": "127.0.0.1",
                "internal_port": 9443,
                "public_port": 443,
                "udp_public_port": 443,
                "network": "tcp",
                "exposure": "tcp_sni",
                "security": "",
                "sni_names": [],
                "transport": "tcp",
                "transport_path": "",
                "transport_hosts": [],
                "alpn": [],
                "port_bindings": [{"port": 9443, "protocol": "TCP"}],
                "clienthello_match_fingerprint": "",
            }
        ]
        manifest["decoys"]["enabled"] = True

        extended, _ = configure_decoy_routing_mode(manifest, audit, "extended")

        self.assertEqual(
            extended["decoys"]["extended_routes"][0]["strategy"],
            "trusttunnel_clienthello_split",
        )
        self.assertEqual(
            extended["protocols"][0]["clienthello_match_fingerprint"],
            "sha256:0123456789ab",
        )

    def test_yes_no_question_uses_numeric_options_only(self) -> None:
        output: list[str] = []
        prompts: list[str] = []
        answers = iter(["да", "1"])

        self.assertTrue(
            _yes_no(
                "Создать заглушки?",
                False,
                input_fn=lambda prompt: prompts.append(prompt) or next(answers),
                output_fn=output.append,
            )
        )
        rendered = "\n".join(output + prompts)
        self.assertIn("1. Да", rendered)
        self.assertIn("2. Нет", rendered)
        self.assertIn("Введите 1 или 2", rendered)
        self.assertNotIn("Д/н", rendered)

    def test_post_update_refresh_reclassifies_native_naive_capability(self) -> None:
        audit = Audit(
            os_id="debian",
            os_version="12",
            supported_os=True,
            db_path="/etc/x-ui/x-ui.db",
            db_schema_supported=True,
            settings={"webPort": "2083", "subPort": "2096"},
            inbounds=[
                Inbound(
                    id=7,
                    protocol="naive",
                    remark="Naive",
                    enable=True,
                    listen="127.0.0.1",
                    port=47863,
                    share_addr="naive.example.com",
                    network="tcp",
                    security="tls",
                    suggested_public_port=443,
                    server_names=["naive.example.com"],
                )
            ],
            naive_caddyfile={
                "found": True,
                "binary_path": "/usr/local/x-ui/bin/caddy-naive-linux-amd64",
                "files": [
                    {
                        "path": "/usr/local/x-ui/bin/tunnel/naive-7.caddyfile",
                        "sha256": "b" * 64,
                        "capabilities": {
                            "forward_proxy": True,
                            "file_server": False,
                            "native_decoy": False,
                        },
                    }
                ],
            },
        )
        manifest = default_manifest(audit)
        manifest["protocols"] = [
            {
                "inbound_id": 7,
                "protocol": "naive",
                "remark": "Naive",
                "domain": "naive.example.com",
                "internal_host": "127.0.0.1",
                "internal_port": 47863,
                "public_port": 443,
                "udp_public_port": 443,
                "network": "tcp",
                "exposure": "tcp_sni",
                "security": "tls",
                "transport": "tcp",
                "transport_path": "",
                "transport_hosts": [],
                "alpn": [],
                "sni_names": ["naive.example.com"],
                "port_bindings": [],
            }
        ]
        manifest["decoys"].update(
            {
                "enabled": True,
                "routing_mode": "extended",
                "extended_user_confirmed": True,
                "sites": [
                    {
                        "domain": "naive.example.com",
                        "root": "/var/www/lucx-decoys/naive.example.com",
                    }
                ],
                "extended_routes": [
                    {
                        "inbound_id": 7,
                        "strategy": "naive_native",
                        "status": "ready",
                        "source_caddyfile_sha256": "a" * 64,
                    }
                ],
            }
        )
        manifest["components"].update(
            {"haproxy": True, "nginx": True, "extended_tls_split": True}
        )

        refreshed, warnings = refresh_manifest_from_audit(manifest, audit)

        route = refreshed["decoys"]["extended_routes"][0]
        self.assertEqual(route["strategy"], "naive_managed")
        self.assertEqual(route["source_caddyfile_sha256"], "b" * 64)
        self.assertTrue(refreshed["components"]["naive_frontend"])
        self.assertTrue(any("Naive" in warning for warning in warnings))

    def test_direct_inbound_public_port_is_rebased_to_listener_after_refresh(self) -> None:
        """A stale Host port (20100) must not break a qwdtt/mieru direct repair."""

        audit = _audit("qwdtt")
        inbound = audit.inbounds[0]
        inbound.network = "both"
        inbound.port = 56000
        inbound.suggested_public_port = 20100  # stale hosts row
        inbound.port_bindings = [
            {"port": 56000, "protocol": "TCP_UDP"},
            {"port": 56001, "protocol": "UDP"},
        ]
        manifest = default_manifest(audit)
        manifest["protocols"] = [
            {
                "inbound_id": inbound.id,
                "protocol": "qwdtt",
                "remark": inbound.remark,
                "domain": "qwdtt.example.com",
                "internal_host": "127.0.0.1",
                "internal_port": 56000,
                "public_port": 56000,
                "udp_public_port": 56000,
                "network": "both",
                "exposure": "tcp_udp_direct",
                "security": "",
                "sni_names": [],
                "port_bindings": inbound.port_bindings,
                "sync_public_endpoint": True,
            }
        ]
        manifest["lucx"]["settings_management"]["user_confirmed"] = True

        refreshed, _warnings = refresh_manifest_from_audit(manifest, audit)

        protocol = refreshed["protocols"][0]
        self.assertEqual(protocol["public_port"], 56000)
        self.assertEqual(protocol["udp_public_port"], 56000)
        self.assertEqual(protocol["exposure"], "tcp_udp_direct")
    def test_decoys_are_created_automatically_for_every_unique_protocol_domain(self) -> None:
        manifest = default_manifest()
        manifest["protocols"] = [
            {
                "inbound_id": 2,
                "protocol": "vless",
                "domain": "test2.example.test",
                "security": "reality",
                "network": "tcp",
                "exposure": "tcp_sni",
                "public_port": 443,
                "sni_names": ["www.microsoft.com"],
            },
            {
                "inbound_id": 3,
                "protocol": "trojan",
                "domain": "test3.example.test",
                "exposure": "tcp_sni",
                "public_port": 443,
                "sni_names": ["test3.example.test"],
            },
            {
                "inbound_id": 6,
                "protocol": "awg",
                "domain": "test5.example.test",
                "exposure": "udp_direct",
                "public_port": 8443,
                "sni_names": [],
            },
            {
                "inbound_id": 7,
                "protocol": "naive",
                "domain": "test6.example.test",
                "exposure": "tcp_sni",
                "public_port": 443,
                "sni_names": ["test6.example.test"],
            },
        ]
        answers = iter(["1", "1", "2"])
        changed, warnings = configure_protocol_decoys_interactively(
            manifest,
            input_fn=lambda _prompt: next(answers),
            output_fn=lambda _line: None,
        )
        self.assertEqual(
            [site["domain"] for site in changed["decoys"]["sites"]],
            [
                "test2.example.test",
                "test3.example.test",
                "test5.example.test",
                "test6.example.test",
            ],
        )
        self.assertTrue(changed["components"]["nginx"])
        self.assertEqual(changed["network"]["unknown_sni_action"], "reject")
        self.assertEqual(
            decoy_reachability(changed),
            [
                {"domain": "test2.example.test", "delivery": "direct_nginx"},
                {
                    "domain": "test3.example.test",
                    "delivery": "existing_protocol_fallback",
                },
                {"domain": "test5.example.test", "delivery": "direct_nginx"},
                {"domain": "test6.example.test", "delivery": "naive_caddy"},
            ],
        )
        self.assertEqual(len(warnings), 2)

    def _run_defaults(self, protocol: str) -> tuple[dict, list[str]]:
        prompts: list[str] = []

        def answer(prompt: str) -> str:
            prompts.append(prompt)
            return ""

        manifest = build_manifest_interactively(
            _audit(protocol), input_fn=answer, output_fn=prompts.append
        )
        return manifest, prompts

    def test_awg_candidate_is_asked_but_default_answer_does_not_enable_sidecar(self) -> None:
        manifest, prompts = self._run_defaults("awg")
        self.assertTrue(any("subscription-sidecar" in prompt for prompt in prompts))
        self.assertFalse(manifest["components"]["sidecar"])
        self.assertFalse(manifest["sidecar"]["user_confirmed"])

    def test_amneziawg_candidate_is_also_asked_without_auto_enable(self) -> None:
        manifest, prompts = self._run_defaults("amneziawg")
        self.assertTrue(any("subscription-sidecar" in prompt for prompt in prompts))
        self.assertFalse(manifest["components"]["sidecar"])

    def test_single_vless_topology_still_asks_but_does_not_enable_sidecar(self) -> None:
        manifest, prompts = self._run_defaults("vless")
        self.assertEqual([item["protocol"] for item in manifest["protocols"]], ["vless"])
        self.assertEqual(manifest["protocols"][0]["public_port"], 443)
        self.assertEqual(manifest["protocols"][0]["exposure"], "tcp_sni")
        self.assertEqual(manifest["protocols"][0]["sni_names"], ["www.microsoft.com"])
        self.assertEqual(manifest["network"]["non_tls_backend_inbound_id"], 1)
        self.assertTrue(any("subscription-sidecar" in prompt for prompt in prompts))
        self.assertFalse(manifest["components"]["sidecar"])

    def test_cloudflare_origin_restriction_is_not_enabled_without_confirmation(self) -> None:
        manifest, prompts = self._run_defaults("vless")
        self.assertTrue(any("Cloudflare" in prompt for prompt in prompts))
        self.assertFalse(manifest["cloudflare"]["enabled"])
        self.assertFalse(manifest["cloudflare"]["user_confirmed"])

    def test_transport_metadata_is_carried_into_plan_and_post_update_refresh(self) -> None:
        audit = _audit("vless")
        inbound = audit.inbounds[0]
        inbound.transport = "httpupgrade"
        inbound.transport_path = "/route"
        inbound.transport_hosts = ["vless.example.com"]
        inbound.alpn = ["h2", "http/1.1"]
        inbound.udp_over_tcp = True

        manifest = build_manifest_interactively(
            audit, input_fn=lambda _: "", output_fn=lambda _: None
        )
        planned = manifest["protocols"][0]
        self.assertEqual(planned["transport"], "httpupgrade")
        self.assertEqual(planned["transport_path"], "/route")
        self.assertEqual(planned["transport_hosts"], ["vless.example.com"])
        self.assertEqual(planned["alpn"], ["h2", "http/1.1"])
        self.assertTrue(planned["udp_over_tcp"])

        inbound.transport = "xhttp"
        inbound.transport_path = "/new-route"
        inbound.transport_hosts = ["new-vless.example.com"]
        inbound.transport_mode = "stream-up"
        inbound.alpn = ["h2"]
        inbound.udp_over_tcp = False
        refreshed, _warnings = refresh_manifest_from_audit(manifest, audit)
        planned = refreshed["protocols"][0]
        self.assertEqual(planned["transport"], "xhttp")
        self.assertEqual(planned["transport_path"], "/new-route")
        self.assertEqual(planned["transport_hosts"], ["new-vless.example.com"])
        self.assertEqual(planned["transport_mode"], "stream-up")
        self.assertEqual(planned["alpn"], ["h2"])
        self.assertFalse(planned["udp_over_tcp"])

    def test_root_cert_path_automatically_enables_acme_renewal(self) -> None:
        import unittest.mock
        audit = _audit("vless")
        audit.settings["webCertFile"] = "/root/cert/example.test/fullchain.pem"
        audit.settings["webKeyFile"] = "/root/cert/example.test/privkey.pem"
        with unittest.mock.patch("lucx_post_configurator.questionnaire._has_acme_record", return_value=True):
            manifest = build_manifest_interactively(
                audit, input_fn=lambda _: "", output_fn=lambda _: None
            )
        self.assertTrue(manifest["certificates"]["renewal"]["enabled"])
        self.assertEqual(manifest["certificates"]["renewal"]["provider"], "acme.sh")
        self.assertEqual(manifest["certificates"]["renewal"]["primary_domain"], "example.test")
        self.assertTrue(manifest["components"]["tls_hook"])


    def test_build_manifest_normalizes_empty_share_addr_endpoints(self) -> None:
        from lucx_post_configurator.models import validate_manifest
        audit = _audit("vless")
        # Add second inbound with empty share_addr and invalid public_endpoints placeholder
        qwdtt = Inbound(
            id=11,
            protocol="qwdtt",
            remark="qwdtt",
            enable=True,
            listen="",
            port=56000,
            share_addr="",
            network="both",
            security="",
            server_names=[],
            public_endpoints=[
                {
                    "host_id": 0,
                    "address": "",
                    "port": 56000,
                    "sni": "",
                    "sni_source": "inherited",
                    "keep_sni_blank": False,
                    "http_host": "",
                    "valid": False,
                }
            ],
        )
        audit.inbounds.append(qwdtt)
        def answer(prompt: str) -> str:
            if "Внешний домен протокола" in prompt:
                return "qwdtt.example.test"
            return ""

        manifest = build_manifest_interactively(
            audit, input_fn=answer, output_fn=lambda _: None
        )
        self.assertEqual(manifest["protocols"][1]["public_endpoints"][0]["address"], "qwdtt.example.test")
        self.assertTrue(manifest["protocols"][1]["public_endpoints"][0]["valid"])
        # Manifest must validate cleanly without raising ValueError("Публичный endpoint не прошёл аудит")
        validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
