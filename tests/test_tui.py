from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

from lucx_post_configurator.models import Audit, Inbound, default_manifest
from lucx_post_configurator.trusttunnel_backend import BackendProbe
from lucx_post_configurator.status import (
    coverage_summary,
    domain_status_rows,
    mutation_preview,
)
from lucx_post_configurator.tui import (
    _show_audit_result,
    _show_mutation_preview,
    _show_operation_result,
    _print_decoy_status,
    _extended_route_blockers,
    _yes_no,
    _trusttunnel_backend_menu,
    run_tui,
)
from lucx_post_configurator.trusttunnel_status import TrustTunnelStatus
from lucx_post_configurator.tui import _show_quick_help


class StatusProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = default_manifest()
        self.manifest["decoys"]["capabilities"] = [
            {
                "domain": "direct.example.com",
                "status": "direct_tcp_decoy",
                "managed": True,
                "reason": "safe direct route",
                "evidence": ["inbound #1 tcp"],
                "probe": {"state": "site_observed"},
            },
            {
                "domain": "udp.example.com",
                "status": "udp_with_tcp_decoy",
                "managed": True,
                "reason": "UDP leaves TCP free",
                "evidence": ["inbound #2 udp"],
            },
            {
                "domain": "fallback.example.com",
                "status": "existing_fallback_observed",
                "managed": False,
                "reason": "existing fallback",
                "evidence": ["passive HTTPS observation"],
                "probe": {"state": "site_observed"},
            },
            {
                "domain": "naive.example.com",
                "status": "naive_caddy_owned_readonly",
                "managed": False,
                "reason": "Naive owns SNI",
                "evidence": ["Caddyfile found=true"],
            },
            {
                "domain": "collision.example.com",
                "status": "blocked_sni_collision",
                "managed": False,
                "reason": "protocol owns SNI",
                "evidence": ["inbound #4 owns SNI"],
            },
            {
                "domain": "unknown.example.com",
                "status": "unsupported_safe",
                "managed": False,
                "reason": "transport unknown",
                "evidence": [],
            },
        ]

    def test_coverage_summary_reports_four_required_groups(self) -> None:
        self.assertEqual(
            coverage_summary(self.manifest),
            {
                "managed": 2,
                "existing_fallback": 1,
                "naive_readonly": 1,
                "blocked_or_unknown": 2,
            },
        )

    def test_domain_rows_are_redacted_status_projections(self) -> None:
        rows = domain_status_rows(self.manifest)
        direct = next(item for item in rows if item["domain"] == "direct.example.com")
        self.assertEqual(direct["status"], "direct_tcp_decoy")
        self.assertEqual(direct["reason"], "safe direct route")
        self.assertEqual(direct["probe"], "site_observed")
        self.assertEqual(direct["evidence"], "inbound #1 tcp")
        self.assertEqual(
            next(item for item in rows if item["domain"] == "udp.example.com")["probe"],
            "not-run",
        )

    def test_mutation_preview_lists_exact_targets_and_protected_scope(self) -> None:
        plan = {
            "immutable": ["Naive Caddyfile", "LucX clients and inbounds"],
            "actions": [
                {
                    "phase": "stage",
                    "component": "haproxy",
                    "targets": ["/etc/haproxy/haproxy.cfg"],
                    "services": ["haproxy.service"],
                },
                {
                    "phase": "database",
                    "component": "lucx-settings",
                    "targets": ["/etc/x-ui/x-ui.db"],
                    "database_fields": ["settings.webDomain", "settings.subDomain"],
                    "services": ["x-ui.service"],
                },
            ],
            "warnings": ["collision.example.com: blocked_sni_collision — VPN has priority"],
        }
        self.assertEqual(
            mutation_preview(plan),
            {
                "files": ["/etc/haproxy/haproxy.cfg"],
                "database_files": ["/etc/x-ui/x-ui.db"],
                "database_fields": ["settings.subDomain", "settings.webDomain"],
                "services": ["haproxy.service", "x-ui.service"],
                "backup_root": "/var/backups/lucx-post-configurator",
                "protected_objects": ["Naive Caddyfile", "LucX clients and inbounds"],
                "blockers": [
                    "collision.example.com: blocked_sni_collision — VPN has priority"
                ],
            },
        )


class GroupedTuiTests(unittest.TestCase):
    def test_extended_route_blockers_are_human_readable(self) -> None:
        manifest = default_manifest()
        manifest["decoys"]["extended_routes"] = [
            {
                "inbound_id": 9,
                "domain": "trust.example.net",
                "status": "blocked",
                "reason": "matcher отсутствует",
            },
            {
                "inbound_id": 10,
                "domain": "ready.example.net",
                "status": "ready",
                "reason": "ok",
            },
        ]
        self.assertEqual(
            _extended_route_blockers(manifest),
            ["inbound #9 trust.example.net: matcher отсутствует"],
        )

    def test_decoy_status_is_a_compact_table_without_evidence_wall(self) -> None:
        manifest = default_manifest()
        manifest["decoys"]["capabilities"] = [
            {"domain": "one.example.net", "status": "extended_ready", "managed": True, "probe": {"state": "not-run"}},
            {"domain": "two.example.net", "status": "extended_blocked", "managed": False, "reason": "technical detail", "evidence": ["long evidence"]},
        ]
        engine = SimpleNamespace(fs=object())
        output: list[str] = []
        with mock.patch("lucx_post_configurator.tui.load_state", return_value={"manifest": manifest}):
            _print_decoy_status(engine, output.append)  # type: ignore[arg-type]
        rendered = "\n".join(output)
        self.assertIn("Домен", rendered)
        self.assertIn("one.example.net", rendered)
        self.assertIn("заблокирован", rendered)
        self.assertNotIn("technical detail", rendered)
        self.assertNotIn("long evidence", rendered)

    def test_confirmation_uses_numbers_only_and_defaults_to_no(self) -> None:
        prompts: list[str] = []
        output: list[str] = []

        self.assertFalse(
            _yes_no(
                "Применить?",
                lambda prompt: prompts.append(prompt) or "",
                output.append,
            )
        )
        self.assertTrue(
            _yes_no(
                "Применить?",
                lambda prompt: prompts.append(prompt) or "1",
                output.append,
            )
        )
        answers = iter(["да", "2"])
        self.assertFalse(
            _yes_no(
                "Применить?",
                lambda _prompt: next(answers),
                output.append,
            )
        )
        rendered = "\n".join(output + prompts)
        self.assertIn("1. Да", rendered)
        self.assertIn("2. Нет", rendered)
        self.assertNotIn("[д/Н]", rendered)
        self.assertIn("Введите 1 или 2", rendered)

    def test_operation_result_is_human_readable_not_raw_json(self) -> None:
        output: list[str] = []
        _show_operation_result(
            {
                "ok": False,
                "errors": ["haproxy недоступен"],
                "changed_managed_files": ["/etc/haproxy/haproxy.cfg"],
                "run_id": "20260831T081405Z-311065",
            },
            output.append,
            title="Проверка установленной конфигурации",
        )
        rendered = "\n".join(output)
        self.assertIn("Состояние: требуется внимание", rendered)
        self.assertIn("Транзакция: 20260831T081405Z-311065", rendered)
        self.assertIn("haproxy недоступен", rendered)
        self.assertIn("/etc/haproxy/haproxy.cfg", rendered)
        self.assertNotIn("{", rendered)
        self.assertNotIn('"ok"', rendered)

    def test_update_job_status_is_rendered_as_human_reconnect_progress(self) -> None:
        output: list[str] = []
        _show_operation_result(
            {
                "pending_post_update_repair": True,
                "job_status": {
                    "job_id": "20260901T091114Z-629799",
                    "state": "running_repair",
                    "phase_current": 3,
                    "phase_total": 3,
                    "phase_label": "Восстановление управляемых маршрутов",
                    "updated_at": "2026-09-01T09:12:14+00:00",
                },
            },
            output.append,
            title="Доступные источники обновления",
        )

        rendered = "\n".join(output)
        self.assertIn("Задание обновления: 20260901T091114Z-629799", rendered)
        self.assertIn("выполняется восстановление", rendered)
        self.assertIn("Этап: 3/3", rendered)
        self.assertIn("Восстановление управляемых маршрутов", rendered)
        self.assertNotIn("{", rendered)

    def test_read_only_audit_is_a_compact_table_not_raw_json(self) -> None:
        output: list[str] = []
        _show_audit_result(
            Audit(
                os_id="debian",
                os_version="13",
                supported_os=True,
                db_path="/etc/x-ui/x-ui.db",
                db_schema_supported=True,
                inbounds=[
                    Inbound(
                        id=10,
                        protocol="anytls",
                        remark="test10",
                        enable=True,
                        listen="127.0.0.1",
                        port=18443,
                        share_addr="test9.example.net",
                        suggested_public_port=443,
                    )
                ],
                warnings=["пример предупреждения"],
            ),
            output.append,
        )
        rendered = "\n".join(output)
        self.assertIn("Debian 13", rendered)
        self.assertIn("Подключения: 1/1 включены", rendered)
        self.assertIn(" 10  anytls", rendered)
        self.assertIn("Службы: 0/0 активны", rendered)
        self.assertIn("Предупреждений: 1", rendered)
        self.assertNotIn("внутренний 127.0.0.1:18443", rendered)
        self.assertNotIn("рекомендуемый внешний TCP/443", rendered)
        self.assertNotIn("{", rendered)

    def test_main_banner_shows_certificate_expiry_and_renewal_status(self) -> None:
        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.net"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.net"
        manifest["certificates"]["renewal"] = {"enabled": True, "provider": "certbot"}
        engine = SimpleNamespace(fs=object())
        output: list[str] = []
        with (
            mock.patch("lucx_post_configurator.tui.load_state", return_value={"manifest": manifest}),
            mock.patch("lucx_post_configurator.tui.update_source_status", return_value={}),
            mock.patch(
                "lucx_post_configurator.tui.certificate_status",
                return_value={"selected": {"expires_at": "2026-11-30T17:03:59+00:00"}},
            ),
        ):
            run_tui(engine, input_fn=lambda _prompt: "0", output_fn=output.append)  # type: ignore[arg-type]

        rendered = "\n".join(output)
        self.assertIn("Сертификат: действителен до 2026-11-30", rendered)
        self.assertIn("Автопродление: настройка сохранена (certbot), расписание не проверено", rendered)

    def test_main_menu_is_grouped_and_exit_is_read_only(self) -> None:
        output: list[str] = []
        self.assertEqual(
            run_tui(object(), input_fn=lambda _prompt: "0", output_fn=output.append),  # type: ignore[arg-type]
            0,
        )
        rendered = "\n".join(output)
        for label in (
            "Статус и диагностика",
            "Настройка",
            "Сеть и защита",
            "Обслуживание",
            "Краткая справка",
        ):
            self.assertIn(label, rendered)

    def test_main_menu_shows_current_panel_subscription_and_update_job(self) -> None:
        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.net"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.net"
        engine = SimpleNamespace(fs=object())
        output: list[str] = []
        with (
            mock.patch(
                "lucx_post_configurator.tui.load_state",
                return_value={"manifest": manifest, "run_id": "example"},
            ),
            mock.patch(
                "lucx_post_configurator.tui.update_source_status",
                return_value={
                    "job_status": {
                        "job_id": "20260901T100000Z-1",
                        "state": "running_repair",
                        "phase_current": 3,
                        "phase_total": 3,
                        "phase_label": "repair",
                    }
                },
            ),
        ):
            run_tui(engine, input_fn=lambda _prompt: "0", output_fn=output.append)  # type: ignore[arg-type]

        rendered = "\n".join(output)
        self.assertIn("Панель: https://panel.example.net/", rendered)
        self.assertIn("Подписка: https://sub.example.net/", rendered)
        self.assertIn("Обновление: восстановление конфигурации (3/3)", rendered)

    def test_main_menu_labels_finished_failure_as_historical(self) -> None:
        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.net"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.net"
        engine = SimpleNamespace(fs=object())
        output: list[str] = []
        with (
            mock.patch("lucx_post_configurator.tui.load_state", return_value={"manifest": manifest}),
            mock.patch(
                "lucx_post_configurator.tui.update_source_status",
                return_value={"job_status": {"job_id": "old-job", "state": "failed", "historical": True, "phase_current": 3, "phase_total": 3}},
            ),
        ):
            run_tui(engine, input_fn=lambda _prompt: "0", output_fn=output.append)  # type: ignore[arg-type]

        rendered = "\n".join(output)
        self.assertNotIn("ошибка (3/3)", rendered)

    def test_quick_help_explains_actions_without_raw_json(self) -> None:
        output: list[str] = []
        _show_quick_help(output.append)
        rendered = "\n".join(output)
        self.assertIn("Краткая справка x-tuna", rendered)
        self.assertIn("DNS", rendered)
        self.assertIn("TrustTunnel HTTPS/TCP", rendered)
        self.assertIn("GitHub", rendered)
        self.assertNotIn('"manifest"', rendered)

    def test_trusttunnel_menu_reports_lucx_separately_from_optional_backend(self) -> None:
        inputs = iter(["1", "0"])
        output: list[str] = []
        status = TrustTunnelStatus(
            discovery_state="observed",
            listener_state="observed",
            protocol_probe_state="not_checked",
            configured_inbounds=1,
            enabled_inbounds=1,
            configured_inbound_ids=[7],
            enabled_inbound_ids=[7],
            observed_listener_inbound_ids=[7],
            optional_backend_enabled=False,
        )
        engine = SimpleNamespace(trusttunnel_status=lambda: status)

        _trusttunnel_backend_menu(
            engine,  # type: ignore[arg-type]
            input_fn=lambda _prompt: next(inputs),
            output_fn=output.append,
        )

        rendered = "\n".join(output)
        self.assertIn("LucX TrustTunnel: наблюдается", rendered)
        self.assertIn("Listener: наблюдается", rendered)
        self.assertIn("HTTPS/h2 CONNECT: не проверен", rendered)
        self.assertIn("Опциональный backend x-tuna в manifest: выключен", rendered)
        self.assertNotIn("неисправ", rendered.lower())
        self.assertNotIn("заблокирован", rendered.lower())

    def test_candidate_metadata_without_connect_is_not_called_ready(self) -> None:
        inputs = iter(["2", "/opt/example/trusttunnel_endpoint", "26444", "0"])
        output: list[str] = []
        candidate = BackendProbe(
            binary="/opt/example/trusttunnel_endpoint",
            version="TrustTunnel v1.1.0",
            metadata_state="observed",
            supports_tcp=True,
            supports_http2_connect=True,
            supports_standard_uri=True,
            supports_config_file=True,
            staging_port_state="available",
            loopback_available=True,
            protocol_probe_state="not_checked",
            live_ready=False,
            ready=False,
            reasons=["реальный HTTPS/h2 CONNECT не проверен"],
        )
        engine = SimpleNamespace(
            probe_trusttunnel_candidate=lambda **_kwargs: candidate,
        )

        _trusttunnel_backend_menu(
            engine,  # type: ignore[arg-type]
            input_fn=lambda _prompt: next(inputs),
            output_fn=output.append,
        )

        rendered = "\n".join(output)
        self.assertIn("Метаданные кандидата: наблюдаются", rendered)
        self.assertIn("HTTPS/h2 CONNECT: не проверен", rendered)
        self.assertIn("Готовность endpoint: не подтверждена", rendered)
        self.assertNotIn("Состояние: готов", rendered)

    def test_mutation_preview_is_human_readable(self) -> None:
        output: list[str] = []
        _show_mutation_preview(
            {
                "files": ["/etc/haproxy/haproxy.cfg"],
                "database_files": [],
                "database_fields": [],
                "services": ["haproxy.service"],
                "backup_root": "/var/backups/lucx-post-configurator",
                "protected_objects": ["Naive Caddyfile"],
                "blockers": [],
            },
            output.append,
        )
        rendered = "\n".join(output)
        self.assertIn("Точный предпросмотр изменений", rendered)
        self.assertIn("/etc/haproxy/haproxy.cfg", rendered)
        self.assertIn("haproxy.service", rendered)
        self.assertIn("Naive Caddyfile", rendered)


    def test_quick_help_does_not_exit_tui_prematurely(self) -> None:
        inputs = iter(["5", "", "0"])
        output: list[str] = []
        code = run_tui(object(), input_fn=lambda _prompt: next(inputs), output_fn=output.append)  # type: ignore[arg-type]
        self.assertEqual(code, 0)
        rendered = "\n".join(output)
        self.assertIn("Краткая справка x-tuna", rendered)
        self.assertIn("1. Статус и диагностика", rendered)
        self.assertIn("2. Настройка", rendered)

    def test_submenus_show_actionable_error_when_state_missing(self) -> None:
        from lucx_post_configurator.tui import _decoy_menu, _sidecar_menu
        engine = SimpleNamespace(fs=SimpleNamespace(path=lambda p: Path(p)))
        output: list[str] = []
        with mock.patch("lucx_post_configurator.tui.load_state", side_effect=FileNotFoundError("state.json missing")):
            _decoy_menu(engine, input_fn=lambda _prompt: "", output_fn=output.append)  # type: ignore[arg-type]
            _sidecar_menu(engine, input_fn=lambda _prompt: "", output_fn=output.append)  # type: ignore[arg-type]
        rendered = "\n".join(output)
        self.assertIn("Сохранённая конфигурация недоступна", rendered)
        self.assertIn("Первичная настройка", rendered)

    def test_network_menu_works_without_saved_state(self) -> None:
        from lucx_post_configurator.tui import _network_menu
        engine = SimpleNamespace(
            fs=SimpleNamespace(path=lambda p: Path(p)),
            get_network_tuning_status=lambda: {"is_fully_optimized": False, "active_congestion_control": "cubic"},
        )
        output: list[str] = []
        with mock.patch("lucx_post_configurator.tui.load_state", side_effect=FileNotFoundError("no state")):
            _network_menu(engine, input_fn=lambda _prompt: "0", output_fn=output.append)  # type: ignore[arg-type]
        rendered = "\n".join(output)
        self.assertIn("Сеть и защита", rendered)
        self.assertIn("Смена системного DNS", rendered)
        self.assertIn("Оптимизация TCP BBR", rendered)

    def test_network_menu_cloudflare_origin_dialog_toggle(self) -> None:
        from lucx_post_configurator.tui import _cloudflare_origin_dialog
        manifest = default_manifest()
        manifest["cloudflare"] = {"enabled": False, "user_confirmed": False}
        engine = SimpleNamespace(
            fs=SimpleNamespace(path=lambda p: Path(p)),
            audit=lambda _db: SimpleNamespace(settings={}),
            prepare_operation=lambda m, audit=None: m,
            plan=lambda m, _a: {"actions": [], "files": [], "warnings": [], "immutable": [], "packages": [], "services": []},
            apply=lambda m, audit=None: {"status": "complete", "warnings": []},
        )
        output: list[str] = []
        inputs = iter(["1", "1", "1"])
        with (
            mock.patch("lucx_post_configurator.tui.load_state", return_value={"manifest": manifest}),
            mock.patch("lucx_post_configurator.tui.fetch_cloudflare_networks", return_value={"ipv4": ["173.245.48.0/20"], "ipv6": ["2400:cb00::/32"]}),
        ):
            _cloudflare_origin_dialog(engine, input_fn=lambda _prompt: next(inputs), output_fn=output.append)  # type: ignore[arg-type]
        rendered = "\n".join(output)
        self.assertIn("Ограничение Cloudflare origin включено", rendered)

    def test_certificate_menu_offers_enabling_renewal_for_detected_acme_cert(self) -> None:
        from lucx_post_configurator.tui import _certificate_menu
        manifest = default_manifest()
        manifest["certificates"]["renewal"] = {"enabled": False, "provider": "auto"}
        manifest['certificates'].update(cert_path='/root/cert/example.test/fullchain.pem',
                                        key_path='/root/cert/example.test/privkey.pem')
        applied_manifest = {}
        def mock_apply(m, *, selected):
            nonlocal applied_manifest
            applied_manifest = m
            return {"status": "complete", "warnings": []}

        engine = SimpleNamespace(
            fs=SimpleNamespace(path=lambda p: Path(p)),
            audit=lambda _db: SimpleNamespace(settings={}),
            prepare_operation=lambda m, audit=None: m,
            plan_certificate_renewal=lambda m, audit=None: {"actions": [], "files": [], "warnings": [], "immutable": [], "packages": [], "services": []},
            enable_certificate_renewal=mock_apply,
            plan=lambda m, _a: {"actions": [], "files": [], "warnings": [], "immutable": [], "packages": [], "services": []},
            apply=mock.Mock(side_effect=AssertionError('Узкая регистрация не должна вызывать full apply')),
        )
        output: list[str] = []
        inputs = iter(["1", "1", "0"])
        with (
            mock.patch("lucx_post_configurator.tui.load_state", return_value={"manifest": manifest}),
            mock.patch('lucx_post_configurator.tui.observed_renewal_status', return_value={
                'provider': 'acme.sh', 'registered': False, 'hook_present': False, 'schedule_verified': False}),
            mock.patch(
                "lucx_post_configurator.tui.certificate_status",
                return_value={
                    "required_domains": ["panel.example.net"],
                    "selected": {
                        "cert_path": "/root/cert/example.test/fullchain.pem",
                        "key_path": "/root/cert/example.test/privkey.pem",
                        "expires_at": "2026-11-30T17:03:59+00:00",
                        "source": "acme.sh",
                        "renewal_name": "example.test",
                    },
                },
            ),
        ):
            _certificate_menu(engine, input_fn=lambda _prompt: next(inputs), output_fn=output.append)  # type: ignore[arg-type]
        rendered = "\n".join(output)
        self.assertIn("Автопродление: hook не зарегистрирован", rendered)
        self.assertIn("1. Включить автопродление для найденного сертификата (acme.sh)", rendered)
        self.assertIn("Hook автопродления проверен (acme.sh)", rendered)
        self.assertTrue(applied_manifest["certificates"]["renewal"]["enabled"])
        self.assertEqual(applied_manifest["certificates"]["renewal"]["provider"], "acme.sh")
        self.assertEqual(applied_manifest["certificates"]["renewal"]["primary_domain"], "example.test")


if __name__ == "__main__":
    unittest.main()
