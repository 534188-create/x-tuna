from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .certificate_manager import certificate_status
from .discovery import redacted_audit_dict
from .engine import ApplyError, Engine
from .models import ConfigurationError, dump_manifest, load_manifest
from .manifest_source import read_manifest_source
from .planner import format_plan
from .questionnaire import (
    build_manifest_interactively,
    configure_decoy_routing_mode,
    configure_protocol_decoys_interactively,
    reconfigure_domains_interactively,
)
from .repair import format_repair_check, repair_apply, repair_check
from .runner import Runner
from .self_install import install_self
from .transaction import FAILED_STATE_PATH, load_state
from .tui import run_tui
from .trusttunnel_backend import probe_backend
from .updates import AUTOMATIC_UPDATE_BLOCKED_REASON, run_update_worker, update_lucx, update_source_status


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lucx-post-configure",
        description="Транзакционный постконфигуратор для установленной LucX",
    )
    modes = parser.add_mutually_exclusive_group(required=False)
    modes.add_argument("--tui", action="store_true", help="интерактивное текстовое меню (по умолчанию)")
    modes.add_argument("--audit", action="store_true", help="аудит сервера без изменений")
    modes.add_argument("--plan", action="store_true", help="интерактивное построение плана без изменений")
    modes.add_argument("--apply", action="store_true", help="применить утверждённый manifest")
    modes.add_argument("--validate", action="store_true", help="проверить последнюю применённую конфигурацию")
    modes.add_argument("--resume", action="store_true", help="повторить manifest последнего неудачного запуска")
    modes.add_argument("--rollback", action="store_true", help="восстановить файлы из последнего backup")
    modes.add_argument("--reconfigure", action="store_true", help="изменить управляемые домены и найти подходящий wildcard-сертификат")
    modes.add_argument("--repair-check", action="store_true", help="проверка восстановления после обновления без изменений")
    modes.add_argument("--repair-apply", action="store_true", help="транзакционно пересобрать маршруты по текущим данным LucX")
    modes.add_argument("--install-tui", action="store_true", help="установить постоянные команды TUI и lucx-sub-repair")
    modes.add_argument("--certificate-check", action="store_true", help="найти сертификат, покрывающий управляемые домены")
    modes.add_argument("--update-lucx", action="store_true", help="запустить официальный updater LucX и post-update repair")
    modes.add_argument("--configure-decoys", action="store_true", help="создать или синхронизировать заглушки всех протокольных доменов")
    modes.add_argument("--trusttunnel-backend-probe", action="store_true", help="проверить переданный TrustTunnel backend без изменений")
    modes.add_argument("--protocol-test", action="store_true", help="комплексный автотест всех протоколов и сайтов-заглушек (live probe)")
    modes.add_argument("--network-tuning-status", action="store_true", help="показать статус TCP BBR, очередей FQ и буферов")
    modes.add_argument("--network-tuning-apply", action="store_true", help="применить оптимизацию TCP BBR и сетевых буферов")
    modes.add_argument("--network-tuning-revert", action="store_true", help="откатить оптимизацию TCP BBR к значениям по умолчанию")
    modes.add_argument("--dns-diagnostic", action="store_true", help="расширенная диагностика DNS и изоляции портов")
    modes.add_argument("--update-worker", action="store_true", help=argparse.SUPPRESS)
    modes.add_argument("--sync-naive-inbound", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--manifest", help="путь входного или выходного manifest")
    parser.add_argument("--output", help="записать JSON-результат в этот файл")
    parser.add_argument("--db", help="переопределить путь к базе LucX только для чтения")
    parser.add_argument("--yes", action="store_true", help="подтвердить итоговое применение или откат")
    parser.add_argument("--force", action="store_true", help="разрешить откат поверх изменённых managed-файлов")
    parser.add_argument(
        "--update-source",
        choices=("auto", "sourcecraft", "github", "custom"),
        default="auto",
        help="источник архива обновления LucX",
    )
    parser.add_argument("--mirror-url", default="", help="пользовательский HTTPS tar-архив обновления LucX")
    parser.add_argument("--backend-path", default="", help="путь к локальному TrustTunnel backend для read-only проверки")
    parser.add_argument("--backend-port", type=int, default=0, help="loopback-порт для read-only проверки TrustTunnel backend")
    parser.add_argument(
        "--github-proxy",
        action="append",
        default=[],
        help="шаблон HTTPS GitHub proxy с {url}; можно указать несколько раз",
    )
    parser.add_argument("--update-job-id", default="", help=argparse.SUPPRESS)
    parser.add_argument(
        "--decoy-routing-mode",
        choices=("strict", "extended"),
        default="extended",
        help="внутренний селектор совместимости; TUI использует автоматический режим",
    )
    parser.add_argument("--root", default="/", help=argparse.SUPPRESS)
    return parser


def _emit(data: dict, output: str | None) -> None:
    rendered = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if output:
        target = Path(output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        print(f"Записано: {target}")
    else:
        print(rendered, end="")


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    try:
        return input(prompt + "\n1. Да\n2. Нет (по умолчанию)\nНомер варианта [2]: ").strip() in {"1"}
    except (UnicodeDecodeError, EOFError, KeyboardInterrupt):
        return False


def _require_live_root(args: argparse.Namespace) -> None:
    if args.root != "/":
        raise ConfigurationError("изменяющие режимы нельзя запускать с --root")


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except Exception:
                pass
    args = _parser().parse_args(argv)
    engine = Engine(args.root, runner=Runner(dry_run=False if args.root == "/" else True))
    try:
        if args.tui or not any(
            (
                args.audit,
                args.plan,
                args.apply,
                args.validate,
                args.resume,
                args.rollback,
                args.reconfigure,
                args.repair_check,
                args.repair_apply,
                args.install_tui,
                args.certificate_check,
                args.update_lucx,
                args.configure_decoys,
                args.trusttunnel_backend_probe,
                args.protocol_test,
                args.network_tuning_status,
                args.network_tuning_apply,
                args.network_tuning_revert,
                args.dns_diagnostic,
                args.update_worker,
                args.sync_naive_inbound is not None,
            )
        ):
            return run_tui(engine, db_path=args.db)

        if args.sync_naive_inbound is not None:
            _require_live_root(args)
            if hasattr(os, 'geteuid') and os.geteuid() != 0:
                raise ConfigurationError('Синхронизация Naive требует прав root')
            if args.sync_naive_inbound <= 0:
                raise ConfigurationError('Некорректный номер Naive inbound')
            _emit(engine.sync_naive_inbound(args.sync_naive_inbound), args.output)
            return 0

        if args.update_worker:
            _require_live_root(args)
            if not args.update_job_id:
                raise ConfigurationError("update worker requires --update-job-id")
            _emit(run_update_worker(engine, args.update_job_id), args.output)
            return 0

        if args.protocol_test:
            results = engine.run_protocol_test(output_fn=print if not args.output else None)
            if args.output:
                res_dict = {
                    "total": len(results),
                    "passed": sum(1 for r in results if r.ok),
                    "results": [
                        {
                            "category": r.category,
                            "name": r.name,
                            "endpoint": r.endpoint,
                            "port": r.port,
                            "transport": r.transport,
                            "ok": r.ok,
                            "latency_ms": r.latency_ms,
                            "status_code": r.status_code,
                            "detail": r.detail,
                        }
                        for r in results
                    ],
                }
                _emit(res_dict, args.output)
            return 0 if all(r.ok for r in results) else 1

        if args.network_tuning_status:
            status = engine.get_network_tuning_status()
            _emit(status, args.output)
            return 0

        if args.network_tuning_apply:
            _require_live_root(args)
            result = engine.apply_network_tuning()
            _emit(result, args.output)
            return 0 if result.get("ok") else 1

        if args.network_tuning_revert:
            _require_live_root(args)
            result = engine.revert_network_tuning()
            _emit(result, args.output)
            return 0 if result.get("ok") else 1

        if args.dns_diagnostic:
            diag = engine.run_dns_security_diagnostic()
            _emit(diag, args.output)
            return 0 if diag.get("ok") else 1

        if args.trusttunnel_backend_probe:
            result = probe_backend(
                engine.runner,
                binary=args.backend_path or None,
                loopback_port=args.backend_port,
            )
            _emit(result.as_dict(), args.output)
            return 0 if result.ready else 3

        if args.audit:
            audit = engine.audit(args.db)
            _emit(redacted_audit_dict(audit), args.output)
            return 0 if audit.supported_os and audit.db_schema_supported else 2

        if args.plan:
            audit = engine.audit(args.db)
            if not audit.db_schema_supported:
                raise ConfigurationError(
                    "схема LucX несовместима с безопасным read-only адаптером. Варианты: "
                    "обновить configurator под эту схему, использовать совместимую версию LucX "
                    "или сохранить --audit --output для разбора; запись в БД как обход запрещена"
                )
            manifest = load_manifest(args.manifest) if args.manifest and Path(args.manifest).is_file() else build_manifest_interactively(audit)
            manifest = engine.prepare_operation(manifest, audit=audit)
            plan = engine.plan(manifest, audit)
            print(format_plan(plan))
            if args.manifest:
                dump_manifest(manifest, args.manifest)
                print(f"Манифест сохранен: {args.manifest}")
            if args.output:
                _emit(plan, args.output)
            return 0

        if args.rollback:
            _require_live_root(args)
            if not _confirm("Восстановить управляемые файлы из последнего backup?", args.yes):
                print("Откат отменен.")
                return 1
            run_id = engine.rollback(force=args.force)
            print(f"Откат backup {run_id} завершен. Проверьте сервисы командой --validate.")
            return 0

        if args.validate:
            result = engine.validate_installed()
            _emit(result, args.output)
            return 0 if result["ok"] else 3

        if args.repair_check:
            result = repair_check(engine)
            if args.output:
                _emit(result, args.output)
            else:
                print(format_repair_check(result))
            return 0 if not result.get("repair_required") else 3

        if args.certificate_check:
            result = certificate_status(engine)
            _emit(result, args.output)
            return 0 if result.get("selected") else 3

        if args.configure_decoys:
            _require_live_root(args)
            state = load_state(engine.fs)
            manifest, warnings = configure_protocol_decoys_interactively(
                state["manifest"],
                show_capabilities=args.decoy_routing_mode == "strict",
            )
            if not manifest.get("decoys", {}).get("enabled"):
                print("Настройка заглушек отменена.")
                return 1
            audit = engine.audit(manifest["lucx"]["db_path"])
            manifest, mode_warnings = configure_decoy_routing_mode(
                manifest, audit, args.decoy_routing_mode
            )
            manifest = engine.prepare_operation(manifest, audit=audit)
            plan = engine.plan(manifest, audit)
            plan["warnings"] = list(
                dict.fromkeys(
                    list(plan.get("warnings") or []) + warnings + mode_warnings
                )
            )
            print(format_plan(plan))
            if not _confirm(
                "Создать все сайты-заглушки с backup и применить маршруты?",
                args.yes,
            ):
                print("Настройка заглушек отменена.")
                return 1
            _emit(engine.apply(manifest, audit=audit), args.output)
            return 0

        if args.install_tui:
            _require_live_root(args)
            if not _confirm("Установить/обновить постоянные TUI и lucx-sub-repair команды?", args.yes):
                print("Установка команд отменена.")
                return 1
            _emit(install_self(engine.fs, engine.runner), args.output)
            return 0

        if args.repair_apply:
            _require_live_root(args)
            check = repair_check(engine)
            print(format_repair_check(check))
            print(format_plan(check["proposed_plan"]))
            if not _confirm(
                "Создать backup и транзакционно восстановить маршруты из текущей БД LucX?",
                args.yes,
            ):
                print("Восстановление отменено.")
                return 1
            _emit(repair_apply(engine), args.output)
            return 0

        if args.update_lucx:
            _require_live_root(args)
            status = update_source_status(engine)
            if status.get("automatic_update_available") is not True:
                raise ConfigurationError(
                    status.get("automatic_update_reason") or AUTOMATIC_UPDATE_BLOCKED_REASON
                )
            check = repair_check(engine)
            print(format_repair_check(check))
            if check.get("repair_required"):
                raise ConfigurationError(
                    "перед обновлением выполните --repair-apply; текущая конфигурация требует восстановления"
                )
            print(json.dumps(status, ensure_ascii=False, indent=2))
            if not _confirm(
                f"Обновить LucX из источника {args.update_source} с backup и post-update repair?",
                args.yes,
            ):
                print("Обновление отменено.")
                return 1
            _emit(
                update_lucx(
                    engine,
                    source=args.update_source,
                    custom_url=args.mirror_url,
                    github_proxy_templates=args.github_proxy,
                ),
                args.output,
            )
            return 0

        _require_live_root(args)
        audit = engine.audit(args.db)
        extra_warnings: list[str] = []
        manifest_source = None
        if args.reconfigure:
            state = load_state(engine.fs)
            manifest = state["manifest"]
            if sys.stdin.isatty():
                manifest, extra_warnings = reconfigure_domains_interactively(
                    manifest, audit, engine.fs, engine.runner
                )
            else:
                raise ConfigurationError(
                    "неинтерактивный --reconfigure требует подготовленный --manifest; "
                    "для автоматической смены DNS-суффикса используйте TUI x-tuna"
                )
        elif args.resume:
            manifest, manifest_source = read_manifest_source(
                engine.fs.path(FAILED_STATE_PATH), envelope="state"
            )
        elif args.manifest:
            manifest, manifest_source = read_manifest_source(args.manifest)
        else:
            manifest = build_manifest_interactively(audit)

        manifest, manifest_source = engine.prepare_manifest_source(manifest, manifest_source, audit=audit)
        plan = engine.plan(manifest, audit)
        plan["warnings"] = list(dict.fromkeys(plan["warnings"] + extra_warnings))
        print(format_plan(plan))
        if not _confirm("Применить этот точный план с автоматическим backup и rollback?", args.yes):
            print("Применение отменено; сервер не изменен.")
            return 1
        report = engine.apply(manifest, audit=audit, manifest_source=manifest_source)
        _emit(report, args.output)
        return 0
    except (ConfigurationError, ApplyError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
