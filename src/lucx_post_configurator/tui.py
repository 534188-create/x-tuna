from __future__ import annotations

import copy
import getpass
import re
from collections.abc import Callable

from .certificate_manager import (
    certificate_status,
    certificate_status_for_manifest,
    issue_certbot_cloudflare,
)
from .certificate_renewal import renewal_status as observed_renewal_status
from .cloudflare import fetch_cloudflare_networks
from .engine import Engine
from .models import Audit
from .planner import format_plan
from .progress import ProgressDisplay
from .questionnaire import (
    build_manifest_interactively,
    configure_decoy_routing_mode,
    configure_protocol_decoys_interactively,
    reconfigure_domains_interactively,
    migrate_domain_zone,
    refresh_manifest_from_audit,
)
from .repair import format_repair_check, repair_apply, repair_check
from .self_install import install_self
from .status import coverage_summary, domain_status_rows, mutation_preview
from .transaction import BACKUP_ROOT, load_state
from .updates import AUTOMATIC_UPDATE_BLOCKED_REASON, update_lucx, update_source_status
from .trusttunnel_backend import probe_backend


InputFn = Callable[[str], str]
OutputFn = Callable[[str], None]


def _prepare_plan(engine: Engine, manifest: dict, audit: Audit | None = None, *,
                  kind: str = 'apply', selected: dict | None = None) -> dict:
    """Сохраняет намерение при ошибке, обновляет доказательства до preview."""
    intent = {'manifest': copy.deepcopy(manifest), 'kind': kind, 'selected': copy.deepcopy(selected)}
    try:
        candidate = engine.prepare_operation(copy.deepcopy(manifest), audit=audit)
        manifest.clear()
        manifest.update(candidate)
        plan = (engine.plan_certificate_renewal(manifest, audit=audit) if kind == 'renewal'
                else engine.plan(manifest, audit))
    except Exception as error:
        engine._tui_pending_operation = intent
        engine._tui_operation_error = error
        raise
    engine._tui_current_operation = intent
    engine._tui_pending_operation = None
    engine._tui_operation_error = None
    return plan


def _apply_prepared(engine: Engine, manifest: dict, *, audit: Audit | None = None) -> dict:
    intent = getattr(engine, '_tui_current_operation', None) or {
        'manifest': copy.deepcopy(manifest), 'kind': 'apply', 'selected': None}
    try:
        if intent['kind'] == 'renewal':
            result = engine.enable_certificate_renewal(manifest, selected=intent['selected'])
        else:
            result = engine.apply(manifest, audit=audit)
    except Exception as error:
        engine._tui_pending_operation = copy.deepcopy(intent)
        engine._tui_operation_error = error
        raise
    engine._tui_pending_operation = None
    engine._tui_current_operation = None
    engine._tui_operation_error = None
    return result


def _explain_operation_error(error: Exception, output_fn: OutputFn) -> None:
    from .diagnostics import redact
    message = str(error).lower()
    sensitive = any(marker in message for marker in ('upstream', 'credentials', 'password', 'secret', 'token', 'socks5://'))
    output_fn('Детали проверки: ' + ('данные авторизации скрыты; источник не подтверждён.'
              if sensitive else str(redact(str(error)))))
    if 'lock' in message or 'блокиров' in message or 'busy' in message:
        output_fn('\nОперация не завершена. Причина: другая операция удерживает блокировку.')
        output_fn('Дождитесь завершения текущей операции. Активную блокировку удалять нельзя.')
    elif 'исполняемый файл' in message and 'права' in message:
        output_fn('\nОперация не завершена. Причина: владелец или права исполняемого файла Xray небезопасны.')
        output_fn('Проверьте происхождение бинарника, затем восстановите владельца root и режим 0755. '
                  'Исходный Caddyfile Naive менять не требуется.')
    elif any(marker in message for marker in ('credentials', 'клиент', 'protected', 'защищ', 'transport')):
        output_fn('\nОперация не завершена. Причина: изменились защищённые настройки или источник не прошёл проверку.')
        output_fn('Проверьте изменения панели и восстановите согласованную конфигурацию. '
                  'Повторная проверка не разрешает изменение клиентов, авторизации или транспорта.')
    elif 'naive' in message or 'snapshot' in message or 'source changed' in message or 'upstream' in message:
        output_fn('\nОперация не завершена. Причина: сохранённый снимок не совпадает с проверяемым источником Naive.')
        output_fn('Источник или сохранённый снимок Naive не прошёл проверку. Дождитесь завершения '
                  'перезапуска LucX; повторная проверка должна подтвердить новое состояние.')
    else:
        output_fn(f'\nОперация не завершена. Причина: проверка или выполнение завершились ошибкой ({type(error).__name__}).')
        output_fn('Устраните указанную причину и проверьте состояние служб и отчёт операции.')
    output_fn('Затем выберите «6. Повторно проверить и подготовить новый план». '
              'Применение требует нового подтверждения; сохраняющаяся причина блокирует запись.')


def _retry_pending_operation(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    intent = getattr(engine, '_tui_pending_operation', None)
    if intent is None:
        state = _safe_load_state(engine, output_fn, input_fn, context='повторной проверки')
        if state is None:
            return
        intent = {'manifest': state['manifest'], 'kind': 'apply', 'selected': None}
        output_fn('Повторная проверка сохранённой конфигурации; несохранённого действия нет.')
    manifest = copy.deepcopy(intent['manifest'])
    try:
        audit = _run_progress('Повторный read-only аудит', output_fn,
                              lambda: engine.audit(manifest['lucx']['db_path']))
        plan = _prepare_plan(engine, manifest, audit, kind=intent['kind'], selected=intent['selected'])
        output_fn(format_plan(plan))
        _show_plan_preview(plan, output_fn)
        if not _yes_no('Проверка завершена. Применить этот новый план запрошенного действия?', input_fn, output_fn):
            output_fn('Применение отменено.')
            return
        _show_operation_result(_run_progress('Применение повторно проверенного плана', output_fn,
                                               lambda: _apply_prepared(engine, manifest, audit=audit)),
                               output_fn, title='Запрошенное действие завершено')
    except Exception as exc:
        engine._tui_pending_operation = copy.deepcopy(intent)
        _explain_operation_error(exc, output_fn)


def _renewal_time_label(expression: str) -> str:
    match = re.fullmatch(r'([0-9]{1,2}) ([0-9]{1,2}(?:,[0-9]{1,2})*) \* \* \*', expression)
    if match:
        minute = int(match[1])
        hours = sorted({int(hour) for hour in match[2].split(',')})
        if minute <= 59 and all(hour <= 23 for hour in hours):
            return 'ежедневно в ' + ', '.join(f'{hour:02d}:{minute:02d}' for hour in hours)
    return expression


def _renewal_observation(engine: Engine, selected: dict, manifest: dict) -> tuple[str, bool, str]:
    configured = ((manifest.get('certificates') or {}).get('renewal') or {})
    provider = str(configured.get('provider') or 'auto')
    source = str(selected.get('source') or '').lower()
    path = str(selected.get('cert_path') or '')
    if provider == 'acme.sh' or source == 'acme.sh' or '/.acme.sh/' in path or path.startswith('/root/cert/'):
        try:
            facts = observed_renewal_status(engine.fs, path, str(selected.get('key_path') or ''),
                                           runner=getattr(engine, 'runner', None))
            registered = bool(facts.get('registered'))
            label = 'hook зарегистрирован' if registered else 'hook не зарегистрирован'
            if registered and not facts.get('hook_present'):
                label += ', файл hook не найден'
            if facts.get('schedule_found'):
                entries = [_renewal_time_label(str(item['expression'])) + ' ('
                           + (item.get('timezone') or 'часовой пояс не проверен') + ')'
                           for item in facts.get('schedules', [])]
                label += ', расписание cron: ' + '; '.join(entries) if entries else ', расписание cron найдено'
            elif facts.get('schedule_state') == 'absent':
                label += ', расписание cron не найдено'
            else:
                label += ', расписание не проверено'
            if facts.get('schedule_state') == 'unreadable':
                label += ': часть записей cron не удалось прочитать'
            elif facts.get('schedule_state') == 'unsupported':
                label += ': неподдерживаемая запись cron'
            if facts.get('cron_active') is True:
                label += ', cron активен'
            elif facts.get('cron_active') is False:
                label += ', cron неактивен'
            else:
                label += ', служба cron не проверена'
            return label + ' (acme.sh)', registered, 'acme.sh'
        except Exception:
            return 'регистрация не проверена (acme.sh)', False, 'acme.sh'
    # Сохранённый флаг других провайдеров — настройка, а не доказательство cron.
    label = 'настройка сохранена' if configured.get('enabled') else 'не настроено'
    if provider not in {'', 'auto'}:
        label += f' ({provider})'
    return label + ', расписание не проверено', bool(configured.get('enabled')), provider


def _run_progress(title: str, output_fn: OutputFn, operation: Callable[[], object]) -> object:
    return ProgressDisplay(output_fn, title).run(operation)


def _validate_installed(engine: Engine, output_fn: OutputFn) -> object:
    return _run_progress(
        "Проверка управляемой конфигурации",
        output_fn,
        engine.validate_installed,
    )


def _secret_input(prompt: str, input_fn: InputFn) -> str:
    """Ввод секрета: использует getpass в интерактивном консольном режиме, input_fn в остальных случаях."""
    if input_fn is input:
        try:
            return getpass.getpass(prompt)
        except Exception:
            return input(prompt)
    return input_fn(prompt)


def _safe_load_state(
    engine: Engine,
    output_fn: OutputFn,
    input_fn: InputFn | None = None,
    *,
    context: str = "выбранного действия",
) -> dict[str, object] | None:
    """Безопасная загрузка сохранённого состояния с понятным объяснением и инструкцией."""
    try:
        return load_state(engine.fs)
    except Exception as exc:
        output_fn(f"\n⚠ Сохранённая конфигурация недоступна для {context}.")
        output_fn(f"  Причина: {exc}")
        output_fn("\n  Что нужно сделать:")
        output_fn("   1. Если сервер настраивается впервые, перейдите в «2. Настройка» → «1. Первичная настройка».")
        output_fn("   2. Если вы уже настраивали сервер, проверьте целостность файла /var/lib/lucx-post-configurator/state.json")
        output_fn("      или перейдите в «4. Обслуживание» → «2. Ремонт после обновления».")
        output_fn("  Сервер не изменён.")
        if input_fn is not None:
            try:
                input_fn("\nНажмите Enter для возврата...")
            except (EOFError, KeyboardInterrupt):
                pass
        return None


def _yes_no(prompt: str, input_fn: InputFn, output_fn: OutputFn) -> bool:
    output_fn(prompt)
    output_fn("  1. Да")
    output_fn("  2. Нет (по умолчанию)")
    while True:
        try:
            value = input_fn("Номер варианта [2]: ").strip()
        except UnicodeDecodeError:
            continue
        except (EOFError, KeyboardInterrupt):
            output_fn("")
            return False
        if value in {"", "2"}:
            return False
        if value == "1":
            return True
        output_fn("Введите 1 или 2.")


def _show_list(label: str, values: object, output_fn: OutputFn) -> bool:
    items = list(values or []) if isinstance(values, (list, tuple, set)) else []
    if not items:
        return False
    output_fn(label + ":")
    for item in items:
        if isinstance(item, dict):
            message = item.get("message") or item.get("error") or item.get("source")
            output_fn(f"  - {message or 'подробность сохранена в отчёте'}")
        else:
            output_fn(f"  - {item}")
    return True


def _show_operation_result(
    result: object,
    output_fn: OutputFn,
    *,
    title: str = "Результат операции",
) -> None:
    """Render a concise TUI projection; machine-readable JSON remains a CLI concern."""

    output_fn("\n" + title)
    if not isinstance(result, dict):
        output_fn(f"Состояние: {result}")
        return

    ok = result.get("ok")
    status = str(result.get("status") or "").strip().lower()
    if isinstance(ok, bool):
        output_fn(f"Состояние: {'исправно' if ok else 'требуется внимание'}")
    elif status:
        translated = {
            "complete": "завершено",
            "completed": "завершено",
            "ok": "исправно",
            "success": "завершено",
            "installed": "установлено",
            "started": "запущено в фоне",
        }.get(status, status)
        output_fn(f"Состояние: {translated}")
    else:
        output_fn("Состояние: операция завершена")

    if result.get("run_id"):
        output_fn(f"Транзакция: {result['run_id']}")
    scalar_fields = (
        ("source", "Источник"),
        ("sourcecraft", "Зеркало SourceCraft"),
        ("github", "Источник GitHub"),
        ("backup", "Backup"),
        ("tui_command", "Команда TUI"),
        ("pending_post_update_repair", "Ожидается repair после обновления"),
        ("reboot_may_be_scheduled_by_lucx", "LucX может запланировать перезагрузку"),
    )
    for key, label in scalar_fields:
        if key not in result:
            continue
        value = result[key]
        if isinstance(value, bool):
            value = "да" if value else "нет"
        if value not in (None, ""):
            output_fn(f"{label}: {value}")

    job_status = result.get("job_status")
    if isinstance(job_status, dict) and job_status.get("job_id"):
        state_label = {
            "queued": "ожидает запуска",
            "running_updater": "выполняется обновление LucX",
            "running_repair": "выполняется восстановление",
            "complete": "завершено",
            "failed": "завершилось с ошибкой",
        }.get(str(job_status.get("state") or ""), "состояние неизвестно")
        if job_status.get("historical"):
            output_fn(f"Последнее задание обновления: {job_status['job_id']}")
            output_fn("  Это историческая ошибка, активная операция сейчас не выполняется.")
        else:
            output_fn(f"Задание обновления: {job_status['job_id']}")
        output_fn(f"  Состояние: {state_label}")
        current = job_status.get("phase_current")
        total = job_status.get("phase_total")
        label = str(job_status.get("phase_label") or "").strip()
        if isinstance(current, int) and isinstance(total, int) and total > 0:
            output_fn(f"  Этап: {current}/{total}" + (f" — {label}" if label else ""))
        elif label:
            output_fn(f"  Этап: {label}")
        if job_status.get("updated_at"):
            output_fn(f"  Последнее обновление: {job_status['updated_at']}")
        if job_status.get("error"):
            output_fn(f"  Ошибка: {job_status['error']}")

    shown = False
    shown |= _show_list("Ошибки", result.get("errors"), output_fn)
    shown |= _show_list("Ошибки резервного источника", result.get("fallback_errors"), output_fn)
    shown |= _show_list("Предупреждения", result.get("warnings"), output_fn)
    shown |= _show_list(
        "Изменённые управляемые файлы",
        result.get("changed_managed_files"),
        output_fn,
    )
    shown |= _show_list("Установленные пакеты", result.get("installed_packages"), output_fn)
    if isinstance(result.get("repair"), dict):
        repair = result["repair"]
        output_fn("Восстановление после обновления:")
        if repair.get("run_id"):
            output_fn(f"  - транзакция {repair['run_id']}")
        _show_list("  Предупреждения", repair.get("warnings"), output_fn)
    if not shown and isinstance(ok, bool) and ok:
        output_fn("Ошибок и изменений управляемых файлов не обнаружено.")


def _show_audit_result(audit: Audit, output_fn: OutputFn) -> None:
    output_fn("\nRead-only аудит LucX и системы")
    os_name = "Debian" if audit.os_id.lower() == "debian" else (audit.os_id or "неизвестная ОС")
    output_fn(
        f"ОС: {os_name} {audit.os_version or 'неизвестно'}; "
        f"поддерживается: {'да' if audit.supported_os else 'нет'}"
    )
    output_fn(
        f"База LucX: {audit.db_path or 'не найдена'}; "
        f"схема поддерживается: {'да' if audit.db_schema_supported else 'нет'}"
    )
    enabled = sum(1 for inbound in audit.inbounds if inbound.enable)
    output_fn(f"Подключения: {enabled}/{len(audit.inbounds)} включены")
    active_services = sum(1 for state in audit.services.values() if str(state).lower() in {"active", "running", "enabled"})
    output_fn(f"Службы: {active_services}/{len(audit.services)} активны")
    output_fn(f"Предупреждений: {len(audit.warnings)}")
    if audit.inbounds:
        output_fn("Подключения:")
        output_fn(" ID  Протокол       Домен                      Публикация")
        for inbound in audit.inbounds:
            domain = str(inbound.share_addr or "-").split(":", 1)[0]
            network = str(inbound.network or "tcp").lower()
            transport = "UDP" if network == "udp" else "TCP/UDP" if network == "both" else "TCP"
            public = int(inbound.suggested_public_port or inbound.port)
            output_fn(f" {inbound.id:>2}  {inbound.protocol[:13]:<13} {domain[:25]:<25} {transport}/{public}")
    output_fn("Подробные параметры: отдельный технический отчёт.")


def _certificate_banner(engine: Engine) -> tuple[str, str]:
    """Return short, read-only certificate and renewal status for the main menu."""
    try:
        result = certificate_status(engine)
        selected = result.get("selected") or {}
        expires_at = str(selected.get("expires_at") or "")
        if expires_at:
            expires_at = expires_at[:10]
            certificate = f"действителен до {expires_at}"
        else:
            certificate = "не найден"
        manifest = load_state(engine.fs).get("manifest") or {}
        label, _, _ = _renewal_observation(engine, selected, manifest)
        return certificate, label
    except Exception as exc:
        err_type = type(exc).__name__
        return f"не удалось проверить ({err_type})", "состояние неизвестно"


def _show_mutation_preview(preview: dict[str, object], output_fn: OutputFn) -> None:
    output_fn("\nТочный предпросмотр изменений")
    groups = (
        ("Файлы", "files"),
        ("Файлы БД", "database_files"),
        ("Разрешённые поля БД", "database_fields"),
        ("Службы", "services"),
        ("Защищённые объекты", "protected_objects"),
        ("Безопасно исключённые/заблокированные маршруты", "blockers"),
    )
    for label, key in groups:
        values = list(preview.get(key) or [])  # type: ignore[arg-type]
        output_fn(f"{label}:")
        if values:
            for value in values:
                output_fn(f"  - {value}")
        else:
            output_fn("  - нет")
    output_fn(f"Каталог backup: {preview.get('backup_root') or BACKUP_ROOT}")
    output_fn("Любое подтверждение по умолчанию: НЕТ.")


def _show_plan_preview(plan: dict[str, object], output_fn: OutputFn) -> None:
    _show_mutation_preview(mutation_preview(plan), output_fn)


def _extended_route_blockers(manifest: dict[str, object]) -> list[str]:
    decoys = manifest.get("decoys") or {}
    if not isinstance(decoys, dict):
        return []
    return [
        f"inbound #{item.get('inbound_id')} {item.get('domain')}: "
        f"{item.get('reason') or 'безопасная стратегия не доказана'}"
        for item in decoys.get("extended_routes") or []
        if isinstance(item, dict) and item.get("status") != "ready"
    ]


def _operation_preview(
    *,
    files: list[str] | None = None,
    database_files: list[str] | None = None,
    database_fields: list[str] | None = None,
    services: list[str] | None = None,
    protected_objects: list[str] | None = None,
    blockers: list[str] | None = None,
) -> dict[str, object]:
    return {
        "files": files or [],
        "database_files": database_files or [],
        "database_fields": database_fields or [],
        "services": services or [],
        "backup_root": BACKUP_ROOT,
        "protected_objects": protected_objects
        or ["LucX clients/inbounds/listeners/credentials", "Naive Caddyfile"],
        "blockers": blockers or [],
    }


def _audit(engine: Engine, db_path: str | None, output_fn: OutputFn) -> None:
    audit = _run_progress("Read-only аудит LucX и системы", output_fn, lambda: engine.audit(db_path))
    _show_audit_result(audit, output_fn)  # type: ignore[arg-type]


def _initial_apply(
    engine: Engine, db_path: str | None, input_fn: InputFn, output_fn: OutputFn
) -> None:
    audit = _run_progress("Read-only аудит перед настройкой", output_fn, lambda: engine.audit(db_path))
    manifest = build_manifest_interactively(audit, input_fn=input_fn, output_fn=output_fn)
    plan = _prepare_plan(engine, manifest, audit)
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    if not _yes_no(
        "Применить именно этот план с backup и автоматическим rollback?",
        input_fn,
        output_fn,
    ):
        output_fn("Применение отменено; сервер не изменен.")
        return
    _show_operation_result(
        _run_progress(
            "Транзакционное применение и проверка",
            output_fn,
            lambda: _apply_prepared(engine, manifest, audit=audit),
        ),
        output_fn,
        title="Первичная настройка завершена",
    )


def _repair(
    engine: Engine, apply: bool, input_fn: InputFn, output_fn: OutputFn
) -> None:
    check = _run_progress(
        "Проверка необходимости восстановления", output_fn, lambda: repair_check(engine)
    )
    output_fn(format_repair_check(check))
    if not apply:
        return
    output_fn(format_plan(check["proposed_plan"]))
    _show_plan_preview(check["proposed_plan"], output_fn)
    if not _yes_no(
        "Создать backup и транзакционно восстановить маршруты из текущей БД LucX?",
        input_fn,
        output_fn,
    ):
        output_fn("Восстановление отменено.")
        return
    _show_operation_result(
        _run_progress(
            "Backup, восстановление и проверка",
            output_fn,
            lambda: repair_apply(engine),
        ),
        output_fn,
        title="Транзакционное восстановление завершено",
    )


def _reconfigure(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    state = _safe_load_state(engine, output_fn, input_fn, context="смены доменов")
    if state is None:
        return
    audit = _run_progress(
        "Read-only аудит перед сменой доменов",
        output_fn,
        lambda: engine.audit(state["manifest"]["lucx"]["db_path"]),
    )
    if not audit.db_schema_supported:
        output_fn("Схема LucX не поддерживается безопасным адаптером; сервер не изменён.")
        return
    output_fn(
        "Можно заменить только DNS-суффикс всех доменов. Левая часть имени сохранится: "
        "test.example.test -> test.new-zone.example."
    )
    if _yes_no("Использовать автоматическую замену DNS-суффикса?", input_fn, output_fn):
        old_zone = input_fn("Старая DNS-зона: ").strip()
        new_zone = input_fn("Новая DNS-зона: ").strip()
        refreshed, refresh_warnings = refresh_manifest_from_audit(state["manifest"], audit)
        manifest = migrate_domain_zone(refreshed, old_zone, new_zone)
        for warning in refresh_warnings:
            output_fn("Предупреждение: " + warning)
        output_fn(
            "Новые домены построены. Теперь будет найден или выпущен сертификат, "
            "покрывающий корневую зону и wildcard."
        )
        status = _run_progress(
            "Поиск wildcard/SAN сертификата",
            output_fn,
            lambda: certificate_status_for_manifest(engine, manifest),
        )
        tls_candidates = [
            item
            for item in manifest.get("protocols", [])
            if str(item.get("security") or "").strip().lower() != "reality"
        ]
        sync_naive_endpoint = False
        if tls_candidates:
            field_labels = {
                "naive": "domain",
                "trusttunnel": "hostname",
                "anytls": "sni",
            }
            affected = ", ".join(
                f"#{item.get('inbound_id')} {item.get('protocol')} "
                f"({field_labels.get(str(item.get('protocol')), 'TLS SNI')})"
                for item in tls_candidates
            )
            output_fn(
                "Найдены TLS-протоколы, чьи настройки LucX содержат старый домен "
                "и пути сертификата: " + affected + "."
            )
            output_fn(
                "LucX перегенерирует свои tunnel-конфигурации сам; этот инструмент "
                "никогда не редактирует их файлы напрямую."
            )
            sync_naive_endpoint = _yes_no(
                "Синхронизировать TLS-протоколы с новой зоной (домен/SNI и пути сертификата в настройках LucX)?",
                input_fn,
                output_fn,
            )
            if not sync_naive_endpoint:
                output_fn(
                    "Отменено: без синхронизации протоколы продолжат отдавать старый "
                    "домен и сертификат, а TrustTunnel отклонит новый SNI. Обновите "
                    "настройки вручную в панели LucX и повторите смену зоны."
                )
                return
            # The engine reads the flag per protocol; mirror the user's answer
            # onto every planned TLS inbound (Reality is never touched).
            for protocol in manifest.get("protocols", []):
                if str(protocol.get("security") or "").strip().lower() != "reality":
                    protocol["sync_naive_endpoint"] = True
        if not status.get("selected"):
            output_fn(
                "Подходящий сертификат не найден. Для продолжения будет выпущен "
                "wildcard-сертификат новой DNS-зоны через Cloudflare DNS-01."
            )
            output_fn("Выберите способ авторизации Cloudflare:")
            output_fn("  1. API Token")
            output_fn("  2. Global API Key + email")
            while True:
                auth_choice = input_fn("Номер варианта [1]: ").strip() or "1"
                if auth_choice in {"1", "2"}:
                    break
                output_fn("Неверный вариант. Введите 1 (API Token) или 2 (Global API Key).")
            api_token = _secret_input("Cloudflare API Token: ", input_fn) if auth_choice == "1" else ""
            global_key = _secret_input("Cloudflare Global API Key: ", input_fn) if auth_choice == "2" else ""
            cloudflare_email = (
                input_fn("Email аккаунта Cloudflare: ").strip() if auth_choice == "2" else ""
            )
            result = _run_progress(
                "Выпуск wildcard-сертификата новой DNS-зоны",
                output_fn,
                lambda: issue_certbot_cloudflare(
                    engine,
                    zone=new_zone,
                    api_token=api_token or None,
                    global_api_key=global_key or None,
                    cloudflare_email=cloudflare_email,
                    manifest_override=manifest,
                ),
            )
            manifest = result["manifest"]
            selected = {
                "cert_path": manifest["certificates"]["cert_path"],
                "key_path": manifest["certificates"]["key_path"],
            }
        else:
            selected = status["selected"]
        manifest["certificates"]["cert_path"] = selected["cert_path"]
        manifest["certificates"]["key_path"] = selected["key_path"]
        manifest["components"]["tls_hook"] = True
        # Mirror the renewal metadata that issuance would have recorded: the
        # banner reads these flags, and a pre-existing certificate selected
        # during a zone migration must not look like "renewal not configured".
        renewal = manifest["certificates"].setdefault("renewal", {})
        if str(selected.get("source") or "").lower() == "certbot" or str(
            selected.get("cert_path") or ""
        ).startswith("/etc/letsencrypt/live/"):
            renewal["enabled"] = True
            renewal["provider"] = "certbot"
        elif (
            "/.acme.sh/" in str(selected.get("cert_path") or "")
            or str(selected.get("cert_path") or "").startswith("/root/cert/")
            or str(selected.get("source") or "").lower() == "acme.sh"
        ):
            renewal["enabled"] = True
            renewal["provider"] = "acme.sh"
        primary_domain = str(
            selected.get("renewal_name") or ""
        ) or manifest["certificates"]["renewal"].get("primary_domain")
        if primary_domain:
            renewal["primary_domain"] = primary_domain
        manifest.setdefault("lucx", {}).setdefault("settings_management", {}).update(
            {
                "sync_certificate_paths": True,
                "sync_naive_endpoint": sync_naive_endpoint,
                "user_confirmed": True,
            }
        )
        audit = _run_progress(
            "Read-only аудит перед применением новой DNS-зоны",
            output_fn,
            lambda: engine.audit(manifest["lucx"]["db_path"]),
        )
        plan = _prepare_plan(engine, manifest, audit)
        output_fn(format_plan(plan))
        _show_plan_preview(plan, output_fn)
        if _yes_no("Применить новую DNS-зону с backup и rollback?", input_fn, output_fn):
            _show_operation_result(
                _run_progress("Смена DNS-зоны", output_fn, lambda: _apply_prepared(engine, manifest, audit=audit)),
                output_fn,
                title="DNS-зона изменена",
            )
        return
    manifest, warnings = reconfigure_domains_interactively(
        state["manifest"],
        audit,
        engine.fs,
        engine.runner,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    plan = _prepare_plan(engine, manifest, audit)
    plan["warnings"] = list(dict.fromkeys(list(plan.get("warnings") or []) + warnings))
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    if not _yes_no(
        "Применить смену доменов с backup и автоматическим rollback?",
        input_fn,
        output_fn,
    ):
        output_fn("Смена доменов отменена.")
        return
    _show_operation_result(
        _run_progress(
            "Транзакционное применение новых доменов",
            output_fn,
            lambda: _apply_prepared(engine, manifest, audit=audit),
        ),
        output_fn,
        title="Смена доменов завершена",
    )


def _enable_existing_cert_renewal(
    engine: Engine,
    selected: dict[str, object],
    provider: str,
    input_fn: InputFn,
    output_fn: OutputFn,
) -> None:
    state = _safe_load_state(engine, output_fn, input_fn, context="настройки автопродления")
    if not state:
        return
    manifest = copy.deepcopy(state.get("manifest") or {})
    if any(selected.get(key) != (manifest.get('certificates') or {}).get(key)
           for key in ('cert_path', 'key_path')):
        output_fn('Найдена другая пара сертификата. Смена путей сертификата и ключа требует отдельного '
                  'плана переключения сертификата; регистрация прежней пары отменена.')
        return
    renewal = manifest["certificates"].setdefault("renewal", {})
    renewal["enabled"] = True
    renewal["provider"] = provider
    primary_domain = str(selected.get("renewal_name") or "") or renewal.get("primary_domain") or manifest.get("lucx", {}).get("panel", {}).get("domain") or ""
    if primary_domain:
        renewal["primary_domain"] = primary_domain
    manifest.setdefault("components", {})["tls_hook"] = True
    if provider != 'acme.sh':
        manifest.setdefault('lucx', {}).setdefault('settings_management', {}).update(
            {'sync_certificate_paths': True, 'user_confirmed': True})
    audit = _run_progress(
        "Read-only аудит перед регистрацией hook",
        output_fn,
        lambda: engine.audit(manifest["lucx"]["db_path"]),
    )
    plan = _prepare_plan(engine, manifest, audit, kind='renewal' if provider == 'acme.sh' else 'apply',
                         selected=dict(selected) if provider == 'acme.sh' else None)
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    if _yes_no(
        f"Включить и зарегистрировать автопродление ({provider}) для {selected['cert_path']}?",
        input_fn,
        output_fn,
    ):
        _show_operation_result(
            _run_progress(
                f"Регистрация автопродления ({provider}) и reload hook",
                output_fn,
                lambda: _apply_prepared(engine, manifest, audit=audit),
            ),
            output_fn,
            title=f"Hook автопродления проверен ({provider}); расписание проверяется отдельно",
        )


def _issue_certbot_flow(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    output_fn(
        "Если Certbot или DNS Cloudflare plugin отсутствуют, TUI установит их через APT; "
        "файловый rollback не удаляет установленные пакеты."
    )
    zone = input_fn("DNS-зона (например, example.test): ").strip()
    email = input_fn("Email Certbot (можно оставить пустым): ").strip()
    output_fn("Выберите способ авторизации Cloudflare DNS API:")
    output_fn("  1. API Token (рекомендуется, с правами Zone/DNS/Edit)")
    output_fn("  2. Global API Key + email аккаунта")
    while True:
        auth_choice = input_fn("Номер варианта [1]: ").strip() or "1"
        if auth_choice in {"1", "2"}:
            break
        output_fn("Неверный вариант. Введите 1 (API Token) или 2 (Global API Key).")
    token = _secret_input("Cloudflare API Token: ", input_fn) if auth_choice == "1" else ""
    global_key = _secret_input("Cloudflare Global API Key: ", input_fn) if auth_choice == "2" else ""
    cloudflare_email = input_fn("Email аккаунта Cloudflare: ").strip() if auth_choice == "2" else ""
    _show_mutation_preview(
        _operation_preview(
            files=[
                "/etc/letsencrypt/",
                "/etc/letsencrypt/cloudflare-lucx.ini",
            ],
            services=[],
            blockers=[
                "APT-пакеты Certbot/plugin не удаляются файловым rollback, если потребуется их установка."
            ],
        ),
        output_fn,
    )
    if not _yes_no(
        f"Запустить DNS-01 выпуск для {zone} и точных доменов из манифеста?",
        input_fn,
        output_fn,
    ):
        output_fn("Выпуск сертификата отменен.")
        return
    result = _run_progress(
        "Certbot DNS-01: выпуск сертификата",
        output_fn,
        lambda: issue_certbot_cloudflare(
            engine,
            zone=zone,
            api_token=token or None,
            global_api_key=global_key or None,
            cloudflare_email=cloudflare_email,
            email=email,
        ),
    )
    output_fn(
        f"Сертификат выпущен: {result['candidate']['cert_path']}. "
        "Для переключения сервисов нужен отдельный транзакционный apply."
    )
    audit = _run_progress(
        "Read-only аудит перед переключением сертификата",
        output_fn,
        lambda: engine.audit(result["manifest"]["lucx"]["db_path"]),
    )
    plan = _prepare_plan(engine, result["manifest"], audit)
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    if _yes_no(
        "Применить новый сертификат к управляемым сервисам и renewal hook?",
        input_fn,
        output_fn,
    ):
        _show_operation_result(
            _run_progress(
                "Применение сертификата и renewal hook",
                output_fn,
                lambda: _apply_prepared(engine, result["manifest"], audit=audit),
            ),
            output_fn,
            title="Новый сертификат применён",
        )
    else:
        output_fn("Сертификат сохранен Certbot, но активная конфигурация не изменена.")


def _certificate_menu(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    while True:
        status = _run_progress(
            "Проверка сертификатов", output_fn, lambda: certificate_status(engine)
        )
        output_fn("\nСертификаты и автопродление")
        output_fn("Домены управляемого сертификата: " + ", ".join(status["required_domains"]))
        selected = status.get("selected")
        if selected:
            output_fn(
                f" Подходящая пара: {selected['cert_path']} / {selected['key_path']}\n"
                f" Истекает: {selected['expires_at']}"
            )
        else:
            output_fn(" Действующая пара, покрывающая все домены, не найдена.")

        try:
            manifest = load_state(engine.fs).get("manifest") or {}
        except Exception:
            manifest = {}
        renewal_label, renewal_enabled, renewal_provider = _renewal_observation(engine, selected or {}, manifest)
        output_fn(f" Автопродление: {renewal_label}\n")

        output_fn("Выберите действие:")
        if selected and not renewal_enabled:
            cert_p = str(selected.get("cert_path") or "")
            src = str(selected.get("source") or "")
            detected_provider = "acme.sh" if ("acme" in src.lower() or "/root/cert/" in cert_p or "/.acme.sh/" in cert_p) else ("certbot" if ("certbot" in src.lower() or cert_p.startswith("/etc/letsencrypt/")) else "auto")
            output_fn(f" 1. Включить автопродление для найденного сертификата ({detected_provider})")
            output_fn(" 2. Выпустить/обновить сертификат через Certbot DNS Cloudflare")
            output_fn(" 0. Назад")
            choice = _read_choice("Выберите действие: ", input_fn, output_fn)
            if choice == "0":
                return
            if choice == "1":
                _enable_existing_cert_renewal(engine, selected, detected_provider, input_fn, output_fn)
                continue
            elif choice == "2":
                _issue_certbot_flow(engine, input_fn, output_fn)
                continue
            else:
                output_fn("Неизвестный пункт.")
        elif selected and renewal_enabled:
            output_fn(f" 1. Перерегистрировать хук автопродления ({renewal_provider})")
            output_fn(" 2. Выпустить/обновить сертификат через Certbot DNS Cloudflare")
            output_fn(" 0. Назад")
            choice = _read_choice("Выберите действие: ", input_fn, output_fn)
            if choice == "0":
                return
            if choice == "1":
                _enable_existing_cert_renewal(engine, selected, renewal_provider, input_fn, output_fn)
                continue
            elif choice == "2":
                _issue_certbot_flow(engine, input_fn, output_fn)
                continue
            else:
                output_fn("Неизвестный пункт.")
        else:
            output_fn(" 1. Выпустить сертификат через Certbot DNS Cloudflare")
            output_fn(" 0. Назад")
            choice = _read_choice("Выберите действие: ", input_fn, output_fn)
            if choice == "0":
                return
            if choice == "1":
                _issue_certbot_flow(engine, input_fn, output_fn)
                continue
            else:
                output_fn("Неизвестный пункт.")


def _configure_decoys(
    engine: Engine,
    input_fn: InputFn,
    output_fn: OutputFn,
) -> None:
    state = _safe_load_state(engine, output_fn, input_fn, context="настройки сайтов-заглушек")
    if state is None:
        return
    manifest, warnings = configure_protocol_decoys_interactively(
        state["manifest"],
        default_enabled=True,
        show_capabilities=True,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    if not manifest.get("decoys", {}).get("enabled"):
        output_fn("Настройка заглушек отменена.")
        return
    audit = _run_progress(
        "Read-only аудит маршрутов заглушек",
        output_fn,
        lambda: engine.audit(manifest["lucx"]["db_path"]),
    )
    manifest, mode_warnings = configure_decoy_routing_mode(manifest, audit, "extended")
    blocked_xhttp = [
        route
        for route in manifest.get("decoys", {}).get("extended_routes", [])
        if route.get("status") == "blocked"
        and str(route.get("transport") or "").lower() == "xhttp"
        and str(route.get("transport_path") or "/") == "/"
    ]
    if blocked_xhttp:
        output_fn("Обнаружены XHTTP-маршруты с корневым path, который нельзя безопасно разделить с браузером:")
        for route in blocked_xhttp:
            output_fn(
                f"  - inbound #{route.get('inbound_id')} {route.get('domain')}: "
                "текущий path=/"
            )
        if _yes_no(
            "Разрешить изменить только XHTTP path на отдельный путь для browser/VPN-разделения",
            input_fn,
            output_fn,
        ):
            for route in blocked_xhttp:
                inbound_id = int(route.get("inbound_id") or 0)
                default_path = f"/xhttp-{inbound_id}"
                while True:
                    new_path = input_fn(
                        f"Новый XHTTP path для inbound #{inbound_id} [{default_path}]: "
                    ).strip() or default_path
                    if (
                        new_path.startswith("/")
                        and new_path != "/"
                        and ".." not in new_path.split("/")
                        and "\x00" not in new_path
                    ):
                        break
                    output_fn("Укажите непустой путь, начинающийся с '/', без '..'.")
                manifest.setdefault("lucx", {}).setdefault("inbound_changes", []).append(
                    {"inbound_id": inbound_id, "field": "transport_path", "value": new_path}
                )
            manifest["lucx"].setdefault("settings_management", {})[
                "allow_inbound_changes"
            ] = True
            manifest, refreshed_warnings = configure_decoy_routing_mode(
                manifest, audit, "extended"
            )
            mode_warnings = list(dict.fromkeys(mode_warnings + refreshed_warnings))
    warnings = list(dict.fromkeys(warnings + mode_warnings))
    output_fn("Матрица маршрутов: готовые будут применены, заблокированные останутся без перехвата VPN.")
    for route in manifest["decoys"].get("extended_routes") or []:
        state_label = "готов" if route.get("status") == "ready" else "заблокирован"
        output_fn(
            f"  - #{route.get('inbound_id')} {route.get('protocol')} "
            f"{route.get('domain')}: {state_label}; {route.get('reason') or 'причина не указана'}"
        )
    plan = _prepare_plan(engine, manifest, audit)
    plan["warnings"] = list(dict.fromkeys(list(plan.get("warnings") or []) + warnings))
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    if not _yes_no(
        "Создать все сайты-заглушки с backup и применить маршруты?",
        input_fn,
        output_fn,
    ):
        output_fn("Настройка заглушек отменена.")
        return
    _show_operation_result(
        _run_progress(
            "Применение сайтов-заглушек и маршрутов",
            output_fn,
            lambda: _apply_prepared(engine, manifest, audit=audit),
        ),
        output_fn,
        title="Сайты-заглушки и маршруты применены",
    )


def _update(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    output_fn(
        "\nОбновление панели LucX\n"
        "Что произойдет:\n"
        " - создается backup базы и состояния;\n"
        " - официальный обновляющий скрипт LucX запускается отдельным\n"
        "   systemd-заданием (не зависит от TUI и SSH);\n"
        " - после обновления автоматически восстанавливаются управляемые\n"
        "   маршруты (repair) и выполняется проверка служб;\n"
        " - LucX может запланировать перезагрузку для AWG/kernel.\n"
        "\n"
        "Если проверка перед обновлением показывает 'требуется внимание',\n"
        "сначала выполните пункт 8 (Ремонт после обновления).\n"
    )
    status = _run_progress(
        "Проверка источников обновления", output_fn, lambda: update_source_status(engine)
    )
    _show_operation_result(status, output_fn, title="Текущий статус обновления")
    if isinstance(status, dict) and status.get("automatic_update_available") is not True:
        output_fn(status.get("automatic_update_reason") or AUTOMATIC_UPDATE_BLOCKED_REASON)
        return
    output_fn(
        "\nВыберите источник скачивания LucX:\n"
        " 1. Автоматически: gh-proxy -> GitHub -> ваши proxy -> зеркало (рекомендуется)\n"
        " 2. GitHub напрямую\n"
        " 3. Собственный HTTPS tar-архив"
    )
    while True:
        choice = input_fn("Номер варианта [1]: ").strip() or "1"
        source = {"1": "auto", "2": "github", "3": "custom"}.get(choice)
        if source is not None:
            break
        output_fn("Неизвестный источник. Введите 1, 2 или 3.")
    custom = input_fn("HTTPS URL tar-архива: ").strip() if source == "custom" else ""
    proxy_templates: list[str] = []
    if source == "auto":
        output_fn(
            "Дополнительные GitHub-proxy шаблоны (необязательно).\n"
            "Формат: https://proxy.example/download?url={url}\n"
            "Пустая строка — пропустить и продолжить."
        )
        while True:
            value = input_fn("GitHub proxy {url} (пусто = дальше): ").strip()
            if not value:
                break
            proxy_templates.append(value)
    check = _run_progress(
        "Проверка восстановления перед обновлением",
        output_fn,
        lambda: repair_check(engine),
    )
    output_fn(format_repair_check(check))
    if check.get("repair_required"):
        output_fn(
            "\nОбновление заблокировано: конфигурация требует восстановления.\n"
            "Что делать:\n"
            " 1. Выйдите в главное меню;\n"
            " 2. Откройте пункт 8 (Ремонт после обновления);\n"
            " 3. Выберите 'Проверить и восстановить';\n"
            " 4. После успешного ремонта повторите обновление.\n"
            "Сервер не изменен."
        )
        return
    output_fn(
        "Перед обновлением будут установлены постоянные команды, создан backup БД/состояния "
        "и маркер post-update repair. Сам LucX может запланировать перезагрузку для AWG/kernel."
    )
    _show_mutation_preview(
        _operation_preview(
            files=[
                "/usr/local/sbin/lucx-post-configure",
                "/usr/local/sbin/lucx-sub-repair",
                "/usr/local/sbin/x-tuna",
                "/etc/systemd/system/lucx-post-update@.service",
                "/var/lib/lucx-post-configurator/pending-post-update-repair",
            ],
            database_files=["/etc/x-ui/x-ui.db (только backup; обновляющий скрипт LucX внешний)"],
            services=["x-ui.service", "lucx-post-update-repair.service"],
            blockers=["Обновляющий скрипт LucX является внешним действием и отдельно журналируется."],
        ),
        output_fn,
    )
    if not _yes_no("Обновить LucX из выбранного источника?", input_fn, output_fn):
        output_fn("Обновление отменено.")
        return
    _show_operation_result(
        _run_progress(
            "Подготовка и запуск фонового обновления",
            output_fn,
            lambda: update_lucx(
                engine,
                source=source,
                custom_url=custom,
                github_proxy_templates=proxy_templates,
            ),
        ),
        output_fn,
        title="Обновление LucX",
    )


def _install_commands(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    _show_mutation_preview(
        _operation_preview(
            files=[
                "/usr/local/sbin/lucx-post-configure",
                "/usr/local/sbin/lucx-sub-repair",
                "/usr/local/sbin/x-tuna",
                "/etc/systemd/system/lucx-post-update-repair.service",
                "/etc/systemd/system/lucx-post-update@.service",
            ],
            services=["lucx-post-update-repair.service", "lucx-post-update@.service"],
        ),
        output_fn,
    )
    if not _yes_no(
        "Установить/обновить TUI, команду x-tuna и lucx-sub-repair?",
        input_fn,
        output_fn,
    ):
        return
    _show_operation_result(
        _run_progress(
            "Установка постоянных команд",
            output_fn,
            lambda: install_self(engine.fs, engine.runner),
        ),
        output_fn,
        title="Команды TUI установлены/обновлены",
    )


def _rollback(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    _show_mutation_preview(
        _operation_preview(
            files=["управляемые файлы из последней транзакции"],
            database_files=["LucX DB только для разрешённых publication-полей из транзакции"],
            services=["только службы, затронутые восстановленными файлами"],
        ),
        output_fn,
    )
    if not _yes_no("Восстановить управляемые файлы из последнего backup?", input_fn, output_fn):
        return
    try:
        run_id = _run_progress(
            "Откат последней транзакции", output_fn, engine.rollback
        )
        output_fn(f"Откат backup {run_id} завершен. Выполните проверку конфигурации.")
    except Exception as exc:
        output_fn(f"\nОшибка при обычном откате: {exc}")
        output_fn("Обычный откат блокируется, если управляемые файлы были изменены вручную после создания backup.")
        if _yes_no("Выполнить ПРИНУДИТЕЛЬНЫЙ откат (перезаписать изменённые файлы)?", input_fn, output_fn):
            try:
                run_id = _run_progress(
                    "Принудительный откат последней транзакции",
                    output_fn,
                    lambda: engine.rollback(force=True),
                )
                output_fn(f"Принудительный откат {run_id} завершен успешно.")
            except Exception as force_exc:
                output_fn(f"Принудительный откат также завершился с ошибкой: {force_exc}")


def _reboot(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    if not engine.fs.is_live:
        raise RuntimeError("перезагрузка доступна только в живой системе")
    _show_mutation_preview(
        _operation_preview(
            services=["полная перезагрузка ОС; все активные подключения будут прерваны"],
        ),
        output_fn,
    )
    if not _yes_no("Отдельно перезагрузить сервер прямо сейчас?", input_fn, output_fn):
        return
    if not _yes_no("Подтвердите еще раз: активные подключения будут прерваны", input_fn, output_fn):
        return
    res = engine.runner.run(["systemctl", "reboot"], check=False)
    if hasattr(res, "returncode") and res.returncode != 0:
        err = getattr(res, "stderr", "") or getattr(res, "stdout", "")
        output_fn(f"Ошибка при вызове reboot (код возврата {res.returncode}): {err}")
    else:
        output_fn("Команда перезагрузки отправлена операционной системе.")


def _read_choice(prompt: str, input_fn: InputFn, output_fn: OutputFn) -> str:
    try:
        return input_fn(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        output_fn("")
        return "0"


def _print_decoy_status(engine: Engine, output_fn: OutputFn) -> None:
    state = _safe_load_state(engine, output_fn, context="просмотра сайтов-заглушек")
    if state is None:
        return
    manifest = state["manifest"]
    routing_mode = str(manifest.get("decoys", {}).get("routing_mode") or "strict")
    output_fn(
        "Режим маршрутизации: "
        + (
            "расширенный (разделение браузера и VPN)"
            if routing_mode == "extended"
            else "строгий безопасный"
        )
    )
    summary = coverage_summary(manifest)
    output_fn(
        "Заглушки: "
        f"{summary['managed']} управляются, "
        f"{summary['existing_fallback']} через fallback, "
        f"{summary['naive_readonly']} Naive/Caddy, "
        f"{summary['blocked_or_unknown']} заблокированы"
    )
    output_fn("Домен                         Состояние")
    for row in domain_status_rows(manifest):
        status = {
            "extended_ready": "готов",
            "existing_fallback_observed": "fallback",
            "naive_caddy_owned_readonly": "Naive/Caddy",
            "extended_blocked": "заблокирован",
            "unsupported_safe": "неизвестно",
        }.get(row["status"], row["status"])
        output_fn(f"{row['domain'][:28]:28} {status}")
    output_fn("Подробности и причины доступны в техническом отчёте.")


def _print_state_summary(engine: Engine, output_fn: OutputFn) -> None:
    try:
        state = load_state(engine.fs)
    except Exception as exc:
        output_fn(f"Сохранённое состояние недоступно только для чтения: {exc}")
        output_fn(
            "Изменяющие действия из сохранённого состояния заблокированы; read-only аудит доступен отдельно."
        )
        return
    manifest = state["manifest"]
    output_fn(f"Последняя транзакция: {state.get('run_id') or 'неизвестно'}")
    output_fn(f"Версия манифеста: {manifest.get('schema_version')}")
    output_fn(
        "Панель: https://" + str(manifest["lucx"]["panel"].get("domain") or "не настроена")
    )
    output_fn(
        "Подписка: https://"
        + str(manifest["lucx"]["subscription"].get("domain") or "не настроена")
    )
    output_fn(
        "Sidecar: "
        + ("включён (явно подтверждён)" if manifest["components"].get("sidecar") else "выключен")
    )
    integrity = manifest.get("integrity") or {}
    caddy = integrity.get("naive_caddyfile") or {}
    output_fn(
        "Naive Caddyfile: "
        + (
            f"только чтение, sha256={caddy.get('sha256', 'нет хеша')}"
            if caddy.get("found")
            else "не обнаружен"
        )
    )
    coverage = coverage_summary(manifest)
    output_fn(
        "Маршрутизация: "
        + ("расширенная" if manifest.get("decoys", {}).get("routing_mode") == "extended" else "строгая")
    )
    output_fn(
        "Заглушки: "
        f"{coverage['managed']} управляются, "
        f"{coverage['existing_fallback']} через fallback, "
        f"{coverage['blocked_or_unknown']} заблокированы"
    )
    backend = manifest.get("trusttunnel_backend") or {}
    output_fn(
        "TrustTunnel backend: "
        + ("включён" if manifest.get("components", {}).get("trusttunnel_backend") else "выключен")
    )
    if backend.get("public_domain"):
        output_fn(f"TrustTunnel: https://{backend['public_domain']}/")
    output_fn("Подробности: раздел «Покрытие заглушками»")


def _public_url(endpoint: dict[str, object]) -> str:
    domain = str(endpoint.get("domain") or "").strip()
    if not domain:
        return "не настроена"
    try:
        port = int(endpoint.get("public_port") or 443)
    except (TypeError, ValueError):
        port = 443
    suffix = "" if port == 443 else f":{port}"
    return f"https://{domain}{suffix}/"


def _main_state_banner(engine: Engine) -> str:
    """Return the high-value saved state shown before every main-menu choice."""

    try:
        state = load_state(engine.fs)
        manifest = state["manifest"]
    except Exception:
        return " Панель: не настроена\n Подписка: не настроена\n Обновление: нет данных"

    update_label = "нет активного задания"
    try:
        job = update_source_status(engine).get("job_status") or {}
    except Exception:
        job = {}
    if isinstance(job, dict) and job.get("job_id"):
        if job.get("historical"):
            # The main banner describes only the current operation.
            # Historical results remain available in the update details.
            job = {}
        else:
            update_label = {
                "queued": "ожидает запуска",
                "running_updater": "обновление LucX",
                "running_repair": "восстановление конфигурации",
                "complete": "завершено",
                "failed": "ошибка",
            }.get(str(job.get("state") or ""), "состояние неизвестно")
            current = job.get("phase_current")
            total = job.get("phase_total")
            if isinstance(current, int) and isinstance(total, int) and total > 0:
                update_label += f" ({current}/{total})"
    certificate, renewal = _certificate_banner(engine)
    decoy_roots = sorted(
        {
            str(site.get("root") or "").strip()
            for site in (manifest.get("decoys") or {}).get("sites") or []
            if str(site.get("root") or "").strip()
        }
    )
    if decoy_roots:
        if len(decoy_roots) <= 2:
            decoy_label = ", ".join(decoy_roots)
        else:
            base = decoy_roots[0].rsplit("/", 1)[0] if "/" in decoy_roots[0] else decoy_roots[0]
            decoy_label = f"{base}/<домен> ({len(decoy_roots)} сайтов)"
    else:
        decoy_label = "не созданы"
    return (
        f" Панель: {_public_url(manifest['lucx']['panel'])}\n"
        f" Подписка: {_public_url(manifest['lucx']['subscription'])}\n"
        f" Сертификат: {certificate}\n"
        f" Автопродление: {renewal}\n"
        f" Файлы сайтов: {decoy_label}\n"
        f" Обновление: {update_label}"
    )


def _status_menu(
    engine: Engine, db_path: str | None, input_fn: InputFn, output_fn: OutputFn
) -> None:
    while True:
        output_fn(
            "\nСтатус и диагностика\n"
            " 1. Общая сводка сохранённого состояния\n"
            " 2. Полный read-only аудит LucX/системы\n"
            " 3. Проверить установленную конфигурацию (health check)\n"
            " 4. Проверить целостность и необходимость repair\n"
            " 5. Покрытие заглушками по доменам\n"
            " 6. Комплексный автотест всех протоколов (live probe)\n"
            " 7. Расширенная диагностика DNS и сетевой безопасности\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _print_state_summary(engine, output_fn)
        elif choice == "2":
            _audit(engine, db_path, output_fn)
        elif choice == "3":
            _show_operation_result(
                _validate_installed(engine, output_fn),
                output_fn,
                title="Проверка установленной конфигурации",
            )
        elif choice == "4":
            _repair(engine, False, input_fn, output_fn)
        elif choice == "5":
            _print_decoy_status(engine, output_fn)
        elif choice == "6":
            run_test_fn = getattr(engine, "run_protocol_test", None)
            if run_test_fn is not None:
                run_test_fn(output_fn=output_fn)
            else:
                output_fn("Автотест протоколов недоступен в данном окружении.")
        elif choice == "7":
            _dns_security_dialog(engine, output_fn)
        else:
            output_fn("Неизвестный пункт.")


def _domains_menu(
    engine: Engine, db_path: str | None, input_fn: InputFn, output_fn: OutputFn
) -> None:
    while True:
        output_fn(
            "\nДомены и маршрутизация\n"
            " 1. Сменить домены и повторно подобрать сертификат\n"
            " 2. Повторно обнаружить домены/listener (read-only аудит)\n"
            " 3. Показать безопасные и заблокированные маршруты заглушек\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _reconfigure(engine, input_fn, output_fn)
        elif choice == "2":
            _audit(engine, db_path, output_fn)
        elif choice == "3":
            _print_decoy_status(engine, output_fn)
        else:
            output_fn("Неизвестный пункт.")


def _decoy_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    while True:
        state = _safe_load_state(engine, output_fn, input_fn, context="управления сайтами-заглушками")
        if state is None:
            return
        manifest = state["manifest"]
        routing_mode = str(manifest.get("decoys", {}).get("routing_mode") or "strict")
        mode_label = "расширенный (разделение браузера и VPN)" if routing_mode == "extended" else "строгий безопасный"
        output_fn(
            "\nСайты-заглушки\n"
            f" Текущий режим: {mode_label}\n"
            " 1. Матрица покрытия всех протокольных доменов\n"
            " 2. Создать/синхронизировать заглушки везде, где это возможно\n"
            " 3. Проверить установленную конфигурацию и HTTPS health\n"
            " 4. Переключить режим маршрутизации (strict <-> extended)\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _print_decoy_status(engine, output_fn)
        elif choice == "2":
            _configure_decoys(engine, input_fn, output_fn)
        elif choice == "3":
            _show_operation_result(
                _validate_installed(engine, output_fn),
                output_fn,
                title="Проверка сайтов-заглушек и HTTPS",
            )
        elif choice == "4":
            new_mode = "strict" if routing_mode == "extended" else "extended"
            new_mode_label = "строгий безопасный" if new_mode == "strict" else "расширенный (с разделением по path)"
            output_fn(f"\nПереключение режима маршрутизации заглушек на: {new_mode_label}")
            if _yes_no("Применить переключение режима маршрутизации?", input_fn, output_fn):
                audit = _run_progress(
                    "Read-only аудит перед сменой режима",
                    output_fn,
                    lambda: engine.audit(manifest["lucx"]["db_path"]),
                )
                updated_manifest, _ = configure_decoy_routing_mode(manifest, audit, new_mode)
                plan = _prepare_plan(engine, updated_manifest, audit)
                output_fn(format_plan(plan))
                _show_plan_preview(plan, output_fn)
                if _yes_no("Применить этот план с backup и rollback?", input_fn, output_fn):
                    _show_operation_result(
                        _run_progress(
                            "Применение режима сайтов-заглушек",
                            output_fn,
                            lambda: _apply_prepared(engine, updated_manifest, audit=audit),
                        ),
                        output_fn,
                        title="Режим маршрутизации обновлён",
                    )
        else:
            output_fn("Неизвестный пункт.")


def _trusttunnel_backend_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    """Probe an operator-supplied backend; installation is deliberately separate."""
    while True:
        output_fn(
            "\nСовместимый TrustTunnel backend\n"
            " 1. Показать статус TrustTunnel\n"
            " 2. Проверить backend в разрешённом локальном пути\n"
            " 3. Показать требования к backend\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            status = getattr(engine, "trusttunnel_status", lambda: None)()
            if status is not None:
                discovery_label = {
                    "observed": "наблюдается",
                    "not_observed": "не наблюдается",
                    "not_checked": "не проверен",
                }.get(status.discovery_state, status.discovery_state)
                listener_label = {
                    "observed": "наблюдается",
                    "not_observed": "не наблюдается",
                    "not_checked": "не проверен",
                }.get(status.listener_state, status.listener_state)
                probe_label = {
                    "observed": "проверен",
                    "ok": "проверен",
                    "not_checked": "не проверен",
                }.get(status.protocol_probe_state, status.protocol_probe_state)
                backend_label = "включён" if status.optional_backend_enabled else "выключен"
                output_fn(f"LucX TrustTunnel: {discovery_label}")
                output_fn(f"Listener: {listener_label}")
                output_fn(f"HTTPS/h2 CONNECT: {probe_label}")
                output_fn(f"Опциональный backend x-tuna в manifest: {backend_label}")
        elif choice == "2":
            path = input_fn("Путь к локальному backend: ").strip()
            port_text = input_fn("Свободный loopback-порт [26444]: ").strip()
            try:
                port = int(port_text or "26444")
                probe_fn = getattr(engine, "probe_trusttunnel_candidate", None)
                if probe_fn is not None:
                    result = probe_fn(binary=path, loopback_port=port)
                else:
                    result = probe_backend(engine.runner, binary=path, loopback_port=port)
                meta_label = {
                    "observed": "наблюдаются",
                    "not_checked": "не проверены",
                }.get(getattr(result, "metadata_state", ""), "не определены")
                output_fn(f"Метаданные кандидата: {meta_label}")
                connect_label = {
                    "ok": "проверен",
                    "not_checked": "не проверен",
                }.get(getattr(result, "protocol_probe_state", ""), "не проверен")
                output_fn(f"HTTPS/h2 CONNECT: {connect_label}")
                ready_label = "подтверждена" if getattr(result, "live_ready", False) else "не подтверждена"
                output_fn(f"Готовность endpoint: {ready_label}")
                if result.ready:
                    output_fn("Состояние: готов")
                _show_list("Причины блокировки", result.reasons, output_fn)
            except (OSError, ValueError) as exc:
                output_fn(f"Ошибка проверки: {exc}")
        elif choice == "3":
            output_fn("Требуются: pinned SHA-256, TCP, HTTP/2 CONNECT, стандартный URI и запуск через config-файл.")
            output_fn("Backend должен слушать только loopback; публичный 443 не переключается во время probe.")
        else:
            output_fn("Неизвестный пункт.")


def _sidecar_apply(
    engine: Engine, enabled: bool, input_fn: InputFn, output_fn: OutputFn
) -> None:
    state = _safe_load_state(engine, output_fn, input_fn, context="настройки sidecar")
    if state is None:
        return
    manifest = copy.deepcopy(state["manifest"])
    if enabled and not _yes_no(
        "Sidecar является опциональным. Явно установить/обновить его?",
        input_fn,
        output_fn,
    ):
        output_fn("Sidecar не изменён.")
        return
    manifest["components"]["sidecar"] = enabled
    manifest["sidecar"]["user_confirmed"] = enabled
    subscription = manifest["lucx"]["subscription"]
    if enabled:
        audit = _run_progress(
            "Read-only аудит перед настройкой sidecar",
            output_fn,
            lambda: engine.audit(manifest["lucx"]["db_path"]),
        )
        manifest["sidecar"]["allowed_hosts"] = [subscription["domain"]]
        manifest["sidecar"]["allowed_path_prefixes"] = list(
            dict.fromkeys(
                [
                    subscription["path_prefix"],
                    audit.settings.get("subClashPath", "/clash/") or "/clash/",
                    audit.settings.get("subAwgPath", "/awg/") or "/awg/",
                    audit.settings.get("subJsonPath", "/json/") or "/json/",
                ]
            )
        )
        manifest["sidecar"]["upstream_port"] = subscription["internal_port"]
    else:
        audit = _run_progress(
            "Read-only аудит перед удалением sidecar",
            output_fn,
            lambda: engine.audit(manifest["lucx"]["db_path"]),
        )
    plan = _prepare_plan(engine, manifest, audit)
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    action = "установить/обновить" if enabled else "удалить из управляемой обвязки"
    if not _yes_no(f"{action.capitalize()} sidecar транзакционно?", input_fn, output_fn):
        output_fn("Sidecar не изменён.")
        return
    _show_operation_result(
        _run_progress(
            "Транзакционная настройка sidecar",
            output_fn,
            lambda: _apply_prepared(engine, manifest, audit=audit),
        ),
        output_fn,
        title="Настройка sidecar завершена",
    )


def _sidecar_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    while True:
        state = _safe_load_state(engine, output_fn, input_fn, context="управления sidecar")
        if state is None:
            return
        enabled = bool(state["manifest"]["components"].get("sidecar"))
        output_fn(
            "\nПодписки и sidecar\n"
            f" Текущее состояние: {'включён' if enabled else 'выключен'}\n"
            " 1. Установить/обновить sidecar (отдельное согласие, по умолчанию НЕТ)\n"
            " 2. Удалить sidecar из управляемой обвязки\n"
            " 3. Проверить опубликованную подписку и управляемую конфигурацию\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _sidecar_apply(engine, True, input_fn, output_fn)
        elif choice == "2":
            _sidecar_apply(engine, False, input_fn, output_fn)
        elif choice == "3":
            _show_operation_result(
                _validate_installed(engine, output_fn),
                output_fn,
                title="Проверка подписки и управляемой конфигурации",
            )
        else:
            output_fn("Неизвестный пункт.")


def _change_dns_dialog(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    current = engine.get_current_system_dns()
    current_str = ", ".join(current) if current else "не определен"
    output_fn("\nСмена системного DNS")
    output_fn(f"Текущий активный DNS: {current_str}")
    output_fn("Выполняется замер задержки (RTT) до популярных DNS-резолверов...")

    probe_fn = getattr(engine, "probe_dns_candidates", None)
    candidates = probe_fn() if probe_fn is not None else []

    output_fn("\nРезультаты замера задержки:")
    output_fn(f" {'#':<3} {'Провайдер':<12} {'Серверы':<30} {'Задержка':<12} {'Описание'}")
    output_fn("-" * 90)

    candidate_map: dict[str, list[str]] = {}
    for idx, cand in enumerate(candidates, 1):
        servers_str = ", ".join(cand.servers)
        if cand.latency_ms is not None:
            lat_str = f"{cand.latency_ms:.1f} ms"
        else:
            lat_str = "таймаут"
        output_fn(f" {idx:<3} {cand.name:<12} {servers_str:<30} {lat_str:<12} {cand.description}")
        candidate_map[str(idx)] = list(cand.servers)

    custom_idx = str(len(candidates) + 1)
    output_fn(f" {custom_idx:<3} {'Свой DNS':<12} {'(ввод вручную)':<30} {'-':<12} Ввести IP-адреса вручную")
    output_fn(" 0.  Отмена (вернуться назад)")

    while True:
        choice = _read_choice(f"Выберите вариант [1-{custom_idx}, 0]: ", input_fn, output_fn)
        if choice == "0":
            return
        chosen_servers: list[str] = []
        if choice in candidate_map:
            chosen_servers = candidate_map[choice]
            break
        elif choice == custom_idx:
            raw_ips = input_fn("Введите IP-адреса DNS через пробел или запятую (до 3 шт): ").strip()
            if not raw_ips:
                output_fn("Ввод отменен.")
                return
            cleaned = [ip.strip() for ip in raw_ips.replace(",", " ").split() if ip.strip()]
            from .dns_manager import validate_dns_servers
            try:
                chosen_servers = validate_dns_servers(cleaned)
                break
            except ValueError as exc:
                output_fn(f"Ошибка валидации: {exc}")
                continue
        else:
            output_fn("Неверный выбор. Повторите попытку.")

    output_fn(f"\nВыбранные DNS-серверы: {', '.join(chosen_servers)}")
    if not _yes_no("Применить выбранную конфигурацию DNS?", input_fn, output_fn):
        output_fn("Смена DNS отменена.")
        return

    try:
        result = engine.set_system_dns(chosen_servers)
        output_fn("\nРезультат применения:")
        output_fn(f"  Статус: {'успешно' if result.get('ok') else 'ошибка'}")
        output_fn(f"  Резолвер: {result.get('resolver')}")
        output_fn(f"  Активные серверы: {', '.join(result.get('servers', []))}")
        if result.get("resolution_verified"):
            output_fn("  Проверка резолва: подтверждена (домены разрешаются)")
        else:
            output_fn("  Проверка резолва: предупреждение (тестовый домен не разрешился)")
    except Exception as exc:
        output_fn(f"Ошибка при установке DNS: {exc}")


def _network_tuning_dialog(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    status = engine.get_network_tuning_status()
    output_fn("\nОптимизация TCP BBR и сетевых буферов")
    output_fn(f"  Текущий алгоритм: {status.get('active_congestion_control', 'неизвестно')}")
    output_fn(f"  Доступные алгоритмы: {', '.join(status.get('available_congestion_control', []))}")
    output_fn(f"  Диспетчер очередей (qdisc): {status.get('default_qdisc', 'неизвестно')}")
    cfg_status = "активен (/etc/sysctl.d/60-lucx-bbr.conf)" if status.get("config_file_present") else "отсутствует"
    output_fn(f"  Файл конфигурации: {cfg_status}")
    if status.get("is_fully_optimized"):
        output_fn("  Статус: ✔ Стек полностью оптимизирован (BBR + FQ + 64MB buffers)")
    elif status.get("bbr_active"):
        output_fn("  Статус: ✔ BBR активен, но расширенные буферы можно обновить")
    else:
        output_fn("  Статус: ℹ Доступна оптимизация BBR для снижения потерь и задержек")

    output_fn(
        "\n 1. Применить / обновить оптимизацию TCP BBR и буферов\n"
        " 2. Откатить оптимизацию (вернуть настройки по умолчанию)\n"
        " 0. Назад"
    )
    choice = _read_choice("Выберите действие: ", input_fn, output_fn)
    if choice == "0":
        return
    if choice == "1":
        if not _yes_no("Применить оптимизацию ядра Linux (BBR + FQ + увеличенные буферы TCP)?", input_fn, output_fn):
            output_fn("Применение отменено.")
            return
        res = engine.apply_network_tuning()
        if res.get("ok"):
            output_fn("✔ Оптимизация успешно применена и сохранена в /etc/sysctl.d/60-lucx-bbr.conf.")
        else:
            output_fn(f"Ошибка применения: {res.get('error') or 'не удалось применить параметры sysctl'}")
    elif choice == "2":
        if not _yes_no("Удалить файл /etc/sysctl.d/60-lucx-bbr.conf и вернуть настройки?", input_fn, output_fn):
            output_fn("Откат отменен.")
            return
        res = engine.revert_network_tuning()
        output_fn("✔ Конфигурационный файл удален, системные параметры перезагружены.")


def _dns_security_dialog(engine: Engine, output_fn: OutputFn) -> None:
    output_fn("\nРасширенная диагностика DNS и сетевой безопасности")
    output_fn("Выполняется проверка резолверов, задержек и изоляции портов...")
    res = engine.run_dns_security_diagnostic()

    output_fn(f"\nРезолвер системы: {res.get('resolver')} (resolv.conf symlink: {'да' if res.get('is_symlink') else 'нет'})")
    output_fn("DNS-серверы:")
    for s in res.get("servers", []):
        lat = f"{s.get('latency_ms')} ms" if s.get("latency_ms") is not None else "не отвечает"
        output_fn(f"  - {s.get('ip')}: {lat}")

    output_fn("Разрешение внешних доменов:")
    for domain, ok in res.get("resolution_checks", {}).items():
        output_fn(f"  - {domain}: {'✔ успешно' if ok else '✖ сбой'}")

    output_fn("Сетевая изоляция внутренних служб (loopback-only):")
    ports = res.get("port_isolation", [])
    if ports:
        for p in ports:
            status_icon = "✔ Loopback" if p.get("is_loopback") else "✖ ВНИМАНИЕ: PUBLIC"
            proc = f" ({p.get('process')})" if p.get("process") else ""
            output_fn(f"  - Порт {p.get('port')} [{p.get('local_addr')}]: {status_icon}{proc}")
    else:
        output_fn("  - Внутренние службы изолированы.")

    warnings = res.get("warnings", [])
    if warnings:
        output_fn("\nПредупреждения:")
        for w in warnings:
            output_fn(f"  ! {w}")
    else:
        output_fn("\n✔ Замечаний по сетевой безопасности и резолву имён не обнаружено.")


def _cloudflare_origin_dialog(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    state = _safe_load_state(engine, output_fn, input_fn, context="настройки Cloudflare origin")
    if not state:
        return
    manifest = copy.deepcopy(state.get("manifest") or {})
    cf_cfg = manifest.setdefault("cloudflare", {})
    is_enabled = bool(cf_cfg.get("enabled"))
    output_fn("\nОграничение доступа Cloudflare origin")
    if is_enabled:
        output_fn(
            "Текущий статус: ВКЛЮЧЕНО (защита активна).\n"
            "Трафик к панели и подпискам разрешён ТОЛЬКО из сетей Cloudflare (оранжевое облако / proxy).\n"
            "Прямой доступ по IP сервера к этим доменам блокируется на уровне HAProxy и firewall.\n\n"
            "При отключении:\n"
            "  - Прямой доступ к панели и подпискам будет разрешён со всех IP-адресов.\n"
            "  - Будет удалена ACL в HAProxy и остановлен таймер обновления сетей Cloudflare."
        )
        if not _yes_no("Отключить ограничение Cloudflare origin?", input_fn, output_fn):
            output_fn("Отмена.")
            return
        cf_cfg["enabled"] = False
        cf_cfg["user_confirmed"] = False
        manifest.setdefault("components", {})["cloudflare"] = False
    else:
        output_fn(
            "Текущий статус: ВЫКЛЮЧЕНО.\n"
            "Панель и подписки доступны напрямую со всех IP-адресов.\n\n"
            "При включении:\n"
            "  - Загружается официальный список сетей Cloudflare (IPv4 и IPv6).\n"
            "  - HAProxy и firewall настраиваются принимать запросы к панели и подпискам ТОЛЬКО из сетей Cloudflare.\n"
            "  - Устанавливается systemd-таймер ежедневного обновления диапазонов Cloudflare.\n"
            "  - Любые прямые подключения в обход Cloudflare будут отклоняться.\n\n"
            "⚠ ВНИМАНИЕ: Домены панели и подписок ДОЛЖНЫ быть проксированы через Cloudflare\n"
            "  (включено оранжевое облако в DNS Cloudflare). Если проксирование выключено,\n"
            "  доступ к панели будет заблокирован!"
        )
        if not _yes_no("Домены панели и подписок проксируются через Cloudflare (оранжевое облако)?", input_fn, output_fn):
            output_fn("Отмена: сначала включите оранжевое облако (proxy) в панели Cloudflare DNS.")
            return
        if not _yes_no("Включить ограничение Cloudflare origin?", input_fn, output_fn):
            output_fn("Отмена.")
            return
        try:
            networks = _run_progress(
                "Загрузка официальных сетей Cloudflare",
                output_fn,
                lambda: fetch_cloudflare_networks(),
            )
            cf_cfg["networks"] = networks
        except Exception as exc:
            output_fn(f"Ошибка загрузки сетей Cloudflare: {exc}")
            input_fn("\nНажмите Enter...")
            return
        cf_cfg["enabled"] = True
        cf_cfg["user_confirmed"] = True
        manifest.setdefault("components", {})["cloudflare"] = True

    audit = _run_progress(
        "Read-only аудит перед изменением сетевой защиты",
        output_fn,
        lambda: engine.audit(manifest["lucx"]["db_path"]),
    )
    plan = _prepare_plan(engine, manifest, audit)
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    action_word = "отключение" if not cf_cfg["enabled"] else "включение"
    if _yes_no(f"Применить {action_word} Cloudflare origin с backup и rollback?", input_fn, output_fn):
        _show_operation_result(
            _run_progress(
                f"Применение ({action_word} Cloudflare origin)",
                output_fn,
                lambda: _apply_prepared(engine, manifest, audit=audit),
            ),
            output_fn,
            title=f"Ограничение Cloudflare origin {'включено' if cf_cfg['enabled'] else 'отключено'}",
        )


def _network_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    while True:
        try:
            state = load_state(engine.fs)
            manifest = state.get("manifest") or {}
        except Exception:
            manifest = {}
        bbr_fn = getattr(engine, "get_network_tuning_status", None)
        bbr_status = bbr_fn() if bbr_fn is not None else {}
        bbr_label = "включено (оптимизировано)" if bbr_status.get("is_fully_optimized") else ("BBR активен" if bbr_status.get("bbr_active") else bbr_status.get("active_congestion_control", "неизвестно"))
        cf_label = "включено" if manifest.get("cloudflare", {}).get("enabled") else "выключено"
        fw_label = manifest.get("firewall", {}).get("mode", "не настроен")
        dns_label = ", ".join(manifest.get("dns", {}).get("servers") or []) or "системный"
        output_fn(
            "\nСеть и защита\n"
            f" TCP BBR & FQ: {bbr_label}\n"
            f" Cloudflare origin restriction: {cf_label}\n"
            f" Firewall: {fw_label}\n"
            f" DNS: {dns_label}\n"
            " 1. Смена системного DNS (с замером пинга/задержки)\n"
            " 2. Оптимизация TCP BBR и сетевых буферов\n"
            " 3. Ограничение доступа Cloudflare origin (включить / выключить)\n"
            " 4. Проверить установленную сетевую конфигурацию\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _change_dns_dialog(engine, input_fn, output_fn)
        elif choice == "2":
            _network_tuning_dialog(engine, input_fn, output_fn)
        elif choice == "3":
            _cloudflare_origin_dialog(engine, input_fn, output_fn)
        elif choice == "4":
            _show_operation_result(
                _validate_installed(engine, output_fn),
                output_fn,
                title="Проверка сетевой конфигурации",
            )
        else:
            output_fn("Неизвестный пункт.")


def _repair_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    while True:
        failed_state = engine.fs.path("/var/lib/lucx-post-configurator/failed-state.json")
        has_failed = failed_state.is_file()
        output_fn(
            "\nРемонт после обновления\n"
            + (" ⚠ Обнаружена незавершённая упавшая транзакция (доступно возобновление)\n" if has_failed else "")
            + " 1. Только check (проверить необходимость ремонта)\n"
            " 2. Apply с точным планом, backup и rollback\n"
            + (" 3. Возобновить незавершённую транзакцию (resume failed state)\n" if has_failed else "")
            + " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _repair(engine, False, input_fn, output_fn)
        elif choice == "2":
            _repair(engine, True, input_fn, output_fn)
        elif choice == "3" and has_failed:
            if _yes_no("Возобновить упавшую транзакцию из сохранённого failed-state.json?", input_fn, output_fn):
                try:
                    from .transaction import load_state as t_load_state
                    failed_manifest = t_load_state(engine.fs, path=str(failed_state)).get("manifest")
                    if failed_manifest:
                        audit = _run_progress(
                            "Read-only аудит перед возобновлением",
                            output_fn,
                            lambda: engine.audit(failed_manifest.get("lucx", {}).get("db_path")),
                        )
                        plan = _prepare_plan(engine, failed_manifest, audit)
                        output_fn(format_plan(plan))
                        _show_plan_preview(plan, output_fn)
                        if _yes_no("Применить возобновление транзакции?", input_fn, output_fn):
                            res = _run_progress(
                                "Возобновление транзакции",
                                output_fn,
                                lambda: _apply_prepared(engine, failed_manifest, audit=audit),
                            )
                            _show_operation_result(res, output_fn, title="Транзакция возобновлена")
                except Exception as exc:
                    _explain_operation_error(exc, output_fn)
        else:
            output_fn("Неизвестный пункт.")


def _backup_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    while True:
        output_fn(
            "\nБэкапы и откат\n"
            " 1. Показать локальные backup-транзакции\n"
            " 2. Откатить последнюю транзакцию\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            root = engine.fs.path(BACKUP_ROOT)
            if not root.is_dir():
                output_fn("Backup-транзакции не найдены.")
            else:
                for path in sorted(root.iterdir(), reverse=True):
                    if path.is_dir():
                        output_fn(f"- {path.name}")
        elif choice == "2":
            _rollback(engine, input_fn, output_fn)
        else:
            output_fn("Неизвестный пункт.")


def _config_menu(
    engine: Engine, db_path: str | None, input_fn: InputFn, output_fn: OutputFn
) -> None:
    while True:
        output_fn(
            "\nНастройка\n"
            " 1. Первичная настройка (полный интерактивный мастер)\n"
            " 2. Домены и маршрутизация\n"
            " 3. Сайты-заглушки\n"
            " 4. Подписки и sidecar\n"
            " 5. Сертификаты и автопродление\n"
            " 6. TrustTunnel backend\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _initial_apply(engine, db_path, input_fn, output_fn)
        elif choice == "2":
            _domains_menu(engine, db_path, input_fn, output_fn)
        elif choice == "3":
            _decoy_menu(engine, input_fn, output_fn)
        elif choice == "4":
            _sidecar_menu(engine, input_fn, output_fn)
        elif choice == "5":
            _certificate_menu(engine, input_fn, output_fn)
        elif choice == "6":
            _trusttunnel_backend_menu(engine, input_fn, output_fn)
        else:
            output_fn("Неизвестный пункт.")


def _maintenance_menu(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    while True:
        output_fn(
            "\nОбслуживание\n"
            " 1. Обновление LucX\n"
            " 2. Ремонт после обновления\n"
            " 3. Бэкапы и откат\n"
            " 4. Установка/обновление команд TUI\n"
            " 5. Перезагрузка сервера\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _update(engine, input_fn, output_fn)
        elif choice == "2":
            _repair_menu(engine, input_fn, output_fn)
        elif choice == "3":
            _backup_menu(engine, input_fn, output_fn)
        elif choice == "4":
            _install_commands(engine, input_fn, output_fn)
        elif choice == "5":
            _reboot(engine, input_fn, output_fn)
        else:
            output_fn("Неизвестный пункт.")


def _show_quick_help(output_fn: OutputFn) -> None:
    output_fn(
        "\nКраткая справка x-tuna\n"
        "\n"
        "Главное меню разделено на 5 логических разделов:\n"
        "\n"
        "1. Статус и диагностика\n"
        "   - Read-only аудит ОС, LucX, сертификатов, inbounds и портов.\n"
        "   - Комплексный автотест всех протоколов (live probe) с замером задержки.\n"
        "   - Диагностика резолверов DNS и сетевой изоляции внутренних служб (loopback-only).\n"
        "   - Проверка сайтов-заглушек и валидация конфигурации без изменения системы.\n"
        "\n"
        "2. Настройка\n"
        "   - Первичная настройка: создание полного плана обвязки (HAProxy/Nginx/DNS/firewall).\n"
        "   - Домены: переключение DNS-зоны (sub.old -> sub.new) с подбором wildcard-сертификата.\n"
        "   - Сайты-заглушки: защита VPN-портов заглушками и переключение режима strict/extended.\n"
        "   - Подписки и sidecar: разделение подписок и исправление форматов для клиентов.\n"
        "   - Сертификаты и автопродление: управление сертификатами (acme.sh / Certbot) и выпуск через Cloudflare DNS-01.\n"
        "   - TrustTunnel backend: подключение совместимого endpoint (TrustTunnel HTTPS/TCP).\n"
        "\n"
        "3. Сеть и защита\n"
        "   - Смена DNS: выбор быстрого резолвера с живым замером RTT или ввод своих адресов.\n"
        "   - Оптимизация ядра: включение TCP BBR + FQ и буферов 64MB для стабильного канала.\n"
        "   - Ограничение Cloudflare origin: запрет прямого доступа к панели и подпискам в обход Cloudflare proxy.\n"
        "   - Проверка сетевой конфигурации.\n"
        "\n"
        "4. Обслуживание\n"
        "   - Обновление LucX: фоновое независимое обновление панели (GitHub, зеркала или файл).\n"
        "   - Ремонт после обновления: автоматическое восстановление маршрутов из базы LucX.\n"
        "   - Бэкапы и откат: откат последней транзакции (включая принудительный force-откат).\n"
        "   - Установка команд: регистрация x-tuna и lucx-sub-repair в /usr/local/sbin.\n"
        "   - Перезагрузка: безопасный перезапуск ОС с двойным подтверждением.\n"
        "\n"
        "5. Справка\n"
        "   - Этот справочный раздел.\n"
        "\n"
        "Правило безопасности: любое изменяющее действие показывает план, backup, службы и rollback."
    )


def run_tui(
    engine: Engine,
    *,
    db_path: str | None = None,
    input_fn: InputFn = input,
    output_fn: OutputFn = print,
) -> int:
    raw_input_fn = input_fn

    def _safe_input_wrapper(prompt: str = "") -> str:
        while True:
            try:
                return raw_input_fn(prompt)
            except UnicodeDecodeError:
                continue

    input_fn = _safe_input_wrapper
    actions = {
        "1": lambda: _status_menu(engine, db_path, input_fn, output_fn),
        "2": lambda: _config_menu(engine, db_path, input_fn, output_fn),
        "3": lambda: _network_menu(engine, input_fn, output_fn),
        "4": lambda: _maintenance_menu(engine, input_fn, output_fn),
        "6": lambda: _retry_pending_operation(engine, input_fn, output_fn),
    }
    while True:
        output_fn(
            "\nLucX post-configurator\n"
            + _main_state_banner(engine)
            + "\n\n"
            " 1. Статус и диагностика\n"
            " 2. Настройка\n"
            " 3. Сеть и защита\n"
            " 4. Обслуживание\n"
            " 5. Краткая справка\n"
            " 6. Повторно проверить и подготовить новый план\n"
            " 0. Выход"
        )
        blocked = getattr(engine, '_tui_operation_error', None)
        if blocked is not None:
            _explain_operation_error(blocked, output_fn)
        try:
            choice = input_fn("Выберите раздел: ").strip()
        except (EOFError, KeyboardInterrupt):
            output_fn("")
            return 0
        if choice in {"0", "exit", "quit"}:
            return 0
        if choice == "5":
            _show_quick_help(output_fn)
            try:
                input_fn("\nНажмите Enter для возврата в меню...")
            except (EOFError, KeyboardInterrupt):
                pass
            continue
        action = actions.get(choice)
        if action is None:
            output_fn("Неизвестный пункт. Введите цифру от 0 до 6.")
            continue
        try:
            action()
        except Exception as exc:
            _explain_operation_error(exc, output_fn)
