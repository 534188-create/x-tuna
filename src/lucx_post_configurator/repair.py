from __future__ import annotations

import json
import copy
from typing import Any

from .engine import Engine, ApplyError
from .integrity import capture_integrity, compare_integrity
from .questionnaire import refresh_manifest_from_audit
from .transaction import load_state, managed_target_state, STATE_PATH
from .trusttunnel_backend import discover_existing_backend_credentials


PENDING_POST_UPDATE_REPAIR = "/var/lib/lucx-post-configurator/pending-post-update-repair"


def _dynamic_changes(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    old = {int(item["inbound_id"]): item for item in before.get("protocols", [])}
    old_routes = {
        int(item.get("inbound_id") or 0): item
        for item in (before.get("decoys") or {}).get("extended_routes") or []
    }
    new_routes = {
        int(item.get("inbound_id") or 0): item
        for item in (after.get("decoys") or {}).get("extended_routes") or []
    }
    result: list[dict[str, Any]] = []
    compared = (
        "protocol",
        "domain",
        "internal_host",
        "internal_port",
        "public_port",
        "udp_public_port",
        "network",
        "exposure",
        "security",
        "sni_names",
        "port_bindings",
        "clienthello_match_fingerprint",
    )
    for current in after.get("protocols", []):
        inbound_id = int(current["inbound_id"])
        previous = old.get(inbound_id, {})
        names = [
            name
            for name in compared
            if (
                (previous.get(name) or "") != (current.get(name) or "")
                if name == "clienthello_match_fingerprint"
                else previous.get(name) != current.get(name)
            )
        ]
        old_route = old_routes.get(inbound_id) or {}
        new_route = new_routes.get(inbound_id) or {}
        route_fields = (
            ("strategy", "decoy_strategy"),
            ("status", "decoy_status"),
            ("source_caddyfile_sha256", "source_caddyfile_sha256"),
            ("binary_path", "naive_binary_path"),
            ("managed_listen_port", "managed_listen_port"),
        )
        names.extend(
            report_name
            for field, report_name in route_fields
            if old_route.get(field) != new_route.get(field)
        )
        if names:
            result.append(
                {
                    "inbound_id": inbound_id,
                    "protocol": current.get("protocol", ""),
                    "changed_fields": names,
                }
            )
    return result


def repair_check(engine: Engine) -> dict[str, Any]:
    """Read current state and describe exactly what a repair would rebuild."""

    seal = managed_target_state(engine.fs, STATE_PATH)
    state = load_state(engine.fs)
    if managed_target_state(engine.fs, STATE_PATH) != seal:
        raise ApplyError('Состояние изменилось при подготовке repair; повторите проверку')
    saved = state["manifest"]
    if saved.get("components", {}).get("trusttunnel_backend"):
        backend = saved.setdefault("trusttunnel_backend", {})
        if not backend.get("credentials"):
            backend["credentials"] = discover_existing_backend_credentials(engine.fs.root)
    audit = engine.audit(saved["lucx"]["db_path"])
    refreshed, warnings = refresh_manifest_from_audit(saved, audit)
    refreshed = engine.prepare_operation(refreshed, audit)
    engine._prepared_repair = (copy.deepcopy(refreshed), audit, seal, list(warnings))
    # Preflight must remain bounded. The full listener and HTTPS health checks
    # run after apply or through the explicit --validate command.
    validation = engine.validate_installed(include_live=False)
    changes = _dynamic_changes(saved, refreshed)
    expected_integrity = saved.get("integrity") or {}
    # The last successful apply records its narrowly approved LucX metadata
    # writes. Reuse those exact old/new values during drift checking; otherwise
    # repair-check would report our own publication sync as an unexplained edit.
    allowed_integrity_changes = list(state.get("lucx_publication_changes") or [])
    current_integrity = capture_integrity(
        engine.fs,
        saved["lucx"]["db_path"],
        audit.naive_caddyfile,
    )
    integrity_errors = (
        compare_integrity(
            expected_integrity,
            current_integrity,
            allowed_integrity_changes,
            naive_content_volatile=bool(
                (saved.get("lucx", {}).get("settings_management") or {}).get(
                    "sync_naive_share_addr"
                )
                or (saved.get("decoys", {}).get("naive_frontends") or [])
            ),
        )
        if (expected_integrity.get("protected_lucx") or expected_integrity.get("naive_caddyfile"))
        else []
    )
    panel_listener_changed = saved["lucx"]["panel"].get("internal_port") != refreshed[
        "lucx"
    ]["panel"].get("internal_port")
    subscription_listener_changed = saved["lucx"]["subscription"].get(
        "internal_port"
    ) != refreshed["lucx"]["subscription"].get("internal_port")
    return {
        "ok": bool(validation.get("ok")) and not changes and not integrity_errors,
        "run_id": state.get("run_id"),
        "schema_supported": audit.db_schema_supported,
        "services": audit.services,
        "installed_validation": validation,
        "dynamic_changes": changes,
        "integrity_errors": integrity_errors,
        "panel_listener_changed": panel_listener_changed,
        "subscription_listener_changed": subscription_listener_changed,
        "warnings": warnings,
        "repair_required": not bool(validation.get("ok")) or bool(changes) or bool(integrity_errors),
        "proposed_plan": engine.plan(refreshed, audit),
    }


def repair_apply(engine: Engine) -> dict[str, Any]:
    """Transactionally regenerate managed files from explicitly accepted live metadata.

    Repair is specifically used after a LucX update, so a changed protected
    snapshot is expected.  The refresh core still refuses schema changes and a
    changed enabled-inbound set.  Engine.apply then establishes a fresh
    read-only baseline and verifies that LucX/Naive do not change during this
    transaction.
    """

    prepared = getattr(engine, '_prepared_repair', None)
    if prepared and managed_target_state(engine.fs, STATE_PATH) != prepared[2]:
        raise ApplyError('Состояние изменилось после плана repair; повторите проверку и подтверждение')
    state = load_state(engine.fs)
    saved = state["manifest"]
    if saved.get("components", {}).get("trusttunnel_backend"):
        backend = saved.setdefault("trusttunnel_backend", {})
        if not backend.get("credentials"):
            backend["credentials"] = discover_existing_backend_credentials(engine.fs.root)
    audit = engine.audit(saved["lucx"]["db_path"])
    expected_integrity = saved.get("integrity") or {}
    accepted_integrity_changes: list[str] = []
    if expected_integrity.get("protected_lucx") or expected_integrity.get("naive_caddyfile"):
        current_integrity = capture_integrity(
            engine.fs,
            saved["lucx"]["db_path"],
            audit.naive_caddyfile,
        )
        accepted_integrity_changes = compare_integrity(
            expected_integrity, current_integrity, []
        )
    if prepared:
        refreshed, audit, _, refresh_warnings = prepared
    else:
        # Программный post-update repair разрешён отдельной операцией updater.
        refreshed, refresh_warnings = refresh_manifest_from_audit(saved, audit)
        refreshed = engine.prepare_operation(refreshed, audit)
    report = engine.apply(refreshed, audit=audit)
    engine._prepared_repair = None
    rebaseline_warnings = [
        "Явно подтверждённый repair принял текущее read-only состояние после "
        f"обновления LucX: {item}."
        for item in accepted_integrity_changes
    ]
    report["warnings"] = list(
        dict.fromkeys(
            list(report.get("warnings") or [])
            + refresh_warnings
            + rebaseline_warnings
        )
    )
    pending = engine.fs.path(PENDING_POST_UPDATE_REPAIR)
    if pending.is_file() and not pending.is_symlink():
        pending.unlink()
    return report


def format_repair_check(result: dict[str, Any]) -> str:
    lines = [
        "Проверка восстановления LucX",
        f"Состояние: {'исправно' if result.get('ok') else 'требуется внимание'}",
        f"Схема БД поддерживается: {'да' if result.get('schema_supported') else 'нет'}",
    ]
    changes = result.get("dynamic_changes") or []
    if changes:
        lines.append("Изменения актуальной топологии:")
        for item in changes:
            fields = ", ".join(item.get("changed_fields") or [])
            lines.append(
                f"- inbound #{item.get('inbound_id')} {item.get('protocol')}: {fields}"
            )
    validation = result.get("installed_validation") or {}
    for error in validation.get("errors") or []:
        lines.append(f"- ошибка: {error}")
    for error in result.get("integrity_errors") or []:
        lines.append(f"- блокировка целостности: {error}")
    for path in validation.get("changed_managed_files") or []:
        lines.append(f"- изменен управляемый файл: {path}")
    for warning in result.get("warnings") or []:
        lines.append(f"- предупреждение: {warning}")
    return "\n".join(lines)


def repair_check_json(engine: Engine) -> str:
    from .diagnostics import redact

    return json.dumps(redact(repair_check(engine)), ensure_ascii=False, indent=2) + "\n"
