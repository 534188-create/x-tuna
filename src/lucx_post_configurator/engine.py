from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .cloudflare import CloudflareNetworkError, fetch_cloudflare_networks
from .discovery import Audit, audit_system
from .diagnostics import build_diagnostic_report, redact, stable_fingerprint
from .decoy_health import decoy_acceptance_summary, required_vpn_probe_errors, vpn_acceptance_summary
from .staging_integrity import capture_staged_candidate
from .extended_decoys import exact_client_random_prefix, classify_extended_decoy_routes
from .routing_profiles import inbound_routing_metadata, source_routing_fingerprint
from .routing_rebase import RebaseBaseline, capture_rebase_baseline, verify_authorized_rebase
from .integrity import capture_integrity, compare_caddy, compare_integrity
from .models import validate_manifest
from .planner import build_plan
from .renderers import GeneratedFile, render_files, render_managed_naive_files, render_tls_hook
from .runner import Runner, install_packages, missing_packages
from .targetfs import TargetFS
from .transaction import (
    FAILED_STATE_PATH,
    STATE_PATH,
    Backup,
    backup_lucx_database,
    commit_managed_transition,
    clear_failed_state,
    create_backup,
    load_state,
    load_backup,
    managed_target_digest,
    managed_target_state,
    new_run_id,
    restore_backup,
    remove_staging,
    remove_managed_targets,
    rollback_latest,
    rollback_lucx_publication,
    synchronize_lucx_inbound_changes,
    save_failed_state,
    save_state,
    stage_files,
    synchronize_lucx_publication,
    validated_removal_targets,
)
from .trusttunnel_backend import (
    discover_existing_backend_credentials,
    probe_backend,
    probe_endpoint_from_manifest,
    validate_backend_manifest,
)
from .validation import (
    routing_audit_snapshot,
    validate_routing_snapshot,
    validate_required_acceptance,
    rollback_health_status,
    validate_audit_against_manifest,
    validate_certificate,
    validate_generated,
    validate_live_configuration,
    validate_lucx_tls_coverage,
    validate_public_bind_conflicts,
)
from .vpn_probe_registry import installed_vpn_probes
from .staging_eligibility import staging_eligibility_errors
from .staging_probes import prepare_functional_staging, run_functional_staging
from .manifest_source import ManifestSourceFence


REPORT_ROOT = "/var/lib/lucx-post-configurator/reports"
SIDECAR_MANAGED_TARGETS = (
    "/usr/local/libexec/lucx-sub-sidecar.py",
    "/etc/lucx-sub-sidecar/env",
    "/etc/systemd/system/lucx-sub-sidecar.service",
)
TRUSTTUNNEL_BACKEND_MANAGED_TARGETS = (
    "/etc/x-tuna/trusttunnel/vpn.toml",
    "/etc/x-tuna/trusttunnel/hosts.toml",
    "/etc/x-tuna/trusttunnel/rules.toml",
    "/etc/x-tuna/trusttunnel/credentials.toml",
    "/etc/systemd/system/x-tuna-trusttunnel-backend.service",
)


class ApplyError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _managed_decoy_directories(manifest: dict[str, Any]) -> dict[str, int]:
    if not (
        (manifest.get("components") or {}).get("nginx")
        and (manifest.get("decoys") or {}).get("enabled")
    ):
        return {}
    base = Path("/var/www/lucx-decoys")
    result = {str(base): 0o755}
    for site in (manifest.get("decoys") or {}).get("sites") or []:
        root = Path(str(site.get("root") or ""))
        if root != base and base not in root.parents:
            raise ApplyError(f"decoy root is outside the managed directory: {root}")
        result[str(root)] = 0o755
    return result


def _ephemeral_routing_material(
    fs: TargetFS,
    audit: Audit,
    manifest: dict[str, Any],
) -> dict[int, dict[str, Any]]:
    """Load secrets only for the current transaction from exact audited paths.

    Source contents are deliberately not added to the manifest, state or report.
    """

    material: dict[int, dict[str, Any]] = {}
    cached_routes = (manifest.get("decoys") or {}).get("extended_routes") or []
    extended = (manifest.get("decoys") or {}).get("routing_mode") == "extended"
    fresh_routes = classify_extended_decoy_routes(manifest, audit) if extended else []
    candidates = [route for route in fresh_routes if route.get("strategy") == "naive_connect_h2"]
    if extended and (candidates or any(route.get("strategy") == "naive_connect_h2" for route in cached_routes)):
        from .naive_frontend import parse_naive_connect_source, parse_naive_native_source
        from .naive_probe_source import _capture

        try:
            # Пустой cache допустим только как запрос свежей классификации;
            # частичный либо подменённый сохранённый набор не разрешает чтение.
            fresh_ids = [route["inbound_id"] for route in fresh_routes]
            cached_ids = [route.get("inbound_id") for route in cached_routes]
            if (any(type(value) is not int or value <= 0 for value in fresh_ids + cached_ids)
                    or len(set(fresh_ids)) != len(fresh_ids)
                    or (cached_routes and (len(set(cached_ids)) != len(cached_ids)
                                           or set(cached_ids) != set(fresh_ids)))):
                raise ValueError("Набор Naive маршрутов не подтверждён")
            fresh_by_id = {route["inbound_id"]: route for route in fresh_routes}
            for saved in cached_routes:
                actual = fresh_by_id[saved["inbound_id"]]
                if any(name not in saved or name not in actual or saved[name] != actual[name]
                       for name in (set(saved) | set(actual)) - {"reason", "evidence"}):
                    raise ValueError("Сохранённый Naive маршрут устарел")
            for candidate in candidates:
                inbound_id = candidate["inbound_id"]
                expected = candidate["source_identity"]
                path = fs.path(expected["path"])
                payload, snapshot, captured = _capture(path)
                if any(captured[name] != expected[name] for name in captured):
                    raise ValueError("Идентичность Naive source изменилась")
                text = payload.decode("utf-8")
                parsed = parse_naive_connect_source(text)
                if parsed.upstream or parsed.probe_resistance:
                    parse_naive_native_source(text)
                if (not 1 <= len(parsed.auth_pairs) <= 128
                        or len({user for user, _ in parsed.auth_pairs}) != len(parsed.auth_pairs)
                        or any(not user or not password for user, password in parsed.auth_pairs)):
                    raise ValueError("Структура Naive source не подтверждена")
                if _capture(path)[1] != snapshot:
                    raise ValueError("Naive source изменился во время проверки")
                metadata = next(item for item in audit.naive_caddyfile["files"]
                                if item.get("path") == expected["path"])
                material[inbound_id] = {"naive_caddyfile_text": text,
                    "naive_source_metadata": copy.deepcopy(metadata),
                    "naive_binary_path": str((audit.naive_caddyfile or {}).get("binary_path") or "")}
        except (OSError, ValueError, TypeError, KeyError, StopIteration):
            raise ApplyError("Исходный Naive CONNECT source не подтверждён свежим аудитом") from None
    audited_files = {
        str(item.get("path") or ""): item
        for item in (audit.naive_caddyfile or {}).get("files") or []
        if isinstance(item, dict) and str(item.get("path") or "").startswith("/")
    }
    for route in (manifest.get("decoys") or {}).get("extended_routes") or []:
        if route.get("strategy") not in {"naive_managed", "naive_native"} or route.get("status") != "ready":
            continue
        inbound_id = int(route.get("inbound_id") or 0)
        source_path = str(route.get("source_caddyfile") or "")
        expected = str(route.get("source_caddyfile_sha256") or "").lower()
        metadata = audited_files.get(source_path)
        if inbound_id <= 0 or metadata is None:
            raise ApplyError(
                f"Naive inbound #{inbound_id or '?'} source is not the exact audited Caddyfile"
            )
        if str(metadata.get("sha256") or "").lower() != expected:
            raise ApplyError(f"Naive inbound #{inbound_id} source changed after audit")
        try:
            payload = fs.read_bytes(source_path)
        except OSError as exc:
            raise ApplyError(f"Naive inbound #{inbound_id} source cannot be read") from exc
        if len(payload) > 1024 * 1024:
            raise ApplyError(f"Naive inbound #{inbound_id} source exceeds the safe parser limit")
        current = hashlib.sha256(payload).hexdigest()
        if current != expected:
            raise ApplyError(f"Naive inbound #{inbound_id} source changed after audit")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ApplyError(f"Naive inbound #{inbound_id} source is not valid UTF-8") from exc
        material[inbound_id] = {
            "naive_caddyfile_text": text,
            "naive_source_metadata": copy.deepcopy(metadata),
            "naive_binary_path": str((audit.naive_caddyfile or {}).get("binary_path") or ""),
        }

    trust_routes = {
        int(route.get("inbound_id") or 0): route
        for route in (manifest.get("decoys") or {}).get("extended_routes") or []
        if route.get("strategy") == "trusttunnel_clienthello_split"
        and route.get("status") == "ready"
        and int(route.get("inbound_id") or 0) > 0
    }
    anytls_routes = {
        int(route.get("inbound_id") or 0): route
        for route in (manifest.get("decoys") or {}).get("extended_routes") or []
        if route.get("strategy") == "binary_tls_split"
        and route.get("status") == "ready"
        and int(route.get("inbound_id") or 0) > 0
    }
    db_targets = sorted(set(trust_routes) | set(anytls_routes))
    if db_targets:
        db_path = str((manifest.get("lucx") or {}).get("db_path") or "")
        path = fs.path(db_path)
        if not path.is_file() or path.is_symlink():
            raise ApplyError("Routing metadata database is unavailable")
        database: sqlite3.Connection | None = None
        try:
            database = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
            database.row_factory = sqlite3.Row
            database.execute("PRAGMA query_only=ON")
            columns = {
                str(row[1]) for row in database.execute("PRAGMA table_info(inbounds)")
            }
            if not {"id", "protocol", "enable", "settings"}.issubset(columns):
                raise ApplyError("Routing metadata schema is unsupported")
            placeholders = ",".join("?" for _ in db_targets)
            rows = database.execute(
                "SELECT id, protocol, enable, settings FROM inbounds "
                f"WHERE id IN ({placeholders}) ORDER BY id",
                tuple(db_targets),
            )
            found: set[int] = set()
            for row in rows:
                inbound_id = int(row["id"])
                proto = str(row["protocol"] or "").lower()
                if not bool(row["enable"]):
                    continue
                try:
                    settings = json.loads(str(row["settings"] or "{}"))
                except (TypeError, ValueError):
                    settings = {}
                if not isinstance(settings, dict):
                    settings = {}
                if proto in {"trusttunnel", "trust-tunnel"} and inbound_id in trust_routes:
                    raw_prefix = str(
                        settings.get("clientRandomPrefix")
                        or settings.get("client_random_prefix")
                        or ""
                    ).strip()
                    prefix = exact_client_random_prefix(raw_prefix)
                    expected = str(
                        trust_routes[inbound_id].get("clienthello_match_fingerprint") or ""
                    )
                    if not prefix or stable_fingerprint(raw_prefix) != expected:
                        raise ApplyError(
                            f"TrustTunnel inbound #{inbound_id} routing material changed after audit"
                        )
                    material[inbound_id] = {"clienthello_hex_prefix": prefix}
                    found.add(inbound_id)
                elif proto == "anytls" and inbound_id in anytls_routes:
                    passwords = []
                    main_pw = str(settings.get("password") or "").strip()
                    if main_pw:
                        passwords.append(main_pw)
                    for client in settings.get("clients") or []:
                        if isinstance(client, dict) and bool(client.get("enable", True)):
                            client_pw = str(client.get("password") or "").strip()
                            if client_pw:
                                passwords.append(client_pw)
                    hashes = [
                        hashlib.sha256(pw.encode("utf-8")).hexdigest()
                        for pw in dict.fromkeys(passwords)
                    ]
                    material[inbound_id] = {"auth_sha256_hashes": hashes}
                    found.add(inbound_id)
            missing = sorted(set(trust_routes) - found)
            if missing:
                raise ApplyError(
                    "TrustTunnel routing material is unavailable for inbound(s): "
                    + ", ".join(str(value) for value in missing)
                )
        except sqlite3.Error as exc:
            raise ApplyError("Routing metadata could not be read safely") from exc
        finally:
            if database is not None:
                database.close()
    return material


def _managed_naive_services(generated: dict[str, GeneratedFile]) -> list[str]:
    result: list[str] = []
    for target, artifact in generated.items():
        if artifact.component != "naive_frontend":
            continue
        if target.startswith("/etc/systemd/system/lucx-naive-"):
            name = target.removeprefix("/etc/systemd/system/")
            if name.endswith(".service") and "-decoy-" in name:
                result.append(name)
            elif name.endswith(".path") and "-sync-" in name:
                result.append(name)
    return sorted(set(result))


def _managed_naive_services_from_targets(targets: list[str]) -> list[str]:
    services: list[str] = []
    for target in targets:
        match_decoy = re.fullmatch(
            r"/etc/systemd/system/(lucx-naive-decoy-(\d+)\.service)", target
        )
        if match_decoy and int(match_decoy.group(2)) > 0:
            services.append(match_decoy.group(1))
        match_path = re.fullmatch(
            r"/etc/systemd/system/(lucx-naive-sync-(\d+)\.path)", target
        )
        if match_path and int(match_path.group(2)) > 0:
            services.append(match_path.group(1))
    return sorted(set(services))


def _component_removal_targets(
    fs: TargetFS,
    manifest: dict[str, Any],
    installed_hashes: dict[str, str],
) -> list[str]:
    requested: list[str] = []
    if not manifest.get("components", {}).get("sidecar"):
        requested.extend(SIDECAR_MANAGED_TARGETS)
    desired_naive_ids = {
        int(route.get("inbound_id") or 0)
        for route in (manifest.get("decoys") or {}).get("extended_routes") or []
        if manifest.get("components", {}).get("naive_frontend")
        and route.get("strategy") == "naive_managed"
        and route.get("status") == "ready"
        and int(route.get("inbound_id") or 0) > 0
    }
    for target in installed_hashes:
        config_match = re.fullmatch(
            r"/etc/lucx-post-configurator/naive/naive-(\d+)\.caddyfile", target
        )
        unit_match = re.fullmatch(
            r"/etc/systemd/system/lucx-naive-(?:decoy|sync)-(\d+)\.(?:service|path)", target
        )
        match = config_match or unit_match
        if match and int(match.group(1)) not in desired_naive_ids:
            requested.append(target)
    if not manifest.get("components", {}).get("naive_frontend"):
        if "/usr/local/libexec/lucx-naive-sync.py" in installed_hashes:
            requested.append("/usr/local/libexec/lucx-naive-sync.py")
    if not manifest.get("components", {}).get("trusttunnel_backend"):
        requested.extend(TRUSTTUNNEL_BACKEND_MANAGED_TARGETS)
    return validated_removal_targets(fs, installed_hashes, requested)


class Engine:
    def __init__(self, root: str | Path = "/", *, runner: Runner | None = None) -> None:
        self.fs = TargetFS(root)
        self.runner = runner or Runner(dry_run=not self.fs.is_live)

    def audit(self, db_path: str | None = None) -> Audit:
        return audit_system(self.fs.root, db_path)

    def trusttunnel_status(self, db_path: str | None = None):
        """Наблюдение существующего LucX без записи и запуска staging."""
        from .trusttunnel_status import observe_trusttunnel

        manifest = {}
        state_error = False
        if self.fs.exists(STATE_PATH):
            try:
                # Для статуса нужен только флаг: credentials-файлы не читаются.
                state = json.loads(self.fs.path(STATE_PATH).read_text(encoding="utf-8"))
                manifest = state.get("manifest") or {}
                if not isinstance(manifest, dict):
                    raise ValueError("manifest")
            except (OSError, ValueError, AttributeError):
                state_error = True
                manifest = {}
        result = observe_trusttunnel(
            self.audit(db_path), self.runner,
            optional_backend_enabled=bool((manifest.get("components") or {}).get("trusttunnel_backend")),
        )
        if state_error:
            result.errors.append("сохранённое состояние опционального backend недоступно; LucX проверен отдельно")
        return result

    def probe_trusttunnel_candidate(self, *, binary: str | Path | None = None, loopback_port: int = 0):
        """Проверка отдельного кандидата не устанавливает и не включает его."""
        return probe_backend(self.runner, binary=binary, loopback_port=loopback_port)

    def probe_dns_candidates(self, timeout: float = 1.2):
        """Параллельный замер задержки популярных системных DNS-резолверов."""
        from .dns_manager import probe_dns_candidates
        return probe_dns_candidates(timeout=timeout)

    def get_current_system_dns(self) -> list[str]:
        """Чтение активных адресов DNS-серверов из системы."""
        from .dns_manager import read_current_system_dns
        return read_current_system_dns(self.fs)

    def set_system_dns(self, servers: list[str]) -> dict[str, Any]:
        """Атомарная установка и проверка системного DNS с синхронизацией состояния."""
        from .dns_manager import apply_system_dns
        with self._exclusive_lock():
            result = apply_system_dns(self.fs, self.runner, servers)
            if self.fs.exists(STATE_PATH):
                try:
                    state = json.loads(self.fs.path(STATE_PATH).read_text(encoding="utf-8"))
                    state.setdefault("manifest", {}).setdefault("dns", {})["servers"] = result["servers"]
                    state["manifest"]["dns"]["enabled"] = True
                    self.fs.atomic_write_text(
                        STATE_PATH,
                        json.dumps(state, ensure_ascii=False, indent=2) + "\n",
                        mode=0o600,
                    )
                except Exception:
                    pass
            return result

    def get_network_tuning_status(self) -> dict[str, Any]:
        """Текущий статус алгоритма BBR, очереди FQ и параметров TCP-стека."""
        from .network_tuning import get_network_tuning_status
        return get_network_tuning_status(self.runner, self.fs)

    def apply_network_tuning(self) -> dict[str, Any]:
        """Атомарное применение BBR, FQ и оптимизированных буферов памяти."""
        from .network_tuning import apply_network_tuning
        return apply_network_tuning(self.runner, self.fs)

    def revert_network_tuning(self) -> dict[str, Any]:
        """Откат параметров BBR и удаление конфигурационного файла."""
        from .network_tuning import revert_network_tuning
        return revert_network_tuning(self.runner, self.fs)

    def run_protocol_test(self, output_fn: Any = None) -> list[Any]:
        """Комплексный автотест всех протоколов, сайтов-заглушек и служб."""
        from .protocol_test import run_comprehensive_protocol_test
        return run_comprehensive_protocol_test(self, output_fn=output_fn)

    def run_dns_security_diagnostic(self) -> dict[str, Any]:
        """Расширенная диагностика DNS, резолверов и сетевой изоляции портов."""
        from .dns_manager import run_dns_security_diagnostic
        return run_dns_security_diagnostic(self.fs, self.runner)

    @contextmanager
    def _exclusive_lock(self, *, wait_timeout=0):
        if not self.fs.is_live:
            yield
            return
        import fcntl

        lock_path = self.fs.path("/run/lock/lucx-post-configurator.lock")
        metadata_path = self.fs.path("/run/lock/lucx-post-configurator.lock.json")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+", encoding="ascii") as handle:
            try:
                deadline = time.monotonic() + wait_timeout
                while True:
                    try:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if wait_timeout <= 0 or time.monotonic() >= deadline:
                            raise
                        # Ожидание только ДО транзакции. Commit не прерывается.
                        time.sleep(0.25)
            except BlockingIOError as exc:
                owner = ""
                try:
                    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                    pid = int(metadata.get("pid") or 0)
                    operation = str(metadata.get("operation") or "change")
                    if pid > 0:
                        os.kill(pid, 0)
                        owner = f" (PID {pid}, {operation})"
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    owner = " (владелец не определен; lock удерживается активным процессом)"
                raise ApplyError(
                    "другая операция lucx-post-configurator уже выполняется"
                    + owner
                    + "; дождитесь ее завершения"
                ) from exc
            try:
                metadata_path.write_text(
                    json.dumps(
                        {"pid": os.getpid(), "operation": "configuration", "started_at": _utc_now()},
                        ensure_ascii=True,
                    )
                    + "\n",
                    encoding="ascii",
                )
                os.chmod(metadata_path, 0o600)
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                try:
                    metadata_path.unlink()
                except FileNotFoundError:
                    pass

    def plan(self, manifest: dict[str, Any], audit: Audit | None = None) -> dict[str, Any]:
        plan = build_plan(manifest, audit)
        if manifest.get('naive_generation_adoption'):
            plan['warnings'].append('Первичная привязка поколения Naive: прежнее состояние не содержит '
                'отпечатков клиентской политики. Новый базовый снимок будет принят из проверенной '
                'текущей БД LucX после подтверждения этого плана.')
        if self.fs.exists(STATE_PATH):
            state = load_state(self.fs)
            removals = _component_removal_targets(
                self.fs,
                manifest,
                dict(state.get("installed_hashes") or {}),
            )
            if removals:
                removal_services = _managed_naive_services_from_targets(removals)
                if "/etc/systemd/system/lucx-sub-sidecar.service" in removals:
                    removal_services.append("lucx-sub-sidecar.service")
                plan["actions"].insert(
                    1,
                    {
                        "phase": "stage",
                        "component": "managed-remove",
                        "description": (
                            "Stop and remove only unchanged disabled-component files previously "
                            "written by lucx-post-configurator"
                        ),
                        "targets": removals,
                        "reversible": True,
                        "services": sorted(set(removal_services)),
                        "database_fields": [],
                    },
                )
        return plan

    def prepare_operation(self, manifest: dict[str, Any], audit: Audit | None = None) -> dict[str, Any]:
        """Свежие доказательства до preview; применение их молча не обновляет."""
        from .naive_lifecycle import prepare_naive_manifest
        try:
            fresh = audit if audit is not None else self.audit(manifest['lucx']['db_path'])
            return prepare_naive_manifest(self.fs, manifest, fresh)
        except ValueError as error:
            raise ApplyError(str(error)) from None
        except OSError:
            raise ApplyError('Naive: источник или защищённые настройки не подтверждены. '
                             'Дождитесь завершения запуска LucX и повторно проверьте план; '
                             'если ошибка остаётся, проверьте настройки подключения и права исходного файла.') from None

    def prepare_manifest_source(self, manifest, source, audit=None):
        """Файл остаётся под тем же CAS; производный кандидат показывается заново."""
        from dataclasses import replace
        from .manifest_source import _digest
        self._verify_manifest_source(source, manifest)
        candidate = self.prepare_operation(manifest, audit)
        rebound = replace(source, _manifest_digest=_digest(candidate)) if source else None
        self._verify_manifest_source(rebound, candidate)
        return candidate, rebound

    def _expect_naive_restart(self, manifest):
        self._naive_runtime_before_restart = {
            k: v['process_epoch_sha256'] for k, v in (manifest.get('naive_generations') or {}).items()
            if v.get('process_epoch_sha256')}

    def _settle_naive_generation(self, manifest, *, attempts=24, rebase=False):
        """Ждёт согласованный source/runtime после управляемого restart/reload."""
        if not manifest.get('naive_generations') and not rebase:
            return copy.deepcopy(manifest), self.audit(manifest['lucx']['db_path'])
        required = dict(getattr(self, '_naive_runtime_before_restart', {}))
        basis = copy.deepcopy(manifest)
        if rebase:
            basis.pop('naive_generations', None)
        previous = None
        for attempt in range(attempts):
            try:
                audit = self.audit(manifest['lucx']['db_path'])
                candidate = self.prepare_operation(basis, audit)
                generation = candidate['naive_generations']
                new_runtime = all(generation.get(k, {}).get('process_epoch_sha256') not in ('', None, value)
                                  for k, value in required.items())
                if generation == previous and new_runtime:
                    self._naive_runtime_before_restart = {}
                    return candidate, audit
                previous = generation
            except ApplyError:
                previous = None
            if attempt + 1 < attempts:
                time.sleep(0.5)
        raise ApplyError('Naive: LucX не сформировал согласованный источник и внутренний мост. '
                         'Проверьте состояние LucX, затем выберите повторную проверку плана.')

    def _synchronize_naive_generation_locked(self, manifest, *, installed_hashes=None,
                                              mutation_journal=None, persist=True, run_id=None,
                                              expected_state=None):
        """Общий путь фонового sync и reload; вызывается только под lock Engine."""
        from .naive_sync import synchronize_managed_naive
        state_before = managed_target_state(self.fs, STATE_PATH)
        if expected_state is not None and state_before != expected_state:
            raise ApplyError('Состояние изменилось после выбора операции Naive')
        state = load_state(self.fs) if persist else None
        if persist and managed_target_state(self.fs, STATE_PATH) != state_before:
            raise ApplyError('Состояние изменилось во время чтения Naive')
        candidate, audit = self._settle_naive_generation(manifest)
        material = _ephemeral_routing_material(self.fs, audit, candidate)
        all_files = render_managed_naive_files(candidate, material)
        desired = {p: f for p, f in all_files.items() if p.endswith('.caddyfile')}
        routes = {f"/etc/lucx-post-configurator/naive/naive-{r['inbound_id']}.caddyfile": r
                  for r in (candidate.get('decoys') or {}).get('extended_routes', [])
                  if r.get('strategy') == 'naive_managed' and r.get('status') == 'ready'}
        bindings = {p: {'binary_path': routes[p]['binary_path'],
                        'service': f"lucx-naive-decoy-{routes[p]['inbound_id']}.service"} for p in desired}
        hashes = installed_hashes if installed_hashes is not None else dict((state or {}).get('installed_hashes') or {})
        journal = mutation_journal if mutation_journal is not None else {}
        baseline = capture_integrity(self.fs, candidate['lucx']['db_path'], audit.naive_caddyfile)

        def source_fence():
            fresh = self.prepare_operation(candidate)
            if fresh.get('naive_generations') != candidate.get('naive_generations'):
                raise ApplyError('Naive: источник изменился во время синхронизации; повторите проверку')
            current = capture_integrity(self.fs, candidate['lucx']['db_path'], audit.naive_caddyfile)
            if compare_integrity(baseline, current, []):
                raise ApplyError('Защищённые данные изменились во время синхронизации Naive')
            if persist and managed_target_state(self.fs, STATE_PATH) != state_before:
                raise ApplyError('Состояние изменилось во время синхронизации Naive')

        def commit(updated, receipts):
            source_fence()
            hashes.update(updated)
            candidate['integrity'] = baseline
            if persist:
                state['manifest'] = candidate
                state['installed_hashes'] = hashes
                state['naive_sync'] = {'run_id': operation_id, 'status': 'complete'}
                try:
                    journal[STATE_PATH] = save_state(self.fs, state)
                    if managed_target_state(self.fs, STATE_PATH) != journal[STATE_PATH]:
                        raise ApplyError('State изменился сразу после синхронизации Naive')
                except Exception:
                    restore_backup(self.fs, state_backup, expected_current={STATE_PATH: journal[STATE_PATH]}
                                   if STATE_PATH in journal else {})
                    raise

        operation_id = run_id or new_run_id() + '-naive-' + uuid.uuid4().hex[:8]
        state_backup = create_backup(self.fs, {}, operation_id + '-state', extra_targets=[STATE_PATH]) if persist else None
        source_fence()
        synchronize_managed_naive(self.fs, self.runner, desired, bindings=bindings,
            installed_hashes=hashes, source_fence=source_fence, run_id=operation_id,
            commit_state=commit, mutation_journal=journal)
        return candidate

    def sync_naive_inbound(self, inbound_id: int) -> dict[str, Any]:
        if type(inbound_id) is not int or inbound_id <= 0:
            raise ApplyError('Некорректный номер Naive inbound')
        with self._exclusive_lock(wait_timeout=180):
            seal = managed_target_state(self.fs, STATE_PATH)
            state = load_state(self.fs)
            if managed_target_state(self.fs, STATE_PATH) != seal:
                raise ApplyError('Состояние изменилось во время чтения Naive')
            manifest = state.get('manifest') or {}
            if not any(p.get('protocol') == 'naive' and p.get('inbound_id') == inbound_id
                       for p in manifest.get('protocols') or []):
                raise ApplyError('Управляемый Naive inbound не найден')
            if not manifest.get('naive_generations'):
                raise ApplyError('Нужна первичная привязка Naive: откройте пункт повторной проверки '
                                 'в меню x-tuna и подтвердите свежий план')
            candidate = self.prepare_operation(manifest)
            self._synchronize_naive_generation_locked(candidate, expected_state=seal)
            return {'status': 'complete', 'inbound_id': inbound_id}

    def plan_certificate_renewal(self, manifest, audit=None):
        targets = ['/usr/local/sbin/lucx-tls-reload', STATE_PATH]
        services = ['x-ui.service']
        for component, service in (('haproxy', 'haproxy'), ('nginx', 'nginx'), ('sidecar', 'lucx-sub-sidecar')):
            if manifest.get('components', {}).get(component):
                services.append(service + '.service')
        for route in manifest.get('decoys', {}).get('extended_routes', []):
            if route.get('strategy') == 'naive_managed' and route.get('status') == 'ready':
                targets.append(f"/etc/lucx-post-configurator/naive/naive-{route['inbound_id']}.caddyfile")
                services.append(f"lucx-naive-decoy-{route['inbound_id']}.service")
        return {'actions': [{'phase': 'backup', 'component': 'certificates',
                    'description': 'Сохранить hook, состояние, управляемую копию и точную запись существующего ACME',
                    'targets': targets, 'reversible': True},
                {'phase': 'commit', 'component': 'certificates',
                    'description': 'Подключить проверенный reload hook, проверить службы и поколение Naive',
                    'services': services, 'reversible': True}],
                'files': ['/usr/local/sbin/lucx-tls-reload'], 'packages': [], 'services': [],
                'warnings': ['Регистрация hook не доказывает будущий запуск задания продления.'] +
                    (['Первая привязка Naive примет проверенную текущую клиентскую политику LucX '
                      'как базовую; прежняя версия не сохраняла её отпечаток.']
                     if manifest.get('naive_generation_adoption') else []),
                'immutable': ['Клиенты, протоколы, внутренние порты и исходный Naive Caddyfile']}

    def enable_certificate_renewal(self, manifest, *, selected):
        from .certificate_renewal import register_existing_renewal, HOOK_PATH
        with self._exclusive_lock():
            state_seal = managed_target_state(self.fs, STATE_PATH)
            state = load_state(self.fs)
            if managed_target_state(self.fs, STATE_PATH) != state_seal:
                raise ApplyError('Состояние изменилось во время чтения')
            saved = state['manifest']
            candidate = copy.deepcopy(manifest)
            # Этот режим разрешает ровно подключение renewal к прежней паре.
            fresh = self.audit(candidate['lucx']['db_path'])
            expected = self.prepare_operation(saved, fresh)
            def intent(value):
                value = copy.deepcopy(value)
                value['components'].pop('tls_hook', None)
                value['certificates'].pop('renewal', None)
                return value
            if intent(candidate) != intent(expected):
                raise ApplyError('Настройки изменились: для смены маршрутов или сертификата нужен отдельный план')
            _ephemeral_routing_material(self.fs, fresh, candidate)
            candidate['components']['tls_hook'] = True
            candidate['certificates']['renewal'].update(enabled=True, provider='acme.sh')
            run_id = new_run_id() + '-renewal-' + uuid.uuid4().hex[:8]
            hook = GeneratedFile(render_tls_hook(candidate).encode(), mode=0o750, component='certificates')
            shadow_files = {p: GeneratedFile(b'', mode=0o600) for p in state.get('installed_hashes', {})
                            if p.startswith('/etc/lucx-post-configurator/naive/') and p.endswith('.caddyfile')}
            backup = create_backup(self.fs, shadow_files, run_id + '-state', extra_targets=[STATE_PATH])
            journal = {}
            hashes = dict(state.get('installed_hashes') or {})

            def validate_candidate():
                errors = validate_certificate(self.fs, candidate, self.runner)
                staged = stage_files(self.fs, {HOOK_PATH: hook}, run_id)
                check = self.runner.run(['sh', '-n', str(staged[HOOK_PATH])], check=False)
                if errors or check.returncode:
                    raise ApplyError('Сертификат, ключ или кандидат reload hook не прошли проверку')
                if managed_target_state(self.fs, STATE_PATH) != state_seal:
                    raise ApplyError('Сохранённый план изменился до регистрации hook')

            def post_reload():
                nonlocal candidate
                candidate = self._synchronize_naive_generation_locked(candidate,
                    installed_hashes=hashes, mutation_journal=journal, persist=False, run_id=run_id + '-naive')
                audit = self.audit(candidate['lucx']['db_path'])
                errors = validate_live_configuration(candidate, self.runner, fs=self.fs, audit=audit)
                if errors:
                    raise ApplyError('Проверка служб после reload hook не пройдена; выполните диагностику')

            def commit_state():
                confirmed = self.prepare_operation(candidate)
                if confirmed.get('naive_generations') != candidate.get('naive_generations'):
                    raise ApplyError('Naive изменился во время health-check; повторите проверку плана')
                if managed_target_state(self.fs, STATE_PATH) != state_seal:
                    raise ApplyError('Сохранённое состояние изменилось перед регистрацией результата')
                candidate.pop('naive_generation_adoption', None)
                hashes[HOOK_PATH] = hashlib.sha256(hook.content).hexdigest()
                state['manifest'] = candidate
                state['installed_hashes'] = hashes
                state['certificate_renewal'] = {'registered': True, 'checked_at': _utc_now()}
                journal[STATE_PATH] = save_state(self.fs, state)
                if managed_target_state(self.fs, STATE_PATH) != journal[STATE_PATH]:
                    raise ApplyError('State изменился после регистрации результата')

            try:
                status = register_existing_renewal(self.fs, self.runner, candidate, selected,
                    hook=hook, validate_candidate=validate_candidate, post_reload=post_reload,
                    before_reload=lambda: self._expect_naive_restart(candidate),
                    commit_state=commit_state, run_id=run_id)
                return {'status': 'complete', 'run_id': run_id, 'renewal': status}
            except Exception:
                self._naive_runtime_before_restart = {}
                conflicts = restore_backup(self.fs, backup, expected_current=journal)
                if conflicts:
                    raise ApplyError('Откат регистрации ограничен: сторонние изменения сохранены') from None
                for target in journal:
                    match = re.fullmatch(r'/etc/lucx-post-configurator/naive/naive-(\d+)\.caddyfile', target)
                    if match:
                        self.runner.run(['systemctl', 'restart', f'lucx-naive-decoy-{match[1]}.service'], check=False)
                raise

    def _resolver(self) -> str:
        if not self.fs.is_live:
            return "resolvconf"
        if self.runner.available("systemctl"):
            active = self.runner.run(
                ["systemctl", "is-active", "--quiet", "systemd-resolved.service"], check=False
            )
            if active.returncode == 0:
                return "systemd-resolved"
        if self.runner.available("resolvconf") or self.fs.exists("/etc/resolvconf"):
            return "resolvconf"
        resolv_conf = self.fs.path("/etc/resolv.conf")
        if resolv_conf.is_file() and not resolv_conf.is_symlink():
            return "static"
        raise ApplyError("no safely managed resolver was found (systemd-resolved, resolvconf, or a regular /etc/resolv.conf)")

    def _write_report(self, run_id: str, report: dict[str, Any]) -> None:
        safe_report = build_diagnostic_report(report=report)
        self.fs.atomic_write_text(
            f"{REPORT_ROOT}/{run_id}.json",
            json.dumps(safe_report, ensure_ascii=False, indent=2) + "\n",
            mode=0o600,
        )
        report = safe_report
        lines = [
            f"# LucX post-configurator run {run_id}",
            "",
            f"- Status: `{report.get('status', 'unknown')}`",
            f"- Started: `{report.get('started_at', '')}`",
        ]
        if report.get("completed_at"):
            lines.append(f"- Completed: `{report['completed_at']}`")
        if report.get("failed_at"):
            lines.append(f"- Failed: `{report['failed_at']}`")
        lines.extend(["", "## Phases", ""])
        for phase in report.get("phases", []):
            lines.append(f"- `{phase.get('name')}`: {phase.get('status')} at {phase.get('at', '')}")
            if phase.get("directory"):
                lines.append(f"  - Backup: `{phase['directory']}`")
        if report.get("warnings"):
            lines.extend(["", "## Warnings", ""])
            lines.extend(f"- {warning}" for warning in report["warnings"])
        if report.get("error"):
            lines.extend(["", "## First error", "", str(report["error"])])
        if report.get("rollback"):
            lines.extend(["", "## Automatic rollback", "", str(report["rollback"])])
        lines.extend(
            [
                "",
                "## Immutable scope",
                "",
                "LucX clients, inbound listeners/settings, certificate contents, and the Naive Caddyfile were not write targets. "
                "Only explicitly confirmed public URL metadata and certificate file paths may be synchronized transactionally.",
            ]
        )
        self.fs.atomic_write_text(
            f"{REPORT_ROOT}/{run_id}.md", "\n".join(lines) + "\n", mode=0o600
        )

    def _existing_dns_text(self, resolver: str) -> str:
        if resolver == "resolvconf":
            return self.fs.read_text("/etc/resolvconf/resolv.conf.d/head")
        if resolver == "static":
            return self.fs.read_text("/etc/resolv.conf")
        return ""

    def _activate(self, generated: dict[str, GeneratedFile], resolver: str) -> None:
        components = {artifact.component for artifact in generated.values()}
        if {"firewall", "sidecar", "cloudflare", "naive_frontend", "trusttunnel_backend"} & components:
            self.runner.run(["systemctl", "daemon-reload"])
        if "nginx" in components:
            self.runner.run(["systemctl", "enable", "nginx.service"])
            self.runner.run(["systemctl", "reload-or-restart", "nginx.service"])
        if "naive_frontend" in components:
            for service in _managed_naive_services(generated):
                self.runner.run(["systemctl", "enable", service])
                self.runner.run(["systemctl", "restart", service])
        if "haproxy" in components:
            self.runner.run(["systemctl", "enable", "haproxy.service"])
            self.runner.run(["systemctl", "reload-or-restart", "haproxy.service"])
        if "firewall" in components:
            self.runner.run(["systemctl", "enable", "lucx-post-firewall.service"])
            self.runner.run(["systemctl", "restart", "lucx-post-firewall.service"])
        if "sidecar" in components:
            self.runner.run(["systemctl", "enable", "lucx-sub-sidecar.service"])
            self.runner.run(["systemctl", "restart", "lucx-sub-sidecar.service"])
        if "trusttunnel_backend" in components:
            self.runner.run(["systemctl", "enable", "x-tuna-trusttunnel-backend.service"])
            self.runner.run(["systemctl", "restart", "x-tuna-trusttunnel-backend.service"])
        if "cloudflare" in components:
            self.runner.run(["systemctl", "enable", "--now", "lucx-cloudflare-ips-update.timer"])
        if "dns" in components:
            if resolver == "systemd-resolved":
                self.runner.run(["systemctl", "reload-or-restart", "systemd-resolved.service"])
            else:
                if resolver == "resolvconf":
                    self.runner.run(["resolvconf", "-u"])

    def _preserve_existing_decoy_content(
        self, generated: dict[str, GeneratedFile], manifest: dict[str, Any], report: dict[str, Any]
    ) -> None:
        for site in manifest["decoys"].get("sites", []):
            target = site["root"] + "/index.html"
            if target not in generated:
                continue
            root = self.fs.path(site["root"])
            if root.exists() and (not root.is_dir() or any(root.iterdir())):
                generated.pop(target)
                report["warnings"].append(
                    f"existing decoy content was preserved and not overwritten: {site['root']}"
                )

    def _disable_after_restore(self, service: str) -> list[str]:
        result = self.runner.run(["systemctl", "disable", "--now", service], check=False)
        if result.returncode == 0:
            return []
        # Удалённый unit допустим только при положительном подтверждении
        # отсутствия и неактивности; текст stderr не доказывает остановку.
        observed = self.runner.run(
            ["systemctl", "show", service, "-p", "LoadState", "-p", "ActiveState", "-p", "MainPID"],
            check=False,
        )
        values = dict(line.split("=", 1) for line in observed.stdout.splitlines() if "=" in line)
        no_process = values.get("MainPID") == "0" or (service.endswith(".timer") and "MainPID" not in values)
        if observed.returncode == 0 and values.get("LoadState") == "not-found" and values.get("ActiveState") == "inactive" and no_process:
            return []
        return [f"rollback could not confirm stop/disable of {service}"]

    def _reactivate_after_restore(
        self, generated: dict[str, GeneratedFile], resolver: str, installed_packages: list[str]
    ) -> list[str]:
        errors: list[str] = []
        try:
            if "firewall" in {artifact.component for artifact in generated.values()}:
                self.runner.run(["nft", "delete", "table", "inet", "lucx_post"], check=False)
            if not self.fs.exists("/etc/systemd/system/lucx-sub-sidecar.service"):
                errors.extend(self._disable_after_restore("lucx-sub-sidecar.service"))
            if not self.fs.exists("/etc/systemd/system/lucx-post-firewall.service"):
                errors.extend(self._disable_after_restore("lucx-post-firewall.service"))
            if not self.fs.exists("/etc/systemd/system/lucx-cloudflare-ips-update.timer"):
                errors.extend(self._disable_after_restore("lucx-cloudflare-ips-update.timer"))
            for service in _managed_naive_services(generated):
                if not self.fs.exists(f"/etc/systemd/system/{service}"):
                    errors.extend(self._disable_after_restore(service))
            for service in ("nginx", "haproxy"):
                if service in installed_packages:
                    errors.extend(self._disable_after_restore(f"{service}.service"))
            if not self.fs.exists("/etc/haproxy/haproxy.cfg"):
                errors.extend(self._disable_after_restore("haproxy.service"))
            self.runner.run(["systemctl", "daemon-reload"])
            active_files = {
                target: artifact
                for target, artifact in generated.items()
                if not (
                    artifact.component == "sidecar"
                    and not self.fs.exists("/etc/systemd/system/lucx-sub-sidecar.service")
                )
                and not (
                    artifact.component == "firewall"
                    and not self.fs.exists("/etc/systemd/system/lucx-post-firewall.service")
                )
                and not (
                    artifact.component == "cloudflare"
                    and not self.fs.exists("/etc/systemd/system/lucx-cloudflare-ips-update.timer")
                )
                and not (
                    artifact.component == "haproxy"
                    and not self.fs.exists("/etc/haproxy/haproxy.cfg")
                )
                and not (
                    artifact.component == "naive_frontend"
                    and not (
                        self.fs.path(target).exists()
                        or self.fs.path(target).is_symlink()
                    )
                )
                and artifact.component not in set(installed_packages)
            }
            if (
                any(artifact.component == "haproxy" for artifact in active_files.values())
                and self.fs.exists("/etc/haproxy/haproxy.cfg")
            ):
                self.runner.run(
                    ["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"],
                )
                self.runner.run(["systemctl", "enable", "haproxy.service"])
                self.runner.run(
                    ["systemctl", "reload-or-restart", "haproxy.service"],
                )
                active_files = {
                    target: artifact
                    for target, artifact in active_files.items()
                    if artifact.component != "haproxy"
                }
            self._activate(active_files, resolver)
        except Exception as exc:
            errors.append(str(exc))
        return errors

    def _register_acme_hook(self, manifest, *, complete=None):
        """Регистрация является оболочкой финальных проверок и commit state."""
        from .certificate_renewal import register_existing_renewal, renewal_status, HOOK_PATH
        finish = complete or (lambda: None)
        if not manifest['components'].get('tls_hook'):
            finish()
            return []
        certs = manifest['certificates']
        provider = certs['renewal'].get('provider', 'auto')
        observed = renewal_status(self.fs, certs['cert_path'], certs['key_path'])
        if provider == 'acme.sh' or provider == 'auto' and observed['record_found']:
            hook = GeneratedFile(render_tls_hook(manifest).encode(), mode=0o750, component='certificates')
            def validate():
                if validate_certificate(self.fs, manifest, self.runner):
                    raise ApplyError('Пара сертификата не прошла проверку перед подключением ACME')
                if self.fs.read_bytes(HOOK_PATH) != hook.content:
                    raise ApplyError('Reload hook изменился после commit')
            register_existing_renewal(self.fs, self.runner, manifest, certs,
                hook=hook, validate_candidate=validate, post_reload=lambda: None,
                before_reload=lambda: self._expect_naive_restart(manifest),
                commit_state=finish, run_id=new_run_id() + '-hook-' + uuid.uuid4().hex[:8])
            return []
        finish()
        if provider == 'certbot' or certs['cert_path'].startswith('/etc/letsencrypt/live/'):
            return [] if self.runner.available('certbot') else ['Certbot не найден: расписание продления не подтверждено.']
        return ['Reload hook установлен; подключение к существующему клиенту продления не подтверждено.']

    @staticmethod
    def _verify_manifest_source(source: ManifestSourceFence | None, manifest: dict | None = None) -> None:
        if source is None:
            return
        try:
            if type(source) is not ManifestSourceFence:
                raise ValueError('Неподтверждённый источник')
            source.verify(manifest=manifest)
        except ValueError:
            raise ApplyError('Исходный манифест изменён; повторите чтение и подтверждение плана') from None

    def apply(self, manifest: dict[str, Any], *, audit: Audit | None = None,
              manifest_source: ManifestSourceFence | None = None) -> dict[str, Any]:
        self._verify_manifest_source(manifest_source, manifest)
        with self._exclusive_lock():
            return self._apply_locked(manifest, audit=audit, manifest_source=manifest_source)

    def _verify_manifest_source_target(self, source: ManifestSourceFence | None, target: str) -> None:
        # State может быть одновременно входом и результатом операции. Старый
        # source fence применим до собственной записи; далее действует journal.
        if source is not None and source.guards(self.fs.path(target)):
            self._verify_manifest_source(source)

    def _is_naive_receipt_authorized(
        self,
        manifest: dict[str, Any],
        receipts: list[dict[str, Any]],
        audit: Audit | None = None,
    ) -> bool:
        if any(r.get("protocol") == "naive" for r in receipts):
            return True

        inbound_ids_in_receipts = {
            str(r.get("inbound_id"))
            for r in receipts
            if r.get("inbound_id") is not None
        }
        if inbound_ids_in_receipts:
            if audit and any(
                str(item.id) in inbound_ids_in_receipts and item.protocol == "naive"
                for item in getattr(audit, "inbounds", []) or []
            ):
                return True
            if any(
                str(p.get("inbound_id")) in inbound_ids_in_receipts
                and str(p.get("protocol") or "").strip().lower() == "naive"
                for p in manifest.get("protocols") or []
            ):
                return True

        settings_management = manifest.get("lucx", {}).get("settings_management") or {}
        if (
            settings_management.get("sync_naive_endpoint")
            or settings_management.get("sync_naive_share_addr")
        ):
            return True

        if any(
            str(p.get("protocol") or "").strip().lower() == "naive"
            and (p.get("sync_naive_endpoint") or p.get("sync_public_endpoint"))
            for p in manifest.get("protocols") or []
        ):
            return True

        if any(
            r.get("strategy") == "naive_managed"
            for r in (manifest.get("decoys", {}).get("extended_routes") or [])
        ) or (manifest.get("decoys", {}).get("naive_frontends") or []):
            return True

        has_naive_inbound = (
            bool(audit and any(item.protocol == "naive" for item in getattr(audit, "inbounds", []) or []))
            or any(str(p.get("protocol") or "").strip().lower() == "naive" for p in manifest.get("protocols") or [])
        )
        if receipts and has_naive_inbound and (
            settings_management.get("sync_domains")
            or settings_management.get("sync_public_endpoints")
            or settings_management.get("sync_certificate_paths")
        ):
            return True

        return False


    def _refresh_authorized_routing(
        self, manifest: dict[str, Any], baseline: RebaseBaseline,
        receipts: list[dict[str, Any]],
    ) -> Audit:
        """Принимает новые факты только после сверки точных собственных изменений."""
        db_path = manifest["lucx"]["db_path"]
        try:
            verified = verify_authorized_rebase(self.fs, db_path, baseline, receipts)
            fresh = self.audit(db_path)
            if {item.id: source_routing_fingerprint(item) for item in fresh.inbounds} != verified:
                raise ValueError("LucX изменился после проверки согласованных изменений")
            previous_naive = Audit(naive_caddyfile=baseline.naive_audit_snapshot)
            fresh_naive_integrity = capture_integrity(self.fs, db_path, fresh.naive_caddyfile)["naive_caddyfile"]
            naive_changed = (
                routing_audit_snapshot(fresh)["naive_files"] != routing_audit_snapshot(previous_naive)["naive_files"]
                or fresh_naive_integrity != baseline.naive_integrity
            )
            if naive_changed:
                if not self._is_naive_receipt_authorized(manifest, receipts, fresh):
                    raise ValueError("Исходный Naive Caddyfile изменился; SQL receipt не разрешает обновить его снимок")
                caddy_errors = compare_caddy(baseline.naive_integrity, fresh_naive_integrity, ignore_content=True)
                if caddy_errors:
                    raise ValueError("Исходный Naive Caddyfile изменился недопустимым образом: " + "; ".join(caddy_errors))
                object.__setattr__(baseline, "naive_audit_snapshot", copy.deepcopy(fresh.naive_caddyfile))
                object.__setattr__(baseline, "naive_integrity", fresh_naive_integrity)
        except ValueError as error:
            raise ApplyError(str(error)) from error
        candidate = copy.deepcopy(manifest)
        by_id = {item.id: item for item in fresh.inbounds}
        for protocol in candidate.get("protocols") or []:
            actual = by_id.get(int(protocol["inbound_id"]))
            if actual is None:
                raise ApplyError("Inbound исчез при проверке согласованных изменений")
            protocol.update(inbound_routing_metadata(actual))
            protocol["sni_names"] = list(actual.server_names)
        if (candidate.get("decoys") or {}).get("routing_mode") == "extended":
            candidate["decoys"]["extended_routes"] = classify_extended_decoy_routes(candidate, fresh)
        if "routing_snapshot" in candidate:
            candidate["routing_snapshot"] = routing_audit_snapshot(fresh)
        if manifest.get('naive_generations'):
            # Только verify_authorized_rebase выше разрешает принять намеренно
            # изменённые поля SQL; клиентская политика остаётся защищённой им.
            candidate, fresh = self._settle_naive_generation(candidate, rebase=True)
            checked = verify_authorized_rebase(self.fs, db_path, baseline, receipts)
            if {item.id: source_routing_fingerprint(item) for item in fresh.inbounds} != checked:
                raise ApplyError('LucX изменился во время ожидания нового поколения Naive')
            object.__setattr__(baseline, 'naive_audit_snapshot', copy.deepcopy(fresh.naive_caddyfile))
            object.__setattr__(baseline, 'naive_integrity',
                capture_integrity(self.fs, db_path, fresh.naive_caddyfile)['naive_caddyfile'])
        manifest.clear()
        manifest.update(candidate)
        return fresh

    def _apply_locked(self, manifest: dict[str, Any], *, audit: Audit | None = None,
                      manifest_source: ManifestSourceFence | None = None) -> dict[str, Any]:
        self._verify_manifest_source(manifest_source, manifest)
        # Scope сохраняется до health/rollback; регистрация сама не читает БД.
        with installed_vpn_probes(self.fs, self.runner, manifest):
            return self._apply_with_probes(manifest, audit=audit, manifest_source=manifest_source)

    def _apply_with_probes(self, manifest: dict[str, Any], *, audit: Audit | None = None,
                           manifest_source: ManifestSourceFence | None = None) -> dict[str, Any]:
        if not self.fs.is_live:
            raise ApplyError("apply is allowed only against the live root filesystem")
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise ApplyError("apply requires root privileges")
        manifest = copy.deepcopy(manifest)
        # Опциональный backend умеет запускать probe до основного preflight.
        # Новый Naive split останавливаем раньше чтения credentials и процессов.
        if (manifest.get('components', {}).get('trusttunnel_backend')
                and (manifest.get('decoys') or {}).get('routing_mode') == 'extended'
                and any(item.get('protocol') == 'naive' for item in manifest.get('protocols') or [])):
            fresh_audit = self.audit(manifest['lucx']['db_path'])
            if any(route.get('strategy') == 'naive_connect_h2'
                   for route in classify_extended_decoy_routes(manifest, fresh_audit)):
                raise ApplyError('Naive CONNECT требует полной общей функциональной проверки; применение кандидата пока запрещено')
        # Этот старый probe запускает отдельный backend. Строгий adapter его
        # не покрывает, поэтому отказ нужен ещё до discovery credentials.
        if ((manifest.get('decoys') or {}).get('require_full_acceptance') is True
                and manifest.get('components', {}).get('trusttunnel_backend')):
            raise ApplyError('Опциональный TrustTunnel backend ещё не покрыт строгим staging')
        if manifest.get("components", {}).get("trusttunnel_backend"):
            backend = manifest.setdefault("trusttunnel_backend", {})
            if not backend.get("credentials"):
                backend["credentials"] = discover_existing_backend_credentials(self.fs.root)
        validate_manifest(manifest)
        if manifest.get("components", {}).get("trusttunnel_backend"):
            backend = manifest["trusttunnel_backend"]
            binary = str(backend["binary_path"])
            path = self.fs.path(binary)
            if not path.is_file() or path.is_symlink():
                raise ApplyError("TrustTunnel compatible backend binary is unavailable")
            if self.fs.sha256(binary).lower() != str(backend["sha256"]).lower():
                raise ApplyError("TrustTunnel compatible backend binary SHA-256 does not match the pinned manifest")
            try:
                probe = probe_backend(
                    self.runner,
                    binary=binary,
                    loopback_port=int(backend["listen_port"]),
                )
                probe.protocol_handshake = probe_endpoint_from_manifest(
                    manifest,
                    binary=binary,
                    listen_port=int(backend["listen_port"]),
                )
                probe.ready = bool(
                    probe.version
                    and probe.supports_tcp
                    and probe.supports_http2_connect
                    and probe.supports_standard_uri
                    and probe.supports_config_file
                    and probe.protocol_handshake
                )
                if not probe.protocol_handshake:
                    probe.reasons.append("backend не прошёл реальный staging round-trip")
                validate_backend_manifest(manifest, probe)
            except ValueError as exc:
                raise ApplyError(str(exc)) from exc
        previous_installed_hashes: dict[str, str] = {}
        state_entry_seal = managed_target_state(self.fs, STATE_PATH)
        if self.fs.exists(STATE_PATH):
            previous_state = load_state(self.fs)
            previous_installed_hashes = dict(previous_state.get("installed_hashes") or {})
        if managed_target_state(self.fs, STATE_PATH) != state_entry_seal:
            raise ApplyError('Сохранённое состояние изменилось во время чтения')
        removal_targets = _component_removal_targets(
            self.fs,
            manifest,
            previous_installed_hashes,
        )
        # Re-audit inside the exclusive mutation lock; the interactive plan may
        # have been open while LucX or its listeners changed.
        audit = self.audit(manifest["lucx"]["db_path"])
        errors = validate_audit_against_manifest(
            audit, manifest, allow_pending_publication=True
        )
        # CONNECT split допускается только с полной проверкой всего кандидата.
        strict_staging = (manifest.get('decoys') or {}).get('require_full_acceptance') is True
        native_candidate = False
        if (manifest.get("decoys") or {}).get("routing_mode") == "extended":
            fresh_routes = classify_extended_decoy_routes(manifest, audit)
            native_candidate = any(route.get("strategy") == "naive_connect_h2" for route in fresh_routes)
            if native_candidate and not strict_staging:
                errors.append("Naive CONNECT требует полной общей функциональной проверки")
        errors.extend(validate_public_bind_conflicts(manifest, self.runner))
        errors.extend(required_vpn_probe_errors(manifest, self.runner))
        staging_preflight = None
        if strict_staging and not errors:
            packages_ready = (not manifest['components'].get('install_packages')
                              or not missing_packages(self.plan(manifest, audit)['packages'], self.runner))
            # Только чтение до backup; позже материал сверяется повторно.
            preflight_material = _ephemeral_routing_material(self.fs, audit, manifest)
            eligibility = staging_eligibility_errors(
                manifest, packages_ready=packages_ready, routing_material=preflight_material)
            errors.extend(('Naive CONNECT: ' + error if native_candidate else error) for error in eligibility)
            if removal_targets:
                errors.append('Удаление существующих служб ещё не покрыто функциональным staging')
            if not errors:
                try:
                    staging_preflight = prepare_functional_staging(
                        self.fs, self.runner, manifest, packages_ready=packages_ready,
                        audit=audit, routing_material=preflight_material)
                except ValueError:
                    errors.append('Не подтверждены инструменты и действующие клиенты функционального staging')
        if errors:
            raise ApplyError("preflight failed:\n- " + "\n- ".join(errors))

        settings_management = manifest.get("lucx", {}).get("settings_management") or {}
        publication_requested = any(settings_management.get(key) for key in (
            "sync_domains", "sync_panel_path", "sync_subscription_urls", "sync_naive_share_addr",
            "sync_public_endpoints", "sync_certificate_paths", "sync_naive_endpoint"))
        rebase_baseline = None
        if publication_requested or manifest.get("lucx", {}).get("inbound_changes"):
            try:
                rebase_baseline = capture_rebase_baseline(self.fs, manifest["lucx"]["db_path"], audit)
            except ValueError as error:
                raise ApplyError(str(error)) from error

        integrity_before = capture_integrity(
            self.fs,
            manifest["lucx"]["db_path"],
            audit.naive_caddyfile,
        )
        manifest["integrity"] = integrity_before
        routing_material = _ephemeral_routing_material(self.fs, audit, manifest)
        if (manifest.get("cloudflare") or {}).get("enabled"):
            try:
                manifest["cloudflare"]["networks"] = fetch_cloudflare_networks()
            except CloudflareNetworkError as exc:
                raise ApplyError(
                    "could not obtain a validated official Cloudflare network list; no changes were made"
                ) from exc

        run_id = new_run_id()
        plan = self.plan(manifest, audit)
        report: dict[str, Any] = {
            "schema_version": 1,
            "run_id": run_id,
            "started_at": _utc_now(),
            "status": "started",
            "manifest": manifest,
            "plan": plan,
            "installed_packages": [],
            "warnings": [],
            "phases": [
                {
                    "name": "integrity-baseline",
                    "status": "ok",
                    "at": _utc_now(),
                    "naive_caddyfile": integrity_before["naive_caddyfile"],
                }
            ],
        }
        backup: Backup | None = None
        rollback_backup: Backup | None = None
        generated: dict[str, GeneratedFile] = {}
        database_changes: list[dict[str, Any]] = []
        mutation_journal: dict[str, dict[str, Any]] = {}
        managed_services_touched = False
        resolver = "resolvconf"
        managed_directories = _managed_decoy_directories(manifest)
        try:
            resolver = self._resolver() if manifest["dns"].get("enabled") else "resolvconf"
            preliminary_files = render_files(
                manifest,
                resolver=resolver,
                existing_dns_text=self._existing_dns_text(resolver),
                routing_material=routing_material,
            )
            preliminary_backup = create_backup(
                self.fs,
                preliminary_files,
                run_id + "-pre",
                extra_targets=[
                    STATE_PATH,
                    "/etc/nginx/sites-enabled/default",
                    *removal_targets,
                ],
                directory_targets=managed_directories,
            )
            preliminary_database = backup_lucx_database(
                self.fs, preliminary_backup, manifest["lucx"]["db_path"]
            )
            # Предварительный backup хранит исходную топологию. Автоматический
            # откат ниже восстанавливает только подтверждённые записи этой операции.
            backup = preliminary_backup
            rollback_backup = preliminary_backup
            generated = preliminary_files
            report["phases"].append(
                {
                    "name": "pre-change-backup",
                    "status": "ok",
                    "at": _utc_now(),
                    "directory": str(preliminary_backup.directory),
                    "lucx_database_snapshot": {
                        "path": preliminary_database["path"],
                        "size": preliminary_database["size"],
                        "sha256": preliminary_database["sha256"],
                        "restore_policy": preliminary_database["restore_policy"],
                    },
                }
            )
            inbound_changes_requested = list(
                (manifest.get("lucx", {}).get("inbound_changes") or [])
            )
            if inbound_changes_requested:
                inbound_changes = synchronize_lucx_inbound_changes(
                    self.fs,
                    manifest["lucx"]["db_path"],
                    inbound_changes_requested,
                )
                database_changes.extend(inbound_changes)
                self._expect_naive_restart(manifest)
                self.runner.run(["systemctl", "restart", "x-ui.service"], timeout=60)
                self.runner.run(
                    ["systemctl", "is-active", "--quiet", "x-ui.service"], timeout=20
                )
                audit = self._refresh_authorized_routing(manifest, rebase_baseline, database_changes)
                report["phases"].append(
                    {
                        "name": "lucx-inbound-sync",
                        "status": "ok",
                        "at": _utc_now(),
                        "updated_targets": [
                            f"inbound #{change['inbound_id']} transport_path"
                            for change in inbound_changes
                        ],
                    }
                )
                # Inbound transport metadata is now authoritative. Rebuild
                # the staged configuration from the fresh audit so an XHTTP
                # path change is reflected in HAProxy and health checks.
                routing_material = _ephemeral_routing_material(self.fs, audit, manifest)
                generated = render_files(
                    manifest,
                    resolver=resolver,
                    existing_dns_text=self._existing_dns_text(resolver),
                    routing_material=routing_material,
                )
            settings_management = manifest.get("lucx", {}).get("settings_management") or {}
            if any(
                settings_management.get(key)
                for key in (
                    "sync_domains",
                    "sync_panel_path",
                    "sync_subscription_urls",
                    "sync_naive_share_addr",
                    "sync_public_endpoints",
                    "sync_certificate_paths",
                    "sync_naive_endpoint",
                )
            ):
                public_publications = [
                    {
                        "inbound_id": protocol["inbound_id"],
                        "domain": protocol["domain"],
                        "public_port": protocol["public_port"],
                    }
                    for protocol in manifest.get("protocols", [])
                    if protocol.get("sync_public_endpoint")
                ]
                endpoint_updates: list[dict[str, str]] = []
                audit_inbounds = {
                    int(inbound.id): inbound
                    for inbound in getattr(audit, "inbounds", []) or []
                }
                for protocol in manifest.get("protocols", []):
                    if not protocol.get("sync_naive_endpoint"):
                        continue
                    if str(protocol.get("security") or "").strip().lower() == "reality":
                        continue
                    inbound = audit_inbounds.get(int(protocol["inbound_id"]))
                    if inbound is None:
                        continue
                    endpoint_updates.append(
                        {
                            "inbound_id": protocol["inbound_id"],
                            "domain": protocol["domain"],
                            # share_addr already stores the bare host after
                            # discovery normalization; keep the last segment
                            # after '@' for defensive compatibility.
                            "old_domain": str(inbound.share_addr or "")
                            .rsplit("@", 1)[-1]
                            .strip()
                            .lower(),
                        }
                    )
                database_changes.extend(synchronize_lucx_publication(
                    self.fs,
                    manifest["lucx"]["db_path"],
                    panel_domain=(
                        manifest["lucx"]["panel"]["domain"]
                        if settings_management.get("sync_domains")
                        else None
                    ),
                    subscription_domain=(
                        manifest["lucx"]["subscription"]["domain"]
                        if settings_management.get("sync_domains")
                        else None
                    ),
                    panel_path=(
                        manifest["lucx"]["panel"].get("path_prefix", "/")
                        if settings_management.get("sync_panel_path")
                        else None
                    ),
                    subscription_base_url=(
                        manifest["lucx"].get("subscription", {}).get("public_base_url")
                        if settings_management.get("sync_subscription_urls")
                        else None
                    ),
                    public_publications=public_publications,
                    endpoint_updates=endpoint_updates,
                    certificate_paths=(
                        {
                            "cert_path": manifest["certificates"]["cert_path"],
                            "key_path": manifest["certificates"]["key_path"],
                        }
                        if settings_management.get("sync_certificate_paths")
                        else None
                    ),
                ))
                if database_changes:
                    self._expect_naive_restart(manifest)
                    self.runner.run(["systemctl", "restart", "x-ui.service"], timeout=60)
                    self.runner.run(
                        ["systemctl", "is-active", "--quiet", "x-ui.service"],
                        timeout=20,
                    )
                audit = self._refresh_authorized_routing(manifest, rebase_baseline, database_changes)
                domain_errors = validate_audit_against_manifest(audit, manifest)
                if domain_errors:
                    raise ApplyError(
                        "LucX domain synchronization verification failed:\n- "
                        + "\n- ".join(domain_errors)
                    )
                routing_material = _ephemeral_routing_material(self.fs, audit, manifest)
                report["phases"].append(
                    {
                        "name": "lucx-publication-sync",
                        "status": "ok",
                        "at": _utc_now(),
                        "updated_targets": [
                            (
                                change.get("key")
                                or (
                                    f"host #{change.get('host_id')} for inbound #{change.get('inbound_id')} endpoint"
                                    if change.get("kind") in {"inbound_host_endpoint", "inbound_host_created"}
                                    else f"inbound #{change.get('inbound_id')} share_addr"
                                )
                            )
                            for change in database_changes
                        ],
                    }
                )
            if manifest["components"].get("install_packages"):
                planned_missing = missing_packages(plan["packages"], self.runner)
                if strict_staging and planned_missing:
                    raise ApplyError('Пакеты изменились после preflight; установка до staging запрещена')
                report["installed_packages"] = planned_missing
                report["installed_packages"] = install_packages(
                    plan["packages"], self.runner, missing=planned_missing
                )
                # Debian package post-install scripts may auto-start stock listeners.
                # Keep newly installed frontends stopped until their staged configs pass.
                for service in ("nginx", "haproxy"):
                    if service in report["installed_packages"]:
                        self.runner.run(
                            ["systemctl", "disable", "--now", f"{service}.service"],
                            check=False,
                        )
            report["phases"].append({"name": "prerequisites", "status": "ok", "at": _utc_now()})

            # Re-read the database immediately before final rendering. Package
            # hooks or a concurrent LucX update must not leave us rendering an
            # old listener/SNI/ClientHello plan.
            audit = self.audit(manifest["lucx"]["db_path"])
            if rebase_baseline is not None:
                audit = self._refresh_authorized_routing(manifest, rebase_baseline, database_changes)
            topology_errors = validate_audit_against_manifest(audit, manifest)
            if topology_errors:
                raise ApplyError(
                    "LucX topology changed before final rendering:\n- "
                    + "\n- ".join(topology_errors)
                )
            routing_material = _ephemeral_routing_material(self.fs, audit, manifest)
            staging_snapshot = routing_audit_snapshot(audit)
            report["phases"].append(
                {
                    "name": "final-read-only-audit",
                    "status": "ok",
                    "at": _utc_now(),
                }
            )

            cert_errors = validate_certificate(self.fs, manifest, self.runner)
            cert_errors.extend(
                validate_lucx_tls_coverage(self.fs, audit, manifest, self.runner)
            )
            if cert_errors:
                raise ApplyError("certificate validation failed:\n- " + "\n- ".join(cert_errors))
            resolver = self._resolver() if manifest["dns"].get("enabled") else "resolvconf"
            generated = render_files(
                manifest,
                resolver=resolver,
                existing_dns_text=self._existing_dns_text(resolver),
                routing_material=routing_material,
            )
            if manifest.get("components", {}).get("nginx") or "nginx" in report["installed_packages"]:
                default_site = self.fs.path("/etc/nginx/sites-enabled/default")
                if default_site.exists() or default_site.is_symlink():
                    generated["/etc/nginx/sites-enabled/default"] = GeneratedFile(
                        b"# Disabled by lucx-post-configurator: no public stock Nginx listener.\n",
                        component="nginx",
                    )
                    report["warnings"].append(
                        "the stock Nginx default site was disabled because this run installed Nginx"
                        if "nginx" in report["installed_packages"] else
                        "the stock Nginx default site was disabled to enable port 80 HTTPS redirect"
                    )
            self._preserve_existing_decoy_content(generated, manifest, report)
            report["phases"].append({"name": "render", "status": "ok", "at": _utc_now(), "files": sorted(generated)})

            backup = create_backup(
                self.fs,
                generated,
                run_id,
                extra_targets=[STATE_PATH, *removal_targets],
                directory_targets=managed_directories,
            )
            database_snapshot = backup_lucx_database(
                self.fs, backup, manifest["lucx"]["db_path"]
            )
            report["phases"].append({"name": "backup", "status": "ok", "at": _utc_now(), "directory": str(backup.directory)})
            report["phases"][-1]["lucx_database_snapshot"] = {
                "path": database_snapshot["path"],
                "size": database_snapshot["size"],
                "sha256": database_snapshot["sha256"],
                "restore_policy": database_snapshot["restore_policy"],
            }
            staged = stage_files(self.fs, generated, run_id)
            candidate_seal = capture_staged_candidate(self.fs, manifest, generated, staged, run_id)
            generated_errors = validate_generated(self.fs, generated, staged, manifest, self.runner)
            if generated_errors:
                raise ApplyError("staged validation failed:\n- " + "\n- ".join(generated_errors))
            candidate_seal.verify(self.fs, manifest, generated, staged, run_id)
            report["phases"].append({"name": "validate-staged", "status": "ok", "at": _utc_now()})

            staging_proof = None
            if strict_staging:
                staging_proof = run_functional_staging(
                    self.fs, self.runner, manifest, generated, staged, run_id,
                    staged_seal=candidate_seal, routing_snapshot=staging_snapshot,
                    routing_material=routing_material, preflight=staging_preflight)
                report['phases'].append({'name': 'functional-staging', 'status': 'ok', 'at': _utc_now(),
                                         'acceptance': dict(staging_proof.summary)})

            # Проверяем свежий audit после всех валидаторов, пока mutation lock
            # удерживается и управляемые файлы ещё не заменены.
            commit_audit = self.audit(manifest["lucx"]["db_path"])
            commit_errors = validate_audit_against_manifest(commit_audit, manifest)
            commit_errors.extend(validate_routing_snapshot(commit_audit, staging_snapshot))
            commit_errors.extend(validate_public_bind_conflicts(manifest, self.runner))
            if commit_errors:
                raise ApplyError("Маршруты изменились между staging и commit:\n- " + "\n- ".join(commit_errors))
            _ephemeral_routing_material(self.fs, commit_audit, manifest)
            candidate_seal.verify(self.fs, manifest, generated, staged, run_id)
            report["phases"].append({"name": "pre-commit-read-only-audit", "status": "ok", "at": _utc_now()})
            self._verify_manifest_source(manifest_source)

            if staging_proof is not None:
                staging_proof.verify(self.fs, manifest, generated, staged, staged_seal=candidate_seal,
                    routing_snapshot=routing_audit_snapshot(commit_audit), routing_material=routing_material)

            if "/etc/systemd/system/lucx-sub-sidecar.service" in removal_targets:
                managed_services_touched = True
                self.runner.run(
                    ["systemctl", "disable", "--now", "lucx-sub-sidecar.service"]
                )
            for service in _managed_naive_services_from_targets(removal_targets):
                managed_services_touched = True
                self.runner.run(["systemctl", "disable", "--now", service])
            candidate_seal.verify(self.fs, manifest, generated, staged, run_id)
            self._verify_manifest_source(manifest_source)
            installed_hashes = commit_managed_transition(
                self.fs,
                generated,
                removal_targets,
                previous_installed_hashes,
                directory_targets=managed_directories,
                baseline=backup,
                mutation_journal=mutation_journal,
            )
            if removal_targets:
                self.runner.run(["systemctl", "daemon-reload"])
            report["phases"].append({"name": "commit", "status": "ok", "at": _utc_now()})
            if removal_targets:
                report["phases"].append(
                    {
                        "name": "remove-disabled-components",
                        "status": "ok",
                        "at": _utc_now(),
                        "files": removal_targets,
                    }
                )
            self._activate(generated, resolver)
            def complete():
                nonlocal manifest
                if manifest.get('naive_generations'):
                    manifest = self._synchronize_naive_generation_locked(manifest,
                        installed_hashes=installed_hashes, mutation_journal=mutation_journal,
                        persist=False, run_id=run_id + '-final-naive')
                decoy_results: list[dict[str, Any]] = []
                vpn_results: list[dict[str, Any]] = []
                live_audit = self.audit(manifest["lucx"]["db_path"])
                live_errors = validate_live_configuration(
                    manifest,
                    self.runner,
                    fs=self.fs,
                    audit=live_audit,
                    decoy_results=decoy_results,
                    vpn_results=vpn_results,
                )
                browser_acceptance = decoy_acceptance_summary(manifest, decoy_results, audit=live_audit)
                vpn_summary = vpn_acceptance_summary(manifest, vpn_results)
                vpn_acceptance = vpn_summary["complete"]
                for error in validate_required_acceptance(manifest, decoy_results, vpn_results, audit=live_audit):
                    if error not in live_errors:
                        live_errors.append(error)
                report["acceptance"] = "complete" if browser_acceptance["complete"] and vpn_acceptance else "partial"
                report["phases"].append(
                    {
                        "name": "health",
                        "status": "failed" if live_errors else report["acceptance"],
                        "at": _utc_now(),
                        "decoys": [
                            {**item, "domain": stable_fingerprint(str(item.get("domain") or ""))}
                            for item in decoy_results
                        ],
                        "browser_acceptance": browser_acceptance,
                        "vpn_acceptance": vpn_summary,
                        "vpn": vpn_results,
                    }
                )
                if live_errors:
                    raise ApplyError("health checks failed:\n- " + "\n- ".join(live_errors))
                if not browser_acceptance["complete"]:
                    report["warnings"].append("Полная браузерная приёмка не подтверждена: есть пропущенные или недоступные сайты.")
                if not vpn_acceptance:
                    report["warnings"].append("VPN не проверялся полностью функциональными пробами публичных маршрутов; listeners и TLS не заменяют приёмку VPN.")
                for item in decoy_results:
                    if not item["managed"] and item["state"] not in {"site_observed", "skipped"}:
                        report["warnings"].append(
                            f"passive decoy observation for {item['domain']} did not confirm a site: {item['detail']}"
                        )
                integrity_after = capture_integrity(
                    self.fs,
                    manifest["lucx"]["db_path"],
                    live_audit.naive_caddyfile,
                )
                naive_volatile = bool(
                    settings_management.get("sync_naive_share_addr")
                    or settings_management.get("sync_domains")
                    or settings_management.get("sync_naive_endpoint")
                    or any(
                        r.get("strategy") == "naive_managed"
                        for r in (manifest.get("decoys", {}).get("extended_routes") or [])
                    )
                    or (manifest.get("decoys", {}).get("naive_frontends") or [])
                    or database_changes
                    or self._is_naive_receipt_authorized(manifest, database_changes, audit)
                )
                integrity_errors = compare_integrity(
                    integrity_before,
                    integrity_after,
                    database_changes,
                    naive_content_volatile=naive_volatile,
                )
                if integrity_errors:
                    raise ApplyError(
                        "protected LucX/Naive integrity check failed:\n- "
                        + "\n- ".join(integrity_errors)
                    )
                manifest["integrity"] = integrity_after
                if manifest.get('naive_generations'):
                    confirmed = self.prepare_operation(manifest)
                    if confirmed.get('naive_generations') != manifest.get('naive_generations'):
                        raise ApplyError('Naive изменился во время health-check; повторите проверку плана')
                manifest.pop('naive_generation_adoption', None)
                report["manifest"] = manifest
                report["phases"].append(
                    {"name": "integrity-final", "status": "ok", "at": _utc_now()}
                )
                report["status"] = "complete"
                report["completed_at"] = _utc_now()
                state = {
                    "schema_version": 1,
                    "status": "complete",
                    "run_id": run_id,
                    "manifest": manifest,
                    "installed_hashes": installed_hashes,
                    "installed_packages": report["installed_packages"],
                    "lucx_database_path": manifest["lucx"]["db_path"],
                    "lucx_publication_changes": database_changes,
                    "rollback_backup_id": rollback_backup.run_id if rollback_backup else run_id,
                    "completed_at": report["completed_at"],
                    "acceptance": report["acceptance"],
                }
                self._verify_manifest_source_target(manifest_source, STATE_PATH)
                if managed_target_state(self.fs, STATE_PATH) != state_entry_seal:
                    raise ApplyError('Сохранённое состояние изменилось до commit; повторите план')
                mutation_journal[STATE_PATH] = save_state(self.fs, state)
                if managed_target_state(self.fs, STATE_PATH) != mutation_journal[STATE_PATH]:
                    raise ApplyError("State изменился сразу после commit")
                # Ошибка отчёта ещё должна иметь исходник для безопасного resume.
                self._write_report(run_id, report)
                self._verify_manifest_source_target(manifest_source, FAILED_STATE_PATH)
                clear_failed_state(self.fs)
                return report
            report['warnings'].extend(self._register_acme_hook(manifest, complete=complete))
            return report
        except Exception as exc:
            report["status"] = "failed"
            self._naive_runtime_before_restart = {}
            report["error"] = redact(str(exc))
            report["failed_at"] = _utc_now()
            selected_rollback = backup or rollback_backup
            if selected_rollback is not None:
                try:
                    rollback_file_conflicts = restore_backup(self.fs, selected_rollback,
                                                             expected_current=mutation_journal)
                    rollback_service_errors: list[str] = []
                    if database_changes:
                        rollback_lucx_publication(
                            self.fs,
                            manifest["lucx"]["db_path"],
                            database_changes,
                        )
                        restart_result = self.runner.run(
                            ["systemctl", "restart", "x-ui.service"],
                            check=False,
                            timeout=60,
                        )
                        if restart_result.returncode:
                            rollback_service_errors.append("x-ui.service restart failed after restore")
                    if mutation_journal or managed_services_touched or report["installed_packages"]:
                        rollback_service_errors.extend(self._reactivate_after_restore(
                            generated, resolver, report["installed_packages"]
                        ))
                    if (
                        "/etc/systemd/system/lucx-sub-sidecar.service" in removal_targets
                        and managed_services_touched
                        and self.fs.exists("/etc/systemd/system/lucx-sub-sidecar.service")
                    ):
                        self.runner.run(["systemctl", "daemon-reload"])
                        self.runner.run(
                            ["systemctl", "enable", "lucx-sub-sidecar.service"],
                        )
                        self.runner.run(
                            ["systemctl", "restart", "lucx-sub-sidecar.service"],
                        )
                    for service in _managed_naive_services_from_targets(removal_targets) if managed_services_touched else []:
                        unit = f"/etc/systemd/system/{service}"
                        if self.fs.exists(unit):
                            self.runner.run(["systemctl", "daemon-reload"])
                            self.runner.run(["systemctl", "enable", service])
                            self.runner.run(["systemctl", "restart", service])
                    rollback_integrity = capture_integrity(
                        self.fs,
                        manifest["lucx"]["db_path"],
                        audit.naive_caddyfile,
                    )
                    rollback_naive_volatile = bool(
                        settings_management.get("sync_naive_share_addr")
                        or settings_management.get("sync_domains")
                        or settings_management.get("sync_naive_endpoint")
                        or any(
                            r.get("strategy") == "naive_managed"
                            for r in (manifest.get("decoys", {}).get("extended_routes") or [])
                        )
                        or (manifest.get("decoys", {}).get("naive_frontends") or [])
                        or database_changes
                        or self._is_naive_receipt_authorized(manifest, database_changes, audit)
                    )
                    rollback_integrity_errors = compare_integrity(
                        integrity_before,
                        rollback_integrity,
                        [],
                        naive_content_volatile=rollback_naive_volatile,
                    )
                    if rollback_integrity_errors:
                        report["rollback_integrity_errors"] = rollback_integrity_errors
                    if rollback_service_errors:
                        report["rollback_service_errors"] = rollback_service_errors
                    rollback_health_errors: list[str] = []
                    report["rollback_health"] = "not_tested"
                    if self.fs.is_live and not self.runner.dry_run and self.fs.exists(STATE_PATH):
                        restored_state = load_state(self.fs)
                        restored_manifest = restored_state.get("manifest")
                        if restored_state.get("status") == "complete" and isinstance(restored_manifest, dict):
                            if restored_manifest.get('naive_generations') and not rollback_file_conflicts:
                                restored_manifest = self._synchronize_naive_generation_locked(restored_manifest)
                            restored_audit = self.audit(restored_manifest["lucx"]["db_path"])
                            with installed_vpn_probes(self.fs, self.runner, restored_manifest, audit=restored_audit):
                                rollback_health_errors = validate_live_configuration(
                                    restored_manifest, self.runner, fs=self.fs, audit=restored_audit,
                                    vpn_phase="rollback",
                                )
                            report["rollback_health"] = "failed" if rollback_health_errors else "infrastructure_checked"
                    if rollback_health_errors:
                        report["rollback_health_errors"] = rollback_health_errors
                    report["rollback"] = rollback_health_status(
                        rollback_service_errors, rollback_integrity_errors, rollback_health_errors
                    )
                    if rollback_file_conflicts:
                        report["rollback"] = "failed"
                        report["rollback_file_conflicts"] = rollback_file_conflicts
                except Exception as rollback_exc:
                    report["rollback"] = "failed"
                    report["rollback_error"] = str(rollback_exc)
            try:
                self._verify_manifest_source_target(manifest_source, FAILED_STATE_PATH)
                save_failed_state(
                    self.fs,
                    {
                        "schema_version": 1,
                        "status": "failed",
                        "run_id": run_id,
                        "manifest": manifest,
                        "error": redact(str(exc)),
                        "rollback": report.get("rollback", "not-needed"),
                    },
                )
            except ApplyError:
                report["warnings"].append(
                    "Исходный state изменён: чужой файл сохранён, запись результата для resume пропущена.")
            except OSError:
                pass
            try:
                self._write_report(run_id, report)
            except OSError:
                pass
            if isinstance(exc, ApplyError):
                raise
            raise ApplyError(str(exc)) from exc
        finally:
            try:
                remove_staging(self.fs, run_id)
            except OSError:
                pass

    def rollback(self, *, force: bool = False) -> str:
        with self._exclusive_lock():
            return self._rollback_locked(force=force)

    def _rollback_locked(self, *, force: bool = False) -> str:
        state = load_state(self.fs)
        manifest = state["manifest"]
        rollback_audit = self.audit(manifest["lucx"]["db_path"])
        integrity_at_rollback = capture_integrity(
            self.fs, manifest["lucx"]["db_path"], rollback_audit.naive_caddyfile
        )
        backup = load_backup(self.fs, state.get("rollback_backup_id", state["run_id"]))
        entries = {entry["target"]: entry for entry in backup.metadata["entries"]}
        run_id = rollback_latest(self.fs, force=force)
        database_changes = list(
            state.get("lucx_publication_changes")
            or state.get("lucx_domain_changes")
            or []
        )
        if database_changes:
            rollback_lucx_publication(
                self.fs,
                str(state.get("lucx_database_path") or manifest["lucx"]["db_path"]),
                database_changes,
            )
            self.runner.run(["systemctl", "restart", "x-ui.service"], timeout=60)
        newly_installed_services = {
            service for service in ("nginx", "haproxy") if service in state.get("installed_packages", [])
        }
        stop_errors: list[str] = []
        for service in newly_installed_services:
            stop_errors.extend(self._disable_after_restore(f"{service}.service"))

        firewall_existed = entries.get("/etc/systemd/system/lucx-post-firewall.service", {}).get("existed", False)
        sidecar_existed = entries.get("/etc/systemd/system/lucx-sub-sidecar.service", {}).get("existed", False)
        cloudflare_timer_existed = entries.get(
            "/etc/systemd/system/lucx-cloudflare-ips-update.timer", {}
        ).get("existed", False)
        naive_units = [
            (target, bool(entry.get("existed")))
            for target, entry in sorted(entries.items())
            if re.fullmatch(
                r"/etc/systemd/system/lucx-naive-decoy-\d+\.service", target
            )
        ]
        self.runner.run(["nft", "delete", "table", "inet", "lucx_post"], check=False)
        if not firewall_existed:
            stop_errors.extend(self._disable_after_restore("lucx-post-firewall.service"))
        if not sidecar_existed:
            stop_errors.extend(self._disable_after_restore("lucx-sub-sidecar.service"))
        if not cloudflare_timer_existed:
            stop_errors.extend(self._disable_after_restore("lucx-cloudflare-ips-update.timer"))
        for target, existed in naive_units:
            if not existed:
                stop_errors.extend(self._disable_after_restore(target.removeprefix("/etc/systemd/system/")))
        self.runner.run(["systemctl", "daemon-reload"])
        if (
            manifest["components"].get("haproxy")
            and "haproxy" not in newly_installed_services
            and self.fs.exists("/etc/haproxy/haproxy.cfg")
        ):
            self.runner.run(["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"])
            self.runner.run(["systemctl", "reload-or-restart", "haproxy.service"])
        if manifest["components"].get("nginx") and "nginx" not in newly_installed_services:
            self.runner.run(["nginx", "-t"])
            self.runner.run(["systemctl", "reload-or-restart", "nginx.service"])
        for target, existed in naive_units:
            service = target.removeprefix("/etc/systemd/system/")
            if existed and self.fs.exists(target):
                self.runner.run(["systemctl", "enable", service])
                self.runner.run(["systemctl", "restart", service])
        if firewall_existed:
            self.runner.run(["systemctl", "restart", "lucx-post-firewall.service"])
        if sidecar_existed:
            self.runner.run(["systemctl", "restart", "lucx-sub-sidecar.service"])
        if cloudflare_timer_existed:
            self.runner.run(["systemctl", "restart", "lucx-cloudflare-ips-update.timer"])
        if manifest["dns"].get("enabled"):
            if self.runner.available("resolvconf"):
                self.runner.run(["resolvconf", "-u"])
            elif self.runner.run(["systemctl", "is-active", "--quiet", "systemd-resolved.service"], check=False).returncode == 0:
                self.runner.run(["systemctl", "reload-or-restart", "systemd-resolved.service"])
        restored_integrity = capture_integrity(
            self.fs, manifest["lucx"]["db_path"], rollback_audit.naive_caddyfile
        )
        # Сравнение в направлении старое -> новое допускает только обратные
        # изменения публичных метаданных из транзакции, сохраняя идентичность.
        rollback_settings_mgmt = manifest.get("lucx", {}).get("settings_management") or {}
        rollback_naive_volatile = bool(
            rollback_settings_mgmt.get("sync_naive_share_addr")
            or rollback_settings_mgmt.get("sync_domains")
            or rollback_settings_mgmt.get("sync_naive_endpoint")
            or any(
                r.get("strategy") == "naive_managed"
                for r in (manifest.get("decoys", {}).get("extended_routes") or [])
            )
            or (manifest.get("decoys", {}).get("naive_frontends") or [])
            or database_changes
            or self._is_naive_receipt_authorized(manifest, database_changes, rollback_audit)
        )
        integrity_errors = compare_integrity(
            restored_integrity,
            integrity_at_rollback,
            database_changes,
            naive_content_volatile=rollback_naive_volatile,
        )
        if integrity_errors:
            raise ApplyError("rollback integrity checks failed:\n- " + "\n- ".join(integrity_errors))
        if stop_errors:
            raise ApplyError("rollback service checks failed:\n- " + "\n- ".join(stop_errors))
        if self.fs.is_live and not self.runner.dry_run and self.fs.exists(STATE_PATH):
            restored_state = load_state(self.fs)
            if restored_state.get("run_id") != state.get("run_id") and restored_state.get("status") == "complete":
                restored_manifest = restored_state["manifest"]
                if restored_manifest.get('naive_generations'):
                    restored_manifest = self._synchronize_naive_generation_locked(restored_manifest)
                restored_audit = self.audit(restored_manifest["lucx"]["db_path"])
                with installed_vpn_probes(self.fs, self.runner, restored_manifest, audit=restored_audit):
                    health_errors = validate_live_configuration(
                        restored_manifest, self.runner, fs=self.fs, audit=restored_audit,
                        vpn_phase="rollback",
                    )
                if health_errors:
                    raise ApplyError("rollback health checks failed:\n- " + "\n- ".join(health_errors))
        return run_id

    def validate_installed(self, *, include_live: bool = True) -> dict[str, Any]:
        state = load_state(self.fs)
        manifest = state["manifest"]
        audit = self.audit(manifest["lucx"]["db_path"])
        errors = validate_audit_against_manifest(audit, manifest)
        if manifest.get('naive_generations'):
            try:
                candidate = self.prepare_operation(manifest, audit)
                if candidate.get('naive_generations') != manifest.get('naive_generations'):
                    errors.append('Naive: состояние ожидает синхронизации с новым поколением LucX; '
                                  'выберите повторную проверку в меню')
            except ApplyError as error:
                errors.append(str(error))
        errors.extend(validate_certificate(self.fs, manifest, self.runner))
        errors.extend(validate_lucx_tls_coverage(self.fs, audit, manifest, self.runner))
        if self.fs.is_live and include_live:
            with installed_vpn_probes(self.fs, self.runner, manifest):
                errors.extend(validate_live_configuration(manifest, self.runner, fs=self.fs, audit=audit))
        changed = []
        for target, expected in (state.get("installed_hashes") or {}).items():
            path = self.fs.path(target)
            if not (path.exists() or path.is_symlink()) or managed_target_digest(self.fs, target) != expected:
                changed.append(target)
        return {"ok": not errors and not changed, "errors": errors, "changed_managed_files": changed, "run_id": state["run_id"]}
