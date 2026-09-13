from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .engine import Engine
from .renderers import GeneratedFile
from .repair import PENDING_POST_UPDATE_REPAIR, repair_apply, repair_check
from .runner import CommandResult, Runner
from .self_install import install_self
from .transaction import STATE_PATH, backup_lucx_database, create_backup, load_state, new_run_id


SOURCECRAFT_DIST_URL = (
    "https://codeload.sourcecraft.tech/alexeylcp/lucx-ui/tarball/refs/heads/dist"
)
GITHUB_MAIN_URL = (
    "https://codeload.github.com/AlexeyLCP/lucx-ui/tar.gz/refs/heads/main"
)
GITHUB_PROXY_BASE = "https://gh-proxy.com/en/"
GITHUB_MAIN_PINNED_URL = GITHUB_MAIN_URL
UPDATE_SOURCE_STATE = "/var/lib/lucx-post-configurator/update-source.json"
INSTALL_SOURCE = "/etc/x-ui/install-source"
UPDATE_JOB_ROOT = "/var/lib/lucx-post-configurator/update-jobs"
UPDATE_JOB_STATUS = "/var/lib/lucx-post-configurator/update-status.json"
AUTOMATIC_UPDATE_BLOCKED_REASON = (
    "автоматическое обновление LucX недоступно: официальный обновлятор может "
    "автоматически перезагрузить сервер; проверенный адаптер без reboot ещё не реализован"
)
_JOB_ID_PATTERN = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9]+$")
_PUBLIC_UPDATE_STATUS_FIELDS = (
    "schema_version",
    "job_id",
    "source",
    "state",
    "phase_current",
    "phase_total",
    "phase_label",
    "started_at",
    "updated_at",
    "backup",
    "repair_run_id",
    "error",
)


def _require_safe_automatic_update_adapter() -> None:
    raise RuntimeError(AUTOMATIC_UPDATE_BLOCKED_REASON)


def _launch_update_worker(runner: Runner, job_id: str) -> CommandResult:
    """Start the updater outside the TUI and x-ui service cgroups."""

    return runner.run(
        [
            "systemctl",
            "start",
            "--no-block",
            f"lucx-post-update@{job_id}.service",
        ]
    )


def _job_directory(engine: Engine, job_id: str) -> Path:
    if not _JOB_ID_PATTERN.fullmatch(job_id):
        raise RuntimeError("некорректный идентификатор задания обновления")
    return engine.fs.path(f"{UPDATE_JOB_ROOT}/{job_id}")


def _write_update_status(engine: Engine, payload: dict[str, Any]) -> None:
    payload = dict(payload)
    now = datetime.now(timezone.utc).isoformat()
    payload.setdefault("started_at", now)
    payload["updated_at"] = now
    engine.fs.atomic_write(
        UPDATE_JOB_STATUS,
        (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        mode=0o600,
    )


def _load_update_status(engine: Engine) -> dict[str, Any]:
    path = engine.fs.path(UPDATE_JOB_STATUS)
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _project_update_status(status: dict[str, Any]) -> dict[str, Any]:
    from .diagnostics import redact

    projected = {
        key: status[key]
        for key in _PUBLIC_UPDATE_STATUS_FIELDS
        if key in status
    }
    return redact(projected)


def _cleanup_update_job_payload(engine: Engine, job_id: str) -> None:
    job_dir = _job_directory(engine, job_id)
    resolved_job_dir = job_dir.resolve()
    if job_dir.is_symlink() or job_dir.parent != engine.fs.path(UPDATE_JOB_ROOT):
        raise RuntimeError("небезопасный каталог задания обновления")
    for child in job_dir.iterdir():
        if child.name == "job.json":
            continue
        if child.is_symlink() or child.is_file():
            child.unlink()
            continue
        if child.is_dir() and child.resolve().parent == resolved_job_dir:
            shutil.rmtree(child)
            continue
        raise RuntimeError("небезопасный объект в каталоге задания обновления")


def run_update_worker(engine: Engine, job_id: str) -> dict[str, Any]:
    """Refuse old jobs until a reboot-safe upstream adapter is implemented."""

    _require_safe_automatic_update_adapter()
    job_dir = _job_directory(engine, job_id)
    descriptor_path = job_dir / "job.json"
    if not descriptor_path.is_file() or descriptor_path.is_symlink():
        raise RuntimeError("описание задания обновления не найдено")
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    if descriptor.get("schema_version") != 1 or descriptor.get("job_id") != job_id:
        raise RuntimeError("описание задания обновления несовместимо")
    install_source = str(descriptor.get("install_source") or "")
    if install_source not in {"github", "yandex"}:
        raise RuntimeError("некорректный внутренний источник обновления")
    relative_script = Path(str(descriptor.get("update_script") or ""))
    if relative_script.is_absolute():
        raise RuntimeError("путь update.sh должен быть относительным")
    script = (job_dir / relative_script).resolve()
    resolved_job_dir = job_dir.resolve()
    if resolved_job_dir not in script.parents:
        raise RuntimeError("update.sh находится вне каталога задания")
    if not script.is_file() or script.is_symlink():
        raise RuntimeError("update.sh задания не найден")
    if not engine.fs.exists(PENDING_POST_UPDATE_REPAIR):
        raise RuntimeError("маркер post-update repair отсутствует")

    status = _load_update_status(engine)
    status.update(
        {
            "schema_version": 1,
            "job_id": job_id,
            "source": str(descriptor.get("source") or ""),
            "state": "running_updater",
            "phase_current": 2,
            "phase_total": 3,
            "phase_label": "Официальное обновление LucX",
        }
    )
    _write_update_status(engine, status)
    try:
        update_result = engine.runner.run(
            ["bash", script],
            check=False,
            timeout=1800,
            env={"LUCX_SOURCE": install_source},
        )
        if update_result.returncode:
            detail = (update_result.stderr or update_result.stdout).strip()
            raise RuntimeError(
                "официальный обновлятор LucX завершился с ошибкой"
                + (f": {detail}" if detail else "")
            )
        status["state"] = "running_repair"
        status["phase_current"] = 3
        status["phase_label"] = "Восстановление управляемых маршрутов"
        _write_update_status(engine, status)
        repair_report = repair_apply(engine)
        status.update(
            {
                "state": "complete",
                "phase_current": 3,
                "phase_total": 3,
                "phase_label": "Обновление и восстановление завершены",
                "repair_run_id": str(repair_report.get("run_id") or ""),
            }
        )
        _write_update_status(engine, status)
        try:
            _cleanup_update_job_payload(engine, job_id)
        except Exception as exc:
            status["cleanup_warning"] = str(exc)
            _write_update_status(engine, status)
        return {"status": "complete", **_project_update_status(status)}
    except Exception as exc:
        status.update({"state": "failed", "error": str(exc)})
        _write_update_status(engine, status)
        raise


def _validated_https_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError("URL зеркала должен быть HTTPS без userinfo")
    if parsed.fragment:
        raise RuntimeError("URL зеркала не должен содержать fragment")
    return urllib.parse.urlunsplit(parsed)


def _validated_proxy_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname:
        raise RuntimeError("proxy должен иметь схему http, https, socks5 или socks5h")
    if parsed.fragment:
        raise RuntimeError("proxy URL не должен содержать fragment")
    return urllib.parse.urlunsplit(parsed)


def _proxy_urls_from_environment() -> list[str]:
    result: list[str] = []
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        value = os.environ.get(name, "").strip()
        if value:
            try:
                value = _validated_proxy_url(value)
            except RuntimeError:
                continue
            if value not in result:
                result.append(value)
    return result


def _github_proxy_attempts(url: str, proxy_templates: list[str]) -> list[tuple[str, str, str]]:
    attempts: list[tuple[str, str, str]] = []
    for index, template in enumerate(proxy_templates, start=1):
        template = template.strip()
        if not template:
            continue
        if "{url}" not in template:
            raise RuntimeError("GitHub proxy должен содержать шаблон {url}")
        proxy_url = template.replace("{url}", urllib.parse.quote(url, safe=""))
        proxy_url = _validated_https_url(proxy_url)
        attempts.append((f"github-proxy-{index}", proxy_url, "github"))
    return attempts


def _default_github_proxy_attempt(url: str) -> tuple[str, str, str, str]:
    """Return the configured primary GitHub proxy route."""

    return ("gh-proxy", GITHUB_PROXY_BASE + url, "github", "")


def _download_archive(
    engine: Engine,
    url: str,
    destination: Path,
    *,
    proxy_url: str = "",
) -> None:
    if not engine.runner.available("curl"):
        raise RuntimeError("для загрузки обновления требуется curl")
    proxy_args = ["--proxy", proxy_url] if proxy_url else []
    result = engine.runner.run(
        [
            "curl",
            "-fL",
            "--retry",
            "3",
            "--retry-delay",
            "3",
            "--connect-timeout",
            "15",
            "--max-time",
            "600",
            *proxy_args,
            "-o",
            destination,
            url,
        ],
        check=False,
        timeout=630,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"не удалось загрузить архив обновления: {detail}")
    if not destination.is_file() or destination.stat().st_size < 1024:
        raise RuntimeError("зеркало вернуло пустой или слишком маленький архив")
    if destination.stat().st_size > 2 * 1024 * 1024 * 1024:
        raise RuntimeError("архив обновления слишком большой")


def _safe_extract_tar(archive_path: Path, destination: Path) -> Path:
    """Extract regular files manually; never use TarFile.extractall on target Python."""

    destination = destination.resolve()
    total = 0
    with tarfile.open(archive_path, mode="r:*") as archive:
        members = archive.getmembers()
        if not members:
            raise RuntimeError("архив обновления пуст")
        for member in members:
            if member.issym() or member.islnk() or not (member.isdir() or member.isreg()):
                raise RuntimeError(f"небезопасный тип элемента в архиве: {member.name}")
            name = member.name.replace("\\", "/")
            if not name or name.startswith("/"):
                raise RuntimeError("архив содержит абсолютный путь")
            target = (destination / name).resolve()
            if target != destination and destination not in target.parents:
                raise RuntimeError("архив содержит выход за каталог распаковки")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += int(member.size)
            if member.size > 512 * 1024 * 1024 or total > 2 * 1024 * 1024 * 1024:
                raise RuntimeError("архив обновления превышает безопасный лимит размера")
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"не удалось прочитать элемент архива: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("xb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
            os.chmod(target, 0o755 if target.name.endswith(".sh") else 0o644)
    candidates = sorted(destination.rglob("update.sh"), key=lambda path: (len(path.parts), str(path)))
    if not candidates:
        raise RuntimeError("архив зеркала не содержит update.sh")
    update_script = candidates[0]
    if not update_script.is_file() or update_script.is_symlink():
        raise RuntimeError("update.sh в архиве не является обычным файлом")
    prefix = update_script.read_bytes()[:256]
    if not prefix.startswith((b"#!/bin/bash", b"#!/usr/bin/env bash")):
        raise RuntimeError("update.sh не похож на ожидаемый Bash-скрипт LucX")
    return update_script


def _source_attempts(
    source: str,
    custom_url: str = "",
    github_proxy_templates: list[str] | None = None,
) -> list[tuple[str, str, str, str]]:
    normalized = source.strip().lower()
    if normalized == "auto":
        return [
            _default_github_proxy_attempt(GITHUB_MAIN_URL),
            ("github", GITHUB_MAIN_URL, "github", ""),
            *[(label, url, install_source, "") for label, url, install_source in _github_proxy_attempts(GITHUB_MAIN_URL, github_proxy_templates or [])],
        ]
    if normalized in {"sourcecraft", "yandex"}:
        return [("sourcecraft", SOURCECRAFT_DIST_URL, "yandex", "")]
    if normalized == "github":
        return [
            _default_github_proxy_attempt(GITHUB_MAIN_URL),
            ("github", GITHUB_MAIN_URL, "github", ""),
            *[(label, url, install_source, "") for label, url, install_source in _github_proxy_attempts(GITHUB_MAIN_URL, github_proxy_templates or [])],
        ]
    if normalized == "custom":
        return [("custom", _validated_https_url(custom_url), "github", "")]
    raise RuntimeError("источник обновления должен быть auto, sourcecraft, github или custom")


def update_lucx(
    engine: Engine,
    *,
    source: str = "auto",
    custom_url: str = "",
    github_proxy_templates: list[str] | None = None,
    self_source: str | None = None,
) -> dict[str, Any]:
    """Refuse automatic LucX updates until a reboot-safe adapter exists."""

    if not engine.fs.is_live:
        raise RuntimeError("обновление LucX разрешено только в живой системе")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("обновление LucX требует root")
    _require_safe_automatic_update_adapter()
    preflight = repair_check(engine)
    if preflight.get("repair_required"):
        raise RuntimeError(
            "перед обновлением текущая конфигурация требует восстановления; "
            "выполните lucx-sub-repair --apply и повторите"
        )
    installed = install_self(engine.fs, engine.runner, source=self_source)
    state = load_state(engine.fs)

    errors: list[str] = []
    chosen: tuple[str, str, str, str] | None = None
    update_script: Path | None = None
    job_id = new_run_id()
    job_dir = _job_directory(engine, job_id)
    if job_dir.exists():
        raise RuntimeError("каталог задания обновления уже существует")
    job_dir.mkdir(parents=True, mode=0o700)
    os.chmod(job_dir, 0o700)

    attempts = _source_attempts(source, custom_url, github_proxy_templates)
    environment_proxies = _proxy_urls_from_environment()
    expanded_attempts: list[tuple[str, str, str, str]] = []
    for attempt in attempts:
        expanded_attempts.append(attempt)
        label, url, install_source, _proxy = attempt
        if label == "github" and environment_proxies:
            expanded_attempts.extend(
                (f"{label}-environment-{index}", url, install_source, proxy)
                for index, proxy in enumerate(environment_proxies, start=1)
            )
    for index, attempt in enumerate(expanded_attempts, start=1):
        label, url, install_source, proxy_url = attempt
        archive_path = job_dir / f"source-{index}.tar"
        extract_path = job_dir / f"source-{index}"
        extract_path.mkdir()
        try:
            if proxy_url:
                _download_archive(engine, url, archive_path, proxy_url=proxy_url)
            else:
                _download_archive(engine, url, archive_path)
            update_script = _safe_extract_tar(archive_path, extract_path)
            chosen = attempt
            break
        except Exception as exc:
            errors.append(f"{label}: {exc}")
    if chosen is None or update_script is None:
        raise RuntimeError("все источники обновления недоступны: " + "; ".join(errors))

    label, url, install_source, _proxy_url = chosen
    generated = {
        INSTALL_SOURCE: GeneratedFile(
            (install_source + "\n").encode("ascii"), mode=0o600, component="update"
        ),
        PENDING_POST_UPDATE_REPAIR: GeneratedFile(
            (job_id + "\n").encode("ascii"), mode=0o600, component="update"
        ),
        UPDATE_SOURCE_STATE: GeneratedFile(
            (
                json.dumps(
                    {"source": label, "url": url if label == "custom" else ""},
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n"
            ).encode("utf-8"),
            mode=0o600,
            component="update",
        ),
        UPDATE_JOB_STATUS: GeneratedFile(
            (
                json.dumps(
                    {
                        "schema_version": 1,
                        "job_id": job_id,
                        "source": label,
                        "state": "queued",
                        "phase_current": 1,
                        "phase_total": 3,
                        "phase_label": "Задание подготовлено",
                        "started_at": datetime.now(timezone.utc).isoformat(),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n"
            ).encode("utf-8"),
            mode=0o600,
            component="update",
        ),
    }
    backup = create_backup(
        engine.fs,
        generated,
        job_id + "-before-lucx-update",
        extra_targets=[STATE_PATH],
    )
    database_snapshot = backup_lucx_database(
        engine.fs, backup, state["manifest"]["lucx"]["db_path"]
    )
    for target, artifact in generated.items():
        engine.fs.atomic_write(target, artifact.content, mode=artifact.mode)
    queued_status = _load_update_status(engine)
    queued_status["backup"] = str(backup.directory)
    _write_update_status(engine, queued_status)

    relative_script = update_script.resolve().relative_to(job_dir.resolve()).as_posix()
    descriptor = {
        "schema_version": 1,
        "job_id": job_id,
        "source": label,
        "install_source": install_source,
        "update_script": relative_script,
    }
    engine.fs.atomic_write(
        f"{UPDATE_JOB_ROOT}/{job_id}/job.json",
        (json.dumps(descriptor, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        mode=0o600,
    )
    _launch_update_worker(engine.runner, job_id)
    return {
        "status": "started",
        "job_id": job_id,
        "source": label,
        "fallback_errors": errors,
        "self_install": installed,
        "backup": str(backup.directory),
        "database_snapshot": database_snapshot,
        "pending_post_update_repair": True,
        "reboot_may_be_scheduled_by_lucx": True,
    }


def update_source_status(engine: Engine) -> dict[str, Any]:
    path = engine.fs.path(UPDATE_SOURCE_STATE)
    saved: dict[str, Any] = {}
    if path.is_file() and not path.is_symlink():
        try:
            saved = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            saved = {}
    projected_job = _project_update_status(_load_update_status(engine))
    if (
        isinstance(projected_job, dict)
        and projected_job.get("state") == "failed"
        and not engine.fs.exists(PENDING_POST_UPDATE_REPAIR)
    ):
        projected_job["historical"] = True
    return {
        "automatic_update_available": False,
        "automatic_update_reason": AUTOMATIC_UPDATE_BLOCKED_REASON,
        "saved": saved,
        "sourcecraft": SOURCECRAFT_DIST_URL,
        "github": GITHUB_MAIN_URL,
        "pending_post_update_repair": engine.fs.exists(PENDING_POST_UPDATE_REPAIR),
        "job_status": projected_job,
    }
