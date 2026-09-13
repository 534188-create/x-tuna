"""Управление TCP BBR, очередями пакетов (FQ) и оптимизацией сетевых буферов."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .runner import Runner
from .targetfs import TargetFS

SYSCTL_BBR_PATH = "/etc/sysctl.d/60-lucx-bbr.conf"

RECOMMENDED_SYSCTL_SETTINGS: dict[str, str] = {
    # BBR Congestion Control & Fair Queuing
    "net.core.default_qdisc": "fq",
    "net.ipv4.tcp_congestion_control": "bbr",
    # Socket memory buffers (up to 64MB for high-speed cross-border WAN / packet loss resilience)
    "net.core.rmem_max": "67108864",
    "net.core.wmem_max": "67108864",
    "net.core.rmem_default": "1048576",
    "net.core.wmem_default": "1048576",
    "net.ipv4.tcp_rmem": "4096 87380 67108864",
    "net.ipv4.tcp_wmem": "4096 65536 67108864",
    # Connection queues and backlogs
    "net.core.somaxconn": "32768",
    "net.core.netdev_max_backlog": "16384",
    "net.ipv4.tcp_max_syn_backlog": "8192",
    # Fast Open (3 = enable client + server)
    "net.ipv4.tcp_fastopen": "3",
    # MTU probing (prevents stalling on networks with broken ICMP / path MTU issues)
    "net.ipv4.tcp_mtu_probing": "1",
    # TCP time-wait reuse
    "net.ipv4.tcp_tw_reuse": "1",
}


def render_sysctl_bbr_conf(settings: dict[str, str] | None = None) -> str:
    """Генерирует содержимое файла /etc/sysctl.d/60-lucx-bbr.conf."""
    params = settings or RECOMMENDED_SYSCTL_SETTINGS
    lines = [
        "# Managed by LucX post-configurator: TCP BBR & buffer tuning",
        "# High-performance TCP stack optimization for proxy traffic",
        "",
    ]
    for key, value in params.items():
        lines.append(f"{key} = {value}")
    lines.append("")
    return "\n".join(lines)


def _read_sysctl_param(runner: Runner, fs: TargetFS | None, param: str) -> str:
    """Читает параметр ядра через /proc или sysctl."""
    # 1. Попытка прочитать из TargetFS (/proc/sys/...)
    if fs is not None:
        proc_path = "/proc/sys/" + param.replace(".", "/")
        try:
            val = fs.read_text(proc_path, default="").strip()
            if val:
                return val
        except Exception:
            pass

    # 2. Попытка вызвать sysctl -n
    try:
        res = runner.run(["sysctl", "-n", param], check=False, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass

    return ""


def get_network_tuning_status(
    runner: Runner,
    fs: TargetFS | None = None,
) -> dict[str, Any]:
    """Возвращает текущее состояние алгоритма BBR, очереди FQ и параметров буферов."""
    active_cc = _read_sysctl_param(runner, fs, "net.ipv4.tcp_congestion_control")
    available_cc_raw = _read_sysctl_param(runner, fs, "net.ipv4.tcp_available_congestion_control")
    available_cc = [item.strip() for item in available_cc_raw.split() if item.strip()]
    default_qdisc = _read_sysctl_param(runner, fs, "net.core.default_qdisc")

    # Проверка наличия файла конфигурации
    config_present = False
    config_content = ""
    if fs is not None:
        config_present = fs.exists(SYSCTL_BBR_PATH)
        if config_present:
            config_content = fs.read_text(SYSCTL_BBR_PATH, default="")
    else:
        config_path = Path(SYSCTL_BBR_PATH)
        config_present = config_path.is_file()
        if config_present:
            try:
                config_content = config_path.read_text(encoding="utf-8")
            except Exception:
                config_content = ""

    # Проверка поддержки BBR
    bbr_supported = "bbr" in available_cc
    if not bbr_supported and runner.available("modprobe"):
        # Проверяем, может ли модуль tcp_bbr быть загружен
        try:
            check_mod = runner.run(["modinfo", "tcp_bbr"], check=False, timeout=5)
            if check_mod.returncode == 0:
                bbr_supported = True
        except Exception:
            pass

    # Считываем текущие значения ключевых параметров
    current_values: dict[str, str] = {}
    for key in RECOMMENDED_SYSCTL_SETTINGS:
        val = _read_sysctl_param(runner, fs, key)
        if val:
            current_values[key] = val

    bbr_active = (active_cc == "bbr")
    fq_active = (default_qdisc == "fq")
    is_fully_optimized = bbr_active and fq_active and config_present

    return {
        "active_congestion_control": active_cc,
        "available_congestion_control": available_cc,
        "default_qdisc": default_qdisc,
        "bbr_supported": bbr_supported,
        "bbr_active": bbr_active,
        "fq_active": fq_active,
        "config_file_present": config_present,
        "config_file_path": SYSCTL_BBR_PATH,
        "is_fully_optimized": is_fully_optimized,
        "current_values": current_values,
        "recommended_values": dict(RECOMMENDED_SYSCTL_SETTINGS),
    }


def apply_network_tuning(
    runner: Runner,
    fs: TargetFS | None = None,
    settings: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Применяет BBR, FQ и оптимизированные буферы TCP, сохраняя их в /etc/sysctl.d/60-lucx-bbr.conf."""
    params = settings or RECOMMENDED_SYSCTL_SETTINGS

    # 1. Загружаем модуль tcp_bbr, если он доступен
    if runner.available("modprobe"):
        try:
            runner.run(["modprobe", "tcp_bbr"], check=False, timeout=10)
        except Exception:
            pass

    # 2. Записываем конфигурационный файл
    content = render_sysctl_bbr_conf(params)
    if fs is not None:
        fs.atomic_write_text(SYSCTL_BBR_PATH, content, mode=0o644)
    else:
        target = Path(SYSCTL_BBR_PATH)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    # 3. Применяем параметры через sysctl
    applied = False
    error = ""
    if runner.available("sysctl"):
        try:
            res = runner.run(["sysctl", "-p", SYSCTL_BBR_PATH], check=False, timeout=15)
            if res.returncode == 0:
                applied = True
            else:
                # Попробуем sysctl --system
                res2 = runner.run(["sysctl", "--system"], check=False, timeout=15)
                applied = (res2.returncode == 0)
                if not applied:
                    error = res.stderr or res.stdout
        except Exception as exc:
            error = str(exc)
    else:
        # В dry-run или среде без sysctl считаем записанным
        applied = runner.dry_run

    # 4. Проверяем обновленный статус
    status = get_network_tuning_status(runner, fs)

    return {
        "ok": applied,
        "applied": applied,
        "error": error,
        "config_file": SYSCTL_BBR_PATH,
        "status": status,
    }


def revert_network_tuning(
    runner: Runner,
    fs: TargetFS | None = None,
) -> dict[str, Any]:
    """Удаляет /etc/sysctl.d/60-lucx-bbr.conf и перезагружает стандартные настройки."""
    removed = False
    if fs is not None:
        if fs.exists(SYSCTL_BBR_PATH):
            target_path = fs.path(SYSCTL_BBR_PATH)
            target_path.unlink(missing_ok=True)
            removed = True
    else:
        target = Path(SYSCTL_BBR_PATH)
        if target.is_file():
            target.unlink(missing_ok=True)
            removed = True

    # Перезагружаем настройки ядра
    reloaded = False
    if runner.available("sysctl"):
        try:
            res = runner.run(["sysctl", "--system"], check=False, timeout=15)
            reloaded = (res.returncode == 0)
        except Exception:
            pass
    else:
        reloaded = runner.dry_run

    status = get_network_tuning_status(runner, fs)
    return {
        "ok": True,
        "removed": removed,
        "reloaded": reloaded,
        "status": status,
    }
