"""Управление системными DNS-резолверами, замер задержки и проверка связности."""
from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass
import ipaddress
import socket
import struct
import time
from typing import Any

from .runner import Runner
from .targetfs import TargetFS

DEFAULT_DNS_PROVIDERS: list[tuple[str, tuple[str, ...], str]] = [
    ("Cloudflare", ("1.1.1.1", "1.0.0.1"), "Cloudflare (быстрый, приватный)"),
    ("Google", ("8.8.8.8", "8.8.4.4"), "Google Public DNS (глобальный, надёжный)"),
    ("Quad9", ("9.9.9.9", "149.112.112.112"), "Quad9 (фильтрация вредоносных сайтов)"),
    ("AdGuard", ("94.140.14.14", "94.140.15.15"), "AdGuard DNS (блокировка рекламы и трекеров)"),
    ("DNS.SB", ("185.222.222.222", "45.11.45.11"), "DNS.SB (европейский, no logs, DNSSEC)"),
    ("OpenDNS", ("208.67.222.222", "208.67.220.220"), "OpenDNS / Cisco (высокая надёжность)"),
    ("Yandex", ("77.88.8.8", "77.88.8.1"), "Yandex DNS (быстрый для регионов РФ/СНГ)"),
]


@dataclass(frozen=True)
class DnsCandidate:
    name: str
    servers: tuple[str, ...]
    description: str
    latency_ms: float | None = None


def build_dns_query(domain: str = "dns.google", tx_id: int = 0x5432) -> bytes:
    """Создаёт бинарный пакет DNS-запроса типа A (IN) без сторонних зависимостей."""
    header = struct.pack("!HHHHHH", tx_id & 0xFFFF, 0x0100, 1, 0, 0, 0)
    parts = domain.rstrip(".").split(".")
    qname = b"".join(struct.pack("!B", len(p)) + p.encode("ascii") for p in parts) + b"\x00"
    qtype_qclass = struct.pack("!HH", 1, 1)  # Type A, Class IN
    return header + qname + qtype_qclass


def probe_dns_server(ip: str, timeout: float = 1.0, domain: str = "dns.google") -> float | None:
    """Измеряет задержку RTT (в миллисекундах) до DNS-сервера по UDP:53."""
    tx_id = 0x5432
    query = build_dns_query(domain, tx_id=tx_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        start = time.perf_counter()
        sock.sendto(query, (ip, 53))
        data, _ = sock.recvfrom(512)
        rtt_ms = (time.perf_counter() - start) * 1000.0
        if len(data) >= 12:
            resp_id, flags = struct.unpack("!HH", data[:4])
            if resp_id == tx_id and (flags & 0x8000):  # QR bit = 1 (response)
                return round(rtt_ms, 1)
    except (socket.timeout, TimeoutError, OSError):
        return None
    finally:
        sock.close()
    return None


def probe_dns_candidates(
    providers: list[tuple[str, tuple[str, ...], str]] | None = None,
    timeout: float = 1.2,
) -> list[DnsCandidate]:
    """Параллельно опрашивает список DNS-провайдеров и возвращает результаты с замером задержки."""
    provider_list = providers if providers is not None else DEFAULT_DNS_PROVIDERS
    results: list[DnsCandidate] = []

    def _probe_one(item: tuple[str, tuple[str, ...], str]) -> DnsCandidate:
        name, servers, desc = item
        primary_ip = servers[0] if servers else ""
        lat = probe_dns_server(primary_ip, timeout=timeout) if primary_ip else None
        return DnsCandidate(name=name, servers=servers, description=desc, latency_ms=lat)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(provider_list) or 1, 8)) as executor:
        futures = [executor.submit(_probe_one, item) for item in provider_list]
        for f in futures:
            results.append(f.result())

    return results


def read_current_system_dns(fs: TargetFS) -> list[str]:
    """Читает активные IP-адреса nameserver из /etc/resolv.conf."""
    servers: list[str] = []
    text = fs.read_text("/etc/resolv.conf", default="")
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == "nameserver":
            ip = parts[1].strip()
            try:
                ipaddress.ip_address(ip)
                if ip not in servers:
                    servers.append(ip)
            except ValueError:
                continue
    return servers


def validate_dns_servers(servers: list[str]) -> list[str]:
    """Проверяет корректность списка IP-адресов DNS-серверов."""
    if not servers:
        raise ValueError("Список DNS-серверов не может быть пустым")
    if len(servers) > 3:
        raise ValueError("Максимальное число DNS-серверов — 3")
    cleaned: list[str] = []
    for s in servers:
        s = str(s).strip()
        try:
            ipaddress.ip_address(s)
        except ValueError:
            raise ValueError(f"Некорректный IP-адрес DNS-сервера: {s}")
        if s not in cleaned:
            cleaned.append(s)
    return cleaned


def detect_system_resolver(fs: TargetFS, runner: Runner) -> str:
    """Определяет тип активного DNS-резолвера системы."""
    if not fs.is_live:
        return "resolvconf"
    if runner.available("systemctl"):
        active = runner.run(
            ["systemctl", "is-active", "--quiet", "systemd-resolved.service"],
            check=False,
        )
        if active.returncode == 0:
            return "systemd-resolved"
    if runner.available("resolvconf") or fs.exists("/etc/resolvconf"):
        return "resolvconf"
    resolv_conf = fs.path("/etc/resolv.conf")
    if resolv_conf.is_file() and not resolv_conf.is_symlink():
        return "static"
    return "static"


def verify_dns_resolution(domain: str = "dns.google", timeout: float = 2.0) -> bool:
    """Проверяет работоспособность системного разрешения имён."""
    try:
        res = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
        return bool(res)
    except (socket.gaierror, OSError):
        return False


def apply_system_dns(
    fs: TargetFS,
    runner: Runner,
    servers: list[str],
) -> dict[str, Any]:
    """Безопасно и атомарно применяет системный DNS к конфигурационным файлам хоста."""
    valid_servers = validate_dns_servers(servers)
    resolver = detect_system_resolver(fs, runner)

    # 1. Формируем контент для /etc/resolv.conf
    resolv_lines = [
        "# Managed by lucx-post-configurator",
        *[f"nameserver {server}" for server in valid_servers],
        "",
    ]
    fs.atomic_write_text("/etc/resolv.conf", "\n".join(resolv_lines), mode=0o644)

    # 2. Обновляем специализированные конфиги в зависимости от резолвера
    if resolver == "resolvconf" or fs.exists("/etc/resolvconf"):
        # Debian resolvconf head
        head_path = "/etc/resolvconf/resolv.conf.d/head"
        head_lines = [
            "# Managed by lucx-post-configurator",
            *[f"nameserver {server}" for server in valid_servers],
            "",
        ]
        fs.atomic_write_text(head_path, "\n".join(head_lines), mode=0o644)

        # openresolv: /etc/resolvconf.conf
        if fs.exists("/etc/resolvconf.conf"):
            existing = fs.read_text("/etc/resolvconf.conf", default="")
            updated_lines = []
            for line in existing.splitlines():
                stripped = line.strip()
                if stripped.startswith("name_servers=") or stripped.startswith("#name_servers="):
                    continue
                updated_lines.append(line)
            updated_lines.append(f'name_servers="{" ".join(valid_servers)}"')
            fs.atomic_write_text("/etc/resolvconf.conf", "\n".join(updated_lines) + "\n", mode=0o644)

        if runner.available("resolvconf"):
            runner.run(["resolvconf", "-u"], check=False)

    if resolver == "systemd-resolved":
        resolved_conf = f"[Resolve]\nDNS={' '.join(valid_servers)}\nFallbackDNS=\n"
        fs.atomic_write_text(
            "/etc/systemd/resolved.conf.d/60-lucx-post-configurator.conf",
            resolved_conf,
            mode=0o644,
        )
        if runner.available("systemctl"):
            runner.run(["systemctl", "reload-or-restart", "systemd-resolved.service"], check=False)

    # 3. Верификация резолва домена
    verified = True
    if fs.is_live:
        verified = verify_dns_resolution("dns.google") or verify_dns_resolution("cloudflare.com")

    return {
        "ok": True,
        "servers": valid_servers,
        "resolver": resolver,
        "resolution_verified": verified,
    }


def run_dns_security_diagnostic(
    fs: TargetFS,
    runner: Runner,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Выполняет углублённую диагностику системного DNS, резолверов и сетевой изоляции портов."""
    resolver = detect_system_resolver(fs, runner)
    current_servers = read_current_system_dns(fs)

    # 1. Замер задержки до текущих DNS-серверов
    server_probes: list[dict[str, Any]] = []
    for s in current_servers:
        lat = probe_dns_server(s, timeout=1.5)
        server_probes.append({
            "ip": s,
            "latency_ms": lat,
            "reachable": lat is not None,
        })

    # 2. Проверка разрешения тестовых доменов
    domains_to_test = ["cloudflare.com", "dns.google", "github.com"]
    resolution_checks: dict[str, bool] = {}
    for d in domains_to_test:
        resolution_checks[d] = verify_dns_resolution(d, timeout=1.5)

    all_domains_resolved = all(resolution_checks.values())

    # 3. Проверка привязки внутренних служб к loopback (безопасность)
    internal_ports = {
        2053,   # LucX Panel
        21000,  # Subscription Sidecar
        20000, 20001, 20002,  # Local naive/protocol backends
        30000, 30001, 30002, 30003, 30004, 30005,  # Local sidecars / bridges
    }

    port_isolation: list[dict[str, Any]] = []
    warnings: list[str] = []

    if runner.available("ss"):
        res = runner.run(["ss", "-tulpn"], check=False, timeout=5)
        if res.returncode == 0:
            lines = res.stdout.splitlines()
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[4]  # e.g. 127.0.0.1:2053 or 0.0.0.0:2053
                    if ":" in local_addr:
                        ip_part, port_str = local_addr.rsplit(":", 1)
                        if port_str.isdigit():
                            port_num = int(port_str)
                            if port_num in internal_ports:
                                is_loopback = ("127.0.0.1" in ip_part or "::1" in ip_part)
                                is_public = ("0.0.0.0" in ip_part or ip_part == "*")
                                port_isolation.append({
                                    "port": port_num,
                                    "local_addr": local_addr,
                                    "is_loopback": is_loopback,
                                    "process": parts[-1] if len(parts) >= 7 else "",
                                })
                                if is_public:
                                    warnings.append(
                                        f"Внутренний порт {port_num} открыт на всех интерфейсах ({local_addr}) вместо loopback!"
                                    )

    # Проверка файла resolv.conf
    resolv_path = fs.path("/etc/resolv.conf")
    is_symlink = resolv_path.is_symlink() if resolv_path.exists() else False

    return {
        "ok": all_domains_resolved and not warnings,
        "resolver": resolver,
        "is_symlink": is_symlink,
        "servers": server_probes,
        "resolution_checks": resolution_checks,
        "all_domains_resolved": all_domains_resolved,
        "port_isolation": port_isolation,
        "warnings": warnings,
    }
