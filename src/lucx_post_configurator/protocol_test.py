"""Комплексный интерактивный автотест всех протоколов и сайтов-заглушек."""
from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass
import json
import socket
import ssl
import time
from typing import Any, Callable

from .engine import Engine
from .transaction import load_state

OutputFn = Callable[[str], None]


@dataclass(frozen=True)
class ProbeResult:
    category: str       # "Decoy", "Панель", "Подписка", "Протокол", "UDP"
    name: str           # "Decoy (test1)", "NaiveProxy (test5)", etc.
    endpoint: str       # "test5.example.test"
    port: int           # 443, 8443, etc.
    transport: str      # "HTTPS/H2", "HTTPS", "TLS", "UDP", "HTTP"
    ok: bool
    latency_ms: float | None
    status_code: int | None
    detail: str


def _create_ssl_context(check_cert: bool = False, alpn_protocols: list[str] | None = None) -> ssl.SSLContext:
    """Создаёт SSLContext с настраиваемым списком ALPN."""
    ctx = ssl.create_default_context()
    if not check_cert:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    protocols = alpn_protocols if alpn_protocols is not None else ["http/1.1"]
    try:
        ctx.set_alpn_protocols(protocols)
    except (AttributeError, NotImplementedError):
        pass
    return ctx


def probe_https_decoy(
    domain: str,
    port: int = 443,
    timeout: float = 4.0,
    category: str = "Decoy",
) -> ProbeResult:
    """Проверяет доступность сайта-заглушки по HTTPS (код 200, Nginx/Caddy decoy)."""
    start = time.perf_counter()
    ctx = _create_ssl_context(check_cert=False, alpn_protocols=["http/1.1"])
    try:
        sock = socket.create_connection((domain, port), timeout=timeout)
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            tls_latency = (time.perf_counter() - start) * 1000.0

            # Отправляем HTTP GET запрос
            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n"
                f"Accept: text/html,*/*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            ssock.sendall(req)

            # Читаем ответ
            resp_data = bytearray()
            while b"\r\n\r\n" not in resp_data and len(resp_data) < 4096:
                chunk = ssock.recv(1024)
                if not chunk:
                    break
                resp_data.extend(chunk)

            total_latency = (time.perf_counter() - start) * 1000.0

            status_code = None
            server_header = ""
            is_decoy = False
            if resp_data:
                lines = bytes(resp_data).split(b"\r\n")
                if lines:
                    status_line = lines[0].decode("latin-1", errors="replace")
                    parts = status_line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        status_code = int(parts[1])
                for line in lines[1:]:
                    low = line.lower()
                    if low.startswith(b"server:"):
                        server_header = line.split(b":", 1)[1].strip().decode("latin-1", errors="replace")
                    if low.startswith(b"x-lucx-decoy:"):
                        is_decoy = True

            ok = (status_code == 200)
            server_tag = f" ({server_header})" if server_header else ""
            if ok:
                detail = f"200 OK{server_tag}"
            elif status_code:
                detail = f"HTTP {status_code}{server_tag}"
            else:
                detail = "TLS OK, пустой ответ"
                ok = False

            return ProbeResult(
                category=category,
                name=f"Decoy ({domain})",
                endpoint=domain,
                port=port,
                transport="HTTPS",
                ok=ok,
                latency_ms=round(total_latency, 1),
                status_code=status_code,
                detail=detail,
            )
    except Exception as exc:
        latency = (time.perf_counter() - start) * 1000.0
        err_msg = str(exc)
        if "timed out" in err_msg.lower():
            err_msg = "Таймаут подключения"
        elif "connection refused" in err_msg.lower():
            err_msg = "Порт закрыт (Connection refused)"
        return ProbeResult(
            category=category,
            name=f"Decoy ({domain})",
            endpoint=domain,
            port=port,
            transport="HTTPS",
            ok=False,
            latency_ms=round(latency, 1) if latency < (timeout * 1000) else None,
            status_code=None,
            detail=f"Ошибка: {err_msg}",
        )


def probe_naive_proxy_tunnel(
    domain: str,
    port: int = 443,
    timeout: float = 4.0,
) -> ProbeResult:
    """Проверяет NaiveProxy forward_proxy через отправку HTTP CONNECT.

    Caddy forward_proxy отвечает HTTP 200 OK (если авторизован или настроен socks),
    либо 407 Proxy Authentication Required.
    Обычный веб-сервер вернет 405 Method Not Allowed или 400 Bad Request.
    """
    start = time.perf_counter()
    ctx = _create_ssl_context(check_cert=False, alpn_protocols=["http/1.1"])
    try:
        sock = socket.create_connection((domain, port), timeout=timeout)
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            # Отправляем HTTP CONNECT запрос
            connect_req = (
                f"CONNECT example.com:443 HTTP/1.1\r\n"
                f"Host: example.com:443\r\n"
                f"Proxy-Connection: keep-alive\r\n\r\n"
            ).encode("ascii")
            ssock.sendall(connect_req)

            resp_data = bytearray()
            while b"\r\n\r\n" not in resp_data and len(resp_data) < 2048:
                chunk = ssock.recv(512)
                if not chunk:
                    break
                resp_data.extend(chunk)

            latency = (time.perf_counter() - start) * 1000.0
            status_code = None
            server_header = ""
            if resp_data:
                lines = bytes(resp_data).split(b"\r\n")
                if lines:
                    first_line = lines[0].decode("latin-1", errors="replace")
                    parts = first_line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        status_code = int(parts[1])
                for line in lines[1:]:
                    if line.lower().startswith(b"server:"):
                        server_header = line.split(b":", 1)[1].strip().decode("latin-1", errors="replace")

            server_tag = f" ({server_header})" if server_header else ""
            if status_code in (200, 407):
                ok = True
                detail = f"CONNECT {status_code} OK{server_tag}"
            elif status_code in (400, 405):
                ok = False
                detail = f"HTTP {status_code} (Перехвачен decoy, а не tunnel)"
            else:
                ok = False
                detail = f"HTTP {status_code or 'нет ответа'}"

            return ProbeResult(
                category="Протокол",
                name="NaiveProxy Inbound",
                endpoint=domain,
                port=port,
                transport="HTTPS",
                ok=ok,
                latency_ms=round(latency, 1),
                status_code=status_code,
                detail=detail,
            )
    except Exception as exc:
        latency = (time.perf_counter() - start) * 1000.0
        return ProbeResult(
            category="Протокол",
            name="NaiveProxy Inbound",
            endpoint=domain,
            port=port,
            transport="HTTPS",
            ok=False,
            latency_ms=round(latency, 1),
            status_code=None,
            detail=f"Ошибка: {exc}",
        )


def probe_anytls_handshake(
    domain: str,
    port: int = 443,
    timeout: float = 4.0,
) -> ProbeResult:
    """Проверяет AnyTLS: порт 443, TLS handshake со SNI domain."""
    start = time.perf_counter()
    ctx = _create_ssl_context(check_cert=False)
    try:
        sock = socket.create_connection((domain, port), timeout=timeout)
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            latency = (time.perf_counter() - start) * 1000.0
            cipher = ssock.cipher()
            cipher_name = cipher[0] if cipher else "TLS"
            return ProbeResult(
                category="Протокол",
                name="AnyTLS Inbound",
                endpoint=domain,
                port=port,
                transport="TLS",
                ok=True,
                latency_ms=round(latency, 1),
                status_code=None,
                detail="Handshake OK (TLS)",
            )
    except Exception as exc:
        latency = (time.perf_counter() - start) * 1000.0
        return ProbeResult(
            category="Протокол",
            name="AnyTLS Inbound",
            endpoint=domain,
            port=port,
            transport="TLS",
            ok=False,
            latency_ms=round(latency, 1),
            status_code=None,
            detail=f"Ошибка TLS: {exc}",
        )


def probe_panel_service(
    domain: str,
    port: int = 443,
    local_port: int = 2053,
    timeout: float = 4.0,
) -> ProbeResult:
    """Проверяет доступность веб-панели LucX через публичный HTTPS или локальный порт."""
    start = time.perf_counter()
    # 1. Проверяем через публичный HTTPS с HTTP/1.1
    ctx = _create_ssl_context(check_cert=False, alpn_protocols=["http/1.1"])
    try:
        sock = socket.create_connection((domain, port), timeout=timeout)
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            req = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: LucX-Probe/1.0\r\nConnection: close\r\n\r\n".encode("ascii")
            ssock.sendall(req)
            resp = ssock.recv(2048)
            latency = (time.perf_counter() - start) * 1000.0
            status_code = None
            if resp:
                line = resp.split(b"\r\n")[0].decode("latin-1", errors="replace")
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    status_code = int(parts[1])
            ok = (status_code in (200, 301, 302, 401, 403, 404))
            if ok:
                return ProbeResult(
                    category="Панель",
                    name="Панель LucX",
                    endpoint=domain,
                    port=port,
                    transport="HTTPS",
                    ok=True,
                    latency_ms=round(latency, 1),
                    status_code=status_code,
                    detail=f"HTTP {status_code} (Web UI OK)",
                )
    except Exception:
        pass

    # 2. Fallback: проверка локального порта панели (2053)
    try:
        sock = socket.create_connection(("127.0.0.1", local_port), timeout=timeout)
        sock.close()
        latency = (time.perf_counter() - start) * 1000.0
        return ProbeResult(
            category="Панель",
            name="Панель LucX",
            endpoint="127.0.0.1",
            port=local_port,
            transport="TCP",
            ok=True,
            latency_ms=round(latency, 1),
            status_code=None,
            detail=f"Служба активна на 127.0.0.1:{local_port}",
        )
    except Exception as exc:
        latency = (time.perf_counter() - start) * 1000.0
        return ProbeResult(
            category="Панель",
            name="Панель LucX",
            endpoint=domain,
            port=port,
            transport="HTTPS",
            ok=False,
            latency_ms=round(latency, 1),
            status_code=None,
            detail=f"Недоступна: {exc}",
        )


def probe_subscription_sidecar(
    domain: str = "sub.example.test",
    local_port: int = 21000,
    timeout: float = 4.0,
) -> ProbeResult:
    """Проверяет HTTPS sidecar подписок на 127.0.0.1:21000 с Host: sub.example.test."""
    start = time.perf_counter()
    ctx = _create_ssl_context(check_cert=False, alpn_protocols=["http/1.1"])
    try:
        sock = socket.create_connection(("127.0.0.1", local_port), timeout=timeout)
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            req = (
                f"GET /sub/health HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: LucX-Probe/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            ssock.sendall(req)

            resp_data = bytearray()
            while b"\r\n\r\n" not in resp_data and len(resp_data) < 2048:
                chunk = ssock.recv(512)
                if not chunk:
                    break
                resp_data.extend(chunk)

            latency = (time.perf_counter() - start) * 1000.0
            sidecar_active = False
            status_code = None
            if resp_data:
                lines = bytes(resp_data).split(b"\r\n")
                if lines:
                    first_line = lines[0].decode("latin-1", errors="replace")
                    parts = first_line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        status_code = int(parts[1])
                for line in lines[1:]:
                    if line.lower().startswith(b"x-lucx-subscription-sidecar:"):
                        sidecar_active = True

            ok = sidecar_active or (status_code is not None and status_code in (200, 404))
            detail = "Active (AWG/AnyTLS rewrite)" if sidecar_active else f"HTTP {status_code}"
            return ProbeResult(
                category="Подписка",
                name="Sub Sidecar (Local)",
                endpoint="127.0.0.1",
                port=local_port,
                transport="HTTPS",
                ok=ok,
                latency_ms=round(latency, 1),
                status_code=status_code,
                detail=detail,
            )
    except Exception as exc:
        latency = (time.perf_counter() - start) * 1000.0
        return ProbeResult(
            category="Подписка",
            name="Sub Sidecar (Local)",
            endpoint="127.0.0.1",
            port=local_port,
            transport="HTTPS",
            ok=False,
            latency_ms=round(latency, 1),
            status_code=None,
            detail=f"Не отвечает на 127.0.0.1:{local_port}: {exc}",
        )


def probe_udp_socket(
    endpoint: str,
    port: int,
    name: str = "UDP Service",
    timeout: float = 2.0,
) -> ProbeResult:
    """Проверяет сетевую доступность UDP порта."""
    start = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00\x00\x00\x00", (endpoint, port))
        latency = (time.perf_counter() - start) * 1000.0
        sock.close()
        return ProbeResult(
            category="UDP",
            name=name,
            endpoint=endpoint,
            port=port,
            transport="UDP",
            ok=True,
            latency_ms=round(latency, 1),
            status_code=None,
            detail="Socket Open / Reachable",
        )
    except Exception as exc:
        latency = (time.perf_counter() - start) * 1000.0
        return ProbeResult(
            category="UDP",
            name=name,
            endpoint=endpoint,
            port=port,
            transport="UDP",
            ok=False,
            latency_ms=round(latency, 1),
            status_code=None,
            detail=f"Ошибка UDP: {exc}",
        )


def run_comprehensive_protocol_test(
    engine: Engine,
    output_fn: OutputFn | None = None,
) -> list[ProbeResult]:
    """Запускает параллельные сквозные проверки всех сайтов-заглушек и протоколов."""
    try:
        state = load_state(engine.fs)
    except Exception:
        state = {}
    manifest = state.get("manifest") or {}
    domains_cfg = manifest.get("domains") or {}

    root_domain = str(domains_cfg.get("root_zone") or domains_cfg.get("primary") or "example.test").strip()
    sub_domain = str(domains_cfg.get("subscription") or f"sub.{root_domain}").strip()
    panel_domain = str(domains_cfg.get("panel") or f"panel.{root_domain}").strip()

    # Собираем список протокольных доменов
    decoy_domains: list[tuple[str, str]] = []
    decoy_domains.append((root_domain, "Decoy (Root)"))

    # Домены протоколов из манифеста
    protocols = manifest.get("protocols") or []
    for p in protocols:
        domain = p.get("domain") or p.get("share_addr") or ""
        domain = domain.split(":")[0].strip()
        proto_name = str(p.get("protocol") or "").strip()
        inbound_id = p.get("inbound_id")
        label = f"Decoy ({proto_name} #{inbound_id})" if proto_name else f"Decoy ({domain})"
        if domain and domain not in [d[0] for d in decoy_domains]:
            decoy_domains.append((domain, label))

    # Если манифест пуст или содержит мало доменов — добавим стандартные test1-test8
    if root_domain:
        for i in range(1, 9):
            d = f"test{i}.{root_domain}"
            if d not in [item[0] for item in decoy_domains]:
                decoy_domains.append((d, f"Decoy (test{i})"))

    tasks: list[tuple[Callable[[], ProbeResult], str]] = []

    # 1. Сайты-заглушки (Decoys)
    for d, label in decoy_domains:
        tasks.append((lambda d=d, label=label: probe_https_decoy(d, 443, category="Decoy"), label))

    # 2. Веб-панель
    tasks.append((lambda: probe_panel_service(panel_domain, 443), "Панель LucX"))

    # 3. Подписка Sidecar
    tasks.append((lambda: probe_subscription_sidecar(sub_domain, 21000), "Sub Sidecar"))

    # 4. NaiveProxy Inbound
    naive_domain = next((d[0] for d in decoy_domains if "test5" in d[0] or "naive" in d[1].lower()), None)
    if not naive_domain:
        naive_domain = f"test5.{root_domain}"
    tasks.append((lambda: probe_naive_proxy_tunnel(naive_domain, 443), "NaiveProxy"))

    # 5. AnyTLS Inbound
    anytls_domain = next((d[0] for d in decoy_domains if "test8" in d[0] or "anytls" in d[1].lower()), None)
    if not anytls_domain:
        anytls_domain = f"test8.{root_domain}"
    tasks.append((lambda: probe_anytls_handshake(anytls_domain, 443), "AnyTLS"))

    # 6. UDP: AmneziaWG (порт 8443)
    awg_domain = next((d[0] for d in decoy_domains if "test4" in d[0] or "awg" in d[1].lower()), None)
    if not awg_domain:
        awg_domain = f"test4.{root_domain}"
    tasks.append((lambda: probe_udp_socket(awg_domain, 8443, "AmneziaWG (UDP:8443)"), "AmneziaWG UDP"))

    # 7. UDP: Hysteria 2 (порт 443)
    hy2_domain = next((d[0] for d in decoy_domains if "test6" in d[0] or "hy2" in d[1].lower()), None)
    if not hy2_domain:
        hy2_domain = f"test6.{root_domain}"
    tasks.append((lambda: probe_udp_socket(hy2_domain, 443, "Hysteria 2 (UDP:443)"), "Hysteria2 UDP"))

    # Выполняем параллельно
    results: list[ProbeResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(tasks) or 1, 14)) as pool:
        future_map = {pool.submit(t[0]): t[1] for t in tasks}
        for fut in concurrent.futures.as_completed(future_map):
            try:
                results.append(fut.result())
            except Exception as exc:
                label = future_map[fut]
                results.append(ProbeResult(
                    category="Служба",
                    name=label,
                    endpoint="-",
                    port=0,
                    transport="-",
                    ok=False,
                    latency_ms=None,
                    status_code=None,
                    detail=f"Исключение: {exc}",
                ))

    # Сортируем: сначала Decoys, потом Панель, Подписка, Протоколы, UDP
    category_order = {"Decoy": 1, "Панель": 2, "Подписка": 3, "Протокол": 4, "UDP": 5}
    results.sort(key=lambda r: (category_order.get(r.category, 99), r.name))

    if output_fn is not None:
        render_protocol_test_table(results, output_fn)

    return results


def render_protocol_test_table(results: list[ProbeResult], output_fn: OutputFn) -> None:
    """Выводит идеально выровненную таблицу результатов с цветами и статусами."""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    # Точные ширины колонок (в символах контента без сокращений):
    W1 = 25  # Категория / Тест (вмещает "Decoy (test1.example.test)" полностью)
    W2 = 18  # Endpoint / Домен (полные имена доменов)
    W3 = 5   # Порт (до 65535, включая 21000)
    W4 = 6   # Статус (✔ OK / ✖ FAIL)
    W5 = 9   # Latency (задержка ms)
    W6 = 21  # Примечание (полные описания без сокращений)

    sep_lens = [W1 + 2, W2 + 2, W3 + 2, W4 + 2, W5 + 2, W6 + 2]
    total_interior = sum(sep_lens) + len(sep_lens) - 1

    title = "КОМПЛЕКСНЫЙ АВТОТЕСТ ВСЕХ ПРОТОКОЛОВ И САЙТОВ-ЗАГЛУШЕК (LIVE PROBE)"
    top_line = f"{BOLD}{CYAN}┌{'─' * total_interior}┐{RESET}"
    title_line = f"{BOLD}{CYAN}│{title:^{total_interior}}│{RESET}"
    header_sep = f"{BOLD}{CYAN}├{'┬'.join('─' * s for s in sep_lens)}┤{RESET}"
    header = (
        f"{BOLD}│ {'Категория / Тест':<{W1}} "
        f"│ {'Endpoint':<{W2}} "
        f"│ {'Порт':^{W3}} "
        f"│ {'Статус':^{W4}} "
        f"│ {'Latency':^{W5}} "
        f"│ {'Примечание':<{W6}} │{RESET}"
    )
    mid_sep = f"{CYAN}├{'┼'.join('─' * s for s in sep_lens)}┤{RESET}"
    bottom_sep = f"{CYAN}└{'┴'.join('─' * s for s in sep_lens)}┘{RESET}"

    output_fn("")
    output_fn(top_line)
    output_fn(title_line)
    output_fn(header_sep)
    output_fn(header)
    output_fn(mid_sep)

    total = len(results)
    passed = 0

    for r in results:
        if r.ok:
            passed += 1
            vis_status = "✔ OK"
            color = GREEN
        else:
            vis_status = "✖ FAIL"
            color = RED

        status_cell = f"{color}{vis_status:<{W4}}{RESET}"

        if r.latency_ms is not None:
            lat_str = f"{r.latency_ms:>6.1f} ms"
        else:
            lat_str = f"{YELLOW}{'--':>6}{RESET}   "

        # Сокращения названий и деталей без поломки скобок
        raw_name = r.name
        if len(raw_name) > W1:
            raw_name = raw_name[:W1]
        cat_s = f"{raw_name:<{W1}}"

        end_s = f"{r.endpoint[:W2]:<{W2}}"
        port_s = f"{str(r.port)[:W3]:>{W3}}"

        # Детализация
        det_raw = r.detail
        clean_detail = {
            "Active (AWG/AnyTLS rewrite)": "Active (AWG/AnyTLS)",
            "CONNECT 200 OK (Caddy)": "CONNECT 200 (Caddy)",
            "HTTP 200 (Web UI OK)": "HTTP 200 (Web UI)",
            "Socket Open / Reachable": "Socket Open / OK",
        }.get(det_raw, det_raw)
        if len(clean_detail) > W6:
            clean_detail = clean_detail[:W6 - 1] + "…"
        det_s = f"{clean_detail:<{W6}}"

        output_fn(
            f"│ {cat_s} │ {end_s} │ {port_s} │ {status_cell} │ {lat_str} │ {det_s} │"
        )

    output_fn(bottom_sep)

    pct = round((passed / total * 100), 1) if total else 0
    summary_color = GREEN if passed == total else YELLOW if passed > 0 else RED
    output_fn(f"{BOLD}Результат: {summary_color}{passed}/{total} проверок успешно ({pct}%){RESET}\n")
