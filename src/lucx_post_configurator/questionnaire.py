from __future__ import annotations

import copy
import re
import urllib.parse
from collections.abc import Callable
from pathlib import PurePosixPath

from .cloudflare import CLOUDFLARE_HTTPS_PORTS
from .models import Audit, ConfigurationError, Inbound, default_manifest, ensure_port, valid_domain
from .certificates import select_certificate
from .decoy_capabilities import classify_decoy_capabilities
from .extended_decoys import classify_extended_decoy_routes
from .runner import Runner
from .targetfs import TargetFS


InputFunction = Callable[[str], str]
OutputFunction = Callable[[str], None]


def _ask(
    prompt: str,
    default: str = "",
    *,
    input_fn: InputFunction = input,
    output_fn: OutputFunction = print,
    validator: Callable[[str], bool] | None = None,
) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        try:
            value = input_fn(f"{prompt}{suffix}: ").strip()
        except UnicodeDecodeError:
            continue
        if not value:
            value = default
        if value and (validator is None or validator(value)):
            return value
        output_fn("Некорректное значение, попробуйте еще раз.")


def _yes_no(
    prompt: str,
    default: bool,
    *,
    input_fn: InputFunction = input,
    output_fn: OutputFunction = print,
) -> bool:
    # Сохранённое состояние не является подтверждением новой операции.
    default = False
    output_fn(prompt)
    output_fn("  1. Да" + (" (по умолчанию)" if default else ""))
    output_fn("  2. Нет" + (" (по умолчанию)" if not default else ""))
    default_number = "1" if default else "2"
    while True:
        try:
            value = input_fn(f"Номер варианта [{default_number}]: ").strip()
        except UnicodeDecodeError:
            continue
        if not value:
            return default
        if value == "1":
            return True
        if value == "2":
            return False
        output_fn("Введите 1 или 2.")


def _port(value: str) -> bool:
    try:
        ensure_port(value, "port")
    except ConfigurationError:
        return False
    return True


def _cloudflare_https_port(value: str) -> bool:
    return _port(value) and int(value) in CLOUDFLARE_HTTPS_PORTS


def _path(value: str) -> bool:
    path = PurePosixPath(value)
    return value.startswith("/") and ".." not in path.parts and "\x00" not in value


def _ip_address(value: str) -> bool:
    try:
        __import__("ipaddress").ip_address(value)
    except ValueError:
        return False
    return True


def _domain_list(value: str) -> bool:
    items = [item.strip() for item in value.split(",") if item.strip()]
    return bool(items) and all(valid_domain(item) for item in items)


def _choice(
    prompt: str,
    choices: dict[str, str],
    default: str,
    *,
    input_fn: InputFunction,
    output_fn: OutputFunction,
) -> str:
    output_fn(prompt)
    keys = list(choices)
    for index, key in enumerate(keys, start=1):
        output_fn(f"  {index}. {choices[key]}" + (" (по умолчанию)" if key == default else ""))
    while True:
        try:
            raw = input_fn("Номер варианта: ").strip()
        except UnicodeDecodeError:
            continue
        if not raw:
            return default
        try:
            return keys[int(raw) - 1]
        except (ValueError, IndexError):
            output_fn("Выберите номер из списка.")


def _select_numbered_domains(
    prompt: str,
    domains: list[str],
    *,
    input_fn: InputFunction,
    output_fn: OutputFunction,
) -> list[str]:
    """Select discovered SNI values by number; blank and 1 mean all."""

    choices = list(dict.fromkeys(item.strip().lower() for item in domains if valid_domain(item)))
    if not choices:
        raise ConfigurationError("не найдено допустимых SNI для маршрутизации")
    output_fn(prompt)
    output_fn("  1. Выбрать все (по умолчанию)")
    for index, domain in enumerate(choices, start=2):
        output_fn(f"  {index}. {domain}")
    while True:
        try:
            raw = input_fn("Номера через запятую [1]: ").strip()
        except UnicodeDecodeError:
            continue
        if not raw or raw == "1":
            return choices
        try:
            numbers = [int(item.strip()) for item in raw.split(",") if item.strip()]
        except ValueError:
            numbers = []
        if numbers and 1 not in numbers and all(2 <= number <= len(choices) + 1 for number in numbers):
            return list(dict.fromkeys(choices[number - 2] for number in numbers))
        output_fn("Выберите номера из списка через запятую; 1 — выбрать все.")


def _safe_backend_host(value: str) -> str:
    value = value.strip()
    return "127.0.0.1" if value in {"", "0.0.0.0", "::", "[::]", "localhost"} else value


def _inbound_routing_metadata(inbound: Inbound) -> dict:
    """Copy only non-credential routing facts discovered from the current inbound."""
    from .routing_profiles import inbound_routing_metadata

    return inbound_routing_metadata(inbound)


def infer_exposure(protocol: str, network: str, public_port: int, security: str = "") -> str:
    if public_port == 443 and network in {"tcp", "both"} and (
        security in {"tls", "reality"} or protocol in {
        "naive",
        "trojan",
        "anytls",
        "trusttunnel",
        }
    ):
        return "tcp_sni"
    if network == "udp":
        return "udp_direct"
    if network == "both":
        return "tcp_udp_direct"
    return "tcp_direct"


def default_public_port_for_inbound(inbound: Inbound) -> int:
    """Choose the public default without confusing a TCP listener with its endpoint."""
    if inbound.network in {"tcp", "both"} and (
        inbound.security in {"tls", "reality"}
        or inbound.protocol in {"naive", "trojan", "anytls", "trusttunnel"}
    ):
        return 443
    return int(inbound.suggested_public_port or inbound.port)


def _subscription_sni_names(inbound: Inbound, domain: str) -> list[str]:
    """Return current client-facing SNI values without hardcoded domains."""

    defaults = list(dict.fromkeys(name.lower() for name in inbound.server_names if name))
    # Reality clients deliberately send one of realitySettings.serverNames,
    # which can differ from the endpoint address. Other TLS protocols normally
    # use the endpoint domain; keep any explicit Host/TLS SNI as additional
    # accepted values.
    if not defaults or inbound.security != "reality":
        if domain not in defaults:
            defaults.insert(0, domain)
    return defaults


def _normalize_configured_public_endpoints(
    endpoints: list[dict[str, Any]] | None,
    domain: str,
    public_port: int,
    *,
    exposure: str = "",
    sni_names: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Ensure protocol public_endpoints has valid entries when configured interactively."""
    raw = [dict(ep) for ep in (endpoints or []) if isinstance(ep, dict)]
    if not raw:
        sni = (sni_names[0] if sni_names else domain) if exposure == "tcp_sni" else ""
        return [
            {
                "host_id": 0,
                "address": domain,
                "port": public_port,
                "sni": sni,
                "sni_source": "address" if sni == domain else "explicit" if sni else "inherited",
                "keep_sni_blank": False,
                "http_host": "",
                "valid": bool(domain and 1 <= public_port <= 65535),
            }
        ]
    result = []
    for ep in raw:
        item = dict(ep)
        if ep.get("host_id") == 0 or not ep.get("address") or not ep.get("valid"):
            if not ep.get("address") or ep.get("host_id") == 0:
                item["address"] = domain
            if not ep.get("port") or ep.get("host_id") == 0:
                item["port"] = public_port
            if exposure == "tcp_sni" and not item.get("sni"):
                sni = sni_names[0] if sni_names else domain
                item["sni"] = sni
                item["sni_source"] = "address" if sni == domain else "explicit"
            item["valid"] = bool(item.get("address") and 1 <= int(item.get("port") or 0) <= 65535)
        result.append(item)
    return result


def protocol_decoy_sites(manifest: dict) -> list[dict[str, str]]:
    """Build one deterministic decoy root for every published protocol domain.

    The DNS zone apex (for example ``example.test``) is always included as a
    standalone site: it is not owned by any protocol listener and HAProxy
    routes it directly to the Nginx decoy frontend.
    """
    from .routing_profiles import endpoint_domains

    sites: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(domain_value: str) -> None:
        domain = str(domain_value or "").strip().lower().rstrip(".")
        if not valid_domain(domain) or domain in seen:
            return
        seen.add(domain)
        safe_name = re.sub(r"[^a-z0-9.-]", "-", domain)
        sites.append({"domain": domain, "root": f"/var/www/lucx-decoys/{safe_name}"})

    for protocol in manifest.get("protocols", []):
        for domain in endpoint_domains(protocol):
            add(domain)

    # The zone apex of the panel domain is never owned by a protocol listener
    # (protocols use dedicated subdomains), so a standalone decoy there is
    # always safe and gives the browser a working site on the root domain.
    zone_apex = str((manifest.get("decoys") or {}).get("zone_apex") or "").strip().lower().rstrip(".")
    if zone_apex and valid_domain(zone_apex):
        add(zone_apex)
    else:
        panel_domain = str(
            (manifest.get("lucx") or {}).get("panel", {}).get("domain") or ""
        ).strip().lower().rstrip(".")
        if panel_domain and "." in panel_domain:
            add(panel_domain.split(".", 1)[1])
    return sites


def decoy_reachability(manifest: dict) -> list[dict[str, str]]:
    """Describe whether a browser SNI goes directly to Nginx or needs fallback."""
    return [
        {
            "domain": item["domain"],
            "delivery": (
                "naive_caddy"
                if item["status"] == "naive_caddy_owned_readonly"
                else "existing_protocol_fallback"
                if not item["managed"]
                else "direct_nginx"
            ),
        }
        for item in classify_decoy_capabilities(manifest)
    ]


def configure_protocol_decoys_interactively(
    current: dict,
    *,
    default_enabled: bool = True,
    show_capabilities: bool = True,
    input_fn: InputFunction = input,
    output_fn: OutputFunction = print,
) -> tuple[dict, list[str]]:
    """Enable/synchronize a decoy site for every current protocol domain."""

    manifest = copy.deepcopy(current)
    if not _yes_no(
        "Создать/синхронизировать заглушки для ВСЕХ доменов протоколов",
        default_enabled,
        input_fn=input_fn,
        output_fn=output_fn,
    ):
        return manifest, []
    decoys = manifest["decoys"]
    was_enabled = bool(decoys.get("enabled"))
    decoys["enabled"] = True
    decoys["create_content"] = _yes_no(
        "Создать нейтральные index.html, если каталог сайта пуст",
        bool(decoys.get("create_content")) if was_enabled else True,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    panel_domain = str(
        (manifest.get("lucx") or {}).get("panel", {}).get("domain") or ""
    ).strip().lower().rstrip(".")
    if panel_domain and "." in panel_domain:
        suggested_apex = str(
            (manifest.get("decoys") or {}).get("zone_apex")
            or panel_domain.split(".", 1)[-1]
        ).strip().lower()
        apex = _ask(
            "Корневой домен зоны для автономной заглушки (zone apex)",
            suggested_apex,
            input_fn=input_fn,
            output_fn=output_fn,
            validator=valid_domain,
        ).lower()
        decoys["zone_apex"] = apex
    decoys["sites"] = protocol_decoy_sites(manifest)
    decoys["capabilities"] = classify_decoy_capabilities(manifest)
    if not decoys["sites"]:
        raise ConfigurationError("не найдено ни одного корректного домена протокола")

    warnings: list[str] = []
    if show_capabilities:
        output_fn("Будут созданы отдельные Nginx virtual hosts:")
        for item in decoys["capabilities"]:
            if item["managed"]:
                output_fn(f"- {item['domain']}: {item['reason']}")
            elif item["status"] == "naive_caddy_owned_readonly":
                message = (
                    f"- {item['domain']}: SNI принадлежит Naive/Caddy; каталог Nginx будет "
                    "создан, но отдачу определяет неизменяемый Naive Caddyfile"
                )
                output_fn(message)
                warnings.append(message[2:])
            else:
                message = f"- {item['domain']}: {item['reason']}"
                output_fn(message)
                warnings.append(message[2:])

    output_fn(
        "Неизвестный SNI по умолчанию будет отклоняться. Включение default_server "
        "может раскрыть заглушку посторонним доменам."
    )
    unknown_decoy = _yes_no(
        "Явно отправлять неизвестный SNI на заглушку",
        bool(decoys.get("default_server", False)),
        input_fn=input_fn,
        output_fn=output_fn,
    )
    manifest["network"]["unknown_sni_action"] = (
        "decoy" if unknown_decoy else "reject"
    )
    decoys["default_server"] = unknown_decoy
    manifest["components"]["nginx"] = True
    return manifest, warnings


def configure_decoy_routing_mode(
    current: dict,
    audit: Audit,
    mode: str,
    *,
    refresh_from_audit: bool = True,
) -> tuple[dict, list[str]]:
    """Build the single automatic decoy mode from the current topology."""

    # ``mode`` remains accepted for old CLI callers. The TUI exposes only the
    # automatic mode, while legacy strict manifests remain readable.
    if refresh_from_audit:
        manifest, refresh_warnings = refresh_manifest_from_audit(current, audit)
    else:
        # Начальный мастер уже подтвердил публичные маршруты, ещё не записанные в LucX.
        manifest, refresh_warnings = copy.deepcopy(current), []
    decoys = manifest["decoys"]
    components = manifest["components"]
    components["haproxy"] = True
    components["nginx"] = True

    if mode == "strict":
        decoys["routing_mode"] = "strict"
        decoys["extended_user_confirmed"] = False
        decoys["require_full_acceptance"] = False
        decoys["extended_routes"] = []
        components["extended_tls_split"] = False
        components["naive_frontend"] = False
        decoys["capabilities"] = classify_decoy_capabilities(manifest, audit)
        return manifest, refresh_warnings

    decoys["routing_mode"] = "extended"

    decoys["extended_user_confirmed"] = True
    decoys["require_full_acceptance"] = False
    routes = classify_extended_decoy_routes(manifest, audit)
    decoys["extended_routes"] = routes
    components["extended_tls_split"] = True
    components["naive_frontend"] = any(
        item.get("strategy") == "naive_managed" and item.get("status") == "ready"
        for item in routes
    )
    decoys["capabilities"] = classify_decoy_capabilities(manifest, audit)
    warnings = list(refresh_warnings) + [
        f"{item.get('domain')}: {item.get('reason')}"
        for item in routes
        if item.get("status") != "ready"
    ]
    return manifest, warnings


def _has_acme_record(cert_path: str, fs: TargetFS | None = None) -> bool:
    if not cert_path:
        return False
    if "/.acme.sh/" in cert_path:
        return True
    try:
        p = PurePosixPath(cert_path)
        domain = p.parent.name.removesuffix("_ecc")
        check_paths = [
            f"/root/.acme.sh/{domain}_ecc/{domain}.conf",
            f"/root/.acme.sh/{domain}/{domain}.conf",
        ]
        for cp in check_paths:
            if fs is not None:
                if fs.exists(cp) or fs.path(cp).is_file():
                    return True
            else:
                if Path(cp).is_file():
                    return True
    except Exception:
        pass
    return False


def build_manifest_interactively(
    audit: Audit,
    *,
    input_fn: InputFunction = input,
    output_fn: OutputFunction = print,
) -> dict:
    manifest = copy.deepcopy(default_manifest(audit))
    output_fn("\nLucX post-configurator: транзакционная внешняя конфигурация.")
    output_fn(
        "Клиенты, inbounds и Naive Caddyfile не изменяются. Если домен панели или подписок "
        "пуст, выбранное имя можно безопасно записать в settings LucX после backup.\n"
    )

    panel = manifest["lucx"]["panel"]
    subscription = manifest["lucx"]["subscription"]
    panel["domain"] = _ask(
        "Домен панели", panel.get("domain", ""), input_fn=input_fn, output_fn=output_fn, validator=valid_domain
    ).lower()
    panel["internal_host"] = _safe_backend_host(panel.get("internal_host", ""))
    panel["internal_port"] = int(
        _ask(
            "Внутренний порт панели LucX",
            str(panel.get("internal_port", 2083)),
            input_fn=input_fn,
            output_fn=output_fn,
            validator=_port,
        )
    )
    panel["public_port"] = int(
        _ask(
            "Внешний HTTPS-порт панели через Cloudflare",
            str(panel.get("public_port", 443)),
            input_fn=input_fn,
            output_fn=output_fn,
            validator=_cloudflare_https_port,
        )
    )
    panel["path_prefix"] = (
        "/"
        if _yes_no(
            "Открывать панель по корню домена без дополнительного пути",
            True,
            input_fn=input_fn,
            output_fn=output_fn,
        )
        else _ask(
            "Путь панели",
            panel.get("path_prefix", "/"),
            input_fn=input_fn,
            output_fn=output_fn,
            validator=_path,
        )
    )
    subscription["domain"] = _ask(
        "Домен подписок",
        subscription.get("domain", ""),
        input_fn=input_fn,
        output_fn=output_fn,
        validator=valid_domain,
    ).lower()
    subscription["internal_host"] = _safe_backend_host(subscription.get("internal_host", ""))
    subscription["internal_port"] = int(
        _ask(
            "Внутренний порт подписок LucX",
            str(subscription.get("internal_port", 2096)),
            input_fn=input_fn,
            output_fn=output_fn,
            validator=_port,
        )
    )
    subscription["public_port"] = int(
        _ask(
            "Внешний HTTPS-порт подписок через Cloudflare",
            str(subscription.get("public_port", 443)),
            input_fn=input_fn,
            output_fn=output_fn,
            validator=_cloudflare_https_port,
        )
    )
    subscription["path_prefix"] = _ask(
        "Префикс пути подписок",
        subscription.get("path_prefix", "/sub/"),
        input_fn=input_fn,
        output_fn=output_fn,
        validator=_path,
    )
    current_panel_domain = str(audit.settings.get("webDomain") or "").strip().lower()
    current_subscription_domain = str(audit.settings.get("subDomain") or "").strip().lower()
    current_panel_path = str(audit.settings.get("webBasePath") or "/")
    domains_differ = (
        current_panel_domain != panel["domain"]
        or current_subscription_domain != subscription["domain"]
    )
    panel_path_differs = current_panel_path != panel["path_prefix"]
    if domains_differ or panel_path_differs:
        sync_domains = _yes_no(
            "Записать выбранные публичные домены и путь панели в settings LucX (только после backup)",
            True,
            input_fn=input_fn,
            output_fn=output_fn,
        )
        if not sync_domains:
            raise ConfigurationError(
                "выбранные домены отличаются от LucX; без синхронизации рабочую конфигурацию создать нельзя"
            )
        manifest["lucx"]["settings_management"]["sync_domains"] = True
        manifest["lucx"]["settings_management"]["sync_panel_path"] = panel_path_differs
        manifest["lucx"]["settings_management"]["user_confirmed"] = True

    current_sub_uri = str(audit.settings.get("subURI") or "").strip()
    default_base = f"https://{subscription['domain'].strip().lower()}/"
    proposed_base = default_base if not current_sub_uri else current_sub_uri.split("/sub/")[0] + "/"
    if proposed_base.rstrip("/") != current_sub_uri.rstrip("/").replace("/sub/", "").replace("/json/", "").replace("/clash/", "") or not current_sub_uri:
        sync_sub_urls = _yes_no(
            f"Записать публичный URL подписки {proposed_base} в LucX (ссылки без порта, через HAProxy)",
            True,
            input_fn=input_fn,
            output_fn=output_fn,
        )
        if sync_sub_urls:
            manifest["lucx"]["subscription"]["public_base_url"] = proposed_base.rstrip("/") + "/"
            manifest["lucx"]["settings_management"]["sync_subscription_urls"] = True
            manifest["lucx"]["settings_management"]["user_confirmed"] = True

    certs = manifest["certificates"]
    certs["cert_path"] = _ask(
        "Путь к fullchain сертификата",
        certs.get("cert_path", "") or "/root/.acme.sh/example/fullchain.cer",
        input_fn=input_fn,
        output_fn=output_fn,
        validator=_path,
    )
    certs["key_path"] = _ask(
        "Путь к приватному ключу сертификата",
        certs.get("key_path", "") or "/root/.acme.sh/example/example.key",
        input_fn=input_fn,
        output_fn=output_fn,
        validator=_path,
    )
    if "/.acme.sh/" in certs["cert_path"] or _has_acme_record(certs["cert_path"]):
        certs["renewal"]["provider"] = "acme.sh"
        certs["renewal"]["enabled"] = True
        manifest.setdefault("components", {})["tls_hook"] = True
        if certs["cert_path"].startswith("/root/cert/"):
            certs["renewal"]["primary_domain"] = PurePosixPath(certs["cert_path"]).parent.name
        else:
            certs["renewal"]["primary_domain"] = PurePosixPath(certs["cert_path"]).parent.name.removesuffix("_ecc")
    elif certs["cert_path"].startswith("/etc/letsencrypt/live/"):
        certs["renewal"]["provider"] = "certbot"
        certs["renewal"]["enabled"] = True
        manifest.setdefault("components", {})["tls_hook"] = True

    ssh_default = str(manifest["network"].get("ssh_port", 22))
    manifest["network"]["ssh_port"] = int(
        _ask("Порт SSH", ssh_default, input_fn=input_fn, output_fn=output_fn, validator=_port)
    )
    manifest["network"]["ssh_ports"] = list(
        dict.fromkeys([manifest["network"]["ssh_port"], *audit.ssh_ports])
    )
    manifest["network"]["public_bind_address"] = _ask(
        "Публичный IP, на котором HAProxy принимает TCP",
        manifest["network"].get("public_bind_address", "0.0.0.0"),
        input_fn=input_fn,
        output_fn=output_fn,
        validator=_ip_address,
    )
    if _yes_no(
        "Включить строгий firewall allowlist (SSH и все обнаруженные порты будут сохранены, остальные входящие заблокированы)",
        False,
        input_fn=input_fn,
        output_fn=output_fn,
    ):
        manifest["firewall"]["mode"] = "strict_allowlist"
    cloudflare_enabled = _yes_no(
        "Панель и подписки находятся под оранжевым облаком Cloudflare: разрешить доступ к ним только из актуальных сетей Cloudflare",
        True,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    manifest["cloudflare"]["enabled"] = cloudflare_enabled
    manifest["cloudflare"]["user_confirmed"] = cloudflare_enabled

    enabled = [item for item in audit.inbounds if item.enable]
    if not enabled:
        raise ConfigurationError("в базе LucX нет включенных inbounds; продолжение небезопасно")
    output_fn(f"\nОбнаружено включенных inbounds: {len(enabled)}")
    for inbound in enabled:
        output_fn(f"\n#{inbound.id} {inbound.remark or inbound.protocol} ({inbound.protocol})")
        domain_default = inbound.share_addr or (inbound.server_names[0] if inbound.server_names else "")
        domain = _ask(
            "Внешний домен протокола",
            domain_default,
            input_fn=input_fn,
            output_fn=output_fn,
            validator=valid_domain,
        ).lower()
        default_public_port = default_public_port_for_inbound(inbound)
        public_port = int(
            _ask(
                "Внешний основной порт",
                str(default_public_port),
                input_fn=input_fn,
                output_fn=output_fn,
                validator=_port,
            )
        )
        exposure_default = infer_exposure(inbound.protocol, inbound.network, public_port, inbound.security)
        if inbound.network == "udp":
            choices = {"udp_direct": "UDP напрямую в LucX", "none": "не управлять внешней публикацией"}
        elif inbound.network == "both":
            choices = {
                "tcp_udp_direct": "TCP и UDP напрямую",
                "tcp_sni": "TCP через HAProxy по SNI; UDP напрямую на порту inbound",
                "none": "не управлять внешней публикацией",
            }
        else:
            choices = {
                "tcp_sni": "TCP через HAProxy по SNI",
                "tcp_direct": "TCP напрямую, без HAProxy",
                "none": "не управлять внешней публикацией",
            }
        exposure = _choice(
            "Как опубликован этот inbound?",
            choices,
            exposure_default if exposure_default in choices else next(iter(choices)),
            input_fn=input_fn,
            output_fn=output_fn,
        )
        # Prevent hard crash: if tcp_direct/udp_direct chosen but ports mismatch,
        # offer interactive correction instead of falling through to validation error.
        if exposure in {"tcp_direct", "udp_direct", "tcp_udp_direct"} and public_port != inbound.port:
            output_fn(
                f"\n⚠ Порт {public_port} не совпадает с внутренним портом LucX ({inbound.port})."
                f"\n  Для режима «напрямую» внешний порт обязан совпадать с портом LucX,"
                f"\n  так как NAT не управляется постконфигуратором."
            )
            fix_choices = {}
            fix_default = ""
            if inbound.network in {"tcp", "both"} and "tcp_sni" not in choices:
                pass  # tcp_sni not available for this network type
            elif inbound.network in {"tcp", "both"}:
                fix_choices["sni"] = f"Переключить на HAProxy SNI (внешний порт {public_port}, внутренний {inbound.port})"
                fix_default = "sni"
            fix_choices["port"] = f"Исправить внешний порт на {inbound.port} (прямой доступ)"
            fix_choices["none"] = "Не управлять публикацией этого inbound"
            if not fix_default:
                fix_default = "port"
            fix = _choice(
                "Как исправить?",
                fix_choices,
                fix_default,
                input_fn=input_fn,
                output_fn=output_fn,
            )
            if fix == "sni":
                exposure = "tcp_sni"
                output_fn(f"  → Режим переключён на HAProxy SNI, внешний порт {public_port}")
            elif fix == "port":
                public_port = inbound.port
                output_fn(f"  → Внешний порт изменён на {public_port}")
            else:
                exposure = "none"
                output_fn("  → Публикация этого inbound отключена")
        sni_names: list[str] = []
        if exposure == "tcp_sni":
            defaults = _subscription_sni_names(inbound, domain)
            sni_names = _select_numbered_domains(
                "SNI для маршрутизации",
                defaults,
                input_fn=input_fn,
                output_fn=output_fn,
            )
        sync_share_addr = False
        if inbound.protocol == "naive" and exposure == "tcp_sni":
            sync_share_addr = _yes_no(
                f"Записать публичный адрес Naive как {domain}:{public_port}, сохранив внутренний порт {inbound.port}",
                True,
                input_fn=input_fn,
                output_fn=output_fn,
            )
            if not sync_share_addr:
                raise ConfigurationError(
                    "Naive через общий внешний порт требует синхронизации его публичного Host в LucX"
                )
            manifest["lucx"]["settings_management"]["sync_naive_share_addr"] = True
            manifest["lucx"]["settings_management"]["user_confirmed"] = True
        sync_public_endpoint = exposure != "none"
        if sync_public_endpoint:
            manifest["lucx"]["settings_management"]["sync_public_endpoints"] = True
            manifest["lucx"]["settings_management"]["user_confirmed"] = True
        meta = _inbound_routing_metadata(inbound)
        meta["public_endpoints"] = _normalize_configured_public_endpoints(
            meta.get("public_endpoints"),
            domain,
            public_port,
            exposure=exposure,
            sni_names=sni_names,
        )
        manifest["protocols"].append(
            {
                "inbound_id": inbound.id,
                "protocol": inbound.protocol,
                "remark": inbound.remark,
                "domain": domain,
                "internal_host": _safe_backend_host(inbound.listen),
                "internal_port": inbound.port,
                "public_port": public_port,
                "udp_public_port": (
                    inbound.port if inbound.network == "both" and exposure == "tcp_sni" else public_port
                ),
                "network": inbound.network,
                "exposure": exposure,
                "security": inbound.security,
                "sni_names": sni_names,
                "port_bindings": inbound.port_bindings,
                "sync_share_addr": sync_share_addr,
                "sync_public_endpoint": sync_public_endpoint,
                **meta,
            }
        )

    reality_candidates = [
        item
        for item in manifest["protocols"]
        if item.get("security") == "reality" and item.get("exposure") == "tcp_sni"
    ]
    if len(reality_candidates) == 1:
        manifest["network"]["non_tls_backend_inbound_id"] = reality_candidates[0]["inbound_id"]

    manifest, _decoy_warnings = configure_protocol_decoys_interactively(
        manifest,
        default_enabled=True,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    if manifest.get("decoys", {}).get("enabled"):
        manifest, _mode_warnings = configure_decoy_routing_mode(
            manifest, audit, "extended", refresh_from_audit=False
        )
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
                True,
                input_fn=input_fn,
                output_fn=output_fn,
            ):
                for route in blocked_xhttp:
                    inbound_id = int(route.get("inbound_id") or 0)
                    default_path = f"/xhttp-{inbound_id}"
                    while True:
                        new_path = _ask(
                            f"Новый XHTTP path для inbound #{inbound_id}",
                            default_path,
                            input_fn=input_fn,
                            output_fn=output_fn,
                        ).strip()
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
                manifest, _mode_warnings = configure_decoy_routing_mode(
                    manifest, audit, "extended", refresh_from_audit=False
                )

    output_fn(
        "\nSubscription-sidecar обеспечивает совместимость AWG (WireGuard), AnyTLS и Mieru "
        "для всех клиентов (Throne, NekoBox, Happ, v2rayN и др.). "
        "Рекомендуется держать включённым."
    )
    manifest["components"]["sidecar"] = _yes_no(
        "Установить subscription-sidecar",
        True,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    if manifest["components"]["sidecar"]:
        sidecar = manifest["sidecar"]
        sidecar["user_confirmed"] = True
        sidecar["allowed_hosts"] = [subscription["domain"]]
        sidecar["allowed_path_prefixes"] = list(
            dict.fromkeys(
                [
                    subscription["path_prefix"],
                    audit.settings.get("subClashPath", "/clash/") or "/clash/",
                    audit.settings.get("subAwgPath", "/awg/") or "/awg/",
                    audit.settings.get("subJsonPath", "/json/") or "/json/",
                ]
            )
        )
        sidecar["upstream_port"] = subscription["internal_port"]

    if not certs["renewal"].get("enabled"):
        certs["renewal"]["enabled"] = _yes_no(
            "Установить hook перезагрузки сертификатов для всех управляемых сервисов",
            True,
            input_fn=input_fn,
            output_fn=output_fn,
        )
        manifest["components"]["tls_hook"] = certs["renewal"]["enabled"]
    else:
        output_fn("Hook перезагрузки сертификатов включен автоматически для обнаруженного сертификата.")
        manifest["components"]["tls_hook"] = True
    if not certs["renewal"].get("primary_domain"):
        certs["renewal"]["primary_domain"] = panel["domain"]
    return manifest


def reconfigure_domains_interactively(
    current: dict,
    audit: Audit,
    fs: TargetFS,
    runner: Runner,
    *,
    input_fn: InputFunction = input,
    output_fn: OutputFunction = print,
) -> tuple[dict, list[str]]:
    """Change managed domains, synchronize LucX names, and locate a covering certificate."""
    manifest = copy.deepcopy(current)
    warnings: list[str] = []
    output_fn("\nСмена доменов управляемой внешней конфигурации.")
    output_fn(
        "После backup будут изменены только webDomain/subDomain в LucX. "
        "Клиенты, inbounds, их порты и Naive Caddyfile остаются неизменными.\n"
    )

    panel = manifest["lucx"]["panel"]
    subscription = manifest["lucx"]["subscription"]
    panel["domain"] = _ask(
        "Новый домен панели",
        panel["domain"],
        input_fn=input_fn,
        output_fn=output_fn,
        validator=valid_domain,
    ).lower()
    panel["public_port"] = int(
        _ask(
            "Новый внешний HTTPS-порт панели через Cloudflare",
            str(panel.get("public_port", manifest["network"].get("public_tcp_port", 443))),
            input_fn=input_fn,
            output_fn=output_fn,
            validator=_cloudflare_https_port,
        )
    )
    panel["path_prefix"] = (
        "/"
        if _yes_no(
            "Открывать панель по корню нового домена без дополнительного пути",
            True,
            input_fn=input_fn,
            output_fn=output_fn,
        )
        else _ask(
            "Новый путь панели",
            panel.get("path_prefix", "/"),
            input_fn=input_fn,
            output_fn=output_fn,
            validator=_path,
        )
    )
    subscription["domain"] = _ask(
        "Новый домен подписок",
        subscription["domain"],
        input_fn=input_fn,
        output_fn=output_fn,
        validator=valid_domain,
    ).lower()
    subscription["public_port"] = int(
        _ask(
            "Новый внешний HTTPS-порт подписок через Cloudflare",
            str(subscription.get("public_port", manifest["network"].get("public_tcp_port", 443))),
            input_fn=input_fn,
            output_fn=output_fn,
            validator=_cloudflare_https_port,
        )
    )
    sync_domains = _yes_no(
        "Синхронизировать новые домены панели и подписок с settings LucX после backup",
        True,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    if not sync_domains:
        raise ConfigurationError("смена доменов отменена: settings LucX остались бы несогласованными")
    manifest["lucx"]["settings_management"] = {
        "sync_domains": True,
        "sync_panel_path": True,
        "sync_naive_share_addr": False,
        "sync_public_endpoints": True,
        "user_confirmed": True,
    }

    by_id = {int(item["inbound_id"]): item for item in manifest.get("protocols", [])}
    discovered = {item.id: item for item in audit.inbounds if item.enable}
    domain_changes: dict[str, str] = {}
    for inbound_id, protocol in by_id.items():
        actual = discovered.get(inbound_id)
        if actual is None:
            raise ConfigurationError(
                f"inbound #{inbound_id} больше не включен или отсутствует; создайте новый полный --plan"
            )
        old_topology = (
            protocol.get("protocol"),
            protocol.get("internal_port"),
            protocol.get("public_port"),
            protocol.get("network"),
            protocol.get("security"),
        )
        protocol.update(
            {
                "protocol": actual.protocol,
                "remark": actual.remark,
                "internal_host": _safe_backend_host(actual.listen),
                "internal_port": actual.port,
                "public_port": actual.suggested_public_port or actual.port,
                "network": actual.network,
                "security": actual.security,
                "port_bindings": actual.port_bindings,
                **_inbound_routing_metadata(actual),
            }
        )
        protocol["exposure"] = infer_exposure(
            actual.protocol,
            actual.network,
            int(protocol["public_port"]),
            actual.security,
        )
        protocol["udp_public_port"] = (
            actual.port
            if actual.network == "both" and protocol["exposure"] == "tcp_sni"
            else int(protocol["public_port"])
        )
        old_domain = protocol["domain"]
        protocol["domain"] = _ask(
            f"Новый домен {protocol.get('remark') or protocol['protocol']} (inbound #{inbound_id})",
            actual.share_addr or protocol["domain"],
            input_fn=input_fn,
            output_fn=output_fn,
            validator=valid_domain,
        ).lower()
        domain_changes[old_domain] = protocol["domain"]
        protocol["sni_names"] = (
            _subscription_sni_names(actual, protocol["domain"])
            if protocol["exposure"] == "tcp_sni"
            else []
        )
        protocol["public_endpoints"] = _normalize_configured_public_endpoints(
            protocol.get("public_endpoints"),
            protocol["domain"],
            int(protocol["public_port"]),
            exposure=protocol["exposure"],
            sni_names=protocol["sni_names"],
        )
        new_topology = (
            protocol.get("protocol"),
            protocol.get("internal_port"),
            protocol.get("public_port"),
            protocol.get("network"),
            protocol.get("security"),
        )
        if new_topology != old_topology:
            warnings.append(
                f"Inbound #{inbound_id}: топология изменилась; внешний маршрут пересобран из текущих данных LucX."
            )
        if protocol.get("protocol") == "naive" and protocol.get("exposure") == "tcp_sni":
            protocol["sync_share_addr"] = True
        protocol["sync_public_endpoint"] = protocol.get("exposure") != "none"

    missing = sorted(set(discovered) - set(by_id))
    if missing:
        raise ConfigurationError(
            f"обнаружены новые включенные inbounds {missing}; создайте новый полный --plan, чтобы явно подтвердить их публикацию"
        )

    reality_candidates = [
        item
        for item in manifest.get("protocols", [])
        if item.get("security") == "reality" and item.get("exposure") == "tcp_sni"
    ]
    manifest["network"]["non_tls_backend_inbound_id"] = (
        reality_candidates[0]["inbound_id"] if len(reality_candidates) == 1 else None
    )

    if manifest["decoys"].get("enabled"):
        old_sites = manifest["decoys"].get("sites", [])
        sites: list[dict[str, str]] = []
        seen_sites: set[str] = set()
        for site in old_sites:
            domain = domain_changes.get(site["domain"], site["domain"])
            if domain not in seen_sites:
                sites.append({"domain": domain, "root": site["root"]})
                seen_sites.add(domain)
        manifest["decoys"]["sites"] = sites
        manifest["decoys"]["capabilities"] = classify_decoy_capabilities(manifest)

    output_fn(
        "Sidecar остается отдельной опцией совместимости AWG с Throne и не включается автоматически."
    )
    use_sidecar = _yes_no(
        "Использовать subscription-sidecar после смены доменов",
        bool(manifest["components"].get("sidecar")),
        input_fn=input_fn,
        output_fn=output_fn,
    )
    manifest["components"]["sidecar"] = use_sidecar
    manifest["sidecar"]["user_confirmed"] = use_sidecar
    if manifest["components"].get("sidecar"):
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

    required_domains = {panel["domain"], subscription["domain"]}
    if manifest["decoys"].get("enabled"):
        required_domains.update(site["domain"] for site in manifest["decoys"].get("sites", []))
    current_cert = manifest["certificates"].get("cert_path", "")
    candidate = select_certificate(
        fs,
        required_domains,
        runner,
        extra_cert_paths=[
            current_cert,
            audit.settings.get("webCertFile", ""),
            audit.settings.get("subCertFile", ""),
        ],
    )
    if candidate is None:
        raise ConfigurationError(
            "не найден сертификат с совпадающим приватным ключом, покрывающий все новые домены; "
            "сначала выпустите wildcard/SAN-сертификат и повторите --reconfigure"
        )
    manifest["certificates"]["cert_path"] = candidate.cert_path
    manifest["certificates"]["key_path"] = candidate.key_path
    output_fn(
        f"Автоматически выбран {candidate.source} сертификат: {candidate.cert_path} "
        f"(истекает {candidate.expires_at})."
    )
    if not candidate.wildcard:
        warnings.append("Wildcard не найден; выбран действующий SAN-сертификат, покрывающий все новые домены.")

    if any(protocol.get("sync_public_endpoint") for protocol in manifest.get("protocols", [])):
        warnings.append(
            "После backup LucX синхронизирует публичные endpoint-метаданные всех выбранных inbound; клиенты, transports и внутренние порты не изменяются."
        )
    if candidate.source == "acme.sh":
        manifest["certificates"]["renewal"]["provider"] = "acme.sh"
        manifest["certificates"]["renewal"]["primary_domain"] = candidate.renewal_name or panel["domain"]
        manifest["certificates"]["renewal"]["enabled"] = True
        manifest.setdefault("components", {})["tls_hook"] = True
    elif candidate.source == "Certbot":
        manifest["certificates"]["renewal"]["provider"] = "certbot"
        manifest["certificates"]["renewal"]["primary_domain"] = candidate.renewal_name or panel["domain"]
        manifest["certificates"]["renewal"]["enabled"] = True
        manifest.setdefault("components", {})["tls_hook"] = True
    else:
        manifest["certificates"]["renewal"]["primary_domain"] = panel["domain"]
    return manifest, list(dict.fromkeys(warnings))


def migrate_domain_zone(
    manifest: dict,
    old_zone: str,
    new_zone: str,
) -> dict:
    """Replace only the DNS suffix while preserving each host label."""

    old_zone = old_zone.strip().lower().rstrip(".")
    new_zone = new_zone.strip().lower().rstrip(".")
    if not valid_domain(old_zone) or not valid_domain(new_zone):
        raise ConfigurationError("некорректная старая или новая DNS-зона")
    if old_zone == new_zone:
        raise ConfigurationError("DNS-зоны совпадают")

    result = copy.deepcopy(manifest)

    def replace(value: str) -> str:
        value = str(value or "").strip().lower().rstrip(".")
        if value == old_zone:
            return new_zone
        suffix = "." + old_zone
        return value[:-len(suffix)] + "." + new_zone if value.endswith(suffix) else value

    result["lucx"]["panel"]["domain"] = replace(result["lucx"]["panel"]["domain"])
    result["lucx"]["subscription"]["domain"] = replace(result["lucx"]["subscription"]["domain"])
    for protocol in result.get("protocols") or []:
        protocol["domain"] = replace(protocol.get("domain", ""))
        if str(protocol.get("security") or "").lower() != "reality":
            protocol["sni_names"] = [replace(value) for value in protocol.get("sni_names") or []]
            protocol["sni_names"] = list(dict.fromkeys(protocol["sni_names"]))
        protocol["transport_hosts"] = [
            replace(value) for value in protocol.get("transport_hosts") or []
        ]
        protocol["transport_hosts"] = list(dict.fromkeys(protocol["transport_hosts"]))
    domains_by_inbound = {
        int(protocol.get("inbound_id") or 0): str(protocol.get("domain") or "")
        for protocol in result.get("protocols") or []
        if int(protocol.get("inbound_id") or 0) > 0
    }
    for route in result.get("decoys", {}).get("extended_routes") or []:
        inbound_id = int(route.get("inbound_id") or 0)
        if inbound_id in domains_by_inbound:
            route["domain"] = domains_by_inbound[inbound_id]
            if str(route.get("security") or "").lower() != "reality":
                route["sni_names"] = [replace(value) for value in route.get("sni_names") or []]
                route["sni_names"] = list(dict.fromkeys(route["sni_names"]))
    # Rebuild sites from the migrated protocol map, rather than carrying stale
    # entries from a previous failed run or an older manifest.
    migrated_sites: list[dict[str, str]] = []
    seen_sites: set[str] = set()

    def add_migrated_site(domain_value: str) -> None:
        domain = str(domain_value or "").strip().lower().rstrip(".")
        if not valid_domain(domain) or domain in seen_sites:
            return
        seen_sites.add(domain)
        safe_name = re.sub(r"[^a-z0-9.-]", "-", domain)
        migrated_sites.append(
            {"domain": domain, "root": f"/var/www/lucx-decoys/{safe_name}"}
        )

    for domain in domains_by_inbound.values():
        add_migrated_site(domain)
    # Always expose a standalone decoy on the new DNS zone apex. The apex is
    # derived from the migrated panel domain so it stays consistent with
    # protocol_decoy_sites() and classify_decoy_capabilities().
    zone_apex = new_zone
    result.setdefault("decoys", {})["zone_apex"] = zone_apex
    add_migrated_site(zone_apex)
    result.setdefault("decoys", {})["sites"] = migrated_sites
    result["decoys"]["capabilities"] = classify_decoy_capabilities(result)
    result["sidecar"]["allowed_hosts"] = [result["lucx"]["subscription"]["domain"]]
    result["lucx"].setdefault("settings_management", {}).update(
        {
            "sync_domains": True,
            "sync_panel_path": True,
            "sync_public_endpoints": True,
            "user_confirmed": True,
        }
    )
    # A previously configured subscription base URL still points at the old
    # zone; without rewriting it the public subURI family would be recreated
    # with the stale domain and links would break after the migration.
    subscription_domain = str(result["lucx"]["subscription"]["domain"] or "").strip().lower().rstrip(".")
    old_sub_url = str(result["lucx"]["subscription"].get("public_base_url") or "")
    if old_sub_url:
        result["lucx"]["subscription"]["public_base_url"] = replace(
            urllib.parse.urlsplit(old_sub_url).netloc
        ) + "/"
    elif subscription_domain:
        result["lucx"]["subscription"]["public_base_url"] = f"https://{subscription_domain}/"
    for protocol in result.get("protocols") or []:
        if protocol.get("exposure") != "none":
            protocol["sync_public_endpoint"] = True
    return result


def refresh_manifest_from_audit(
    current: dict,
    audit: Audit,
) -> tuple[dict, list[str]]:
    """Rebuild dynamic listener and SNI data from the current LucX database.

    This is the non-interactive core used by post-update repair.  It never
    guesses about a changed set of enabled inbounds: adding or removing an
    inbound still requires a new interactive plan.  For the same inbound set,
    ports, transports, public Host rows, TLS/Reality SNI values and subscription
    paths are refreshed from LucX instead of being copied from an old server.
    """

    manifest = copy.deepcopy(current)
    warnings: list[str] = []
    from .routing_profiles import endpoint_domains
    original_protocol_domains: set[str] = set()
    for p in manifest.get("protocols", []):
        original_protocol_domains.update(endpoint_domains(p))
    if not audit.db_schema_supported:
        raise ConfigurationError(
            "схема LucX изменилась и не поддерживается безопасным read-only адаптером; "
            "автоматическое восстановление остановлено. Варианты: обновить configurator "
            "под новую схему, сохранить redacted --audit для адаптации или не применять "
            "изменения до выбора совместимой версии LucX"
        )

    discovered = {item.id: item for item in audit.inbounds if item.enable}
    planned = {
        int(item["inbound_id"]): item for item in manifest.get("protocols", [])
    }
    missing = sorted(set(planned) - set(discovered))
    added = sorted(set(discovered) - set(planned))
    if missing or added:
        details: list[str] = []
        if missing:
            details.append(f"отключены/удалены: {missing}")
        if added:
            details.append(f"новые: {added}")
        raise ConfigurationError(
            "набор включенных inbounds изменился ("
            + "; ".join(details)
            + "); откройте TUI и создайте новый полный план"
        )

    panel = manifest["lucx"]["panel"]
    subscription = manifest["lucx"]["subscription"]

    def current_port(key: str, fallback: int) -> int:
        try:
            value = int(audit.settings.get(key, "") or fallback)
        except (TypeError, ValueError):
            return fallback
        return value if 1 <= value <= 65535 else fallback

    old_panel_listener = (panel.get("internal_host"), panel.get("internal_port"))
    old_subscription_listener = (
        subscription.get("internal_host"),
        subscription.get("internal_port"),
    )
    panel["internal_host"] = _safe_backend_host(
        audit.settings.get("webListen", "") or panel.get("internal_host", "")
    )
    panel["internal_port"] = current_port(
        "webPort", int(panel.get("internal_port") or 2083)
    )
    subscription["internal_host"] = _safe_backend_host(
        audit.settings.get("subListen", "")
        or subscription.get("internal_host", "")
    )
    subscription["internal_port"] = current_port(
        "subPort", int(subscription.get("internal_port") or 2096)
    )
    subscription["path_prefix"] = (
        audit.settings.get("subPath", "")
        or subscription.get("path_prefix", "/sub/")
        or "/sub/"
    )
    if old_panel_listener != (panel["internal_host"], panel["internal_port"]):
        warnings.append("Внутренний listener панели изменился и перечитан из LucX.")
    if old_subscription_listener != (
        subscription["internal_host"],
        subscription["internal_port"],
    ):
        warnings.append("Внутренний listener подписок изменился и перечитан из LucX.")

    domain_changes: dict[str, str] = {}
    sync_naive = False
    for inbound_id, protocol in planned.items():
        actual = discovered[inbound_id]
        old_domain = str(protocol.get("domain") or "").lower()
        domain = (actual.share_addr or old_domain).lower()
        if not valid_domain(domain):
            raise ConfigurationError(
                f"inbound #{inbound_id} не содержит корректного публичного домена; "
                "создайте новый интерактивный план"
            )
        exposure = infer_exposure(
            actual.protocol,
            actual.network,
            actual.suggested_public_port or actual.port,
            actual.security,
        )
        public_port = actual.suggested_public_port or actual.port
        # Direct exposures own the raw listener: any stale public port from an
        # old Host row would fail validation and block the whole repair. The
        # listener is authoritative for direct protocols.
        if exposure in {"tcp_direct", "udp_direct", "tcp_udp_direct"}:
            public_port = actual.port
        old_topology = (
            protocol.get("protocol"),
            protocol.get("internal_port"),
            protocol.get("public_port"),
            protocol.get("network"),
            protocol.get("security"),
            tuple(protocol.get("sni_names") or []),
        )
        meta = _inbound_routing_metadata(actual)
        protocol.update(
            {
                "protocol": actual.protocol,
                "remark": actual.remark,
                "domain": domain,
                "internal_host": _safe_backend_host(actual.listen),
                "internal_port": actual.port,
                "public_port": public_port,
                "udp_public_port": (
                    actual.port
                    if actual.network == "both" and exposure == "tcp_sni"
                    else public_port
                ),
                "network": actual.network,
                "exposure": exposure,
                "security": actual.security,
                "sni_names": (
                    _subscription_sni_names(actual, domain)
                    if exposure == "tcp_sni"
                    else []
                ),
                "port_bindings": actual.port_bindings,
                **meta,
            }
        )
        protocol["public_endpoints"] = _normalize_configured_public_endpoints(
            protocol.get("public_endpoints"),
            domain,
            public_port,
            exposure=exposure,
            sni_names=protocol["sni_names"],
        )
        protocol["sync_share_addr"] = bool(
            actual.protocol == "naive" and exposure == "tcp_sni"
        )
        protocol["sync_public_endpoint"] = bool(
            protocol.get("sync_public_endpoint", False)
            or protocol["sync_share_addr"]
        )
        sync_naive = sync_naive or protocol["sync_share_addr"]
        domain_changes[old_domain] = domain
        new_topology = (
            protocol.get("protocol"),
            protocol.get("internal_port"),
            protocol.get("public_port"),
            protocol.get("network"),
            protocol.get("security"),
            tuple(protocol.get("sni_names") or []),
        )
        if old_topology != new_topology:
            warnings.append(
                f"Inbound #{inbound_id}: маршрут обновлен из текущих Host/TLS/Reality данных LucX."
            )

    settings_management = manifest["lucx"].setdefault("settings_management", {})
    settings_management["sync_naive_share_addr"] = sync_naive
    settings_management["sync_public_endpoints"] = any(
        protocol.get("sync_public_endpoint") for protocol in manifest.get("protocols", [])
    )
    if sync_naive or settings_management["sync_public_endpoints"]:
        settings_management["user_confirmed"] = True

    # Keep the subscription base URL consistent with the managed subscription
    # domain; otherwise a zone migration would keep publishing the stale
    # subURI family and public links would keep the old zone.
    subscription_domain = str(subscription.get("domain") or "").strip().lower().rstrip(".")
    if subscription_domain and valid_domain(subscription_domain):
        current_base = str(subscription.get("public_base_url") or "")
        expected_base = f"https://{subscription_domain}/"
        if current_base and urllib.parse.urlsplit(current_base).netloc.lower() != subscription_domain:
            warnings.append(
                f"Публичный URL подписки обновлен с {current_base} на {expected_base}."
            )
            subscription["public_base_url"] = expected_base
            settings_management["sync_subscription_urls"] = True

    # The file may have been regenerated by LucX since the previous run. The
    # refreshed audit is authoritative for the immutable Naive baseline.
    if audit.naive_caddyfile:
        manifest.setdefault("integrity", {})["naive_caddyfile"] = copy.deepcopy(
            audit.naive_caddyfile
        )

    # The deploy hook is installed whenever a managed certificate is in use,
    # so the renewal flags must reflect the real certificate source even when
    # the certificate was not issued by this tool (for example a pre-existing
    # Certbot pair selected during a zone migration).
    certs = manifest.setdefault("certificates", {})
    cert_path = str(certs.get("cert_path") or "")
    renewal = certs.setdefault("renewal", {})
    if cert_path.startswith("/etc/letsencrypt/live/"):
        if not renewal.get("enabled") or str(renewal.get("provider") or "") != "certbot":
            warnings.append("Автопродление сертификата (certbot) подтверждено по его пути.")
        renewal["enabled"] = True
        renewal["provider"] = "certbot"
        if not renewal.get("primary_domain"):
            renewal["primary_domain"] = PurePosixPath(cert_path).parent.name.removesuffix("_ecc")
        manifest.setdefault("components", {})["tls_hook"] = True
    elif "/.acme.sh/" in cert_path or _has_acme_record(cert_path):
        if not renewal.get("enabled") or str(renewal.get("provider") or "") != "acme.sh":
            warnings.append("Автопродление сертификата (acme.sh) подтверждено по его пути.")
        renewal["enabled"] = True
        renewal["provider"] = "acme.sh"
        if not renewal.get("primary_domain"):
            domain_name = PurePosixPath(cert_path).parent.name.removesuffix("_ecc")
            renewal["primary_domain"] = domain_name
        manifest.setdefault("components", {})["tls_hook"] = True

    reality = [
        item
        for item in manifest.get("protocols", [])
        if item.get("security") == "reality" and item.get("exposure") == "tcp_sni"
    ]
    manifest["network"]["non_tls_backend_inbound_id"] = (
        reality[0]["inbound_id"] if len(reality) == 1 else None
    )

    if manifest.get("decoys", {}).get("enabled"):
        current_endpoint_domains = set()
        for protocol in manifest.get("protocols", []):
            current_endpoint_domains.update(endpoint_domains(protocol))

        existing_sites_by_domain = {
            str(site.get("domain") or "").lower().rstrip("."): str(site.get("root") or "")
            for site in manifest["decoys"].get("sites", [])
        }

        sites: list[dict[str, str]] = []
        seen: set[str] = set()

        def add_refreshed_site(domain: str, default_root: str | None = None) -> None:
            if not valid_domain(domain) or domain in seen:
                return
            seen.add(domain)
            safe_name = re.sub(r"[^a-z0-9.-]", "-", domain)
            root = existing_sites_by_domain.get(domain) or default_root or f"/var/www/lucx-decoys/{safe_name}"
            sites.append({"domain": domain, "root": root})

        # Preserve standalone sites (sites that were not part of old protocol endpoints)
        for old_site in manifest["decoys"].get("sites", []):
            d = str(old_site.get("domain") or "").lower().rstrip(".")
            if d not in original_protocol_domains:
                add_refreshed_site(d, old_site.get("root"))

        # Add current endpoint domains
        for protocol in manifest.get("protocols", []):
            for domain in endpoint_domains(protocol):
                add_refreshed_site(domain)

        manifest["decoys"]["sites"] = sites
        if str(manifest["decoys"].get("routing_mode") or "strict") == "extended":
            previous_routes = {
                int(item.get("inbound_id") or 0): item
                for item in manifest["decoys"].get("extended_routes") or []
            }
            refreshed_routes = classify_extended_decoy_routes(manifest, audit)
            manifest["decoys"]["extended_routes"] = refreshed_routes
            manifest["components"]["naive_frontend"] = any(
                item.get("strategy") == "naive_managed"
                and item.get("status") == "ready"
                for item in refreshed_routes
            )
            # Recalculate capabilities after routes are refreshed so blocked
            # strategies are not published as managed probe targets.
            manifest["decoys"]["capabilities"] = classify_decoy_capabilities(manifest, audit)
            for item in refreshed_routes:
                inbound_id = int(item.get("inbound_id") or 0)
                previous = previous_routes.get(inbound_id) or {}
                if (
                    previous.get("strategy") != item.get("strategy")
                    or previous.get("status") != item.get("status")
                    or previous.get("source_caddyfile_sha256")
                    != item.get("source_caddyfile_sha256")
                ):
                    warnings.append(
                        f"Naive/extended маршрут inbound #{inbound_id} повторно "
                        "классифицирован после обновления LucX."
                    )

    sidecar = manifest.get("sidecar") or {}
    if manifest.get("components", {}).get("sidecar"):
        sidecar["upstream_port"] = subscription["internal_port"]
        sidecar["allowed_hosts"] = [subscription["domain"]]
        sidecar["allowed_path_prefixes"] = list(
            dict.fromkeys(
                [
                    subscription["path_prefix"],
                    audit.settings.get("subClashPath", "/clash/") or "/clash/",
                    audit.settings.get("subAwgPath", "/awg/") or "/awg/",
                    audit.settings.get("subJsonPath", "/json/") or "/json/",
                ]
            )
        )
        sidecar["awg_path"] = (
            audit.settings.get("subAwgPath", "/awg/") or "/awg/"
        )
    manifest["sidecar"] = sidecar
    return manifest, list(dict.fromkeys(warnings))
