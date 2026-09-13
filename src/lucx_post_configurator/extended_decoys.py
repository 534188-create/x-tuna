import hashlib
import ipaddress
import json
import re
from typing import Any

from .models import Audit, valid_domain
from .routing_profiles import (
    endpoint_domains,
    public_ingresses,
    routing_fingerprint,
    validated_public_endpoints,
)


HTTP_TRANSPORTS = {"ws", "httpupgrade", "grpc"}
AMBIGUOUS_HTTP_TRANSPORTS = {"http"}
XHTTP_MODES = {"auto", "packet-up", "stream-up", "stream-one"}
BINARY_TLS_PROTOCOLS = {"vmess", "vless", "trojan", "shadowsocks", "anytls"}
SEPARATE_PORT_PROTOCOLS = {"mieru", "qwdtt"}
TRUSTTUNNEL_PROTOCOLS = {"trusttunnel", "trust-tunnel"}
CLIENTHELLO_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{12,64}$", re.IGNORECASE)


def exact_client_random_prefix(value: Any) -> str:
    """Return an exact byte prefix, rejecting masks HAProxy cannot preserve."""

    text = str(value or "").strip().lower()
    if not text:
        return ""
    prefix, separator, mask = text.partition("/")
    if not re.fullmatch(r"[0-9a-f]{2,64}", prefix) or len(prefix) % 2:
        return ""
    if separator and (len(mask) != len(prefix) or set(mask) != {"f"}):
        return ""
    return prefix.upper()


def grpc_method_paths(service_name: str) -> list[str]:
    name = str(service_name or "").strip().strip("/")
    if not name or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        return []
    return [f"/{name}/Tun", f"/{name}/TunMulti"]


def _text(value: Any) -> str:
    return str(value or "").strip().lower()


def _integer(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _bindings(protocol: dict[str, Any], transport: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in protocol.get("port_bindings") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("protocol") or "").upper()
        if transport == "udp" and name not in {"UDP", "TCP_UDP"}:
            continue
        if transport == "tcp" and name not in {"TCP", "TCP_UDP"}:
            continue
        safe: dict[str, Any] = {"protocol": name}
        port = _integer(item.get("port"))
        if 1 <= port <= 65535:
            safe["port"] = port
        port_range = str(item.get("port_range") or "")
        if re.fullmatch(r"\d{1,5}-\d{1,5}", port_range):
            safe["port_range"] = port_range
        if len(safe) > 1 and safe not in result:
            result.append(safe)
    return result


def _owns_tcp_port(protocol: dict[str, Any], port: int) -> bool:
    if _text(protocol.get("network")) in {"tcp", "both"} and _integer(
        protocol.get("public_port")
    ) == port:
        return True
    return any(_integer(item.get("port")) == port for item in _bindings(protocol, "tcp"))


def _naive_metadata(
    audit: Audit | None,
    inbound_id: int,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    files = []
    if audit is not None:
        files = audit.naive_caddyfile.get("files") or []
    elif manifest is not None:
        files = (manifest.get("integrity") or {}).get("naive_caddyfile", {}).get("files") or []
    if not files and manifest is not None:
        for r in (manifest.get("decoys") or {}).get("extended_routes") or []:
            if int(r.get("inbound_id", 0)) == inbound_id and r.get("source_caddyfile"):
                return {
                    "path": r["source_caddyfile"],
                    "sha256": r.get("source_caddyfile_sha256", ""),
                    "capabilities": {
                        "native_decoy": r.get("naive_mode") == "native",
                        "forward_proxy": True,
                    },
                }
    if not files:
        return None
    suffix = f"/naive-{inbound_id}.caddyfile"
    for item in files:
        if isinstance(item, dict) and str(item.get("path") or "").endswith(suffix):
            res = dict(item)
            if "capabilities" not in res and manifest is not None:
                for r in (manifest.get("decoys") or {}).get("extended_routes") or []:
                    if int(r.get("inbound_id", 0)) == inbound_id:
                        res["capabilities"] = {
                            "native_decoy": r.get("naive_mode") == "native",
                            "forward_proxy": True,
                        }
                        break
            return res
    if len(files) == 1 and isinstance(files[0], dict):
        res = dict(files[0])
        if "capabilities" not in res and manifest is not None:
            for r in (manifest.get("decoys") or {}).get("extended_routes") or []:
                if int(r.get("inbound_id", 0)) == inbound_id:
                    res["capabilities"] = {
                        "native_decoy": r.get("naive_mode") == "native",
                        "forward_proxy": True,
                    }
                    break
        return res
    return None


def _base_route(protocol: dict[str, Any], shared_tcp_port: int) -> dict[str, Any]:
    domain = _text(protocol.get("domain"))
    udp_bindings = _bindings(protocol, "udp")
    network = _text(protocol.get("network"))
    return {
        "inbound_id": _integer(protocol.get("inbound_id")),
        "protocol": _text(protocol.get("protocol")) or "unknown",
        "domain": domain,
        "endpoint_domains": endpoint_domains(protocol),
        "strategy": "blocked_unknown",
        "status": "blocked",
        "managed": False,
        "reason": "Топология не доказана; внешний маршрут не создаётся.",
        "evidence": [],
        "network": network,
        "security": _text(protocol.get("security")),
        "transport": _text(protocol.get("transport")) or "tcp",
        "internal_host": str(protocol.get("internal_host") or "127.0.0.1"),
        "internal_port": _integer(protocol.get("internal_port")),
        "public_tcp_port": shared_tcp_port,
        "sni_names": list(dict.fromkeys(_text(value) for value in protocol.get("sni_names") or [] if _text(value))),
        "transport_path": str(protocol.get("transport_path") or ""),
        "transport_mode": _text(protocol.get("transport_mode")),
        "transport_hosts": list(
            dict.fromkeys(
                _text(value) for value in protocol.get("transport_hosts") or [] if _text(value)
            )
        ),
        "transport_details": protocol.get("transport_details", {}),
        "alpn": list(dict.fromkeys(str(value) for value in protocol.get("alpn") or [] if value)),
        "tls_termination": False,
        "backend_tls": False,
        "vpn_action": "unchanged",
        "browser_action": "none",
        "existing_udp_bindings": udp_bindings,
        "managed_udp_bindings": [],
        "preserves_udp": network in {"udp", "both"} or bool(udp_bindings),
        "preflight_required": False,
        "backend_tls_policy": backend_tls_policy(protocol),
        "routing_fingerprint": routing_fingerprint(protocol, shared_tcp_port),
    }


def backend_tls_policy(protocol: dict[str, Any]) -> dict[str, str]:
    """Проверка CA обязательна; неизвестные обходы верификации запрещены."""
    policy = protocol.get("backend_tls_policy", {})
    if not isinstance(policy, dict) or set(policy) - {"ca_file"}:
        raise ValueError("backend_tls_policy принимает только ca_file")
    ca_file = policy.get("ca_file", "/etc/ssl/certs/ca-certificates.crt")
    if (not isinstance(ca_file, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", ca_file)
            or ca_file.endswith("/") or "//" in ca_file or any(part in {".", ".."} for part in ca_file.split("/"))):
        raise ValueError("backend_tls_policy.ca_file должен быть безопасным абсолютным путём")
    return {"ca_file": ca_file}


def _ready(
    route: dict[str, Any],
    strategy: str,
    reason: str,
    *,
    tls_termination: bool = False,
    backend_tls: bool = False,
    vpn_action: str = "unchanged",
    preflight_required: bool = False,
) -> dict[str, Any]:
    route.update(
        {
            "strategy": strategy,
            "status": "ready",
            "managed": True,
            "reason": reason,
            "tls_termination": tls_termination,
            "backend_tls": backend_tls,
            "vpn_action": vpn_action,
            "browser_action": "decoy",
            "preflight_required": preflight_required,
        }
    )
    return route


def _blocked(route: dict[str, Any], reason: str) -> dict[str, Any]:
    route["reason"] = reason
    route["evidence"].append("VPN route retained; no browser ingress is published")
    return route


def classify_naive_connect_candidate(
    manifest: dict[str, Any], audit: Audit, inbound_id: int
) -> dict[str, Any]:
    """Явный кандидат staging; никогда не разрешает production или статус ready.

    Потребитель: будущий staging assembler Engine. После реальных probes нужен
    отдельный receipt с фазой, бинарником и fingerprint; версия HAProxy не proof.
    Общий classifier может вернуть этот кандидат; существующий native fallback
    сохраняет свой путь. Кандидат не является разрешением на применение.
    """
    if type(inbound_id) is not int or inbound_id <= 0:
        raise ValueError("Некорректный Naive inbound кандидата")
    protocols = [item for item in manifest.get("protocols") or []
                 if isinstance(item, dict) and item.get("inbound_id") == inbound_id]
    if len(protocols) != 1:
        raise ValueError("Naive inbound кандидата отсутствует или повторяется")
    protocol = protocols[0]
    details = protocol.get("transport_details", {})
    allowed_details = {"support_status", "settings_keys", "settings_fingerprint", "stream_fingerprint",
        "inbound_settings_fingerprint", "extra", "masks", "unsupported_settings", "unknown_stream_fields",
        "conflicting_settings_alias", "requires_adapter_review"}
    if not isinstance(details, dict) or set(details) - allowed_details:
        raise ValueError("Неизвестная обёртка Naive CONNECT")
    if any(details.get(name) for name in ("settings_keys", "unsupported_settings", "unknown_stream_fields",
            "conflicting_settings_alias", "requires_adapter_review")):
        raise ValueError("Параметры транспорта Naive CONNECT требуют отдельной проверки")
    for name, fields in (("extra", {"present", "keys", "fingerprint"}),
                         ("masks", {"present", "tcp_types", "udp_types", "fingerprint"})):
        entry = details.get(name, {})
        if (not isinstance(entry, dict) or set(entry) - fields
                or any(entry.get(field) for field in fields - {"fingerprint"})):
            raise ValueError("Обёртка Naive CONNECT не подтверждена")
    if (protocol.get("protocol") != "naive" or protocol.get("network") != "tcp"
            or protocol.get("transport", "tcp") != "tcp"
            or protocol.get("security", "") not in {"", "tls"}
            or protocol.get("exposure") != "tcp_sni" or protocol.get("enable") is False
            or protocol.get("udp_over_tcp") or protocol.get("transport_path")
            or protocol.get("transport_mode") or protocol.get("transport_hosts")
            or any(name not in {"h2", "http/1.1"} for name in protocol.get("alpn") or [])):
        raise ValueError("Топология Naive CONNECT не подтверждена")
    host = str(protocol.get("internal_host") or "127.0.0.1")
    try:
        local = host in {"localhost", "0.0.0.0", "::", "[::]"} or ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        local = False
    if not local or type(protocol.get("internal_port")) is not int or not 1 <= protocol["internal_port"] <= 65535:
        raise ValueError("Кандидат требует подтверждённый локальный исходный listener")
    shared = (manifest.get("network") or {}).get("public_tcp_port")
    if type(shared) is not int or not 1 <= shared <= 65535:
        raise ValueError("Не подтверждён публичный TCP-порт кандидата")
    ingresses = public_ingresses(protocol, shared)
    endpoints = validated_public_endpoints(protocol, require_sni=True)
    if not endpoints or any(item["http_host"] for item in endpoints):
        raise ValueError("Кандидат требует все endpoints без HTTP Host override")
    files = [item for item in audit.naive_caddyfile.get("files") or []
             if isinstance(item, dict) and str(item.get("path") or "").endswith(f"/naive-{inbound_id}.caddyfile")]
    if len(files) != 1:
        raise ValueError("Не подтверждён точный исходный Naive Caddyfile")
    source = files[0]
    path = source.get("path")
    if (not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", path)
            or any(part in {".", ".."} for part in path.split("/"))
            or source.get("kind") != "file"
            or not re.fullmatch(r"[0-9a-f]{64}", str(source.get("sha256") or ""))
            or any(type(source.get(name)) is not int or source[name] < 0 for name in ("mode", "uid", "gid"))
            or source["mode"] > 0o7777):
        raise ValueError("Идентичность исходного Naive Caddyfile не подтверждена")
    capabilities = source.get("capabilities") or {}
    if capabilities.get("forward_proxy") is not True or capabilities.get("native_decoy") is not False:
        raise ValueError("Нет подтверждённого CONNECT либо уже существует native fallback")
    route = _base_route(protocol, shared)
    source_identity = {name: source[name] for name in ("path", "kind", "mode", "uid", "gid", "sha256")}
    names = route["sni_names"]
    if route["domain"] in names:
        backend_sni = route["domain"]
    elif len(names) == 1 and valid_domain(names[0]):
        backend_sni = names[0]
    else:
        raise ValueError("TLS SNI исходного Naive backend неоднозначен")
    route.update(strategy="naive_connect_h2", status="rendered_candidate", managed=False,
        preflight_required=True, tls_termination=True, backend_tls=True, vpn_action="candidate_only",
        browser_action="candidate_only", backend_sni=backend_sni,
        public_ingresses=[list(item) for item in ingresses], source_identity=source_identity,
        source_routing_fingerprint=protocol.get("source_routing_fingerprint"),
        site_listener={"host": (manifest.get("decoys") or {}).get("listen_host", "127.0.0.1"),
                       "port": (manifest.get("decoys") or {}).get("listen_port")},
        certificate_paths={name: (manifest.get("certificates") or {}).get(name) for name in ("cert_path", "key_path")},
        required_probes=["naive_h2_connect", "parallel_transfer", "negative_auth", "auth_recovery", "browser_h1_h2"],
        reason="Только изолированный кандидат; реальные staging и capability proofs ещё обязательны.")
    route["candidate_fingerprint"] = "sha256:" + hashlib.sha256(json.dumps(
        route, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
    return route


def classify_extended_decoy_routes(
    manifest: dict[str, Any], audit: Audit | None = None
) -> list[dict[str, Any]]:
    """Return deterministic, secret-free routes for the opt-in extended mode."""

    shared_tcp_port = _integer((manifest.get("network") or {}).get("public_tcp_port"))
    if not 1 <= shared_tcp_port <= 65535:
        shared_tcp_port = 443

    routes: list[dict[str, Any]] = []
    for protocol in manifest.get("protocols") or []:
        if not isinstance(protocol, dict):
            continue
        route = _base_route(protocol, shared_tcp_port)
        name = route["protocol"]
        domain = route["domain"]
        security = route["security"]
        transport = route["transport"]
        tls_protocol = security == "tls" or name == "anytls"
        sni_names = set(route["sni_names"])
        route["evidence"].append(
            f"inbound #{route['inbound_id']} protocol={name} network={route['network']} transport={transport} security={security or 'none'}"
        )

        if route["inbound_id"] <= 0 or not valid_domain(domain):
            routes.append(_blocked(route, "Некорректный inbound ID или endpoint-домен."))
            continue

        try:
            endpoints = validated_public_endpoints(
                protocol, require_sni=tls_protocol and route["network"] in {"tcp", "both"}
            )
        except ValueError as exc:
            routes.append(_blocked(route, f"Некорректная конфигурация public_endpoints: {exc}"))
            continue

        if endpoints:
            if any(item.get("http_host") for item in endpoints):
                routes.append(_blocked(route, "HTTP Host override в public_endpoints не поддерживается в extended routing."))
                continue
            valid_snis = sni_names | {item.get("address") for item in endpoints if item.get("address")}
            if tls_protocol and any(not item.get("sni") or item.get("sni") not in valid_snis for item in endpoints):
                routes.append(_blocked(route, "TLS endpoint SNI не подтверждён данными LucX/Hosts."))
                continue

        if route["network"] == "udp" and not bool(protocol.get("udp_over_tcp")):
            routes.append(
                _ready(
                    route,
                    "tcp_side_site",
                    f"VPN использует UDP; отдельный TCP/{shared_tcp_port} не меняет его listener.",
                )
            )
            continue

        details = protocol.get("transport_details") or {}
        if details:
            allowed_details = {
                "support_status", "settings_keys", "settings_fingerprint", "stream_fingerprint",
                "inbound_settings_fingerprint", "extra", "masks", "unsupported_settings",
                "unknown_stream_fields", "conflicting_settings_alias", "requires_adapter_review"
            }
            if not isinstance(details, dict) or set(details) - allowed_details:
                routes.append(_blocked(route, "Неизвестные параметры transport_details."))
                continue
            if any(details.get(k) for k in ("unsupported_settings", "unknown_stream_fields",
                                            "conflicting_settings_alias", "requires_adapter_review")):
                routes.append(_blocked(route, "Параметры транспорта требуют отдельной проверки."))
                continue
            for k in ("extra", "masks"):
                entry = details.get(k)
                if isinstance(entry, dict) and entry.get("present"):
                    routes.append(_blocked(route, f"Обёртка {k} не поддерживается в extended routing."))
                    break
            else:
                if transport in HTTP_TRANSPORTS | {"xhttp"}:
                    allowed_keys = {
                        "ws": {
                            "path",
                            "headers",
                            "acceptProxyProtocol",
                            "maxEarlyData",
                            "earlyDataHeaderName",
                            "useBrowserForwarding",
                        },
                        "httpupgrade": {"path", "host", "headers"},
                        "grpc": {
                            "serviceName",
                            "authority",
                            "multiMode",
                            "user_agent",
                            "permit_without_stream",
                            "initial_windows_size",
                            "idle_timeout",
                            "health_check",
                        },
                        "xhttp": {
                            "path",
                            "host",
                            "mode",
                            "xPaddingBytes",
                            "scMaxBufferedPosts",
                            "scStreamUpServerSecs",
                            "headers",
                            "xmux",
                            "noSSEHeader",
                        },
                    }
                    keys = details.get("settings_keys")
                    if keys is not None:
                        if not isinstance(keys, list) or any(k not in allowed_keys.get(transport, set()) for k in keys):
                            routes.append(_blocked(route, f"Неизвестные ключи конфигурации транспорта: {keys}"))
                            continue

        if name in SEPARATE_PORT_PROTOCOLS or protocol.get("exposure") in {"tcp_direct", "tcp_udp_direct"}:
            if _owns_tcp_port(protocol, shared_tcp_port):
                routes.append(
                    _blocked(
                        route,
                        f"{name} уже владеет TCP/{shared_tcp_port}; безопасное разделение не доказано.",
                    )
                )
            else:
                routes.append(
                    _ready(
                        route,
                        "tcp_side_site",
                        f"{name} остаётся на исходном порту; TCP/{shared_tcp_port} используется только сайтом.",
                    )
                )
            continue

        if security == "reality":
            endpoint_set = set(route.get("endpoint_domains") or [domain])
            if domain and not (endpoint_set & sni_names):
                routes.append(
                    _ready(
                        route,
                        "reality_endpoint_site",
                        "Endpoint SNI свободен, а Reality camouflage SNI остаётся passthrough.",
                        vpn_action="passthrough",
                    )
                )
            else:
                routes.append(
                    _blocked(
                        route,
                        "Endpoint-домен совпадает с Reality SNI; браузер и VPN нельзя различить безопасно.",
                    )
                )
            continue

        if name == "naive":
            metadata = _naive_metadata(audit, route["inbound_id"], manifest)
            if metadata is None:
                routes.append(
                    _blocked(route, "Исходный Naive Caddyfile не найден; frontend нельзя построить безопасно.")
                )
                continue
            capabilities = metadata.get("capabilities") or {}
            binary_path = str(
                (audit.naive_caddyfile if audit else {}).get("binary_path")
                or (manifest.get("integrity") or {}).get("naive_caddyfile", {}).get("binary_path")
                or next(
                    (
                        str(r.get("binary_path") or "")
                        for r in (manifest.get("decoys") or {}).get("extended_routes") or []
                        if r.get("binary_path")
                    ),
                    "",
                )
            )
            route["source_caddyfile"] = str(metadata.get("path") or "")
            route["source_caddyfile_sha256"] = str(metadata.get("sha256") or "")
            if capabilities.get("native_decoy") is True:
                route["naive_mode"] = "native"
                routes.append(
                    _ready(
                        route,
                        "naive_native",
                        "Штатный Naive frontend поддерживает forward proxy и сайт одновременно.",
                        vpn_action="passthrough",
                    )
                )
            elif capabilities.get("forward_proxy") is True:
                has_aliases = len(protocol.get("public_endpoints") or []) > 1
                if binary_path.startswith("/") and (not has_aliases or (manifest.get("components") or {}).get("naive_frontend") is True):
                    route["naive_mode"] = "managed"
                    route["binary_path"] = binary_path
                    routes.append(
                        _ready(
                            route,
                            "naive_managed",
                            "Требуется отдельный управляемый frontend; исходный Caddyfile остаётся неизменным.",
                            vpn_action="passthrough",
                            preflight_required=True,
                        )
                    )
                else:
                    candidate_route = None
                    try:
                        candidate_route = classify_naive_connect_candidate(manifest, audit, route["inbound_id"])
                    except ValueError:
                        pass
                    if candidate_route is not None:
                        routes.append(candidate_route)
                        continue

                    if not binary_path.startswith("/"):
                        route["naive_mode"] = "blocked"
                        routes.append(
                            _blocked(route, "Исполняемый файл штатного Naive Caddy не найден.")
                        )
                    else:
                        route["naive_mode"] = "blocked"
                        routes.append(
                            _blocked(route, "Для alias endpoints Naive требуется явное включение компонента naive_frontend.")
                        )
            else:
                route["naive_mode"] = "blocked"
                routes.append(
                    _blocked(route, "Структура Naive Caddyfile не подтверждает forward proxy.")
                )
            continue

        if name in TRUSTTUNNEL_PROTOCOLS:
            fingerprint = _text(protocol.get("clienthello_match_fingerprint"))
            if CLIENTHELLO_FINGERPRINT_RE.fullmatch(fingerprint):
                route["clienthello_match_fingerprint"] = fingerprint
                routes.append(
                    _ready(
                        route,
                        "trusttunnel_clienthello_split",
                        "VPN ClientHello имеет подтверждённый matcher; остальные TLS-запросы идут на сайт.",
                        vpn_action="passthrough",
                        preflight_required=True,
                    )
                )
            else:
                routes.append(
                    _blocked(route, "Для TrustTunnel не получен безопасный отпечаток ClientHello matcher.")
                )
            continue

        if tls_protocol and transport == "xhttp" and name in BINARY_TLS_PROTOCOLS:
            path = str(route.get("transport_path") or "").split("?", 1)[0].strip()
            mode = route.get("transport_mode") or "auto"
            route["transport_mode"] = mode
            if not path.startswith("/") or path == "/":
                routes.append(
                    _blocked(
                        route,
                        "XHTTP для общего TCP/443 требует отдельный непустой path; '/' забрал бы браузерный корень у сайта.",
                    )
                )
            elif mode not in XHTTP_MODES:
                routes.append(
                    _blocked(route, f"Неизвестный режим XHTTP {mode}; конфигурация сохраняется без изменений.")
                )
            else:
                routes.append(
                    _ready(
                        route,
                        "xhttp_tls_split",
                        "XHTTP использует отдельный path; корень домена обслуживает сайт.",
                        tls_termination=True,
                        backend_tls=True,
                        vpn_action="tls_reencrypt",
                        preflight_required=True,
                    )
                )
            continue

        if (
            tls_protocol
            and transport in AMBIGUOUS_HTTP_TRANSPORTS
            and name in BINARY_TLS_PROTOCOLS
        ):
            routes.append(
                _blocked(
                    route,
                    f"HTTP transport {transport} не имеет доказанного признака, отделяющего VPN от браузера.",
                )
            )
            continue

        if tls_protocol and transport in HTTP_TRANSPORTS and name in BINARY_TLS_PROTOCOLS:
            path = str(route.get("transport_path") or "").split("?", 1)[0].strip()
            if not path or (transport == "grpc" and not grpc_method_paths(path)):
                routes.append(
                    _blocked(
                        route,
                        f"HTTP transport {transport} не имеет подтверждённого пути запроса.",
                    )
                )
                continue
            routes.append(
                _ready(
                    route,
                    "http_tls_split",
                    "HTTP transport маршрутизируется по path/host после TLS termination.",
                    tls_termination=True,
                    backend_tls=True,
                    vpn_action="tls_reencrypt",
                    preflight_required=True,
                )
            )
            continue

        if name in {"vmess", "vless", "trojan"} and transport in {"raw", "tcp"}:
            routes.append(_blocked(route, "RAW Xray требует отдельной согласованной миграции транспорта в LucX; VPN сохраняется."))
            continue

        if tls_protocol and name in BINARY_TLS_PROTOCOLS and transport in {"", "tcp", "raw"}:
            if domain not in sni_names:
                routes.append(
                    _blocked(route, "TLS endpoint SNI не подтверждён данными LucX/Hosts.")
                )
            else:
                routes.append(
                    _ready(
                        route,
                        "binary_tls_split",
                        "AnyTLS маршрутизируется в backend; браузерные и остальные запросы направляются на сайт-заглушку."
                        if name == "anytls"
                        else "Обычный HTTP обслуживает сайт; бинарный TLS поток повторно шифруется до inbound.",
                        tls_termination=True,
                        backend_tls=True,
                        vpn_action="tls_reencrypt",
                        preflight_required=True,
                    )
                )
            continue

        routes.append(
            _blocked(
                route,
                f"Для protocol={name}, transport={transport}, security={security or 'none'} нет доказанной стратегии.",
            )
        )

    occupied = {
        shared_tcp_port,
        _integer(manifest.get("lucx", {}).get("panel", {}).get("internal_port")),
        _integer(manifest.get("lucx", {}).get("subscription", {}).get("internal_port")),
        _integer(manifest.get("decoys", {}).get("listen_port")),
        _integer(manifest.get("decoys", {}).get("listen_port")) + 1,
    }
    occupied.update(
        _integer(item.get("internal_port")) for item in manifest.get("protocols") or []
    )
    occupied.update(
        _integer(ep.get("port"))
        for item in manifest.get("protocols") or []
        for ep in item.get("public_endpoints") or []
        if isinstance(ep, dict) and _integer(ep.get("port"))
    )
    ranges: list[tuple[int, int]] = []
    for item in manifest.get("protocols") or []:
        for binding in item.get("port_bindings") or []:
            port_range = str(binding.get("port_range") or "")
            if re.fullmatch(r"\d{1,5}-\d{1,5}", port_range):
                low, high = (int(value) for value in port_range.split("-", 1))
                ranges.append((low, high))
    candidate = 26443
    for route in sorted(
        (item for item in routes if item.get("strategy") == "naive_managed"),
        key=lambda item: int(item.get("inbound_id") or 0),
    ):
        while candidate <= 65535 and (
            candidate in occupied or any(low <= candidate <= high for low, high in ranges)
        ):
            candidate += 1
        if candidate > 65535:
            route.update(
                {
                    "strategy": "blocked_unknown",
                    "status": "blocked",
                    "managed": False,
                    "naive_mode": "blocked",
                    "reason": "Нет свободного loopback TCP-порта для управляемого Naive frontend.",
                }
            )
            continue
        route["managed_listen_port"] = candidate
        occupied.add(candidate)
        candidate += 1
    return routes
