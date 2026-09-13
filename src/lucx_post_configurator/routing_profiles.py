from __future__ import annotations

import hashlib
import copy
import json
import re
from typing import Any

from .models import Inbound, valid_domain


ROUTING_FIELDS = (
    "inbound_id", "protocol", "network", "transport", "security", "exposure",
    "domain", "internal_host", "internal_port", "public_port", "udp_public_port",
    "transport_path", "transport_hosts", "transport_mode", "alpn", "sni_names",
    "port_bindings", "udp_over_tcp", "shadowsocks_2022",
    "clienthello_match_fingerprint", "public_endpoints", "transport_details",
    "backend_tls_policy",
)

SOURCE_FIELDS = (
    "id", "protocol", "enable", "listen", "port", "network", "transport",
    "security", "transport_path", "transport_hosts", "transport_mode", "alpn",
    "server_names", "port_bindings", "udp_over_tcp", "shadowsocks_2022",
    "clienthello_match_fingerprint", "public_endpoints", "transport_details",
    "share_addr", "suggested_public_port",
)


def _fingerprint(value: dict[str, Any]) -> str:
    """Полный отпечаток разрешённых полей; значения не попадают в диагностику."""
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=True,
                         separators=(",", ":"), allow_nan=False).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def routing_fingerprint(protocol: dict[str, Any], public_tcp_port: int) -> str:
    profile = {field: protocol.get(field) for field in ROUTING_FIELDS}
    profile["shared_tcp_port"] = public_tcp_port
    return _fingerprint(profile)


def source_routing_fingerprint(inbound: Inbound) -> str:
    return _fingerprint({field: getattr(inbound, field, None) for field in SOURCE_FIELDS})


def inbound_routing_metadata(inbound: Inbound) -> dict[str, Any]:
    """Общие несекретные факты для планирования и проверенного обновления снимка."""
    fields = ("public_endpoints", "transport_details", "transport", "transport_path",
              "transport_hosts", "transport_mode", "alpn", "shadowsocks_2022",
              "udp_over_tcp", "clienthello_match_fingerprint")
    return {"source_routing_fingerprint": source_routing_fingerprint(inbound),
            **{name: copy.deepcopy(getattr(inbound, name)) for name in fields}}


def endpoint_domains(protocol: dict[str, Any]) -> list[str]:
    """Собственные адреса подключения; HTTP Host и camouflage SNI сюда не входят."""
    values = [protocol.get("domain"), *(item.get("address")
        for item in protocol.get("public_endpoints") or [] if isinstance(item, dict))]
    return list(dict.fromkeys(str(value or "").strip().lower().rstrip(".")
        for value in values if valid_domain(str(value or "").strip().lower().rstrip("."))))


def _public_name(value: Any, *, optional: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("Имя публичного endpoint должно быть строкой")
    name = value.strip().lower().rstrip(".")
    if optional and not name:
        return ""
    if not valid_domain(name) or name.startswith("*."):
        raise ValueError("Некорректное имя публичного endpoint")
    return name


def _public_port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not str(value).isdigit():
        raise ValueError("Некорректный порт публичного endpoint")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("Порт публичного endpoint вне допустимого диапазона")
    return port


def validated_public_endpoints(protocol: dict[str, Any], *, require_sni: bool = False) -> list[dict[str, Any]]:
    """Проверяем каждую запись; пустой/неоднозначный SNI не заменяем адресом."""
    endpoints = protocol.get("public_endpoints") or []
    if not isinstance(endpoints, list):
        raise ValueError("public_endpoints должен быть списком")
    result = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or endpoint.get("valid") is False:
            raise ValueError("Публичный endpoint не прошёл аудит")
        item = dict(endpoint)
        item["address"] = _public_name(endpoint.get("address"))
        item["port"] = _public_port(endpoint.get("port"))
        item["sni"] = _public_name(endpoint.get("sni", ""), optional=True)
        item["http_host"] = _public_name(endpoint.get("http_host", ""), optional=True)
        keep_blank = endpoint.get("keep_sni_blank", False)
        if not isinstance(keep_blank, bool):
            raise ValueError("keep_sni_blank должен быть логическим значением")
        inherited = []
        if endpoint.get("sni_source") == "inherited_set":
            raw_names = endpoint.get("inherited_sni_names")
            if (protocol.get("security") != "reality" or protocol.get("protocol") not in {"vless", "trojan"}
                    or keep_blank or item["sni"] or not isinstance(raw_names, list) or len(raw_names) < 2):
                raise ValueError("Набор наследуемых SNI не подтверждён для Reality")
            inherited = [_public_name(name) for name in raw_names]
            confirmed = protocol.get("sni_names")
            confirmed_names = {_public_name(name) for name in confirmed} if isinstance(confirmed, list) else set()
            if len(set(inherited)) != len(inherited) or (require_sni and (
                    not isinstance(confirmed, list) or not set(inherited).issubset(confirmed_names))):
                raise ValueError("Подтверждены не все наследуемые SNI Reality")
            item["inherited_sni_names"] = inherited
        if require_sni and (keep_blank or (not item["sni"] and not inherited)
                            or endpoint.get("sni_source") in {"blank", "ambiguous"}):
            raise ValueError("Публичный TLS endpoint не имеет однозначного подтверждённого SNI")
        result.append(item)
    return result


def public_ingresses(protocol: dict[str, Any], shared_tcp_port: int) -> list[tuple[int, str, str]]:
    """Единая карта TCP-входов: (порт, SNI, назначение site/vpn)."""
    shared_tcp_port = _public_port(shared_tcp_port)
    routed_tcp = protocol.get("exposure") == "tcp_sni" and protocol.get("network") in {"tcp", "both"}
    endpoints = validated_public_endpoints(protocol, require_sni=routed_tcp)
    result: list[tuple[int, str, str]] = []

    def add(port: int, name: str, kind: str) -> None:
        item = (port, _public_name(name), kind)
        if item not in result:
            result.append(item)

    for domain in endpoint_domains(protocol):
        add(shared_tcp_port, domain, "site")
    if routed_tcp:
        primary_port = _public_port(protocol.get("public_port"))
        # Legacy manifest без Hosts хранит единственный SNI в domain.
        # Явно пустой список и новые endpoint-записи так не восстанавливаются.
        names = protocol.get("sni_names", [protocol.get("domain")] if not endpoints else [])
        if not isinstance(names, list) or not names:
            raise ValueError("Не подтверждены SNI публичного TCP-маршрута")
        for name in names:
            add(primary_port, name, "vpn")
        add(primary_port, protocol.get("domain", ""), "site")
        for endpoint in endpoints:
            names = endpoint.get("inherited_sni_names") if endpoint.get("sni_source") == "inherited_set" else [endpoint["sni"]]
            for name in names:
                add(endpoint["port"], name, "vpn")
            add(endpoint["port"], endpoint["address"], "site")
    return result


def reserved_listener_ports(manifest: dict[str, Any]) -> set[int]:
    """Все известные public/internal/binding ports исключены из нового loopback allocation."""
    result: set[int] = set()

    def reserve(value: Any) -> None:
        if value not in (None, "", 0):
            result.add(_public_port(value))

    reserve((manifest.get("network") or {}).get("public_tcp_port"))
    for service in (manifest.get("lucx", {}).get("panel", {}), manifest.get("lucx", {}).get("subscription", {}), manifest.get("sidecar", {})):
        for field in ("public_port", "internal_port", "listen_port"):
            reserve(service.get(field))
    decoy_port = (manifest.get("decoys") or {}).get("listen_port")
    if decoy_port:
        for offset in (0, 1, 2):
            reserve(int(decoy_port) + offset)
    for protocol in manifest.get("protocols") or []:
        for field in ("public_port", "internal_port", "udp_public_port"):
            reserve(protocol.get(field))
        for endpoint in validated_public_endpoints(protocol):
            reserve(endpoint["port"])
        for binding in protocol.get("port_bindings") or []:
            reserve(binding.get("port"))
            if binding.get("port_range"):
                match = re.fullmatch(r"(\d+)-(\d+)", str(binding["port_range"]))
                if not match:
                    raise ValueError("Некорректный диапазон listener-портов")
                low, high = (_public_port(value) for value in match.groups())
                if low > high:
                    raise ValueError("Обратный диапазон listener-портов")
                result.update(range(low, high + 1))
    return result
