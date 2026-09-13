from __future__ import annotations

import dataclasses
import ipaddress
from typing import Any

from .models import Audit
from .runner import Runner


TRUSTTUNNEL_PROTOCOLS = {"trusttunnel", "trust-tunnel"}


@dataclasses.dataclass(slots=True)
class TrustTunnelStatus:
    """Secret-free read-only observations about existing LucX TrustTunnel."""

    discovery_state: str = "not_checked"
    listener_state: str = "not_checked"
    protocol_probe_state: str = "not_checked"
    configured_inbounds: int = 0
    enabled_inbounds: int = 0
    configured_inbound_ids: list[int] = dataclasses.field(default_factory=list)
    enabled_inbound_ids: list[int] = dataclasses.field(default_factory=list)
    observed_listener_inbound_ids: list[int] = dataclasses.field(default_factory=list)
    optional_backend_enabled: bool = False
    ready: bool = False
    errors: list[str] = dataclasses.field(default_factory=list)
    inbounds_info: list[dict[str, Any]] = dataclasses.field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _listener_endpoints(output: str) -> set[tuple[str, int]]:
    """Адреса сравниваются только в памяти; сырой вывод не возвращается."""

    endpoints: set[tuple[str, int]] = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3] if fields[0].upper() == "LISTEN" else fields[2]
        if local.startswith("[") and "]:" in local:
            port_text = local.rsplit("]:", 1)[1]
        elif ":" in local:
            port_text = local.rsplit(":", 1)[1]
        else:
            continue
        try:
            port = int(port_text)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            host = local.rsplit(":", 1)[0].strip("[]")
            endpoints.add((host, port))
    return endpoints


def _covers_listener(observed: str, expected: str) -> bool:
    if observed == expected:
        return True
    try:
        actual = ipaddress.ip_address(observed)
        desired = ipaddress.ip_address(expected)
    except ValueError:
        return False
    return actual.version == desired.version and (actual == desired or actual.is_unspecified)


def observe_trusttunnel(
    audit: Audit,
    runner: Runner,
    *,
    optional_backend_enabled: bool = False,
) -> TrustTunnelStatus:
    """Observe LucX metadata and TCP sockets without probing or changing them."""

    result = TrustTunnelStatus(optional_backend_enabled=bool(optional_backend_enabled))
    if not audit.db_schema_supported:
        result.discovery_state = "error"
        result.errors.append("схема LucX недоступна для безопасного read-only аудита")
        return result

    inbounds = [
        item for item in audit.inbounds if item.protocol.lower() in TRUSTTUNNEL_PROTOCOLS
    ]
    enabled = [item for item in inbounds if item.enable]
    result.discovery_state = "observed"
    result.configured_inbounds = len(inbounds)
    result.enabled_inbounds = len(enabled)
    result.configured_inbound_ids = [int(item.id) for item in inbounds]
    result.enabled_inbound_ids = [int(item.id) for item in enabled]

    def _build_inbounds_info() -> list[dict[str, Any]]:
        return [
            {
                "id": int(item.id),
                "protocol": str(item.protocol),
                "remark": str(item.remark or ""),
                "enable": bool(item.enable),
                "port": int(item.port),
                "listen": str(item.listen or "0.0.0.0"),
                "is_listening": int(item.id) in result.observed_listener_inbound_ids,
                "server_names": list(item.server_names),
                "suggested_public_port": int(item.suggested_public_port or 443),
                "clienthello_fingerprint": str(item.clienthello_match_fingerprint or ""),
            }
            for item in inbounds
        ]

    if getattr(runner, "dry_run", False) or not runner.available("ss"):
        result.listener_state = "not_checked"
        result.inbounds_info = _build_inbounds_info()
        return result

    listener_result = runner.run(["ss", "-H", "-lnt"], check=False, timeout=10)
    if listener_result.returncode != 0:
        result.listener_state = "error"
        result.errors.append("не удалось прочитать TCP listeners через ss")
        result.inbounds_info = _build_inbounds_info()
        return result

    endpoints = _listener_endpoints(listener_result.stdout)
    result.listener_state = "observed"
    result.observed_listener_inbound_ids = [
        int(item.id) for item in enabled
        if any(port == int(item.port) and _covers_listener(host, item.listen or "0.0.0.0")
               for host, port in endpoints)
    ]
    result.inbounds_info = _build_inbounds_info()
    return result
