from __future__ import annotations

from collections import defaultdict
from typing import Any

from .models import Audit, valid_domain
from .extended_decoys import classify_extended_decoy_routes
from .routing_profiles import endpoint_domains, public_ingresses


MANAGED_STATUSES = {
    "direct_tcp_decoy",
    "udp_with_tcp_decoy",
    "reality_endpoint_decoy",
    "extended_ready",
}

CAPABILITY_STATUSES = MANAGED_STATUSES | {
    "existing_fallback_observed",
    "naive_caddy_owned_readonly",
    "blocked_sni_collision",
    "unsupported_safe",
    "extended_ready",
    "extended_blocked",
}

KNOWN_EXPOSURES = {"tcp_sni", "tcp_direct", "udp_direct", "tcp_udp_direct", "none"}
KNOWN_NETWORKS = {"tcp", "udp", "both"}


def _domain(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _port(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _network(item: dict[str, Any]) -> str:
    value = str(item.get("network") or "").lower()
    if value:
        return value
    exposure = str(item.get("exposure") or "")
    if exposure == "udp_direct":
        return "udp"
    if exposure == "tcp_udp_direct":
        return "both"
    if exposure in {"tcp_sni", "tcp_direct", "none"}:
        return "tcp"
    return ""


def _existing_observations(manifest: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for item in (manifest.get("decoys") or {}).get("capabilities") or []:
        probe = item.get("probe") or {}
        if (
            item.get("status") == "existing_fallback_observed"
            and probe.get("state") == "site_observed"
        ):
            domain = _domain(item.get("domain"))
            if domain:
                result.add(domain)
    return result


def _record(
    domain: str,
    protocols: list[dict[str, Any]],
    status: str,
    reason: str,
    evidence: list[str],
) -> dict[str, Any]:
    managed = status in MANAGED_STATUSES
    return {
        "domain": domain,
        "status": status,
        "managed": managed,
        "protocol_ids": sorted(
            int(item.get("inbound_id") or 0)
            for item in protocols
            if int(item.get("inbound_id") or 0) > 0
        ),
        "evidence": list(dict.fromkeys(evidence)),
        "reason": reason,
        "probe_mode": "active" if managed else "passive" if status in {
            "existing_fallback_observed",
            "naive_caddy_owned_readonly",
            "blocked_sni_collision",
        } else "none",
    }


def classify_decoy_capabilities(
    manifest: dict[str, Any],
    audit: Audit | None = None,
    *, for_staging: bool = False,
) -> list[dict[str, Any]]:
    """Classify browser-site coverage without changing a protocol topology."""

    if str((manifest.get("decoys") or {}).get("routing_mode") or "strict") == "extended":
        configured = list((manifest.get("decoys") or {}).get("extended_routes") or [])
        routes = classify_extended_decoy_routes(manifest, audit)
        if configured:
            cached_ids = [_port(item.get("inbound_id")) for item in configured]
            cache = {_port(item.get("inbound_id")): item for item in configured}
            complete = len(cached_ids) == len(set(cached_ids)) and set(cache) == {_port(item.get("inbound_id")) for item in routes}
            ignored = {"reason", "evidence", "source_caddyfile_sha256"}
            for route in routes:
                cached = cache.get(_port(route.get("inbound_id")), {})
                if not complete or any(field not in cached or field not in route or cached[field] != route[field]
                                       for field in (set(route) | set(cached)) - ignored):
                    route.update(status="blocked", managed=False, reason="Снимок маршрута не подтверждён текущим audit; требуется новый план.")
        grouped_routes: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for route in routes:
            for domain in route.get("endpoint_domains") or [route.get("domain")]:
                domain = _domain(domain)
                if domain and valid_domain(domain):
                    grouped_routes[domain].append(route)
        extended_records: list[dict[str, Any]] = []
        for domain in sorted(grouped_routes):
            domain_routes = grouped_routes[domain]
            ready = all(str(item.get("status") or "blocked") == "ready" for item in domain_routes)
            candidate = (for_staging is True and not ready and all(
                item.get('status') == 'ready' or (item.get('status') == 'rendered_candidate'
                    and item.get('strategy') == 'naive_connect_h2') for item in domain_routes))
            strategies = list(
                dict.fromkeys(str(item.get("strategy") or "blocked_unknown") for item in domain_routes)
            )
            evidence: list[str] = []
            for item in domain_routes:
                evidence.extend(str(value) for value in item.get("evidence") or [])
            reasons = [str(item.get("reason") or "") for item in domain_routes]
            extended_records.append(
                {
                    "domain": domain,
                    "status": "extended_ready" if ready else "extended_candidate" if candidate else "extended_blocked",
                    "managed": ready or candidate,
                    "strategy": ",".join(strategies),
                    "protocol_ids": sorted(
                        {
                            _port(item.get("inbound_id"))
                            for item in domain_routes
                            if _port(item.get("inbound_id")) > 0
                        }
                    ),
                    "evidence": list(dict.fromkeys(evidence)),
                    "reason": "; ".join(dict.fromkeys(reason for reason in reasons if reason)),
                    "probe_mode": "active" if ready or candidate else "none",
                    "tls_termination": any(bool(item.get("tls_termination")) for item in domain_routes),
                    "preflight_required": any(bool(item.get("preflight_required")) for item in domain_routes),
                }
            )
        # Самостоятельные сайты также входят в обязательное покрытие.
        strict_manifest = dict(manifest)
        strict_manifest["decoys"] = dict(manifest.get("decoys") or {}, routing_mode="strict")
        for record in classify_decoy_capabilities(strict_manifest, audit):
            if record["domain"] not in grouped_routes:
                extended_records.append(record)
        return sorted(extended_records, key=lambda item: item["domain"])

    shared_port = _port((manifest.get("network") or {}).get("public_tcp_port"))
    observed = _existing_observations(manifest)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for protocol in manifest.get("protocols") or []:
        for domain in endpoint_domains(protocol):
            grouped[domain].append(protocol)

    # Явный корень зоны и все выбранные сайты проходят общий контроль владельцев.
    panel_domain = _domain(
        (manifest.get("lucx") or {}).get("panel", {}).get("domain")
    )
    apex = str((manifest.get("decoys") or {}).get("zone_apex") or "")
    if not apex and panel_domain and "." in panel_domain:
        apex = panel_domain.split(".", 1)[1]
    domains = [apex, *(site.get("domain") for site in (manifest.get("decoys") or {}).get("sites") or [])]
    for value in domains:
        domain = _domain(value)
        if valid_domain(domain) and domain not in grouped:
            grouped[domain] = []

    records: list[dict[str, Any]] = []
    for domain in sorted(grouped):
        protocols = grouped[domain]
        evidence = [
            "inbound #{} {} network={} exposure={} public_port={}".format(
                int(item.get("inbound_id") or 0),
                str(item.get("protocol") or "unknown"),
                _network(item) or "unknown",
                str(item.get("exposure") or "unknown"),
                _port(item.get("public_port")),
            )
            for item in protocols
        ]

        if any(
            item.get("exposure") not in KNOWN_EXPOSURES
            or _network(item) not in KNOWN_NETWORKS
            for item in protocols
        ):
            records.append(
                _record(
                    domain,
                    protocols,
                    "unsupported_safe",
                    "Транспорт или способ публикации не доказан; автоматический маршрут запрещён.",
                    evidence,
                )
            )
            continue

        sni_owners: list[dict[str, Any]] = []
        for item in manifest.get("protocols") or []:
            if item.get("exposure") != "tcp_sni":
                continue
            try:
                names = [name for port, name, kind in public_ingresses(item, shared_port)
                         if port == shared_port and (kind == "vpn" or item.get("security") != "reality")]
            except ValueError:
                names = endpoint_domains(item)
            if domain in names:
                sni_owners.append(item)
                evidence.append(
                    f"inbound #{int(item.get('inbound_id') or 0)} owns ClientHello SNI {domain} on TCP/{shared_port}"
                )

        if sni_owners:
            if any(str(item.get("protocol") or "").lower() == "naive" for item in sni_owners):
                caddy_found = bool(audit and audit.naive_caddyfile.get("found"))
                evidence.append(f"Naive Caddyfile found={str(caddy_found).lower()}")
                records.append(
                    _record(
                        domain,
                        sni_owners,
                        "naive_caddy_owned_readonly",
                        "SNI принадлежит Naive; Caddyfile доступен только для чтения.",
                        evidence,
                    )
                )
            elif domain in observed:
                records.append(
                    _record(
                        domain,
                        sni_owners,
                        "existing_fallback_observed",
                        "Обычный HTTPS-сайт ранее подтверждён через существующий protocol fallback.",
                        evidence,
                    )
                )
            else:
                records.append(
                    _record(
                        domain,
                        sni_owners,
                        "blocked_sni_collision",
                        f"Протокол уже владеет тем же SNI на TCP/{shared_port}; VPN имеет приоритет.",
                        evidence,
                    )
                )
            continue

        direct_public_tcp = [
            item
            for item in manifest.get("protocols") or []
            if item.get("exposure") in {"tcp_direct", "tcp_udp_direct"}
            and _port(item.get("public_port")) == shared_port
        ]
        if direct_public_tcp:
            evidence.append(f"direct protocol listener owns TCP/{shared_port}")
            records.append(
                _record(
                    domain,
                    protocols,
                    "blocked_sni_collision",
                    f"Прямой protocol listener уже занимает TCP/{shared_port}; внешний перехват запрещён.",
                    evidence,
                )
            )
            continue

        reality_endpoint = any(
            item.get("exposure") == "tcp_sni"
            and item.get("security") == "reality"
            and _port(item.get("public_port")) == shared_port
            and domain not in {_domain(value) for value in item.get("sni_names") or []}
            for item in protocols
        )
        if reality_endpoint:
            records.append(
                _record(
                    domain,
                    protocols,
                    "reality_endpoint_decoy",
                    "Endpoint-домен отличается от Reality camouflage SNI; браузерный SNI свободен.",
                    evidence,
                )
            )
            continue

        if protocols and all(_network(item) == "udp" for item in protocols):
            records.append(
                _record(
                    domain,
                    protocols,
                    "udp_with_tcp_decoy",
                    "VPN использует UDP; независимый браузерный TCP listener не меняет протокол.",
                    evidence,
                )
            )
            continue

        records.append(
            _record(
                domain,
                protocols,
                "direct_tcp_decoy",
                f"Для домена не найден владелец protocol SNI или listener на TCP/{shared_port}.",
                evidence,
            )
        )

    return records


def managed_decoy_domains(manifest: dict[str, Any]) -> list[str]:
    capabilities = list((manifest.get("decoys") or {}).get("capabilities") or [])
    if not capabilities:
        capabilities = classify_decoy_capabilities(manifest)
    return sorted(
        {
            _domain(item.get("domain"))
            for item in capabilities
            if item.get("managed") and valid_domain(_domain(item.get("domain")))
        }
    )
