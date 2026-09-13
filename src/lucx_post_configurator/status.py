from __future__ import annotations

from typing import Any

from .decoy_capabilities import classify_decoy_capabilities
from .transaction import BACKUP_ROOT


def _capabilities(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if str((manifest.get("decoys") or {}).get("routing_mode") or "strict") == "extended":
        return classify_decoy_capabilities(manifest)
    values = list((manifest.get("decoys") or {}).get("capabilities") or [])
    return values or classify_decoy_capabilities(manifest)


def coverage_summary(manifest: dict[str, Any]) -> dict[str, int]:
    """Return the four mandatory browser-decoy coverage counters."""

    result = {
        "managed": 0,
        "existing_fallback": 0,
        "naive_readonly": 0,
        "blocked_or_unknown": 0,
    }
    for item in _capabilities(manifest):
        status = str(item.get("status") or "unsupported_safe")
        if bool(item.get("managed")):
            result["managed"] += 1
        elif status == "existing_fallback_observed":
            result["existing_fallback"] += 1
        elif status == "naive_caddy_owned_readonly":
            result["naive_readonly"] += 1
        else:
            result["blocked_or_unknown"] += 1
    return result


def domain_status_rows(manifest: dict[str, Any]) -> list[dict[str, str]]:
    """Project decoy capability records into a concise, secret-free table."""

    rows: list[dict[str, str]] = []
    for item in _capabilities(manifest):
        probe = item.get("probe") or {}
        evidence = item.get("evidence") or []
        if not isinstance(evidence, list):
            evidence = [str(evidence)]
        rows.append(
            {
                "domain": str(item.get("domain") or ""),
                "status": str(item.get("status") or "unsupported_safe"),
                "reason": str(item.get("reason") or ""),
                "probe": str(probe.get("state") or item.get("probe_state") or "not-run"),
                "evidence": "; ".join(str(value)[:240] for value in evidence[:4]),
            }
        )
    return sorted(rows, key=lambda item: item["domain"])


_SERVICE_BY_COMPONENT = {
    "haproxy": ["haproxy.service"],
    "nginx": ["nginx.service"],
    "firewall": ["lucx-post-firewall.service"],
    "sidecar": ["lucx-sub-sidecar.service"],
    "cloudflare": ["lucx-cloudflare-ips-update.timer"],
    "dns": ["systemd-resolved.service or resolvconf"],
    "lucx-settings": ["x-ui.service"],
    "lucx-certificates": ["x-ui.service"],
}


def mutation_preview(plan: dict[str, Any]) -> dict[str, Any]:
    """Return an exact, compact preview rendered before any apply confirmation."""

    files: set[str] = set()
    database_files: set[str] = set()
    database_fields: set[str] = set()
    services: set[str] = set()
    for action in plan.get("actions") or []:
        component = str(action.get("component") or "")
        fields = {str(value) for value in action.get("database_fields") or [] if value}
        targets = {str(value) for value in action.get("targets") or [] if value}
        if fields or component.startswith("lucx-"):
            database_files.update(targets)
            database_fields.update(fields)
        else:
            files.update(targets)
        explicit_services = [
            str(value) for value in action.get("services") or [] if value
        ]
        services.update(explicit_services or _SERVICE_BY_COMPONENT.get(component, []))

    blocker_terms = (
        "blocked_sni_collision",
        "extended_blocked",
        "unsupported_safe",
        "integrity",
        "блокиров",
        "запрещ",
        "refus",
    )
    blockers = [
        str(value)
        for value in plan.get("warnings") or []
        if any(term in str(value).lower() for term in blocker_terms)
    ]
    return {
        "files": sorted(files),
        "database_files": sorted(database_files),
        "database_fields": sorted(database_fields),
        "services": sorted(services),
        "backup_root": BACKUP_ROOT,
        "protected_objects": list(plan.get("immutable") or []),
        "blockers": blockers,
    }
