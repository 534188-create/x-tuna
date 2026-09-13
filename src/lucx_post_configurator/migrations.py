from __future__ import annotations

import copy
from typing import Any

from .models import SCHEMA_VERSION, ConfigurationError


CURRENT_SCHEMA_VERSION = SCHEMA_VERSION


def _migrate_v1_to_v2(result: dict[str, Any]) -> None:
    result.setdefault("decoys", {}).setdefault("capabilities", [])
    result.setdefault(
        "integrity",
        {"protected_lucx": {}, "naive_caddyfile": {}},
    )
    result["schema_version"] = 2


def _migrate_v2_to_v3(result: dict[str, Any]) -> None:
    decoys = result.setdefault("decoys", {})
    decoys.setdefault("routing_mode", "strict")
    decoys.setdefault("extended_user_confirmed", False)
    decoys.setdefault("extended_routes", [])
    decoys.setdefault("naive_frontends", [])
    components = result.setdefault("components", {})
    components.setdefault("extended_tls_split", False)
    components.setdefault("naive_frontend", False)
    components.setdefault("trusttunnel_backend", False)
    result.setdefault(
        "trusttunnel_backend",
        {
            "user_confirmed": False,
            "binary_path": "",
            "listen_host": "127.0.0.1",
            "listen_port": 0,
            "public_domain": "",
            "public_port": 443,
            "source": "",
            "sha256": "",
        },
    )
    settings_management = result.setdefault("lucx", {}).setdefault("settings_management", {})
    settings_management.setdefault("sync_public_endpoints", False)
    settings_management.setdefault("allow_inbound_changes", False)
    for protocol in result.get("protocols") or []:
        if "sync_public_endpoint" not in protocol:
            protocol["sync_public_endpoint"] = bool(protocol.get("sync_share_addr"))
        if protocol.get("sync_public_endpoint"):
            settings_management["sync_public_endpoints"] = True
    result["schema_version"] = 3


def _normalize_v3_publication_sync(result: dict[str, Any]) -> None:
    """Backfill endpoint-sync flags in v3 states created before multi-inbound sync."""

    settings_management = result.setdefault("lucx", {}).setdefault("settings_management", {})
    settings_management.setdefault("sync_public_endpoints", False)
    components = result.setdefault("components", {})
    components.setdefault("trusttunnel_backend", False)
    result.setdefault(
        "trusttunnel_backend",
        {
            "user_confirmed": False,
            "binary_path": "",
            "listen_host": "127.0.0.1",
            "listen_port": 0,
            "public_domain": "",
            "public_port": 443,
            "source": "",
            "sha256": "",
        },
    )
    for protocol in result.get("protocols") or []:
        if "sync_public_endpoint" not in protocol:
            protocol["sync_public_endpoint"] = bool(protocol.get("sync_share_addr"))
        if protocol.get("sync_public_endpoint"):
            settings_management["sync_public_endpoints"] = True


def migrate_manifest(value: dict[str, Any]) -> dict[str, Any]:
    """Return an independent current-schema manifest or reject unsafe versions."""

    result = copy.deepcopy(value)
    try:
        version = int(result.get("schema_version", 0))
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("unsupported manifest schema") from exc

    if version > CURRENT_SCHEMA_VERSION:
        raise ConfigurationError(
            f"newer manifest schema {version} is read-only; "
            f"this build supports {CURRENT_SCHEMA_VERSION}"
        )

    if version == 1:
        _migrate_v1_to_v2(result)
        version = 2

    if version == 2:
        _migrate_v2_to_v3(result)
        version = 3

    if version != CURRENT_SCHEMA_VERSION:
        raise ConfigurationError(f"unsupported manifest schema {version}")

    _normalize_v3_publication_sync(result)

    return result
