from __future__ import annotations

import dataclasses
import hashlib
import importlib.resources
import ipaddress
import re
import shlex
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Literal

from .decoy_capabilities import managed_decoy_domains
from .models import validate_manifest, valid_domain
from .render_runtime import ListenerKey, RenderRuntime
from .routing_profiles import public_ingresses, reserved_listener_ports


@dataclasses.dataclass(frozen=True, slots=True)
class GeneratedFile:
    content: bytes = b""
    mode: int = 0o644
    component: str = "core"
    symlink_target: str = ""


def _acl_name(prefix: str, value: str) -> str:
    clean = re.sub(r"[^a-z0-9_]", "_", value.lower())
    return f"{prefix}_{clean}"[:60]


def _backend_host(value: str) -> str:
    value = str(value or "127.0.0.1").strip()
    if value in {"", "0.0.0.0", "::", "[::]", "localhost"}:
        return "127.0.0.1"
    try:
        parsed = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", value):
            raise ValueError(f"unsafe backend host: {value}")
        return value
    return f"[{parsed}]" if parsed.version == 6 else str(parsed)


def _render_haproxy_strict(manifest: dict[str, Any]) -> str:
    panel = manifest["lucx"]["panel"]
    subscription = manifest["lucx"]["subscription"]
    sidecar_enabled = manifest["components"].get("sidecar", False)
    public_port = int(manifest["network"]["public_tcp_port"])
    panel_public_port = int(panel.get("public_port", public_port))
    subscription_public_port = int(subscription.get("public_port", public_port))
    cloudflare_only = bool((manifest.get("cloudflare") or {}).get("enabled"))
    bind_address = str(manifest["network"]["public_bind_address"])
    if bind_address in {"0.0.0.0", "::"}:
        bind_host = "*"
    elif ":" in bind_address:
        bind_host = f"[{bind_address}]"
    else:
        bind_host = bind_address
    groups: dict[int, list[tuple[str, str, str, int]]] = {}
    groups.setdefault(panel_public_port, []).append(
        (panel["domain"], "be_panel", _backend_host(panel["internal_host"]), int(panel["internal_port"]))
    )
    groups.setdefault(subscription_public_port, []).append(
        (
            subscription["domain"],
            "be_subscription",
            _backend_host(manifest["sidecar"]["listen_host"] if sidecar_enabled else subscription["internal_host"]),
            int(manifest["sidecar"]["listen_port"] if sidecar_enabled else subscription["internal_port"]),
        )
    )
    for protocol in manifest["protocols"]:
        if protocol["exposure"] == "tcp_sni":
            for ingress_port, sni, kind in public_ingresses(protocol, public_port):
                # Свободный endpoint Reality остаётся у сайта; camouflage SNI у VPN.
                if kind == "site" and protocol.get("security") == "reality":
                    continue
                group = groups.setdefault(ingress_port, [])
                entry = (sni, f"be_inbound_{protocol['inbound_id']}",
                         _backend_host(protocol["internal_host"]), int(protocol["internal_port"]))
                if entry not in group:
                    group.append(entry)

    route_domains = {item[0] for item in groups.get(public_port, [])}
    if manifest["decoys"].get("enabled"):
        sites = {site["domain"] for site in manifest["decoys"].get("sites", [])}
        for domain in [
            value
            for value in managed_decoy_domains(manifest)
            if value in sites and value not in route_domains
        ]:
            groups.setdefault(public_port, []).append(
                (
                    domain,
                    "be_decoy",
                    _backend_host(manifest["decoys"]["listen_host"]),
                    int(manifest["decoys"]["listen_port"]),
                )
            )

    lines = [
        "# Managed by lucx-post-configurator. Local edits will be replaced.",
        "global",
        "    log /dev/log local0",
        "    log /dev/log local1 notice",
        "    user haproxy",
        "    group haproxy",
        "    daemon",
        "",
        "defaults",
        "    log global",
        "    mode tcp",
        "    option tcplog",
        "    timeout connect 5s",
        "    timeout client 1m",
        "    timeout server 1m",
    ]
    non_tls_id = manifest["network"].get("non_tls_backend_inbound_id")
    non_tls = next((p for p in manifest["protocols"] if p["inbound_id"] == non_tls_id), None)
    unique_backends: dict[str, tuple[str, int]] = {}

    for frontend_port, routes in sorted(groups.items()):
        known_sni_acl = _acl_name("known_sni", str(frontend_port))
        lines.extend(
            [
                "",
                f"frontend lucx_tls_{frontend_port}",
                f"    bind {bind_host}:{frontend_port}",
                "    mode tcp",
                "    tcp-request inspect-delay 5s",
                "    acl is_tls req.ssl_hello_type 1",
            ]
        )
        route_rules: list[tuple[str, str]] = []
        acls: list[str] = []
        for route_index, (domain, backend, host, port) in enumerate(routes, start=1):
            acl = _acl_name(f"sni_{frontend_port}_{route_index}", domain)
            acls.append(acl)
            lines.append(f"    acl {acl} req.ssl_sni -i {domain}")
            lines.append(f"    acl {known_sni_acl} req.ssl_sni -i {domain}")
            route_rules.append((backend, acl))
            previous = unique_backends.get(backend)
            if previous and previous != (host, port):
                raise ValueError(f"backend {backend} has conflicting targets")
            unique_backends[backend] = (host, port)

        protected_routes = [
            (backend, acl)
            for backend, acl in route_rules
            if backend in {"be_panel", "be_subscription"}
        ]
        if cloudflare_only and protected_routes:
            lines.append("    acl from_cloudflare src -f /etc/haproxy/cloudflare-ips.lst")
            local_sources = ["127.0.0.0/8", "::1"]
            if bind_address not in {"0.0.0.0", "::"}:
                local_sources.append(bind_address)
            lines.append("    acl from_local_health src " + " ".join(local_sources))
            for backend, acl in protected_routes:
                lines.append(
                    f"    tcp-request content reject if is_tls {acl} !from_cloudflare !from_local_health"
                )

        unknown_to_decoy = (
            frontend_port == public_port
            and manifest["network"].get("unknown_sni_action") == "decoy"
        )
        if not unknown_to_decoy and acls:
            lines.append(f"    tcp-request content reject if is_tls !{known_sni_acl}")
        group_non_tls = non_tls if non_tls and int(non_tls["public_port"]) == frontend_port else None
        lines.append("    tcp-request content accept if is_tls")
        if not group_non_tls:
            lines.append("    tcp-request content reject if !is_tls")
        for backend, acl in route_rules:
            lines.append(f"    use_backend {backend} if {acl}")
        if unknown_to_decoy:
            lines.append("    use_backend be_decoy if is_tls")
            unique_backends.setdefault(
                "be_decoy",
                (
                    _backend_host(manifest["decoys"]["listen_host"]),
                    int(manifest["decoys"]["listen_port"]),
                ),
            )
        if group_non_tls:
            lines.append(f"    use_backend be_inbound_{non_tls_id} if !is_tls")

    if non_tls:
        unique_backends.setdefault(
            f"be_inbound_{non_tls_id}",
            (_backend_host(non_tls["internal_host"]), int(non_tls["internal_port"])),
        )
    for backend, (host, port) in unique_backends.items():
        lines.extend(["", f"backend {backend}", "    mode tcp", f"    server local {host}:{port}"])
    return "\n".join(lines) + "\n"


def _safe_clienthello_prefix(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not re.fullmatch(r"[0-9A-F]{2,64}", text) or len(text) % 2:
        raise ValueError("unsafe TrustTunnel routing material")
    return text


def _safe_http_path(value: Any, inbound_id: int) -> str:
    path = str(value or "").split("?", 1)[0]
    if not path.startswith("/") or not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*", path):
        raise ValueError(f"HTTP transport path is missing or unsafe for inbound #{inbound_id}")
    return path


def extended_split_ports(manifest: dict[str, Any], routes: list[dict[str, Any]]) -> dict[int, int]:
    occupied = reserved_listener_ports(manifest)
    occupied.update(
        int(item.get("managed_listen_port") or 0)
        for item in routes
        if 1 <= int(item.get("managed_listen_port") or 0) <= 65535
    )
    result: dict[int, int] = {}
    candidate = int((manifest.get("decoys") or {}).get("tls_split_port_start") or 24443)
    for route in sorted(
        (
            item
            for item in routes
            if item.get("strategy") in {"http_tls_split", "xhttp_tls_split", "binary_tls_split", "trusttunnel_clienthello_split"}
        ),
        key=lambda item: int(item.get("inbound_id") or 0),
    ):
        while candidate in occupied and candidate <= 65535:
            candidate += 1
        if candidate > 65535:
            raise ValueError("no free loopback port remains for extended TLS split")
        inbound_id = int(route["inbound_id"])
        result[inbound_id] = candidate
        occupied.add(candidate)
        candidate += 1
    return result


def _verified_extended_routes(manifest: dict[str, Any], routing_material: dict | None) -> list[dict[str, Any]]:
    """Производные решения восстанавливаются из текущих фактов и ephemeral audit."""
    from .extended_decoys import classify_extended_decoy_routes
    from .models import Audit
    from .naive_frontend import supports_native_decoy, parse_naive_caddyfile, parse_naive_connect_source, parse_naive_native_source

    cached = list((manifest.get("decoys") or {}).get("extended_routes") or [])
    routes_without_source = classify_extended_decoy_routes(manifest, Audit())
    files = []
    binary_paths = set()
    for protocol in manifest.get("protocols") or []:
        if protocol.get("protocol") != "naive":
            continue
        inbound_id = int(protocol.get("inbound_id") or 0)
        independent = [item for item in routes_without_source if item.get("inbound_id") == inbound_id]
        if (len(independent) == 1 and independent[0].get("status") == "ready"
                and independent[0].get("strategy") == "tcp_side_site"):
            # Отдельный VPN listener не использует Caddy source для сайта.
            # Решение получено из текущих параметров, а не из сохранённого cache;
            # сам cache сверяется со свежей классификацией ниже.
            continue
        saved = [route for route in cached if route.get("inbound_id") == inbound_id]
        route = saved[0] if len(saved) == 1 else {}
        material = (routing_material or {}).get(inbound_id) or (routing_material or {}).get(str(inbound_id)) or {}
        source = material.get("naive_caddyfile_text")
        metadata = material.get("naive_source_metadata")
        if metadata is None and isinstance(source, str) and route.get("source_caddyfile"):
            metadata = {
                "path": route.get("source_caddyfile"),
                "sha256": route.get("source_caddyfile_sha256", hashlib.sha256(source.encode("utf-8")).hexdigest()),
            }
        if not isinstance(source, str) or not isinstance(metadata, dict):
            raise ValueError(f"Naive inbound #{inbound_id}: подтверждённый ephemeral source недоступен")
        if len(source.encode("utf-8")) > 1024 * 1024:
            raise ValueError("Naive source exceeds safe parser limit")
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if digest != metadata.get("sha256"):
            raise ValueError("Naive Caddyfile changed after planning")
        path = metadata.get("path")
        if (not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", path)
                or any(part in {"", ".", ".."} for part in path.split("/")[1:])
                or not path.endswith(f"/naive-{inbound_id}.caddyfile")):
            raise ValueError("Naive source path does not match its audit")
        if route.get("strategy") in {"naive_native", "naive_managed"} and (
                path != route.get("source_caddyfile") or digest != route.get("source_caddyfile_sha256")):
            raise ValueError("Naive source changed after planning")
        native = supports_native_decoy(source)
        if not native:
            try:
                if manifest.get("components", {}).get("naive_frontend") is True:
                    parse_naive_caddyfile(source)
                else:
                    parsed = parse_naive_connect_source(source)
                    if parsed.upstream or parsed.probe_resistance:
                        # Только каноническая форма candidate; функциональная
                        # native binding проверяется координатором отдельно.
                        parse_naive_native_source(source)
                    if (not 1 <= len(parsed.auth_pairs) <= 128
                            or len({user for user, _ in parsed.auth_pairs}) != len(parsed.auth_pairs)
                            or any(not user or not password for user, password in parsed.auth_pairs)):
                        raise ValueError("unsupported source")
            except ValueError:
                raise ValueError("Структура исходного Naive Caddyfile не подтверждена") from None
        files.append({**{name: metadata[name] for name in ("kind", "mode", "uid", "gid") if name in metadata},
                      "path": path, "sha256": digest,
                      "capabilities": {"native_decoy": native, "forward_proxy": True}})
        if not native and manifest.get("components", {}).get("naive_frontend") is True:
            binary = material.get("naive_binary_path") or route.get("binary_path")
            if (not isinstance(binary, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", binary)
                    or ".." in binary.split("/")):
                raise ValueError("Naive binary path is not confirmed by audit")
            binary_paths.add(binary)
    if len(binary_paths) > 1:
        raise ValueError("Naive audit contains conflicting binary paths")
    audit = Audit(naive_caddyfile={"files": files, "binary_path": next(iter(binary_paths), "")})
    fresh = classify_extended_decoy_routes(manifest, audit)
    if not cached:
        return fresh
    current = {item["inbound_id"]: item for item in fresh}
    cached_ids = [int(item.get("inbound_id") or 0) for item in cached]
    if len(cached_ids) != len(set(cached_ids)) or set(cached_ids) != set(current):
        raise ValueError("сохранённый набор маршрутов неполон или содержит дубликаты; требуется новый план")
    for route in cached:
        actual = current[int(route["inbound_id"])]
        # Причина и пояснение не управляют маршрутизацией; остальные поля обязательны.
        for field in (set(actual) | set(route)) - {"reason", "evidence"}:
            if field not in actual or field not in route or route[field] != actual[field]:
                raise ValueError(f"inbound #{actual['inbound_id']}: сохранённый маршрут устарел ({field})")
    return fresh


@dataclasses.dataclass(slots=True)
class _ExtendedFrontendPlan:
    routes: list[dict[str, Any]]
    ingress_by_id: dict[int, list[tuple[int, str, str]]]
    split_ports: dict[int, int]
    naive_split_ports: dict[tuple[int, int], int]
    groups: dict[int, list[tuple[str, str, bool]]]
    backends: dict[str, tuple[str, int, str, str]]
    trust_rules: dict[int, list[tuple[str, str, int, list[str]]]]
    bind_address: str
    cloudflare_only: bool


def _extended_frontend_plan(
    manifest: dict[str, Any], routing_material: dict[int | str, dict[str, Any]] | None
) -> _ExtendedFrontendPlan:
    routes = _verified_extended_routes(manifest, routing_material)
    source_paths = {route["source_identity"]["path"] for route in routes
                    if route.get("strategy") == "naive_connect_h2"}
    if source_paths:
        referenced = [(manifest.get("certificates") or {}).get(name, "") for name in ("cert_path", "key_path")]
        referenced.extend((route.get("backend_tls_policy") or {}).get("ca_file", "") for route in routes)
        referenced.extend(site.get("root", "") for site in (manifest.get("decoys") or {}).get("sites") or [])
        if any(path and (path == source or source.startswith(path + "/") or path.startswith(source + "/"))
               for path in referenced for source in source_paths):
            raise ValueError("Исходный Naive Caddyfile не может использоваться как TLS/site материал")
    ingress_by_id = {int(item["inbound_id"]): public_ingresses(item, int(manifest["network"]["public_tcp_port"]))
                     for item in manifest.get("protocols") or []}
    # Не теряем владельца SNI, даже если сайт для него заблокирован.
    blocked_passthrough = []
    protocols_by_id = {int(item["inbound_id"]): item for item in manifest.get("protocols") or []}
    for item in routes:
        if (item.get("status") == "ready" or
                (item.get("strategy") == "naive_connect_h2" and item.get("status") == "rendered_candidate")):
            continue
        protocol = protocols_by_id.get(int(item.get("inbound_id") or 0), {})
        if (protocol.get("exposure") == "tcp_sni"
                and protocol.get("network") in {"tcp", "both"}
                and protocol.get("sni_names")):
            passthrough = dict(item)
            passthrough["strategy"] = "blocked_passthrough"
            blocked_passthrough.append(passthrough)
        elif protocol.get("network") == "udp" and not protocol.get("udp_over_tcp"):
            pass
        else:
            raise ValueError(f"inbound #{item.get('inbound_id')}: заблокированный маршрут не имеет подтверждённого TCP/SNI passthrough")
    routes = [item for item in routes if item.get("status") == "ready" or
              (item.get("strategy") == "naive_connect_h2" and item.get("status") == "rendered_candidate")]
    routes.extend(blocked_passthrough)

    panel = manifest["lucx"]["panel"]
    subscription = manifest["lucx"]["subscription"]
    sidecar_enabled = bool(manifest["components"].get("sidecar"))
    public_port = int(manifest["network"]["public_tcp_port"])
    bind_address = str(manifest["network"]["public_bind_address"])
    cloudflare_only = bool((manifest.get("cloudflare") or {}).get("enabled"))
    split_ports = extended_split_ports(manifest, routes)
    naive_split_ports: dict[tuple[int, int], int] = {}
    occupied = reserved_listener_ports(manifest) | set(split_ports.values())
    occupied.update(int(item.get("managed_listen_port") or 0) for item in routes)
    candidate_port = max(split_ports.values(), default=int(manifest["decoys"].get("tls_split_port_start") or 24443) - 1) + 1
    for route in sorted(routes, key=lambda item: int(item["inbound_id"])):
        if route.get("strategy") != "naive_connect_h2":
            continue
        inbound_id = int(route["inbound_id"])
        for ingress_port in sorted({port for port, _, _ in ingress_by_id[inbound_id]}):
            while candidate_port in occupied and candidate_port <= 65535:
                candidate_port += 1
            if not 1 <= candidate_port <= 65535:
                raise ValueError("Нет свободного loopback порта Naive frontend")
            naive_split_ports[inbound_id, ingress_port] = candidate_port
            occupied.add(candidate_port)
            candidate_port += 1
    by_id = {int(item["inbound_id"]): item for item in manifest.get("protocols") or []}
    decoy_host = _backend_host(manifest["decoys"]["listen_host"])
    decoy_tls_port = int(manifest["decoys"]["listen_port"])
    decoy_h2c_port = decoy_tls_port + 1

    groups: dict[int, list[tuple[str, str, bool]]] = {}
    backends: dict[str, tuple[str, int, str, str]] = {}

    def backend(
        name: str, host: str, port: int, options: str = "", mode: str = "tcp"
    ) -> None:
        target = (host, port, options, mode)
        previous = backends.get(name)
        if previous is not None and previous != target:
            raise ValueError(f"backend {name} has conflicting targets")
        backends[name] = target

    def sni_route(port: int, domain: str, target: str, protected: bool = False) -> None:
        normalized = str(domain or "").strip().lower().rstrip(".")
        if not normalized:
            raise ValueError("empty SNI in extended route")
        group = groups.setdefault(port, [])
        for existing_domain, existing_target, _ in group:
            if existing_domain == normalized and existing_target != target:
                raise ValueError(
                    f"conflicting extended SNI {normalized}: {existing_target} versus {target}"
                )
        item = (normalized, target, protected)
        if item not in group:
            group.append(item)

    panel_port = int(panel.get("public_port", public_port))
    subscription_port = int(subscription.get("public_port", public_port))
    backend("be_panel", _backend_host(panel["internal_host"]), int(panel["internal_port"]))
    backend(
        "be_subscription",
        _backend_host(
            manifest["sidecar"]["listen_host"] if sidecar_enabled else subscription["internal_host"]
        ),
        int(manifest["sidecar"]["listen_port"] if sidecar_enabled else subscription["internal_port"]),
    )
    sni_route(panel_port, panel["domain"], "be_panel", True)
    sni_route(subscription_port, subscription["domain"], "be_subscription", True)
    backend("be_decoy_tls", decoy_host, decoy_tls_port)
    backend("be_decoy_h2c", decoy_host, decoy_h2c_port)
    backend("be_decoy_h2c_http", decoy_host, decoy_h2c_port, "proto h2", "http")
    compatible_backend = manifest.get("trusttunnel_backend") or {}
    if manifest["components"].get("trusttunnel_backend"):
        backend(
            "be_trusttunnel_compatible",
            "127.0.0.1",
            int(compatible_backend["listen_port"]),
        )

    trust_rules: dict[int, list[tuple[str, str, int, list[str]]]] = {}
    side_site_requests: list[tuple[int, str]] = []
    for route in routes:
        inbound_id = int(route["inbound_id"])
        protocol = by_id.get(inbound_id)
        if protocol is None:
            raise ValueError(f"extended route refers to missing inbound #{inbound_id}")
        strategy = str(route["strategy"])
        domain = str(route["domain"])
        domains = route.get("endpoint_domains") or [domain]
        ingresses = ingress_by_id[inbound_id]
        inbound_backend = f"be_inbound_{inbound_id}"
        inbound_host = _backend_host(route.get("internal_host") or protocol.get("internal_host"))
        inbound_port = int(route.get("internal_port") or protocol.get("internal_port"))

        # The compatible endpoint terminates TLS itself and owns only its
        # explicitly confirmed SNI. Its internal LucX listener remains intact
        # for rollback and is not placed behind this public route.
        if (
            manifest["components"].get("trusttunnel_backend")
            and domain.lower() == str(compatible_backend.get("public_domain") or "").lower()
        ):
            if protocol.get("protocol") not in {"trusttunnel", "trust-tunnel"}:
                raise ValueError("домен отдельного TrustTunnel backend уже принадлежит другому протоколу")
            for ingress_port, name, _kind in ingresses:
                if name == domain:
                    sni_route(ingress_port, name, "be_trusttunnel_compatible")
                else:
                    backend(inbound_backend, inbound_host, inbound_port)
                    sni_route(ingress_port, name, inbound_backend)
            continue

        if strategy == "tcp_side_site":
            for ingress_port, name, kind in ingresses:
                if kind == "site":
                    side_site_requests.append((ingress_port, name.strip().lower().rstrip(".")))
                else:
                    sni_route(ingress_port, name, "be_decoy_tls")
        elif strategy == "reality_endpoint_site":
            backend(inbound_backend, inbound_host, inbound_port)
            vpn_keys = {(port, name) for port, name, kind in ingresses if kind == "vpn"}
            for ingress_port, name, _kind in ingresses:
                target = inbound_backend if (ingress_port, name) in vpn_keys else "be_decoy_tls"
                sni_route(ingress_port, name, target)
        elif strategy in {"http_tls_split", "xhttp_tls_split", "binary_tls_split"}:
            split_backend = f"be_split_{inbound_id}"
            backend(split_backend, "127.0.0.1", split_ports[inbound_id])
            for ingress_port, name, _kind in ingresses:
                sni_route(ingress_port, name, split_backend)
        elif strategy == "trusttunnel_clienthello_split":
            material = (routing_material or {}).get(inbound_id) or (routing_material or {}).get(
                str(inbound_id)
            )
            if not isinstance(material, dict):
                raise ValueError(f"TrustTunnel inbound #{inbound_id} routing material is unavailable")
            prefix = _safe_clienthello_prefix(material.get("clienthello_hex_prefix"))
            backend(inbound_backend, inbound_host, inbound_port)
            split_backend = f"be_split_{inbound_id}"
            backend(split_backend, "127.0.0.1", split_ports[inbound_id])
            for ingress_port in sorted({port for port, _, _ in ingresses}):
                names = list(dict.fromkeys(name for port, name, _ in ingresses if port == ingress_port))
                trust_rules.setdefault(ingress_port, []).append(
                    (f"trust_clienthello_{inbound_id}", prefix, len(prefix) // 2, names))
            for ingress_port, name, _kind in ingresses:
                sni_route(ingress_port, name, split_backend)
        elif strategy == "naive_connect_h2":
            for ingress_port, name, _kind in ingresses:
                target_name = f"be_naive_split_{inbound_id}_{ingress_port}"
                backend(target_name, "127.0.0.1", naive_split_ports[inbound_id, ingress_port])
                sni_route(ingress_port, name, target_name)
        elif strategy == "blocked_passthrough":
            backend(inbound_backend, inbound_host, inbound_port)
            for ingress_port, name, _kind in ingresses:
                sni_route(ingress_port, name, inbound_backend)
        elif strategy in {"naive_native", "naive_managed"}:
            target_port = inbound_port
            target_name = inbound_backend
            if strategy == "naive_managed":
                target_port = int(route["managed_listen_port"])
                target_name = f"be_naive_frontend_{inbound_id}"
                # The generated managed Caddyfile always binds loopback even
                # when the original LucX listener used another address.
                backend(target_name, "127.0.0.1", target_port)
            else:
                backend(target_name, inbound_host, target_port)
            for ingress_port, name, _kind in ingresses:
                sni_route(ingress_port, name, target_name)
        else:
            raise ValueError(f"unsupported ready extended strategy: {strategy}")

    # Чистый сайт на общем домене уступает уже подтверждённому VPN-маршруту.
    for ingress_port, name in side_site_requests:
        if not any(existing == name for existing, _, _ in groups.get(ingress_port, [])):
            sni_route(ingress_port, name, "be_decoy_tls")

    # Standalone decoy sites (for example the DNS zone root) are not owned by
    # any inbound: they always serve the Nginx decoy frontend.
    routed_domains = {str(domain).lower() for item in routes
                      for domain in item.get("endpoint_domains") or [item.get("domain") or ""]}
    routed_snis = {
        str(name).lower()
        for item in routes
        for name in [item.get("domain"), *(item.get("sni_names") or [])]
        if name
    }
    for site in (manifest.get("decoys") or {}).get("sites") or []:
        domain = str(site.get("domain") or "").lower().rstrip(".")
        if not domain or valid_domain(domain) is False:
            continue
        if domain in routed_domains or domain in routed_snis or any(name == domain for name, _, _ in groups.get(public_port, [])):
            continue
        sni_route(public_port, domain, "be_decoy_tls")

    return _ExtendedFrontendPlan(routes, ingress_by_id, split_ports, naive_split_ports, groups, backends,
                                 trust_rules, bind_address, cloudflare_only)


def _runtime_listener_inventory(
    manifest: dict[str, Any], plan: _ExtendedFrontendPlan,
) -> tuple[ListenerKey, ...]:
    """Точный набор owned listeners только для поддержанного минимального пути."""
    components = manifest.get("components") or {}
    decoys = manifest.get("decoys") or {}
    inbound_ids = [protocol.get("inbound_id") for protocol in manifest.get("protocols") or []]
    if (any(type(value) is not int or value <= 0 for value in inbound_ids)
            or len(inbound_ids) != len(set(inbound_ids))):
        raise ValueError("Runtime требует уникальные целочисленные inbound identities")
    if (decoys.get("routing_mode") != "extended" or decoys.get("enabled") is not True
            or not decoys.get("sites")
            or any(components.get(name) is not True for name in ("haproxy", "nginx", "extended_tls_split"))
            or components.get("naive_frontend") or components.get("trusttunnel_backend")):
        raise ValueError("Runtime поддерживает только полный extended HAProxy/Nginx frontend")
    if (not plan.routes or len(plan.routes) != len(manifest.get("protocols") or [])
            or any(not ((route.get("status") == "ready"
                         and route.get("strategy") in {"http_tls_split", "xhttp_tls_split"})
                        or (route.get("status") == "rendered_candidate"
                            and route.get("strategy") == "naive_connect_h2"))
                   for route in plan.routes)
            or any(protocol.get("protocol") not in {"vless", "vmess", "naive"}
                   or protocol.get("network") != "tcp"
                   or (protocol.get("security") != "tls" and protocol.get("protocol") != "naive")
                   or protocol.get("exposure") != "tcp_sni"
                   for protocol in manifest.get("protocols") or [])):
        raise ValueError("Runtime не поддерживает весь набор маршрутов исходного плана")
    return (*(ListenerKey("public", port) for port in sorted(plan.groups)),
            *(ListenerKey("split", inbound_id) for inbound_id in sorted(plan.split_ports)),
            *(ListenerKey("split", inbound_id, ingress_port=port) for inbound_id, port in sorted(plan.naive_split_ports)),
            ListenerKey("decoy_tls"), ListenerKey("decoy_h2c"), ListenerKey("decoy_plain"))


def frontend_listener_inventory(
    manifest: dict[str, Any], *, routing_material: dict[int | str, dict[str, Any]] | None = None,
) -> tuple[ListenerKey, ...]:
    """Inventory использует тот же проверенный план, что фактический renderer."""
    try:
        return _runtime_listener_inventory(manifest, _extended_frontend_plan(manifest, routing_material))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        raise ValueError("Не удалось проверить набор listeners frontend") from None


def _runtime_material_inventory(
    manifest: dict[str, Any], plan: _ExtendedFrontendPlan,
) -> Mapping[str, Literal["file", "directory"]]:
    _runtime_listener_inventory(manifest, plan)
    certificate = "/etc/lucx-post-configurator/tls/certificate.pem"
    result: dict[str, Literal["file", "directory"]] = {path: "file" for path in (certificate, certificate + ".key",
              manifest["certificates"]["cert_path"], manifest["certificates"]["key_path"],
              *(route["backend_tls_policy"]["ca_file"] for route in plan.routes))}
    if plan.cloudflare_only:
        result["/etc/haproxy/cloudflare-ips.lst"] = "file"
    for site in manifest["decoys"]["sites"]:
        path = site["root"]
        if path in result and result[path] != "directory":
            raise ValueError("Материалы frontend имеют несовместимые типы")
        result[path] = "directory"
    source_paths = {route["source_identity"]["path"] for route in plan.routes
                    if route.get("strategy") == "naive_connect_h2"}
    if any(path == source or source.startswith(path + "/") or path.startswith(source + "/")
           for path in result for source in source_paths):
        raise ValueError("Исходный Naive Caddyfile не является копируемым материалом frontend")
    if any(type(path) is not str or re.fullmatch(r"/[A-Za-z0-9_./-]+", path) is None
           or any(part in {"", ".", ".."} for part in path.split("/")[1:]) for path in result):
        raise ValueError("Небезопасный путь материала frontend")
    if any(first != second and second.startswith(first + "/") for first in result for second in result):
        raise ValueError("Материалы frontend не должны перекрываться")
    return MappingProxyType(result)


def frontend_material_inventory(
    manifest: dict[str, Any], *, routing_material: dict[int | str, dict[str, Any]] | None = None,
) -> Mapping[str, Literal["file", "directory"]]:
    """Точные file/directory материалы из того же проверенного плана frontend."""
    try:
        return _runtime_material_inventory(manifest, _extended_frontend_plan(manifest, routing_material))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        raise ValueError("Не удалось проверить набор материалов frontend") from None


def _validate_render_runtime(
    manifest: dict[str, Any], plan: _ExtendedFrontendPlan, runtime: RenderRuntime,
) -> None:
    if type(runtime) is not RenderRuntime:
        raise ValueError("Renderer ожидает типизированный RenderRuntime")
    expected = _runtime_listener_inventory(manifest, plan)
    if set(runtime.listeners) != set(expected):
        raise ValueError("Runtime содержит пропущенные или лишние listener-роли")
    occupied = reserved_listener_ports(manifest) | set(plan.split_ports.values())
    occupied.update(target[1] for target in plan.backends.values())
    if occupied & {address.port for address in runtime.listeners.values()}:
        raise ValueError("Listener runtime пересекается с существующим портом")
    certificate = "/etc/lucx-post-configurator/tls/certificate.pem"
    key = certificate + ".key"
    allowed_paths = set(_runtime_material_inventory(manifest, plan))
    if set(runtime.paths) - allowed_paths or set(runtime.paths.values()) & allowed_paths:
        raise ValueError("Runtime содержит неизвестный путь либо ссылку на исходный материал")
    source_paths = {route["source_identity"]["path"] for route in plan.routes
                    if route.get("strategy") == "naive_connect_h2"}
    if any(path == source or source.startswith(path + "/") or path.startswith(source + "/")
           for path in runtime.paths.values() for source in source_paths):
        raise ValueError("Runtime не может затрагивать исходный Naive Caddyfile")
    if ((certificate in runtime.paths) != (key in runtime.paths)
            or (certificate in runtime.paths and runtime.path(key) != runtime.path(certificate) + ".key")):
        raise ValueError("Runtime обязан сохранить согласованную пару HAProxy certificate/key")


def _render_haproxy_extended(
    manifest: dict[str, Any], routing_material: dict[int | str, dict[str, Any]] | None,
    runtime: RenderRuntime | None = None,
) -> str:
    plan = _extended_frontend_plan(manifest, routing_material)
    routes, ingress_by_id, split_ports = plan.routes, plan.ingress_by_id, plan.split_ports
    groups, trust_rules = plan.groups, plan.trust_rules
    bind_address, cloudflare_only = plan.bind_address, plan.cloudflare_only
    bind_host = "*" if bind_address in {"0.0.0.0", "::"} else (
        f"[{bind_address}]" if ":" in bind_address else bind_address
    )
    backends = dict(plan.backends)
    if runtime is not None:
        _validate_render_runtime(manifest, plan, runtime)
        owned_backends = {"be_decoy_tls": ListenerKey("decoy_tls"),
                          "be_decoy_h2c": ListenerKey("decoy_h2c"),
                          "be_decoy_h2c_http": ListenerKey("decoy_h2c"),
                          **{f"be_split_{inbound_id}": ListenerKey("split", inbound_id)
                             for inbound_id in split_ports},
                          **{f"be_naive_split_{inbound_id}_{port}": ListenerKey("split", inbound_id, ingress_port=port)
                             for inbound_id, port in plan.naive_split_ports}}
        for name, listener_key in owned_backends.items():
            address = runtime.listeners[listener_key]
            _host, _port, options, mode = backends[name]
            backends[name] = (_backend_host(address.host), address.port, options, mode)

    def backend(name: str, host: str, port: int, options: str = "", mode: str = "tcp") -> None:
        target = (host, port, options, mode)
        previous = backends.get(name)
        if previous is not None and previous != target:
            raise ValueError(f"backend {name} has conflicting targets")
        backends[name] = target

    lines = [
        "# Managed by lucx-post-configurator. Local edits will be replaced.",
        "global",
        *([] if runtime is not None and runtime.suppress_system_log else [
            "    log /dev/log local0", "    log /dev/log local1 notice"]),
        "    user haproxy",
        "    group haproxy",
        *([] if runtime is not None and runtime.foreground else ["    daemon"]),
        "",
        "defaults",
        *([] if runtime is not None and runtime.suppress_system_log else ["    log global"]),
        "    mode tcp",
        *([] if runtime is not None and runtime.suppress_system_log else ["    option tcplog"]),
        "    timeout connect 5s",
        "    timeout client 1m",
        "    timeout server 1m",
    ]

    for frontend_port, group in sorted(groups.items()):
        known_sni_acl = _acl_name("known_sni", str(frontend_port))
        listener = (runtime.listeners[ListenerKey("public", frontend_port)].authority
                    if runtime is not None else f"{bind_host}:{frontend_port}")
        lines.extend(
            [
                "",
                f"frontend lucx_tls_{frontend_port}",
                f"    bind {listener}",
                "    mode tcp",
                "    tcp-request inspect-delay 5s",
                "    acl is_tls req.ssl_hello_type 1",
            ]
        )
        acl_routes: list[tuple[str, str, bool]] = []
        for index, (domain, target, protected) in enumerate(group, start=1):
            acl = _acl_name(f"sni_{frontend_port}_{index}", domain)
            lines.append(f"    acl {acl} req.ssl_sni -i {domain}")
            lines.append(f"    acl {known_sni_acl} req.ssl_sni -i {domain}")
            acl_routes.append((target, acl, protected))
        for acl, prefix, length, names in trust_rules.get(frontend_port, []):
            lines.append(f"    acl {acl} req.payload(11,{length}),hex -m str -i {prefix}")
            lines.append(f"    acl {acl}_sni req.ssl_sni -i " + " ".join(names))
        protected_routes = [item for item in acl_routes if item[2]]
        if cloudflare_only and protected_routes:
            cloudflare_acl = "/etc/haproxy/cloudflare-ips.lst"
            if runtime is not None:
                cloudflare_acl = runtime.path(cloudflare_acl)
            lines.append(f"    acl from_cloudflare src -f {cloudflare_acl}")
            local_sources = ["127.0.0.0/8", "::1"]
            if bind_address not in {"0.0.0.0", "::"}:
                local_sources.append(bind_address)
            lines.append("    acl from_local_health src " + " ".join(local_sources))
            for _target, acl, _protected in protected_routes:
                lines.append(
                    f"    tcp-request content reject if is_tls {acl} !from_cloudflare !from_local_health"
                )
        public_port = int(manifest.get("network", {}).get("public_port", 443))
        unknown_to_decoy = (
            frontend_port == public_port
            and manifest.get("network", {}).get("unknown_sni_action") == "decoy"
        )
        all_acls = [item[1] for item in acl_routes]
        if not unknown_to_decoy and all_acls:
            lines.append(f"    tcp-request content reject if is_tls !{known_sni_acl}")
        lines.append("    tcp-request content accept if is_tls")
        lines.append("    tcp-request content reject if !is_tls")
        for acl, _prefix, _length, _names in trust_rules.get(frontend_port, []):
            inbound_id = int(acl.rsplit("_", 1)[1])
            lines.append(f"    use_backend be_inbound_{inbound_id} if {acl} {acl}_sni")
        for target, acl, _protected in acl_routes:
            lines.append(f"    use_backend {target} if {acl}")
        if unknown_to_decoy:
            lines.append("    default_backend be_decoy_tls")

    certificate = "/etc/lucx-post-configurator/tls/certificate.pem"
    if runtime is not None:
        certificate = runtime.path(certificate)
    h2_preface = "505249202A20485454502F322E300D0A0D0A534D0D0A0D0A"
    http1_prefixes = (
        "47455420",
        "4845414420",
        "504F535420",
        "50555420",
        "504154434820",
        "4F5054494F4E5320",
        "44454C45544520",
        "434F4E4E45435420",
    )
    for route in sorted(
        (
            item
            for item in routes
            if item.get("strategy") in {"http_tls_split", "xhttp_tls_split", "binary_tls_split", "trusttunnel_clienthello_split"}
        ),
        key=lambda item: int(item["inbound_id"]),
    ):
        inbound_id = int(route["inbound_id"])
        strategy = str(route["strategy"])
        split_listener = (runtime.listeners[ListenerKey("split", inbound_id)].authority
                          if runtime is not None else f"127.0.0.1:{split_ports[inbound_id]}")
        host = _backend_host(route["internal_host"])
        port = int(route["internal_port"])
        names = list(dict.fromkeys(route.get("sni_names") or []))
        if route["domain"] in names or not names:
            sni = str(route["domain"])
        elif len(names) == 1:
            sni = str(names[0])
        else:
            raise ValueError(f"inbound #{inbound_id}: TLS SNI backend неоднозначен")
        ca_file = route["backend_tls_policy"]["ca_file"]
        if runtime is not None:
            ca_file = runtime.path(ca_file)
        tls_options = f"ssl verify required ca-file {ca_file} verifyhost {sni} sni str({sni})"
        options = tls_options
        alpns = [str(value) for value in route.get("alpn") or [] if value]
        if any(value not in {"h2", "http/1.1"} for value in alpns):
            raise ValueError(f"inbound #{inbound_id}: неподтверждённый ALPN для TCP TLS backend")
        if alpns:
            options += " alpn " + ",".join(alpns)
        if strategy in {"http_tls_split", "xhttp_tls_split"}:
            from .extended_decoys import grpc_method_paths

            transport = str(route.get("transport") or "")
            if transport == "grpc":
                paths = grpc_method_paths(str(route.get("transport_path") or ""))
                if not paths:
                    raise ValueError(f"inbound #{inbound_id}: неизвестный gRPC serviceName")
                paths = [_safe_http_path(value, inbound_id) for value in paths]
                path = paths[0]
            else:
                path = _safe_http_path(route.get("transport_path"), inbound_id)
                paths = [path]
            valid_transport_hosts = [
                value for value in (route.get("transport_hosts") or [])
                if valid_domain(value) and not value.startswith("*.")
            ]
            if "endpoint_domains" not in route:
                raise ValueError(f"inbound #{inbound_id}: route missing endpoint_domains")
            hosts = list(valid_transport_hosts or route["endpoint_domains"])
            if any(not valid_domain(value) or value.startswith("*.") for value in hosts):
                raise ValueError(f"inbound #{inbound_id}: unsafe HTTP Host matcher")
            ingress_ports = sorted({port for port, _, _ in ingress_by_id[inbound_id]})
            request_hosts = list(dict.fromkeys([
                *hosts, *(route.get("endpoint_domains") or [])]))
            request_hosts = [value for name in request_hosts
                             for value in [name, *(f"{name}:{number}" for number in ingress_ports)]]
            hosts = list(dict.fromkeys(value for host in hosts for value in [host, *(f"{host}:{port}" for port in ingress_ports)]))
            protocol_conditions = [
                f"protocol_path_{inbound_id}",
                f"protocol_host_{inbound_id}",
            ]
            protocol_acls: list[str] = []
            if transport in {"ws", "httpupgrade"}:
                protocol_acls.extend(
                    [
                        f"    acl protocol_connection_{inbound_id} hdr(Connection) -m reg -i (^|,)[[:space:]]*upgrade[[:space:]]*(,|$)",
                        f"    acl protocol_upgrade_{inbound_id} hdr(Upgrade) -i websocket",
                        f"    acl protocol_method_{inbound_id} method GET",
                    ]
                )
                protocol_conditions.extend(
                    [
                        f"protocol_connection_{inbound_id}",
                        f"protocol_upgrade_{inbound_id}",
                        f"protocol_method_{inbound_id}",
                    ]
                )
            elif transport == "grpc":
                protocol_acls.append(
                    f"    acl protocol_grpc_{inbound_id} req.hdr(content-type) -m reg -i ^application/grpc([+;]|$)"
                )
                protocol_acls.append(f"    acl protocol_method_{inbound_id} method POST")
                protocol_conditions.extend([f"protocol_grpc_{inbound_id}", f"protocol_method_{inbound_id}"])
            elif transport == "xhttp":
                if path == "/":
                    raise ValueError(
                        f"XHTTP inbound #{inbound_id} needs a dedicated non-root path"
                    )
            else:
                raise ValueError(
                    f"HTTP transport {transport or 'unknown'} has no unambiguous browser/VPN matcher"
                )
            if transport == "httpupgrade":
                # HTTPUpgrade использует неполный WebSocket handshake. Сохраняем
                # исходные байты запроса и 101, не пропуская VPN через HTTP mux.
                match = " ".join(protocol_conditions)
                lines.extend([
                    "", f"frontend lucx_split_{inbound_id}",
                    f"    bind {split_listener} ssl crt {certificate} alpn h2,http/1.1",
                    "    mode tcp", "    tcp-request inspect-delay 5s",
                    f"    acl protocol_path_{inbound_id} path {path}",
                    f"    acl protocol_host_{inbound_id} hdr(host) -i " + " ".join(hosts),
                    f"    acl request_host_{inbound_id} hdr(host) -i " + " ".join(request_hosts),
                    *protocol_acls,
                    "    tcp-request content switch-mode http proto h2 if { ssl_fc_alpn -m str h2 }",
                    "    tcp-request content reject if HTTP !{ hdr_cnt(host) eq 1 }",
                    f"    tcp-request content reject if HTTP !request_host_{inbound_id}",
                    f"    tcp-request content set-var(sess.vpn_upgrade) bool(true) if HTTP {match}",
                    "    tcp-request content accept if { var(sess.vpn_upgrade) -m bool }",
                    "    tcp-request content switch-mode http if HTTP",
                    "    tcp-request content reject if WAIT_END",
                    "    http-request deny deny_status 400 unless { hdr_cnt(host) eq 1 }",
                    f"    http-request deny deny_status 421 unless request_host_{inbound_id}",
                    "    http-request deny deny_status 400 if { hdr_cnt(upgrade) gt 0 }",
                    "    http-request deny deny_status 405 unless { method GET HEAD }",
                    *([f"    http-request deny deny_status 400 if protocol_path_{inbound_id}"] if path != "/" else []),
                    f"    use_backend be_http_reencrypt_{inbound_id} if {{ var(sess.vpn_upgrade) -m bool }}",
                    "    default_backend be_decoy_h2c_http",
                ])
                backend(f"be_http_reencrypt_{inbound_id}", host, port,
                        tls_options + " alpn http/1.1", "tcp")
                continue
            lines.extend(
                [
                    "",
                    f"frontend lucx_split_{inbound_id}",
                    f"    bind {split_listener} ssl crt {certificate} alpn h2,http/1.1",
                    "    mode http",
                    *(
                        [
                            f"    acl protocol_path_{inbound_id} path {path}",
                            f"    acl protocol_path_{inbound_id} path_beg {path.rstrip('/')}/",
                        ]
                        if transport == "xhttp"
                        else [f"    acl protocol_path_{inbound_id} path " + " ".join(paths)]
                    ),
                    f"    acl protocol_host_{inbound_id} hdr(host) -i "
                    + " ".join(str(value) for value in hosts),
                    *protocol_acls,
                    f"    acl request_host_{inbound_id} hdr(host) -i " + " ".join(request_hosts),
                    "    http-request deny deny_status 400 unless { hdr_cnt(host) eq 1 }",
                    f"    http-request deny deny_status 421 unless request_host_{inbound_id}",
                    "    http-request set-var(txn.vpn_route) bool(true) if " + " ".join(protocol_conditions),
                    "    http-request deny deny_status 400 if { hdr_cnt(upgrade) gt 0 } !{ var(txn.vpn_route) -m bool }",
                    "    http-request deny deny_status 400 if { hdr(Connection) -m reg -i (^|,)[[:space:]]*upgrade[[:space:]]*(,|$) } !{ var(txn.vpn_route) -m bool }",
                    "    http-request deny deny_status 405 if !{ method GET HEAD } !{ var(txn.vpn_route) -m bool }",
                    *([f"    http-request deny deny_status 400 if protocol_path_{inbound_id} !{{ var(txn.vpn_route) -m bool }}"]
                      if path != "/" else []),
                    f"    use_backend be_http_reencrypt_{inbound_id} if "
                    + " ".join(protocol_conditions),
                    "    default_backend be_decoy_h2c_http",
                ]
            )
            if transport in {"ws", "httpupgrade"}:
                options = tls_options + " alpn http/1.1"
            elif transport == "grpc":
                options = tls_options + " alpn h2 proto h2"
            backend(f"be_http_reencrypt_{inbound_id}", host, port, options, "http")
        elif strategy == "trusttunnel_clienthello_split":
            split_backend_tt = f"be_trusttunnel_{inbound_id}"
            lines.extend(
                [
                    "",
                    f"frontend lucx_split_{inbound_id}",
                    f"    bind {split_listener} ssl crt {certificate} alpn h2,http/1.1",
                    "    mode http",
                    "    acl is_connect method CONNECT",
                    "    acl is_proxy_auth req.hdr(Proxy-Authorization) -m found",
                    "    http-request deny deny_status 405 unless { method GET HEAD CONNECT }",
                    f"    use_backend {split_backend_tt} if is_connect or is_proxy_auth",
                    "    default_backend be_decoy_h2c_http",
                ]
            )
            backend(
                split_backend_tt,
                host,
                port,
                f"ssl verify none sni str({sni}) alpn h2 proto h2",
                "http",
            )
        else:
            material = (
                (routing_material or {}).get(inbound_id)
                or (routing_material or {}).get(str(inbound_id))
                or {}
            )
            raw_hashes = material.get("auth_sha256_hashes") or []
            hashes = [
                str(h).strip().lower()
                for h in raw_hashes
                if re.fullmatch(r"[0-9a-fA-F]{64}", str(h).strip())
            ]
            split_rules = [
                f"    acl is_http1 req.payload(0,16),hex -m beg {prefix}"
                for prefix in http1_prefixes
            ]
            split_rules.append(f"    acl is_http2 req.payload(0,24),hex -m str {h2_preface}")
            if hashes:
                split_rules.append(
                    "    acl is_anytls_auth req.payload(0,32),hex -m str -i "
                    + " ".join(hashes)
                )
                split_rules.extend(
                    [
                        "    tcp-request content accept if is_anytls_auth",
                        "    tcp-request content accept if is_http1",
                        "    tcp-request content accept if is_http2",
                        f"    use_backend be_reencrypt_{inbound_id} if is_anytls_auth",
                        "    default_backend be_decoy_h2c",
                    ]
                )
            else:
                split_rules.extend(
                    [
                        "    tcp-request content accept if is_http1",
                        "    tcp-request content accept if is_http2",
                        "    use_backend be_decoy_h2c if is_http1",
                        "    use_backend be_decoy_h2c if is_http2",
                        f"    default_backend be_reencrypt_{inbound_id}",
                    ]
                )
            lines.extend(
                [
                    "",
                    f"frontend lucx_split_{inbound_id}",
                    f"    bind {split_listener} ssl crt {certificate} alpn h2,http/1.1",
                    "    mode tcp",
                    "    tcp-request inspect-delay 5s",
                    *split_rules,
                ]
            )
            backend(f"be_reencrypt_{inbound_id}", host, port, options)

    for route in sorted(routes, key=lambda item: int(item["inbound_id"])):
        if route.get("strategy") != "naive_connect_h2":
            continue
        inbound_id = int(route["inbound_id"])
        target_name = f"be_naive_existing_{inbound_id}"
        ca_file = route["backend_tls_policy"]["ca_file"]
        if runtime is not None:
            ca_file = runtime.path(ca_file)
        sni = route["backend_sni"]
        backend(target_name, _backend_host(route["internal_host"]), int(route["internal_port"]),
                f"ssl verify required ca-file {ca_file} verifyhost {sni} sni str({sni}) alpn h2 proto h2", "http")
        for (owner, ingress_port), split_port in sorted(plan.naive_split_ports.items()):
            if owner != inbound_id:
                continue
            listener = (runtime.listeners[ListenerKey("split", inbound_id, ingress_port=ingress_port)].authority
                        if runtime is not None else f"127.0.0.1:{split_port}")
            ingresses = [list(item) for item in ingress_by_id[inbound_id] if item[0] == ingress_port]
            lines.extend(["", f"frontend lucx_naive_split_{inbound_id}_{ingress_port}",
                f"    bind {listener} ssl crt {certificate} alpn h2,http/1.1", "    mode http",
                *_naive_connect_http_guards(ingresses, (ingress_port,),
                    vpn_backend=target_name, site_backend="be_decoy_h2c_http")])

    for name, (host, port, options, mode) in backends.items():
        lines.extend(["", f"backend {name}", f"    mode {mode}"])
        suffix = f" {options}" if options else ""
        lines.append(f"    server local {host}:{port}{suffix}")
    return "\n".join(lines) + "\n"


def _naive_connect_http_guards(
    ingresses: list[list[Any]], browser_ports: tuple[int, ...], *, vpn_backend: str, site_backend: str,
) -> list[str]:
    """Общие HTTP guards; CONNECT authority остаётся адресом назначения туннеля."""
    owned = sorted({name for _, name, _ in ingresses})
    vpn = sorted({name for _, name, kind in ingresses if kind == "vpn"})
    sites = sorted({name for _, name, kind in ingresses if kind == "site"})
    authorities = [value for name in sites for value in (name, *(f"{name}:{port}" for port in browser_ports))]
    lines = ["    acl owned_sni ssl_fc_sni -i " + " ".join(owned),
        "    acl site_host hdr(host) -i " + " ".join(authorities),
        "    http-request deny deny_status 421 unless owned_sni",
        "    http-request deny deny_status 405 unless { method GET HEAD CONNECT }",
        "    http-request deny deny_status 400 if { hdr_cnt(upgrade) gt 0 }",
        "    http-request deny deny_status 400 if { hdr(Connection) -m reg -i (^|,)[[:space:]]*upgrade[[:space:]]*(,|$) }",
        "    http-request deny deny_status 400 if !{ method CONNECT } !{ hdr_cnt(host) eq 1 }",
        "    http-request deny deny_status 421 if !{ method CONNECT } !site_host",
        "    http-request deny deny_status 400 if { method CONNECT } !{ ssl_fc_alpn -m str h2 }"]
    for index, name in enumerate(sites):
        # Разные принадлежащие имена также не разрешают несовпадение SNI/Host.
        authorities = " ".join((name, *(f"{name}:{port}" for port in browser_ports)))
        lines.extend([f"    acl browser_sni_{index} ssl_fc_sni -i {name}",
            f"    acl browser_host_{index} hdr(host) -i {authorities}",
            f"    http-request deny deny_status 421 if !{{ method CONNECT }} browser_host_{index} !browser_sni_{index}"])
    if vpn:
        lines.extend(["    acl vpn_sni ssl_fc_sni -i " + " ".join(vpn),
            "    http-request deny deny_status 421 if { method CONNECT } !vpn_sni",
            f"    use_backend {vpn_backend} if {{ method CONNECT }} vpn_sni"])
    else:
        lines.append("    http-request deny deny_status 421 if { method CONNECT }")
    lines.append(f"    default_backend {site_backend}")
    return lines


def render_naive_connect_candidate(
    manifest: dict[str, Any], candidate: dict[str, Any], source_material: dict[str, Any],
    *, listen_ports: dict[int, int] | None = None, runtime: RenderRuntime | None = None,
) -> str:
    """Изолированный loopback renderer для будущего Engine staging assembler.

    Ровно один способ подстановки: прежний listen_ports либо типизированный runtime.
    Runtime переносит frontend/site listeners и точные private TLS материалы.
    source_material содержит только ephemeral source + актуальную audit metadata.
    Результат не подключается к render_files и не разрешает production/ready.
    """
    from .extended_decoys import classify_naive_connect_candidate
    from .models import Audit

    source = source_material.get("naive_caddyfile_text")
    metadata = source_material.get("naive_source_metadata")
    if (not isinstance(source, str) or not isinstance(metadata, dict)
            or len(source.encode("utf-8")) > 1024 * 1024
            or hashlib.sha256(source.encode("utf-8")).hexdigest() != metadata.get("sha256")):
        raise ValueError("Ephemeral source Naive изменился или не подтверждён")
    fresh = classify_naive_connect_candidate(manifest, Audit(naive_caddyfile={"files": [metadata]}), candidate.get("inbound_id"))
    if fresh != candidate:
        raise ValueError("Naive CONNECT candidate устарел; требуется новый audit")
    public_ports = {item[0] for item in fresh["public_ingresses"]}
    certificate = "/etc/lucx-post-configurator/tls/certificate.pem"
    ca_file = fresh["backend_tls_policy"]["ca_file"]
    if (listen_ports is None) == (runtime is None):
        raise ValueError("Нужен ровно один способ подстановки listeners кандидата")
    if runtime is None:
        if (not isinstance(listen_ports, dict) or set(listen_ports) != public_ports
                or any(type(port) is not int or not 1 <= port <= 65535 for port in [*listen_ports, *listen_ports.values()])
                or len(set(listen_ports.values())) != len(listen_ports)
                or set(listen_ports.values()) & reserved_listener_ports(manifest)):
            raise ValueError("Нужны отдельные staging-порты для всех публичных endpoints")
    else:
        if type(runtime) is not RenderRuntime:
            raise ValueError("Кандидат ожидает типизированный RenderRuntime")
        expected = {*(ListenerKey("public", port) for port in public_ports), ListenerKey("decoy_h2c")}
        if set(runtime.listeners) != expected:
            raise ValueError("Runtime кандидата содержит пропущенные или лишние listener-роли")
        if {address.port for address in runtime.listeners.values()} & reserved_listener_ports(manifest):
            raise ValueError("Listener runtime кандидата пересекается с существующим портом")
        if (set(runtime.paths) != {certificate, ca_file}
                or fresh["source_identity"]["path"] in runtime.paths
                or set(runtime.paths.values()) & {certificate, ca_file, fresh["source_identity"]["path"]}):
            raise ValueError("Runtime кандидата требует точные private TLS материалы без исходного Naive")
        certificate, ca_file = runtime.path(certificate), runtime.path(ca_file)
    site = fresh["site_listener"]
    try:
        site_host = ipaddress.ip_address(str(site["host"]).strip("[]"))
    except ValueError as exc:
        raise ValueError("Сайт кандидата должен слушать loopback") from exc
    if not site_host.is_loopback or type(site["port"]) is not int or not 1 <= site["port"] <= 65534:
        raise ValueError("Сайт кандидата должен слушать loopback h2c")
    site_listener = (runtime.listeners[ListenerKey("decoy_h2c")].authority if runtime is not None
        else f"{_backend_host(str(site_host))}:{site['port'] + 1}")
    lines = ["global", "    maxconn 256", "defaults", "    mode http",
        "    timeout connect 5s", "    timeout client 30s", "    timeout server 30s"]
    for public_port in sorted(public_ports):
        listener = (runtime.listeners[ListenerKey("public", public_port)].authority if runtime is not None
            else f"127.0.0.1:{listen_ports[public_port]}")
        browser_ports = (public_port,) if runtime is not None else (public_port, listen_ports[public_port])
        ingresses = [item for item in fresh["public_ingresses"] if item[0] == public_port]
        lines.extend(["", f"frontend naive_candidate_{public_port}",
            f"    bind {listener} ssl crt {certificate} alpn h2,http/1.1",
            *_naive_connect_http_guards(ingresses, browser_ports,
                vpn_backend="naive_existing", site_backend="naive_site")])
    host = _backend_host(fresh["internal_host"])
    sni = fresh["backend_sni"]
    lines.extend(["", "backend naive_existing", "    mode http",
        f"    server existing {host}:{fresh['internal_port']} ssl verify required ca-file {ca_file} verifyhost {sni} sni str({sni}) alpn h2 proto h2",
        "", "backend naive_site", "    mode http",
        f"    server existing {site_listener} proto h2"])
    return "\n".join(lines) + "\n"


def render_haproxy(
    manifest: dict[str, Any],
    routing_material: dict[int | str, dict[str, Any]] | None = None,
    *, runtime: RenderRuntime | None = None,
) -> str:
    if str((manifest.get("decoys") or {}).get("routing_mode") or "strict") == "extended":
        return _render_haproxy_extended(manifest, routing_material, runtime)
    if runtime is not None:
        raise ValueError("Runtime не поддерживает strict renderer")
    return _render_haproxy_strict(manifest)


def render_nginx_decoys(manifest: dict[str, Any], *, runtime: RenderRuntime | None = None,
                       routing_material: dict[int | str, dict[str, Any]] | None = None) -> str:
    if runtime is not None:
        _validate_render_runtime(manifest, _extended_frontend_plan(manifest, routing_material), runtime)
    decoys = manifest["decoys"]
    cert = manifest["certificates"]["cert_path"]
    key = manifest["certificates"]["key_path"]
    listen_host = decoys["listen_host"]
    listen_port = int(decoys["listen_port"])
    extended = str(decoys.get("routing_mode") or "strict") == "extended"
    plain_listen_port = listen_port + 2
    tls_listener = f"{listen_host}:{listen_port}"
    plain_listener = f"{listen_host}:{plain_listen_port}"
    h2c_listener = f"{listen_host}:{listen_port + 1}"
    if runtime is not None:
        cert, key = runtime.path(cert), runtime.path(key)
        tls_listener = runtime.listeners[ListenerKey("decoy_tls")].authority
        plain_listener = runtime.listeners[ListenerKey("decoy_plain")].authority
        h2c_listener = runtime.listeners[ListenerKey("decoy_h2c")].authority
    h2c_listen = (
        f"    listen {h2c_listener} http2;" if extended else ""
    )
    lines = ["# Managed by lucx-post-configurator. Naive Caddyfile is intentionally unrelated."]
    if decoys.get("default_server"):
        lines.extend(
            [
                "server {",
                f"    listen {tls_listener} ssl default_server;",
                *([h2c_listen] if h2c_listen else []),
                "    server_name _;",
                f"    ssl_certificate {cert};",
                f"    ssl_certificate_key {key};",
                "    ssl_protocols TLSv1.2 TLSv1.3;",
                "    return 404;",
                "}",
                "",
            ]
        )
    for site in decoys.get("sites", []):
        site_root = runtime.path(site["root"]) if runtime is not None else site["root"]
        lines.extend(
            [
                "server {",
                f"    listen {tls_listener} ssl http2;",
                *([f"    listen {plain_listener};"] if extended else []),
                *([h2c_listen] if h2c_listen else []),
                f"    server_name {site['domain']};",
                '    if ($http_host = "") { return 400; }',
                f'    if ($host != "{site["domain"]}") {{ return 421; }}',
                f"    ssl_certificate {cert};",
                f"    ssl_certificate_key {key};",
                "    ssl_protocols TLSv1.2 TLSv1.3;",
                "    server_tokens off;",
                f'    add_header X-LucX-Decoy "{site["domain"]}" always;',
                f"    root {site_root};",
                "    index index.html;",
                "    location / { try_files $uri $uri/ /index.html =404; }",
                "}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_decoy_index(domain: str) -> str:
    safe_domain = domain.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>Service available</title>
  <style>body{{font:16px system-ui,sans-serif;max-width:44rem;margin:12vh auto;padding:2rem;color:#27313a}}main{{border:1px solid #d9e0e6;border-radius:12px;padding:2rem}}h1{{font-size:1.5rem}}</style>
</head>
<body><main><h1>Service available</h1><p>{safe_domain}</p></main></body>
</html>
"""


def render_nginx_http_redirect() -> str:
    """Redirect all plain HTTP traffic on port 80 to HTTPS preserving host and request URI."""
    return (
        "# Managed by lucx-post-configurator: redirect all plain HTTP to HTTPS.\n"
        "server {\n"
        "    listen 80 default_server;\n"
        "    listen [::]:80 default_server;\n"
        "    server_name _;\n"
        "    return 301 https://$host$request_uri;\n"
        "}\n"
    )


def _protected_trusttunnel_ports(manifest: dict[str, Any]) -> set[int]:
    """Return listeners proven to be reachable through the managed shared TCP port."""

    decoys = manifest.get("decoys") or {}
    if str(decoys.get("routing_mode") or "strict") != "extended":
        return set()
    public_tcp_port = int((manifest.get("network") or {}).get("public_tcp_port") or 443)
    protocols = {
        int(item.get("inbound_id") or 0): item
        for item in manifest.get("protocols") or []
        if isinstance(item, dict)
        and str(item.get("protocol") or "").strip().lower()
        in {"trusttunnel", "trust-tunnel"}
    }
    protected: set[int] = set()
    for route in decoys.get("extended_routes") or []:
        if not isinstance(route, dict):
            continue
        if (
            str(route.get("strategy") or "") != "trusttunnel_clienthello_split"
            or str(route.get("status") or "") != "ready"
            or route.get("managed") is not True
            or int(route.get("public_tcp_port") or 0) != public_tcp_port
        ):
            continue
        protocol = protocols.get(int(route.get("inbound_id") or 0))
        if not protocol or str(protocol.get("exposure") or "") != "tcp_sni":
            continue
        if int(protocol.get("public_port") or 0) != public_tcp_port:
            continue
        internal_port = int(protocol.get("internal_port") or 0)
        if internal_port != int(route.get("internal_port") or 0):
            continue
        if 1 <= internal_port <= 65535 and internal_port != public_tcp_port:
            protected.add(internal_port)
    return protected


def render_nftables(manifest: dict[str, Any]) -> str:
    internal_tcp = {
        int(manifest["lucx"]["panel"]["internal_port"]),
        int(manifest["lucx"]["subscription"]["internal_port"]),
    }
    if manifest["decoys"].get("enabled"):
        internal_tcp.add(int(manifest["decoys"]["listen_port"]))
        if str(manifest["decoys"].get("routing_mode") or "strict") == "extended":
            internal_tcp.add(int(manifest["decoys"]["listen_port"]) + 1)
            routes = list(manifest["decoys"].get("extended_routes") or [])
            internal_tcp.update(extended_split_ports(manifest, routes).values())
    if manifest["components"].get("sidecar"):
        internal_tcp.add(int(manifest["sidecar"]["listen_port"]))
    ports = ", ".join(str(port) for port in sorted(internal_tcp))
    protected_trusttunnel = _protected_trusttunnel_ports(manifest)
    trusttunnel_rules = ""
    if protected_trusttunnel:
        trust_ports = ", ".join(str(port) for port in sorted(protected_trusttunnel))
        trusttunnel_rules = (
            f'        iifname != "lo" tcp dport {{ {trust_ports} }} counter drop comment "TrustTunnel internal TCP"\n'
            f'        iifname != "lo" udp dport {{ {trust_ports} }} counter drop comment "TrustTunnel internal UDP"\n'
        )
    cloudflare_only = bool((manifest.get("cloudflare") or {}).get("enabled"))
    cloudflare_sets = ""
    cloudflare_rules = ""
    if cloudflare_only:
        from .cloudflare import validate_networks

        stored = (manifest.get("cloudflare") or {}).get("networks") or {}
        networks = validate_networks(
            list(stored.get("ipv4") or []) + list(stored.get("ipv6") or [])
        )
        ipv4 = ", ".join(networks["ipv4"])
        ipv6 = ", ".join(networks["ipv6"])
        protected = ", ".join(
            str(port)
            for port in sorted(
                {
                    int(manifest["lucx"]["panel"]["internal_port"]),
                    int(manifest["lucx"]["subscription"]["internal_port"]),
                }
            )
        )
        cloudflare_sets = f"""    set cloudflare4 {{
        type ipv4_addr
        flags interval
        elements = {{ {ipv4} }}
    }}

    set cloudflare6 {{
        type ipv6_addr
        flags interval
        elements = {{ {ipv6} }}
    }}

"""
        cloudflare_rules = (
            f'        ip saddr @cloudflare4 tcp dport {{ {protected} }} counter accept comment "Cloudflare origin IPv4"\n'
            f'        ip6 saddr @cloudflare6 tcp dport {{ {protected} }} counter accept comment "Cloudflare origin IPv6"\n'
        )
    if manifest.get("firewall", {}).get("mode") != "strict_allowlist":
        return f"""# Managed by lucx-post-configurator. This file never flushes the host ruleset.
table inet lucx_post {{
{cloudflare_sets}
    chain protect_internal {{
        type filter hook input priority -5; policy accept;
{cloudflare_rules}
        iifname != "lo" tcp dport {{ {ports} }} counter drop comment "LucX internal listeners"
{trusttunnel_rules}
    }}
}}
"""

    allowed_tcp: set[str] = {
        str(int(manifest["lucx"]["panel"].get("public_port", manifest["network"]["public_tcp_port"]))),
        str(int(manifest["lucx"]["subscription"].get("public_port", manifest["network"]["public_tcp_port"]))),
    }
    if manifest["decoys"].get("enabled"):
        allowed_tcp.add(str(int(manifest["network"]["public_tcp_port"])))
    allowed_tcp.update(
        str(int(port))
        for port in (manifest["network"].get("ssh_ports") or [manifest["network"]["ssh_port"]])
    )
    allowed_udp: set[str] = set()
    for protocol in manifest.get("protocols", []):
        exposure = protocol.get("exposure")
        if exposure == "none":
            continue
        protected_trusttunnel_listener = (
            str(protocol.get("protocol") or "").strip().lower()
            in {"trusttunnel", "trust-tunnel"}
            and int(protocol.get("internal_port") or 0) in protected_trusttunnel
        )
        public = str(int(protocol["public_port"]))
        if exposure in {"tcp_sni", "tcp_direct", "tcp_udp_direct"}:
            allowed_tcp.add(public)
        if exposure == "tcp_sni":
            allowed_tcp.update(str(port) for port, _, _ in public_ingresses(
                protocol, int(manifest["network"]["public_tcp_port"])))
        if not protected_trusttunnel_listener and (
            exposure in {"udp_direct", "tcp_udp_direct"} or (
            exposure == "tcp_sni" and protocol.get("network") == "both"
            )
        ):
            allowed_udp.add(
                str(
                    int(
                        protocol.get("udp_public_port", protocol.get("internal_port"))
                        if exposure == "tcp_sni"
                        else protocol["public_port"]
                    )
                )
            )
        for binding in protocol.get("port_bindings") or []:
            value = str(binding.get("port") or binding.get("port_range"))
            transport = str(binding.get("protocol") or "").upper()
            if exposure in {"tcp_direct", "tcp_udp_direct"} and transport in {"TCP", "TCP_UDP"}:
                allowed_tcp.add(value)
            if (
                not protected_trusttunnel_listener
                and exposure in {"udp_direct", "tcp_udp_direct", "tcp_sni"}
                and transport in {"UDP", "TCP_UDP"}
            ):
                allowed_udp.add(value)

    def sort_ports(values: set[str]) -> list[str]:
        return sorted(values, key=lambda value: int(value.split("-", 1)[0]))

    tcp_set = ", ".join(sort_ports(allowed_tcp))
    allowed_udp.update({"68", "546"})
    udp_rule = ""
    if allowed_udp:
        udp_set = ", ".join(sort_ports(allowed_udp))
        udp_rule = f'        udp dport {{ {udp_set} }} counter accept comment "LucX public UDP"\n'
    return f"""# Managed by lucx-post-configurator. This file never flushes the host ruleset.
table inet lucx_post {{
{cloudflare_sets}
    chain strict_input {{
        type filter hook input priority 5; policy drop;
        ct state established,related counter accept
        iifname "lo" counter accept
        ip protocol icmp counter accept
        ip6 nexthdr ipv6-icmp counter accept
{cloudflare_rules}
        tcp dport {{ {tcp_set} }} counter accept comment "SSH and LucX public TCP"
{udp_rule}    }}
}}
"""


def render_firewall_unit() -> str:
    return """[Unit]
Description=LucX post-configurator isolated firewall table
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/nft delete table inet lucx_post
ExecStart=/usr/sbin/nft -f /etc/nftables.d/60-lucx-post-configurator.nft
ExecStop=-/usr/sbin/nft delete table inet lucx_post

[Install]
WantedBy=multi-user.target
"""


def render_resolvconf(servers: list[str], existing: str = "") -> str:
    preserved = []
    for line in existing.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("nameserver ") or stripped == "# managed by lucx-post-configurator":
            continue
        if line.strip():
            preserved.append(line)
    result = "# Managed by lucx-post-configurator\n" + "".join(
        f"nameserver {server}\n" for server in servers
    )
    if preserved:
        result += "\n".join(preserved) + "\n"
    return result


def render_resolved(servers: list[str]) -> str:
    return "[Resolve]\nDNS=" + " ".join(servers) + "\nFallbackDNS=\n"


def render_logrotate() -> str:
    return """/var/log/x-ui/*.log {
    daily
    maxsize 10M
    rotate 14
    maxage 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}

/var/log/lucx-sub-sidecar/*.log {
    daily
    maxsize 5M
    rotate 7
    maxage 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
"""


def render_cloudflare_acl(manifest: dict[str, Any]) -> str:
    from .cloudflare import validate_networks

    networks = (manifest.get("cloudflare") or {}).get("networks") or {}
    validated = validate_networks(
        list(networks.get("ipv4") or []) + list(networks.get("ipv6") or [])
    )
    return "\n".join(validated["ipv4"] + validated["ipv6"]) + "\n"


def render_cloudflare_update_unit() -> str:
    return """[Unit]
Description=Refresh official Cloudflare origin networks for LucX
Wants=network-online.target
After=network-online.target haproxy.service
ConditionPathExists=/etc/haproxy/haproxy.cfg

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/sbin/lucx-cloudflare-ips-update
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/etc/haproxy /run/lock
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
"""


def render_cloudflare_update_timer() -> str:
    return """[Unit]
Description=Daily Cloudflare origin network refresh for LucX

[Timer]
OnBootSec=15min
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true
Unit=lucx-cloudflare-ips-update.service

[Install]
WantedBy=timers.target
"""


def render_sidecar_env(manifest: dict[str, Any]) -> str:
    sidecar = manifest["sidecar"]
    certs = manifest["certificates"]
    values = {
        "SIDECAR_LISTEN_HOST": sidecar["listen_host"],
        "SIDECAR_LISTEN_PORT": sidecar["listen_port"],
        "XUI_SUB_HOST": sidecar["upstream_host"],
        "XUI_SUB_PORT": sidecar["upstream_port"],
        "XUI_SUB_SCHEME": sidecar["upstream_scheme"],
        "XUI_DB": manifest["lucx"]["db_path"],
        "SIDECAR_CERT": certs["cert_path"],
        "SIDECAR_KEY": certs["key_path"],
        "SIDECAR_ALLOWED_HOSTS": ",".join(sidecar["allowed_hosts"]),
        "SIDECAR_ALLOWED_PATH_PREFIXES": ",".join(sidecar["allowed_path_prefixes"]),
        "XUI_AWG_PATH": sidecar["awg_path"],
    }
    for value in values.values():
        if "\n" in str(value) or "\r" in str(value):
            raise ValueError("newline in sidecar environment")
    return "".join(f'{key}="{str(value).replace(chr(34), chr(92) + chr(34))}"\n' for key, value in values.items())


def render_sidecar_unit() -> str:
    return """[Unit]
Description=LucX subscription compatibility sidecar
After=network.target x-ui.service
Requires=x-ui.service

[Service]
Type=simple
User=root
Group=root
Environment=PYTHONDONTWRITEBYTECODE=1
EnvironmentFile=/etc/lucx-sub-sidecar/env
ExecStart=/usr/bin/python3 /usr/local/libexec/lucx-sub-sidecar.py
Restart=on-failure
RestartSec=2s
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=
SystemCallArchitectures=native
IPAddressDeny=any
IPAddressAllow=localhost

[Install]
WantedBy=multi-user.target
"""


def render_tls_hook(manifest: dict[str, Any]) -> str:
    naive_ids = []
    for route in manifest.get('decoys', {}).get('extended_routes') or []:
        if route.get('strategy') == 'naive_managed' and route.get('status') == 'ready':
            number = route.get('inbound_id')
            if type(number) is not int or not 0 < number <= 2147483647:
                raise ValueError('Некорректный номер Naive inbound для reload')
            naive_ids.append(number)
    dispatch = ''
    if naive_ids:
        # Каждый reload имеет отдельное задание: события не сливаются с уже
        # работающим sync. Родитель Engine не ждёт worker под своей блокировкой.
        dispatch = """python3 - <<'LUCX_NAIVE_SYNC'
import subprocess
import uuid

for inbound_id in """ + repr(sorted(set(naive_ids))) + """:
    subprocess.run([
        'systemd-run', '--quiet', '--no-block',
        '--unit=lucx-naive-reload-' + str(inbound_id) + '-' + uuid.uuid4().hex,
        '--property=Type=oneshot', '--property=TimeoutStartSec=infinity',
        '--property=UMask=0077', '--', '/usr/local/libexec/lucx-naive-sync.py', str(inbound_id),
    ], check=True)
LUCX_NAIVE_SYNC
"""
    services = ["x-ui"]
    if manifest["components"].get("haproxy"):
        services.append("haproxy")
    if manifest["components"].get("nginx"):
        services.append("nginx")
    if manifest["components"].get("sidecar"):
        services.append("lucx-sub-sidecar")
    service_words = " ".join(services)
    required_domains = {
        manifest["lucx"]["panel"]["domain"],
        manifest["lucx"]["subscription"]["domain"],
    }
    if manifest["decoys"].get("enabled"):
        required_domains.update(site["domain"] for site in manifest["decoys"].get("sites", []))
    domain_words = " ".join(shlex.quote(domain) for domain in sorted(required_domains))
    return f"""#!/bin/sh
set -eu

CERT={shlex.quote(manifest['certificates']['cert_path'])}
KEY={shlex.quote(manifest['certificates']['key_path'])}

test -s "$CERT"
test -s "$KEY"
openssl x509 -in "$CERT" -noout -checkend 86400 >/dev/null

LUCX_TLS_TMP=$(mktemp -d "${{TMPDIR:-/tmp}}/lucx-tls-reload.XXXXXX")
cleanup() {{ rm -rf -- "$LUCX_TLS_TMP"; }}
trap cleanup EXIT HUP INT TERM
openssl x509 -in "$CERT" -pubkey -noout >"$LUCX_TLS_TMP/cert.pub"
openssl pkey -in "$KEY" -pubout >"$LUCX_TLS_TMP/key.pub"
cmp -s "$LUCX_TLS_TMP/cert.pub" "$LUCX_TLS_TMP/key.pub"

python3 - "$CERT" {domain_words} <<'PY'
import ssl
import sys

certificate = ssl._ssl._test_decode_cert(sys.argv[1])
patterns = [value.lower().rstrip(".") for kind, value in certificate.get("subjectAltName", []) if kind == "DNS"]

def covers(pattern, hostname):
    hostname = hostname.lower().rstrip(".")
    if pattern.startswith("*."):
        return hostname.endswith(pattern[1:]) and hostname.count(".") == pattern.count(".")
    return pattern == hostname

missing = [hostname for hostname in sys.argv[2:] if not any(covers(pattern, hostname) for pattern in patterns)]
if missing:
    raise SystemExit("renewed certificate does not cover: " + ", ".join(missing))
PY

if command -v haproxy >/dev/null 2>&1 && systemctl is-enabled haproxy.service >/dev/null 2>&1; then
    haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null
fi
if command -v nginx >/dev/null 2>&1 && systemctl is-enabled nginx.service >/dev/null 2>&1; then
    nginx -t >/dev/null
fi

for service in {service_words}; do
    if systemctl is-enabled "$service.service" >/dev/null 2>&1 || systemctl is-active "$service.service" >/dev/null 2>&1; then
        systemctl try-reload-or-restart "$service.service"
    fi
done
{dispatch}
"""


def render_managed_naive_files(
    manifest: dict[str, Any],
    routing_material: dict[int | str, dict[str, Any]] | None,
) -> dict[str, GeneratedFile]:
    from .naive_frontend import (
        parse_naive_caddyfile,
        render_managed_naive_caddyfile,
        render_naive_frontend_unit,
        render_naive_sync_path,
        render_naive_sync_script,
        render_naive_sync_unit,
    )

    result: dict[str, GeneratedFile] = {}
    routes = [
        item
        for item in (manifest.get("decoys") or {}).get("extended_routes") or []
        if item.get("strategy") == "naive_managed" and item.get("status") == "ready"
    ]
    if not routes:
        return result
    if not (manifest.get("components") or {}).get("naive_frontend"):
        raise ValueError("managed Naive route requires components.naive_frontend")
    result["/usr/local/libexec/lucx-naive-sync.py"] = GeneratedFile(
        render_naive_sync_script().encode(),
        mode=0o755,
        component="naive_frontend",
    )
    sites = {
        str(item.get("domain") or "").lower(): str(item.get("root") or "")
        for item in (manifest.get("decoys") or {}).get("sites") or []
    }
    for route in routes:
        inbound_id = int(route["inbound_id"])
        material = (routing_material or {}).get(inbound_id) or (routing_material or {}).get(
            str(inbound_id)
        )
        if not isinstance(material, dict):
            raise ValueError(f"Naive inbound #{inbound_id} ephemeral source is unavailable")
        source = material.get("naive_caddyfile_text")
        if not isinstance(source, str):
            raise ValueError(f"Naive inbound #{inbound_id} ephemeral source is unavailable")
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if digest != str(route.get("source_caddyfile_sha256") or ""):
            raise ValueError(f"Naive inbound #{inbound_id} source changed after planning")
        parsed = parse_naive_caddyfile(source)
        domain = str(route["domain"]).lower()
        site_root = sites.get(domain, f"/var/www/lucx-decoys/{domain}")
        if not site_root:
            raise ValueError(f"Naive inbound #{inbound_id} has no managed decoy root")
        binary_path = str(route.get("binary_path") or "")
        config_path = f"/etc/lucx-post-configurator/naive/naive-{inbound_id}.caddyfile"
        unit_path = f"/etc/systemd/system/lucx-naive-decoy-{inbound_id}.service"
        path_unit_path = f"/etc/systemd/system/lucx-naive-sync-{inbound_id}.path"
        sync_unit_path = f"/etc/systemd/system/lucx-naive-sync-{inbound_id}.service"
        result[config_path] = GeneratedFile(
            render_managed_naive_caddyfile(
                parsed,
                domain=domain,
                listen_port=int(route["managed_listen_port"]),
                cert_path=str(manifest["certificates"]["cert_path"]),
                key_path=str(manifest["certificates"]["key_path"]),
                site_root=site_root,
            ).encode(),
            mode=0o600,
            component="naive_frontend",
        )
        result[unit_path] = GeneratedFile(
            render_naive_frontend_unit(inbound_id=inbound_id, binary_path=binary_path).encode(),
            component="naive_frontend",
        )
        result[path_unit_path] = GeneratedFile(
            render_naive_sync_path(inbound_id).encode(),
            component="naive_frontend",
        )
        result[sync_unit_path] = GeneratedFile(
            render_naive_sync_unit(inbound_id).encode(),
            component="naive_frontend",
        )
    return result


def render_files(
    manifest: dict[str, Any],
    resolver: str = "auto",
    existing_dns_text: str = "",
    routing_material: dict[int | str, dict[str, Any]] | None = None,
) -> dict[str, GeneratedFile]:
    validate_manifest(manifest)
    components = manifest["components"]
    result: dict[str, GeneratedFile] = {}
    if components.get("trusttunnel_backend"):
        from .trusttunnel_backend import (
            render_backend_credentials_toml,
            render_backend_hosts_toml,
            render_backend_rules_toml,
            render_backend_unit,
            render_backend_vpn_toml,
        )

        result["/etc/x-tuna/trusttunnel/vpn.toml"] = GeneratedFile(
            render_backend_vpn_toml(manifest), mode=0o644, component="trusttunnel_backend"
        )
        result["/etc/x-tuna/trusttunnel/hosts.toml"] = GeneratedFile(
            render_backend_hosts_toml(manifest), mode=0o644, component="trusttunnel_backend"
        )
        result["/etc/x-tuna/trusttunnel/rules.toml"] = GeneratedFile(
            render_backend_rules_toml(manifest), mode=0o644, component="trusttunnel_backend"
        )
        result["/etc/x-tuna/trusttunnel/credentials.toml"] = GeneratedFile(
            render_backend_credentials_toml(manifest), mode=0o600, component="trusttunnel_backend"
        )
        result["/etc/systemd/system/x-tuna-trusttunnel-backend.service"] = GeneratedFile(
            render_backend_unit(manifest), mode=0o644, component="trusttunnel_backend"
        )
    if components.get("haproxy"):
        result["/etc/haproxy/haproxy.cfg"] = GeneratedFile(
            render_haproxy(manifest, routing_material=routing_material).encode(),
            component="haproxy",
        )
        if (
            str((manifest.get("decoys") or {}).get("routing_mode") or "strict") == "extended"
            and components.get("extended_tls_split")
        ):
            result["/etc/lucx-post-configurator/tls/certificate.pem"] = GeneratedFile(
                mode=0o640,
                component="haproxy",
                symlink_target=str(manifest["certificates"]["cert_path"]),
            )
            result["/etc/lucx-post-configurator/tls/certificate.pem.key"] = GeneratedFile(
                mode=0o640,
                component="haproxy",
                symlink_target=str(manifest["certificates"]["key_path"]),
            )
    if (manifest.get("cloudflare") or {}).get("enabled"):
        updater_source = importlib.resources.files("lucx_post_configurator").joinpath(
            "assets/cloudflare_ips_update.py"
        ).read_bytes()
        result["/etc/haproxy/cloudflare-ips.lst"] = GeneratedFile(
            render_cloudflare_acl(manifest).encode(), component="cloudflare"
        )
        result["/usr/local/sbin/lucx-cloudflare-ips-update"] = GeneratedFile(
            updater_source, mode=0o755, component="cloudflare"
        )
        result["/etc/systemd/system/lucx-cloudflare-ips-update.service"] = GeneratedFile(
            render_cloudflare_update_unit().encode(), component="cloudflare"
        )
        result["/etc/systemd/system/lucx-cloudflare-ips-update.timer"] = GeneratedFile(
            render_cloudflare_update_timer().encode(), component="cloudflare"
        )
    if components.get("nginx") and manifest["decoys"].get("enabled"):
        result["/etc/nginx/conf.d/50-lucx-http-redirect.conf"] = GeneratedFile(
            render_nginx_http_redirect().encode(), component="nginx"
        )
        result["/etc/nginx/conf.d/60-lucx-decoys.conf"] = GeneratedFile(
            render_nginx_decoys(manifest).encode(), component="nginx"
        )
        if manifest["decoys"].get("create_content"):
            for site in manifest["decoys"].get("sites", []):
                result[site["root"] + "/index.html"] = GeneratedFile(
                    render_decoy_index(site["domain"]).encode(), component="nginx"
                )
    if components.get("naive_frontend"):
        result.update(render_managed_naive_files(manifest, routing_material))
    if manifest["dns"].get("enabled"):
        servers = manifest["dns"]["servers"]
        if resolver in {"auto", "resolvconf"}:
            result["/etc/resolvconf/resolv.conf.d/head"] = GeneratedFile(
                render_resolvconf(servers, existing_dns_text).encode(), component="dns"
            )
        if resolver == "systemd-resolved":
            result["/etc/systemd/resolved.conf.d/60-lucx-post-configurator.conf"] = GeneratedFile(
                render_resolved(servers).encode(), component="dns"
            )
        if resolver == "static":
            result["/etc/resolv.conf"] = GeneratedFile(
                render_resolvconf(servers, existing_dns_text).encode(), component="dns"
            )
    if components.get("firewall"):
        result["/etc/nftables.d/60-lucx-post-configurator.nft"] = GeneratedFile(
            render_nftables(manifest).encode(), component="firewall"
        )
        result["/etc/systemd/system/lucx-post-firewall.service"] = GeneratedFile(
            render_firewall_unit().encode(), component="firewall"
        )
    if components.get("logrotate"):
        result["/etc/logrotate.d/lucx-x-ui"] = GeneratedFile(render_logrotate().encode(), component="logrotate")
    if components.get("sidecar"):
        sidecar_source = importlib.resources.files("lucx_post_configurator").joinpath("assets/lucx_sub_sidecar.py").read_bytes()
        result["/usr/local/libexec/lucx-sub-sidecar.py"] = GeneratedFile(sidecar_source, mode=0o755, component="sidecar")
        result["/etc/lucx-sub-sidecar/env"] = GeneratedFile(
            render_sidecar_env(manifest).encode(), mode=0o600, component="sidecar"
        )
        result["/etc/systemd/system/lucx-sub-sidecar.service"] = GeneratedFile(
            render_sidecar_unit().encode(), component="sidecar"
        )
    if components.get("tls_hook"):
        hook = render_tls_hook(manifest).encode()
        result["/usr/local/sbin/lucx-tls-reload"] = GeneratedFile(hook, mode=0o750, component="certificates")
        result["/etc/letsencrypt/renewal-hooks/deploy/60-lucx-post-configurator"] = GeneratedFile(
            b"#!/bin/sh\nexec /usr/local/sbin/lucx-tls-reload\n", mode=0o750, component="certificates"
        )
    return result
