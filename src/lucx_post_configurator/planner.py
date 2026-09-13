from __future__ import annotations

import dataclasses
from typing import Any

from .models import Audit, validate_manifest
from .renderers import _protected_trusttunnel_ports


@dataclasses.dataclass(slots=True)
class Action:
    phase: str
    component: str
    description: str
    targets: list[str] = dataclasses.field(default_factory=list)
    reversible: bool = True
    services: list[str] = dataclasses.field(default_factory=list)
    database_fields: list[str] = dataclasses.field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def build_plan(manifest: dict[str, Any], audit: Audit | None = None) -> dict[str, Any]:
    validate_manifest(manifest)
    components = manifest["components"]
    actions: list[Action] = []
    warnings: list[str] = []
    packages: list[str] = []
    register_acme = False

    actions.append(
        Action(
            "pre-backup",
            "transaction",
            "Create a preliminary backup and a consistent read-only LucX database snapshot before APT or service changes",
        )
    )

    if components.get("install_packages"):
        packages.extend(["ca-certificates", "iproute2", "openssl"])
        if components.get("haproxy"):
            packages.append("haproxy")
        if components.get("nginx"):
            packages.append("nginx")
        if manifest.get("decoys", {}).get("enabled"):
            packages.append("curl")
        if components.get("firewall"):
            packages.append("nftables")
        if components.get("logrotate"):
            packages.append("logrotate")
        packages = sorted(set(packages))
        actions.append(
            Action(
                "prerequisites",
                "apt",
                "Install missing external packages: " + ", ".join(packages),
                reversible=False,
            )
        )
        warnings.append("APT package installation is not removed by file rollback.")

    if components.get("haproxy"):
        sni_ports = sorted(
            {int(item["public_port"]) for item in manifest.get("protocols", []) if item.get("exposure") == "tcp_sni"}
            | {
                int(manifest["lucx"]["panel"].get("public_port", manifest["network"]["public_tcp_port"])),
                int(manifest["lucx"]["subscription"].get("public_port", manifest["network"]["public_tcp_port"])),
            }
        )
        if manifest["decoys"].get("enabled"):
            sni_ports.append(int(manifest["network"]["public_tcp_port"]))
            sni_ports = sorted(set(sni_ports))
        actions.append(
            Action(
                "stage",
                "haproxy",
                "Render TCP/SNI routing without terminating protocol TLS on port(s): "
                + ", ".join(str(port) for port in sni_ports),
                ["/etc/haproxy/haproxy.cfg"],
                services=["haproxy.service"],
            )
        )
    if (manifest.get("cloudflare") or {}).get("enabled"):
        actions.append(
            Action(
                "stage",
                "cloudflare",
                "Allow panel and subscription SNI only from dynamically downloaded official Cloudflare IPv4/IPv6 networks",
                [
                    "/etc/haproxy/cloudflare-ips.lst",
                    "/usr/local/sbin/lucx-cloudflare-ips-update",
                    "/etc/systemd/system/lucx-cloudflare-ips-update.service",
                    "/etc/systemd/system/lucx-cloudflare-ips-update.timer",
                ],
                services=["lucx-cloudflare-ips-update.timer"],
            )
        )
    if components.get("nginx") and manifest["decoys"].get("enabled"):
        targets = [
            "/etc/nginx/conf.d/50-lucx-http-redirect.conf",
            "/etc/nginx/conf.d/60-lucx-decoys.conf",
        ]
        if manifest["decoys"].get("create_content"):
            targets.extend(site["root"] + "/index.html" for site in manifest["decoys"].get("sites", []))
        actions.append(
            Action(
                "stage",
                "nginx",
                "Render one loopback TLS decoy virtual host for every unique protocol domain",
                targets,
                services=["nginx.service"],
            )
        )
    if components.get("naive_frontend"):
        managed_naive_ids = sorted(
            {
                int(item.get("inbound_id") or 0)
                for item in manifest["decoys"].get("extended_routes") or []
                if item.get("strategy") == "naive_managed"
                and item.get("status") == "ready"
                and int(item.get("inbound_id") or 0) > 0
            }
        )
        if managed_naive_ids:
            targets: list[str] = [
                "/usr/local/libexec/lucx-naive-sync.py",
            ]
            services: list[str] = []
            for inbound_id in managed_naive_ids:
                targets.extend(
                    [
                        f"/etc/lucx-post-configurator/naive/naive-{inbound_id}.caddyfile",
                        f"/etc/systemd/system/lucx-naive-decoy-{inbound_id}.service",
                        f"/etc/systemd/system/lucx-naive-sync-{inbound_id}.path",
                        f"/etc/systemd/system/lucx-naive-sync-{inbound_id}.service",
                    ]
                )
                services.append(f"lucx-naive-decoy-{inbound_id}.service")
                services.append(f"lucx-naive-sync-{inbound_id}.path")
            actions.append(
                Action(
                    "stage",
                    "naive_frontend",
                    "Render a separate loopback Naive browser frontend from the "
                    "strictly parsed read-only LucX source; never edit the original Caddyfile",
                    targets,
                    services=services,
                )
            )
    if components.get("trusttunnel_backend"):
        backend = manifest.get("trusttunnel_backend") or {}
        actions.append(
            Action(
                "stage",
                "trusttunnel_backend",
                "Install the separately verified TrustTunnel TCP backend on loopback; public 443 is not switched until HTTP/2 CONNECT health-check succeeds",
                [
                    "/etc/x-tuna/trusttunnel/vpn.toml",
                    "/etc/x-tuna/trusttunnel/hosts.toml",
                    "/etc/x-tuna/trusttunnel/rules.toml",
                    "/etc/x-tuna/trusttunnel/credentials.toml",
                    "/etc/systemd/system/x-tuna-trusttunnel-backend.service",
                ],
                services=["x-tuna-trusttunnel-backend.service"],
            )
        )
        warnings.append(
            "TrustTunnel compatible backend is isolated and requires a successful HTTP/2 CONNECT probe before public ingress is changed."
        )
    if manifest["dns"].get("enabled"):
        actions.append(
            Action(
                "stage",
                "dns",
                "Configure up to three system resolvers using the detected Debian resolver manager",
                [
                    "/etc/resolvconf/resolv.conf.d/head",
                    "/etc/systemd/resolved.conf.d/60-lucx-post-configurator.conf",
                ],
                services=["systemd-resolved.service or resolvconf"],
            )
        )
    if components.get("firewall"):
        firewall_mode = manifest.get("firewall", {}).get("mode", "protect_internal")
        actions.append(
            Action(
                "stage",
                "firewall",
                (
                    "Create an isolated nftables table that blocks only managed internal ports"
                    if firewall_mode == "protect_internal"
                    else "Create an explicit nftables allowlist preserving SSH and every discovered/configured protocol listener"
                ),
                [
                    "/etc/nftables.d/60-lucx-post-configurator.nft",
                    "/etc/systemd/system/lucx-post-firewall.service",
                ],
                services=["lucx-post-firewall.service"],
            )
        )
    if components.get("logrotate"):
        actions.append(
            Action(
                "stage",
                "logrotate",
                "Rotate LucX logs daily or at 10 MiB, retaining fourteen compressed archives",
                ["/etc/logrotate.d/lucx-x-ui"],
            )
        )
    if components.get("sidecar"):
        actions.append(
            Action(
                "stage",
                "sidecar",
                "Install the confirmed fail-open Throne AWG compatibility sidecar on loopback without changing other subscription output",
                [
                    "/usr/local/libexec/lucx-sub-sidecar.py",
                    "/etc/lucx-sub-sidecar/env",
                    "/etc/systemd/system/lucx-sub-sidecar.service",
                ],
                services=["lucx-sub-sidecar.service"],
            )
        )
    if components.get("tls_hook"):
        actions.append(
            Action(
                "stage",
                "certificates",
                "Install a deployment hook that validates and reloads LucX, HAProxy, Nginx, and the optional sidecar",
                [
                    "/usr/local/sbin/lucx-tls-reload",
                    "/etc/letsencrypt/renewal-hooks/deploy/60-lucx-post-configurator",
                ],
                services=[
                    "x-ui.service",
                    "haproxy.service",
                    "nginx.service",
                    "lucx-sub-sidecar.service",
                ],
            )
        )
        renewal_provider = manifest["certificates"]["renewal"].get("provider")
        cert_p = str(manifest["certificates"].get("cert_path") or "")
        if renewal_provider == "acme.sh" or (
            renewal_provider == "auto" and ("/.acme.sh/" in cert_p or cert_p.startswith("/root/cert/"))
        ):
            register_acme = True
            warnings.append("acme.sh reload-command registration updates its existing renewal metadata and is not removed by file rollback.")

    actions.extend(
        [
            Action("backup", "transaction", "Create the operational backup of every managed target and record absent targets"),
            Action("validate", "transaction", "Validate certificates and all generated service configuration"),
            Action("commit", "transaction", "Atomically replace managed files and reload only changed services"),
            Action("health", "transaction", "Check local listeners, TLS, service state, DNS, and LucX read-only invariants"),
        ]
    )
    if register_acme:
        actions.append(
            Action(
                "activate",
                "acme.sh",
                "Register the validated reload command in the existing acme.sh renewal record",
                reversible=False,
            )
        )

    if manifest["decoys"].get("default_server"):
        warnings.append("Unknown SNI will intentionally receive the default decoy site.")
    else:
        warnings.append("Unknown SNI remains rejected; no Nginx default_server is created.")
    warnings.append("Naive Caddyfile is read-only and excluded from all backup/write target lists.")
    trusttunnel_ports = sorted(_protected_trusttunnel_ports(manifest))
    if trusttunnel_ports:
        warnings.append(
            "TrustTunnel internal listener ports "
            + ", ".join(str(port) for port in trusttunnel_ports)
            + " will be blocked externally on TCP and UDP; loopback and the confirmed public TCP/443 route remain available."
        )
    if manifest.get("firewall", {}).get("mode") == "strict_allowlist":
        warnings.append("Strict firewall mode will reject inbound ports not represented in this manifest.")
    if (manifest.get("cloudflare") or {}).get("enabled"):
        warnings.append(
            "Panel and subscription SNI will reject direct origin traffic; official Cloudflare networks are fetched before commit and refreshed daily."
        )
    settings_management = manifest.get("lucx", {}).get("settings_management") or {}
    if settings_management.get("sync_domains"):
        actions.insert(
            1,
            Action(
                "database",
                "lucx-settings",
                "After the database backup, transactionally synchronize approved public URL metadata (webDomain, subDomain, webBasePath, and selected inbound share_addr/Host endpoints)",
                [manifest["lucx"]["db_path"]],
                services=["x-ui.service"],
                database_fields=[
                    "settings.webDomain",
                    "settings.subDomain",
                    "settings.webBasePath",
                    "inbounds[*].share_addr (selected public inbound endpoints)",
                    "hosts[*].address/port (selected public inbound endpoints)",
                ],
            ),
        )
    inbound_changes = list(manifest.get("lucx", {}).get("inbound_changes") or [])
    if inbound_changes:
        actions.insert(
            1,
            Action(
                "database",
                "lucx-inbound-settings",
                "After backup, change only explicitly approved inbound transport metadata required for safe browser/VPN separation",
                [manifest["lucx"]["db_path"]],
                services=["x-ui.service"],
                database_fields=[
                    f"inbounds[#{int(change['inbound_id'])}].{change['field']}"
                    for change in inbound_changes
                ],
            ),
        )
        warnings.append(
            "Разрешены только явно перечисленные изменения inbound; клиенты, credentials, listener-порты и остальные настройки защищены."
        )
    if settings_management.get("sync_certificate_paths"):
        actions.insert(
            1,
            Action(
                "database",
                "lucx-certificates",
                "After backup, synchronize the explicitly approved web/sub certificate file paths without changing certificate contents",
                [manifest["lucx"]["db_path"]],
                services=["x-ui.service"],
                database_fields=[
                    "settings.webCertFile",
                    "settings.webKeyFile",
                    "settings.subCertFile",
                    "settings.subKeyFile",
                ],
            ),
        )
    endpoint_updates = [
        item
        for item in manifest.get("protocols", [])
        if item.get("sync_naive_endpoint")
        and str(item.get("security") or "").strip().lower() != "reality"
    ]
    if endpoint_updates:
        field_labels = {
            "naive": "domain",
            "trusttunnel": "hostname",
            "anytls": "sni",
        }
        actions.insert(
            1,
            Action(
                "database",
                "lucx-tls-endpoint",
                "After backup, update the confirmed TLS inbound endpoint fields (hostname-like field, certFile, keyFile or stream TLS settings) so LucX regenerates tunnel configs for the new zone",
                [manifest["lucx"]["db_path"]],
                services=["x-ui.service"],
                database_fields=[
                    (
                        f"inbounds[#{int(item['inbound_id'])}] ({item.get('protocol')})."
                        f"{field_labels.get(str(item.get('protocol')), 'TLS endpoint fields')} + certificate paths"
                    )
                    for item in endpoint_updates
                ],
            ),
        )
    from .decoy_capabilities import classify_decoy_capabilities

    capabilities = list(manifest["decoys"].get("capabilities") or [])
    if not capabilities:
        capabilities = classify_decoy_capabilities(manifest, audit)
    for item in capabilities:
        warnings.append(f"{item['domain']}: {item['status']} — {item['reason']}")
    for item in manifest.get("protocols", []):
        bindings = []
        for binding in item.get("port_bindings") or []:
            value = str(binding.get("port") or binding.get("port_range"))
            bindings.append(f"{binding.get('protocol')}/{value}")
        if bindings:
            warnings.append(
                f"Inbound #{item['inbound_id']} {item['protocol']} discovered listeners: " + ", ".join(bindings)
            )
    if audit:
        warnings.extend(audit.warnings)

    return {
        "schema_version": 1,
        "immutable": [
            "LucX clients, inbound listener ports/settings, and credentials",
            "all LucX database fields except confirmed public URL metadata, selected Naive endpoint, and approved certificate file paths",
            "Naive Caddyfile",
            "certificate and private-key contents",
        ],
        "packages": packages,
        "actions": [action.as_dict() for action in actions],
        "warnings": list(dict.fromkeys(warnings)),
    }


def format_plan(plan: dict[str, Any]) -> str:
    lines = ["LucX post-configuration plan", ""]
    lines.append("Immutable scope:")
    lines.extend(f"  - {value}" for value in plan["immutable"])
    lines.append("")
    lines.append("Actions:")
    for index, action in enumerate(plan["actions"], start=1):
        reversible = "reversible" if action["reversible"] else "not removed by rollback"
        lines.append(f"  {index}. [{action['phase']}/{action['component']}] {action['description']} ({reversible})")
        lines.extend(f"       {target}" for target in action.get("targets", []))
    if plan.get("warnings"):
        lines.extend(["", "Warnings:"])
        lines.extend(f"  - {warning}" for warning in plan["warnings"])
    return "\n".join(lines) + "\n"
