from __future__ import annotations

import dataclasses
import ipaddress
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 3
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


class ConfigurationError(ValueError):
    """Raised when a manifest is unsafe or internally inconsistent."""


def normalize_protocol(value: str) -> str:
    value = (value or "").strip().lower()
    aliases = {
        "amnezia-wg": "amneziawg",
        "naiveproxy": "naive",
        "naive-proxy": "naive",
        "hysteria2": "hysteria",
    }
    return aliases.get(value, value)


def valid_domain(value: str) -> bool:
    value = value.strip().rstrip(".")
    if not value or value.startswith("*."):
        value = value[2:] if value.startswith("*.") else value
    if not value or not DOMAIN_RE.fullmatch(value):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def ensure_port(value: Any, label: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"{label} must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ConfigurationError(f"{label} must be between 1 and 65535")
    return port


@dataclasses.dataclass(slots=True)
class Inbound:
    id: int
    protocol: str
    remark: str
    enable: bool
    listen: str
    port: int
    share_addr: str = ""
    share_addr_strategy: str = ""
    network: str = "tcp"
    security: str = ""
    transport: str = "tcp"
    transport_path: str = ""
    transport_hosts: list[str] = dataclasses.field(default_factory=list)
    transport_mode: str = ""
    alpn: list[str] = dataclasses.field(default_factory=list)
    shadowsocks_2022: bool = False
    udp_over_tcp: bool = False
    clienthello_match_fingerprint: str = ""
    suggested_public_port: int = 0
    server_names: list[str] = dataclasses.field(default_factory=list)
    port_bindings: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    # Все включённые Hosts; старые share_addr/port остаются совместимым первым endpoint.
    public_endpoints: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    # Только безопасные признаки и отпечатки; никаких значений credentials/headers.
    transport_details: dict[str, Any] = dataclasses.field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(slots=True)
class Audit:
    os_id: str = ""
    os_version: str = ""
    supported_os: bool = False
    db_path: str = ""
    db_schema_supported: bool = False
    settings: dict[str, str] = dataclasses.field(default_factory=dict)
    inbounds: list[Inbound] = dataclasses.field(default_factory=list)
    tools: dict[str, bool] = dataclasses.field(default_factory=dict)
    services: dict[str, str] = dataclasses.field(default_factory=dict)
    ssh_ports: list[int] = dataclasses.field(default_factory=lambda: [22])
    public_addresses: list[str] = dataclasses.field(default_factory=list)
    naive_caddyfile: dict[str, Any] = dataclasses.field(default_factory=dict)
    warnings: list[str] = dataclasses.field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        result = dataclasses.asdict(self)
        result["inbounds"] = [item.as_dict() for item in self.inbounds]
        return result


def default_manifest(audit: Audit | None = None) -> dict[str, Any]:
    settings = audit.settings if audit else {}
    def setting_port(name: str, fallback: int) -> int:
        try:
            value = int(settings.get(name, str(fallback)) or fallback)
        except (TypeError, ValueError):
            return fallback
        return value if 1 <= value <= 65535 else fallback

    return {
        "schema_version": SCHEMA_VERSION,
        "lucx": {
            "db_path": (audit.db_path if audit else "/etc/x-ui/x-ui.db"),
            "panel": {
                "domain": settings.get("webDomain", ""),
                "path_prefix": settings.get("webBasePath", "/") or "/",
                "internal_host": settings.get("webListen", "") or "127.0.0.1",
                "internal_port": setting_port("webPort", 2083),
                "public_port": 443,
            },
            "subscription": {
                "domain": settings.get("subDomain", ""),
                "path_prefix": settings.get("subPath", "/sub/") or "/sub/",
                "internal_host": settings.get("subListen", "") or "127.0.0.1",
                "internal_port": setting_port("subPort", 2096),
                "public_port": 443,
            },
            "settings_management": {
                "sync_domains": False,
                "sync_panel_path": False,
                "sync_subscription_urls": False,
                "sync_naive_share_addr": False,
                "sync_public_endpoints": False,
                "allow_inbound_changes": False,
                "sync_certificate_paths": False,
                "sync_naive_endpoint": False,
                "user_confirmed": False,
            },
        },
        "certificates": {
            "cert_path": settings.get("webCertFile") or settings.get("subCertFile", ""),
            "key_path": settings.get("webKeyFile") or settings.get("subKeyFile", ""),
            "renewal": {"enabled": False, "provider": "auto", "primary_domain": ""},
        },
        "network": {
            "public_tcp_port": 443,
            "public_bind_address": (audit.public_addresses[0] if audit and audit.public_addresses else "0.0.0.0"),
            "ssh_port": (audit.ssh_ports[0] if audit and audit.ssh_ports else 22),
            "ssh_ports": list(dict.fromkeys(audit.ssh_ports if audit and audit.ssh_ports else [22])),
            "external_interface": "auto",
            "unknown_sni_action": "reject",
            "non_tls_backend_inbound_id": None,
        },
        "protocols": [],
        "decoys": {
            "enabled": False,
            "routing_mode": "strict",
            "extended_user_confirmed": False,
            "listen_host": "127.0.0.1",
            "listen_port": 8444,
            "create_content": False,
            "default_server": False,
            "sites": [],
            "capabilities": [],
            "extended_routes": [],
            "naive_frontends": [],
        },
        "integrity": {
            "protected_lucx": {},
            "naive_caddyfile": {},
        },
        "dns": {
            "enabled": True,
            "servers": ["9.9.9.9", "77.88.8.8", "45.90.28.147"],
        },
        "firewall": {
            "mode": "protect_internal",
        },
        "cloudflare": {
            "enabled": False,
            "user_confirmed": False,
            "networks": {"ipv4": [], "ipv6": []},
        },
        "components": {
            "install_packages": True,
            "haproxy": True,
            "nginx": True,
            "firewall": True,
            "logrotate": True,
            "tls_hook": False,
            "sidecar": False,
            "extended_tls_split": False,
            "naive_frontend": False,
            "trusttunnel_backend": False,
        },
        "trusttunnel_backend": {
            "user_confirmed": False,
            "binary_path": "",
            "listen_host": "127.0.0.1",
            "listen_port": 0,
            "public_domain": "",
            "public_port": 443,
            "source": "",
            "sha256": "",
            "credentials": [],
            "decoy_address": "127.0.0.1:8446",
        },
        "sidecar": {
            "user_confirmed": False,
            "listen_host": "127.0.0.1",
            "listen_port": 21000,
            "upstream_host": "127.0.0.1",
            "upstream_port": setting_port("subPort", 2096),
            "upstream_scheme": "https",
            "allowed_hosts": [],
            "allowed_path_prefixes": list(
                dict.fromkeys(
                    [
                        settings.get("subPath", "/sub/") or "/sub/",
                        settings.get("subClashPath", "/clash/") or "/clash/",
                        settings.get("subAwgPath", "/awg/") or "/awg/",
                        settings.get("subJsonPath", "/json/") or "/json/",
                    ]
                )
            ),
            "awg_path": settings.get("subAwgPath", "/awg/") or "/awg/",
        },
    }


def load_manifest(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    from .migrations import migrate_manifest

    result = migrate_manifest(raw)
    validate_manifest(result)
    return result


def dump_manifest(manifest: dict[str, Any], path: str | Path) -> None:
    validate_manifest(manifest)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ConfigurationError(
            f"unsupported manifest schema {manifest.get('schema_version')!r}; expected {SCHEMA_VERSION}"
        )

    lucx = manifest.get("lucx") or {}
    db_path = str(lucx.get("db_path") or "")
    if not db_path.startswith("/") or any(character in db_path for character in ("\x00", "\r", "\n")):
        raise ConfigurationError("lucx.db_path must be a safe absolute path")
    for section_name in ("panel", "subscription"):
        section = lucx.get(section_name) or {}
        domain = str(section.get("domain") or "").strip().lower()
        if not valid_domain(domain):
            raise ConfigurationError(f"lucx.{section_name}.domain is not a valid DNS name")
        ensure_port(section.get("internal_port"), f"lucx.{section_name}.internal_port")
        ensure_port(
            section.get("public_port", (manifest.get("network") or {}).get("public_tcp_port", 443)),
            f"lucx.{section_name}.public_port",
        )
    subscription_path = str(lucx.get("subscription", {}).get("path_prefix") or "")
    if not subscription_path.startswith("/") or any(
        character in subscription_path for character in ("\x00", "\r", "\n")
    ):
        raise ConfigurationError("lucx.subscription.path_prefix must be a safe absolute URL path")
    panel_path = str(lucx.get("panel", {}).get("path_prefix") or "")
    if not panel_path.startswith("/") or any(
        character in panel_path for character in ("\x00", "\r", "\n")
    ) or ".." in Path(panel_path).parts:
        raise ConfigurationError("lucx.panel.path_prefix must be a safe absolute URL path")
    settings_management = lucx.get("settings_management") or {}
    if any(
        settings_management.get(key)
        for key in (
            "sync_domains",
            "sync_panel_path",
            "sync_subscription_urls",
            "sync_naive_share_addr",
            "sync_public_endpoints",
            "sync_certificate_paths",
            "sync_naive_endpoint",
        )
    ) and settings_management.get("user_confirmed") is not True:
        raise ConfigurationError("LucX publication synchronization requires explicit confirmation")
    if settings_management.get("sync_naive_endpoint") and not (
        settings_management.get("sync_certificate_paths")
    ):
        raise ConfigurationError(
            "sync_naive_endpoint requires sync_certificate_paths to publish the selected pair to LucX"
        )
    subscription_urls = lucx.get("subscription", {}).get("public_base_url")
    if settings_management.get("sync_subscription_urls"):
        base = str(subscription_urls or "").strip()
        if not base:
            raise ConfigurationError(
                "sync_subscription_urls requires lucx.subscription.public_base_url"
            )
    inbound_changes = list(lucx.get("inbound_changes") or [])
    if inbound_changes and settings_management.get("allow_inbound_changes") is not True:
        raise ConfigurationError("inbound changes require explicit allow_inbound_changes confirmation")
    for index, change in enumerate(inbound_changes):
        if not isinstance(change, dict):
            raise ConfigurationError(f"lucx.inbound_changes[{index}] must be an object")
        try:
            inbound_id = int(change.get("inbound_id"))
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"lucx.inbound_changes[{index}].inbound_id is invalid") from exc
        if inbound_id <= 0 or change.get("field") != "transport_path":
            raise ConfigurationError(
                f"lucx.inbound_changes[{index}] only supports a positive inbound_id and transport_path"
            )
        path = str(change.get("value") or "")
        if not path.startswith("/") or ".." in Path(path).parts or "\x00" in path or path == "/":
            raise ConfigurationError(f"lucx.inbound_changes[{index}].value must be a non-root URL path")

    certs = manifest.get("certificates") or {}
    for key in ("cert_path", "key_path"):
        value = str(certs.get(key) or "")
        if not value.startswith("/") or any(character in value for character in ("\x00", "\r", "\n")):
            raise ConfigurationError(f"certificates.{key} must be an absolute path")

    network = manifest.get("network") or {}
    ensure_port(network.get("public_tcp_port"), "network.public_tcp_port")
    ensure_port(network.get("ssh_port"), "network.ssh_port")
    ssh_ports = list(network.get("ssh_ports") or [network.get("ssh_port")])
    if not ssh_ports:
        raise ConfigurationError("network.ssh_ports must not be empty")
    for index, port in enumerate(ssh_ports):
        ensure_port(port, f"network.ssh_ports[{index}]")
    try:
        ipaddress.ip_address(str(network.get("public_bind_address") or ""))
    except ValueError as exc:
        raise ConfigurationError("network.public_bind_address must be an IPv4 or IPv6 address") from exc
    if network.get("unknown_sni_action") not in {"reject", "decoy"}:
        raise ConfigurationError("network.unknown_sni_action must be reject or decoy")

    dns = manifest.get("dns") or {}
    servers = list(dns.get("servers") or [])
    if dns.get("enabled") and not 1 <= len(servers) <= 3:
        raise ConfigurationError("dns.servers must contain between one and three addresses")
    for server in servers:
        try:
            ipaddress.ip_address(server)
        except ValueError as exc:
            raise ConfigurationError(f"invalid DNS server address: {server}") from exc

    firewall = manifest.get("firewall") or {}
    if firewall.get("mode") not in {"protect_internal", "strict_allowlist"}:
        raise ConfigurationError("firewall.mode must be protect_internal or strict_allowlist")

    decoys = manifest.get("decoys") or {}
    if decoys.get("zone_apex") and not valid_domain(str(decoys["zone_apex"])):
        raise ConfigurationError("decoys.zone_apex is invalid")
    routing_mode = str(decoys.get("routing_mode") or "")
    if routing_mode not in {"strict", "extended"}:
        raise ConfigurationError("decoys.routing_mode must be strict or extended")
    if routing_mode == "extended":
        if decoys.get("extended_user_confirmed") is not True:
            raise ConfigurationError(
                "extended decoy routing requires explicit confirmation"
            )
        if not decoys.get("enabled"):
            raise ConfigurationError("extended decoy routing requires decoys.enabled")
    ensure_port(decoys.get("listen_port"), "decoys.listen_port")
    if decoys.get("default_server") and network.get("unknown_sni_action") != "decoy":
        raise ConfigurationError("default_server requires unknown_sni_action=decoy")
    if network.get("unknown_sni_action") == "decoy" and not decoys.get("enabled"):
        raise ConfigurationError("unknown_sni_action=decoy requires decoys.enabled")
    if network.get("unknown_sni_action") == "decoy" and not decoys.get("default_server"):
        raise ConfigurationError("unknown_sni_action=decoy requires an explicit decoys.default_server")
    components = manifest.get("components") or {}
    backend = manifest.get("trusttunnel_backend") or {}
    if components.get("trusttunnel_backend"):
        if backend.get("user_confirmed") is not True:
            raise ConfigurationError(
                "TrustTunnel compatible backend requires explicit confirmation"
            )
        if backend.get("listen_host") not in {"127.0.0.1", "::1", "localhost"}:
            raise ConfigurationError("TrustTunnel backend must listen on loopback")
        ensure_port(backend.get("listen_port"), "trusttunnel_backend.listen_port")
        if int(backend.get("public_port", 443)) != int(network.get("public_tcp_port", 443)):
            raise ConfigurationError(
                "TrustTunnel backend public port must match the managed TCP frontend"
            )
        if not valid_domain(str(backend.get("public_domain") or "")):
            raise ConfigurationError("trusttunnel_backend.public_domain is invalid")
        binary_path = str(backend.get("binary_path") or "")
        if not binary_path.startswith("/") or any(c in binary_path for c in ("\x00", "\r", "\n")):
            raise ConfigurationError("trusttunnel_backend.binary_path must be an absolute path")
        digest = str(backend.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ConfigurationError("trusttunnel_backend.sha256 must be a SHA-256 digest")
        credentials = backend.get("credentials") or []
        if not isinstance(credentials, list) or not credentials:
            raise ConfigurationError("trusttunnel_backend requires at least one backend credential")
        for index, item in enumerate(credentials):
            if not isinstance(item, dict) or not item.get("username") or not item.get("password"):
                raise ConfigurationError(f"trusttunnel_backend.credentials[{index}] is incomplete")
        decoy_address = str(backend.get("decoy_address") or "")
        decoy_host, separator, decoy_port_text = decoy_address.rpartition(":")
        if not separator or decoy_host not in {"127.0.0.1", "::1", "localhost"}:
            raise ConfigurationError("trusttunnel_backend.decoy_address must be loopback")
        ensure_port(decoy_port_text, "trusttunnel_backend.decoy_address")
        if int(decoy_port_text) in {
            int(lucx.get("panel", {}).get("internal_port")),
            int(lucx.get("subscription", {}).get("internal_port")),
            int(decoys.get("listen_port")),
            int(backend.get("listen_port")),
        }:
            raise ConfigurationError("trusttunnel_backend.decoy_address overlaps a managed listener")
        decoy_domains = {str(site.get("domain") or "").lower() for site in decoys.get("sites") or []}
        if str(backend.get("public_domain") or "").lower() not in decoy_domains:
            raise ConfigurationError("trusttunnel_backend.public_domain requires a managed decoy site")
    if routing_mode == "extended" and (
        not components.get("haproxy") or not components.get("nginx")
    ):
        raise ConfigurationError(
            "extended decoy routing requires HAProxy and Nginx components"
        )
    if any(
        route.get("strategy") == "naive_managed" and route.get("status") == "ready"
        for route in decoys.get("extended_routes") or []
    ) and not components.get("naive_frontend"):
        raise ConfigurationError(
            "ready managed Naive route requires components.naive_frontend"
        )
    if decoys.get("enabled") and (decoys.get("sites") or decoys.get("default_server")) and not components.get("nginx"):
        raise ConfigurationError("enabled decoy sites require components.nginx")
    if network.get("unknown_sni_action") == "decoy" and not components.get("haproxy"):
        raise ConfigurationError("unknown SNI decoy routing requires components.haproxy")
    seen_domains: set[str] = set()
    for index, site in enumerate(decoys.get("sites") or []):
        domain = str(site.get("domain") or "").lower()
        if not valid_domain(domain):
            raise ConfigurationError(f"decoys.sites[{index}].domain is invalid")
        if domain in seen_domains:
            raise ConfigurationError(f"duplicate decoy domain: {domain}")
        seen_domains.add(domain)
        root = str(site.get("root") or "")
        if not root.startswith("/var/www/") or ".." in Path(root).parts:
            raise ConfigurationError(f"unsafe decoy root: {root}")
    from .decoy_capabilities import CAPABILITY_STATUSES, MANAGED_STATUSES

    capability_domains: set[str] = set()
    for index, item in enumerate(decoys.get("capabilities") or []):
        domain = str(item.get("domain") or "").strip().lower()
        status = str(item.get("status") or "")
        if not valid_domain(domain) or domain in capability_domains:
            raise ConfigurationError(f"decoys.capabilities[{index}].domain is invalid or duplicate")
        capability_domains.add(domain)
        if status not in CAPABILITY_STATUSES:
            raise ConfigurationError(f"decoys.capabilities[{index}].status is invalid")
        if bool(item.get("managed")) != (status in MANAGED_STATUSES):
            raise ConfigurationError(f"decoys.capabilities[{index}].managed contradicts its status")

    sidecar = manifest.get("sidecar") or {}
    if components.get("sidecar"):
        if not components.get("haproxy"):
            raise ConfigurationError("sidecar requires components.haproxy for the public subscription route")
        if sidecar.get("user_confirmed") is not True:
            raise ConfigurationError("sidecar requires recorded explicit user confirmation")
        if sidecar.get("listen_host") not in {"127.0.0.1", "::1", "localhost"}:
            raise ConfigurationError("sidecar must listen on loopback")
        if sidecar.get("upstream_host") not in {"127.0.0.1", "::1", "localhost"}:
            raise ConfigurationError("sidecar upstream must be loopback")
        ensure_port(sidecar.get("listen_port"), "sidecar.listen_port")
        ensure_port(sidecar.get("upstream_port"), "sidecar.upstream_port")
        if int(sidecar.get("upstream_port")) != int(lucx.get("subscription", {}).get("internal_port")):
            raise ConfigurationError("sidecar.upstream_port must match the LucX subscription listener")
        hosts = list(sidecar.get("allowed_hosts") or [])
        if not hosts or any(not valid_domain(host) for host in hosts):
            raise ConfigurationError("sidecar.allowed_hosts must contain valid DNS names")
        if str(lucx.get("subscription", {}).get("domain") or "").lower() not in {
            str(host).lower() for host in hosts
        }:
            raise ConfigurationError("sidecar.allowed_hosts must include the subscription domain")
        prefixes = list(sidecar.get("allowed_path_prefixes") or [])
        if not prefixes or any(
            not str(prefix).startswith("/") or "\x00" in str(prefix)
            for prefix in prefixes
        ):
            raise ConfigurationError("sidecar.allowed_path_prefixes must contain absolute URL paths")
        if subscription_path not in {str(prefix) for prefix in prefixes}:
            raise ConfigurationError("sidecar.allowed_path_prefixes must include the LucX subscription path")
        if sidecar.get("upstream_scheme") not in {"http", "https"}:
            raise ConfigurationError("sidecar.upstream_scheme must be http or https")
        awg_path = str(sidecar.get("awg_path") or "")
        if not awg_path.startswith("/") or "\x00" in awg_path:
            raise ConfigurationError("sidecar.awg_path must be an absolute URL path")

    cloudflare = manifest.get("cloudflare") or {}
    if cloudflare.get("enabled"):
        if cloudflare.get("user_confirmed") is not True:
            raise ConfigurationError("Cloudflare origin restriction requires explicit confirmation")
        if not components.get("haproxy"):
            raise ConfigurationError("Cloudflare origin restriction requires HAProxy SNI routing")
        if not components.get("firewall"):
            raise ConfigurationError("Cloudflare origin restriction requires the managed nftables firewall")
        from .cloudflare import CLOUDFLARE_HTTPS_PORTS

        for section_name in ("panel", "subscription"):
            section = lucx.get(section_name) or {}
            public_port = int(section.get("public_port", network.get("public_tcp_port", 443)))
            if public_port not in CLOUDFLARE_HTTPS_PORTS:
                allowed = ", ".join(str(port) for port in CLOUDFLARE_HTTPS_PORTS)
                raise ConfigurationError(
                    f"lucx.{section_name}.public_port must be a Cloudflare HTTPS proxy port: {allowed}"
                )
        networks = cloudflare.get("networks") or {}
        values = list(networks.get("ipv4") or []) + list(networks.get("ipv6") or [])
        if values:
            from .cloudflare import CloudflareNetworkError, validate_networks

            try:
                validate_networks(values)
            except CloudflareNetworkError as exc:
                raise ConfigurationError(str(exc)) from exc

    ids: set[int] = set()
    panel_domain = str(lucx.get("panel", {}).get("domain") or "").lower()
    subscription_domain = str(lucx.get("subscription", {}).get("domain") or "").lower()
    if panel_domain == subscription_domain:
        raise ConfigurationError("panel and subscription domains must be different")
    sni_routes: dict[tuple[int, str], int | str] = {
        (int(lucx.get("panel", {}).get("public_port", network.get("public_tcp_port"))), panel_domain): "panel",
        (int(lucx.get("subscription", {}).get("public_port", network.get("public_tcp_port"))), subscription_domain): "subscription",
    }
    protected_ports = {
        int(lucx.get("panel", {}).get("internal_port")),
        int(lucx.get("subscription", {}).get("internal_port")),
        int(decoys.get("listen_port")),
    }
    if components.get("sidecar"):
        protected_ports.add(int(sidecar.get("listen_port")))
    haproxy_owned_ports = {
        int(lucx.get("panel", {}).get("public_port", network.get("public_tcp_port"))),
        int(lucx.get("subscription", {}).get("public_port", network.get("public_tcp_port"))),
    }
    if decoys.get("enabled"):
        haproxy_owned_ports.add(int(network.get("public_tcp_port")))
    for index, protocol in enumerate(manifest.get("protocols") or []):
        inbound_id = int(protocol.get("inbound_id") or 0)
        if inbound_id <= 0 or inbound_id in ids:
            raise ConfigurationError(f"protocols[{index}].inbound_id is invalid or duplicate")
        ids.add(inbound_id)
        if not protocol.get("protocol"):
            raise ConfigurationError(f"protocols[{index}].protocol is empty")
        domain = str(protocol.get("domain") or "")
        if domain and not valid_domain(domain):
            raise ConfigurationError(f"protocols[{index}].domain is invalid")
        ensure_port(protocol.get("public_port"), f"protocols[{index}].public_port")
        if protocol.get("exposure") not in {"tcp_sni", "tcp_direct", "udp_direct", "tcp_udp_direct", "none"}:
            raise ConfigurationError(f"protocols[{index}].exposure is invalid")
        exposure = protocol.get("exposure")
        public_port = int(protocol.get("public_port"))
        internal_port = ensure_port(protocol.get("internal_port"), f"protocols[{index}].internal_port")
        if (
            str(decoys.get("routing_mode") or "strict") == "extended"
            and str(protocol.get("network") or "") in {"tcp", "both"}
            and internal_port == int(decoys.get("listen_port")) + 1
        ):
            raise ConfigurationError(
                f"extended decoy cleartext listener TCP/{int(decoys.get('listen_port')) + 1} "
                f"overlaps inbound {inbound_id}"
            )
        if protocol.get("sync_share_addr") and not protocol.get("sync_public_endpoint"):
            raise ConfigurationError(
                f"protocols[{index}].sync_share_addr is obsolete; use sync_public_endpoint"
            )
        if protocol.get("sync_public_endpoint"):
            if exposure not in {"tcp_sni", "tcp_direct", "udp_direct", "tcp_udp_direct"}:
                raise ConfigurationError(
                    f"protocols[{index}].sync_public_endpoint requires an externally published inbound"
                )
            if not settings_management.get("sync_public_endpoints"):
                raise ConfigurationError(
                    f"protocols[{index}].sync_public_endpoint requires lucx.settings_management.sync_public_endpoints"
                )
        if exposure in {"tcp_direct", "udp_direct", "tcp_udp_direct"} and public_port != internal_port:
            raise ConfigurationError(
                f"protocols[{index}] direct public port must equal its LucX listener port; external NAT is not managed"
            )
        if protocol.get("network") == "both" and exposure == "tcp_sni":
            udp_public_port = ensure_port(
                protocol.get("udp_public_port", internal_port),
                f"protocols[{index}].udp_public_port",
            )
            if udp_public_port != internal_port:
                raise ConfigurationError(
                    f"protocols[{index}] direct UDP port must equal its LucX listener port; external NAT is not managed"
                )
        if exposure in {"tcp_direct", "tcp_udp_direct"} and public_port in haproxy_owned_ports and (manifest.get("components") or {}).get("haproxy"):
            raise ConfigurationError(
                f"protocols[{index}] cannot bind TCP/{public_port} directly while HAProxy owns that port"
            )
        if exposure in {"tcp_direct", "tcp_udp_direct"} and public_port in protected_ports:
            raise ConfigurationError(
                f"protocols[{index}] public TCP port collides with a protected internal port: {public_port}"
            )
        from .routing_profiles import public_ingresses, validated_public_endpoints

        validated_public_endpoints(protocol)
        sni_names = list(protocol.get("sni_names") or ([domain] if exposure == "tcp_sni" and domain else []))
        if exposure == "tcp_sni" and not sni_names:
            raise ConfigurationError(f"protocols[{index}].sni_names is required for tcp_sni")
        if exposure == "tcp_sni" and not components.get("haproxy"):
            raise ConfigurationError(f"protocols[{index}] uses tcp_sni but components.haproxy is disabled")
        ingress_keys = ({(port, name) for port, name, _ in public_ingresses(protocol, int(network.get("public_tcp_port")))}
                        if exposure == "tcp_sni" else set())
        for ingress_port, sni in ingress_keys:
            if ingress_port in protected_ports:
                raise ConfigurationError(f"protocols[{index}] public endpoint collides with a protected internal port")
            route_key = (ingress_port, sni)
            if route_key in sni_routes and sni_routes[route_key] != inbound_id:
                raise ConfigurationError(
                    f"duplicate SNI route on TCP/{ingress_port}: {sni} ({sni_routes[route_key]} and inbound {inbound_id})"
                )
            sni_routes[route_key] = inbound_id
        for binding in protocol.get("port_bindings") or []:
            transport = str(binding.get("protocol") or "").upper()
            if transport not in {"TCP", "UDP", "TCP_UDP"}:
                raise ConfigurationError(f"protocols[{index}] has an invalid port binding transport")
            if binding.get("port") is not None:
                ensure_port(binding.get("port"), f"protocols[{index}].port_bindings.port")
            elif binding.get("port_range"):
                match = re.fullmatch(r"(\d{1,5})-(\d{1,5})", str(binding["port_range"]))
                if not match or not (1 <= int(match.group(1)) <= int(match.group(2)) <= 65535):
                    raise ConfigurationError(f"protocols[{index}] has an invalid port range")
            else:
                raise ConfigurationError(f"protocols[{index}] has an empty port binding")

    from .decoy_capabilities import managed_decoy_domains

    shared_port = int(network.get("public_tcp_port"))
    protocol_owned_sni = {
        str(sni).lower()
        for protocol in manifest.get("protocols") or []
        if protocol.get("exposure") == "tcp_sni"
        and int(protocol.get("public_port") or 0) == shared_port
        for sni in (protocol.get("sni_names") or [protocol.get("domain", "")])
        if sni
    }
    collisions = (
        []
        if str(decoys.get("routing_mode") or "strict") == "extended"
        else sorted(set(managed_decoy_domains(manifest)) & protocol_owned_sni)
    )
    if collisions:
        raise ConfigurationError(
            "managed decoy route overlaps protocol SNI on the shared TCP port: "
            + ", ".join(collisions)
        )
