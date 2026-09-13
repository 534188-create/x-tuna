from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import re
import socket
import ssl
import tempfile
import time
from pathlib import Path
from typing import Any

from .discovery import Audit
from .certificates import dnsname_matches
from .models import validate_manifest
from .decoy_capabilities import managed_decoy_domains
from .decoy_health import (
    decoy_acceptance_summary, observe_decoy_capabilities, observe_vpn_capabilities,
    validate_decoy_observations, vpn_acceptance_summary,
)
from .renderers import GeneratedFile, _protected_trusttunnel_ports, extended_split_ports
from .runner import Runner
from .routing_profiles import source_routing_fingerprint
from .targetfs import TargetFS


def certificate_metadata(cert_path: Path) -> dict[str, Any]:
    decoded = ssl._ssl._test_decode_cert(str(cert_path))  # type: ignore[attr-defined]
    sans = [value for kind, value in decoded.get("subjectAltName", []) if kind == "DNS"]
    expiry = decoded.get("notAfter", "")
    expires_at = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry), tz=dt.timezone.utc)
    return {"sans": sans, "expires_at": expires_at.isoformat(), "seconds_remaining": (expires_at - dt.datetime.now(dt.timezone.utc)).total_seconds()}


def validate_certificate(fs: TargetFS, manifest: dict[str, Any], runner: Runner) -> list[str]:
    errors: list[str] = []
    cert_target = manifest["certificates"]["cert_path"]
    key_target = manifest["certificates"]["key_path"]
    cert_path = fs.path(cert_target)
    key_path = fs.path(key_target)
    if not cert_path.is_file() or cert_path.stat().st_size == 0:
        errors.append(f"certificate does not exist or is empty: {cert_target}")
    if not key_path.is_file() or key_path.stat().st_size == 0:
        errors.append(f"private key does not exist or is empty: {key_target}")
    if errors:
        return errors
    try:
        metadata = certificate_metadata(cert_path)
    except (OSError, ValueError, ssl.SSLError) as exc:
        return [f"cannot decode certificate {cert_target}: {exc}"]
    if metadata["seconds_remaining"] < 86400:
        errors.append("certificate expires in less than 24 hours")
    required_domains = {
        manifest["lucx"]["panel"]["domain"],
        manifest["lucx"]["subscription"]["domain"],
    }
    if manifest["decoys"].get("enabled"):
        required_domains.update(site["domain"] for site in manifest["decoys"].get("sites", []))
    sans = metadata["sans"]
    for domain in sorted(required_domains):
        if not any(dnsname_matches(pattern, domain) for pattern in sans):
            errors.append(f"certificate SAN does not cover {domain}")

    if fs.is_live and runner.available("openssl"):
        cert_key = runner.run(["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"], check=False)
        private_key = runner.run(["openssl", "pkey", "-in", str(key_path), "-pubout"], check=False)
        if cert_key.returncode or private_key.returncode:
            errors.append("openssl could not extract a public key from the certificate/key pair")
        elif hashlib.sha256(cert_key.stdout.encode()).digest() != hashlib.sha256(private_key.stdout.encode()).digest():
            errors.append("certificate and private key do not match")
    return errors


def _certificate_covers(path: Path, domain: str) -> bool:
    try:
        metadata = certificate_metadata(path)
    except (OSError, ValueError, ssl.SSLError):
        return False
    return any(dnsname_matches(pattern, domain) for pattern in metadata["sans"])


def validate_lucx_tls_coverage(
    fs: TargetFS,
    audit: Audit,
    manifest: dict[str, Any],
    runner: Runner | None = None,
) -> list[str]:
    errors: list[str] = []
    panel_domain = manifest["lucx"]["panel"]["domain"]
    settings_management = manifest.get("lucx", {}).get("settings_management") or {}
    selected_cert = str(manifest.get("certificates", {}).get("cert_path") or "")
    panel_cert = (
        selected_cert
        if settings_management.get("sync_certificate_paths")
        else audit.settings.get("webCertFile", "")
    )
    if (
        not panel_cert.startswith("/")
        or not fs.exists(panel_cert)
        or not _certificate_covers(fs.path(panel_cert), panel_domain)
    ):
        errors.append(
            f"LucX panel certificate configured at {panel_cert or '<empty>'} does not cover {panel_domain}; update it manually in LucX before apply"
        )
    if not manifest["components"].get("sidecar"):
        sub_domain = manifest["lucx"]["subscription"]["domain"]
        sub_cert = (
            selected_cert
            if settings_management.get("sync_certificate_paths")
            else audit.settings.get("subCertFile", "")
        )
        if (
            not sub_cert.startswith("/")
            or not fs.exists(sub_cert)
            or not _certificate_covers(fs.path(sub_cert), sub_domain)
        ):
            errors.append(
                f"LucX subscription certificate configured at {sub_cert or '<empty>'} does not cover {sub_domain}; update it manually in LucX before apply"
            )

    caddy = audit.naive_caddyfile
    planned_naive = [
        protocol
        for protocol in manifest.get("protocols", [])
        if protocol.get("protocol") == "naive" and protocol.get("exposure") == "tcp_sni"
    ]
    # When the user explicitly confirmed a DNS zone migration, the Naive
    # inbound settings are rewritten inside this same transaction and LucX
    # regenerates its Caddyfile at the x-ui restart.  The pre-commit file
    # still describes the old zone, so the strict read-only text checks below
    # would always fail; they are enforced after the restart instead
    # (validate_live_configuration), while rollback restores the database.
    if any(protocol.get("sync_naive_endpoint") for protocol in planned_naive):
        return errors
    if planned_naive and not caddy.get("found"):
        if not fs.is_live:
            errors.append(
                "a Naive SNI route is planned but its read-only Caddyfile was not found"
            )
        else:
            for protocol in planned_naive:
                host = str(protocol.get("internal_host") or "127.0.0.1")
                if host in {"", "0.0.0.0", "::", "[::]", "localhost"}:
                    host = "127.0.0.1"
                sni = str((protocol.get("sni_names") or [protocol.get("domain", "")])[0])
                deadline = time.monotonic() + 30
                last_error: Exception | None = None
                while time.monotonic() < deadline:
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        with socket.create_connection(
                            (host.strip("[]"), int(protocol["internal_port"])), timeout=5
                        ) as raw_socket:
                            with context.wrap_socket(raw_socket, server_hostname=sni) as tls_socket:
                                der = tls_socket.getpeercert(binary_form=True)
                        if not der:
                            raise ssl.SSLError("peer did not return a certificate")
                        with tempfile.NamedTemporaryFile("w", encoding="ascii", delete=False) as handle:
                            handle.write(ssl.DER_cert_to_PEM_cert(der))
                            temporary_cert = Path(handle.name)
                        try:
                            presented = certificate_metadata(temporary_cert)
                        finally:
                            temporary_cert.unlink(missing_ok=True)
                        if not any(dnsname_matches(pattern, sni) for pattern in presented["sans"]):
                            raise ssl.SSLError(f"certificate does not cover {sni}")
                        last_error = None
                        break
                    except (OSError, ValueError, ssl.SSLError) as exc:
                        last_error = exc
                        time.sleep(1)
                if last_error is not None:
                    errors.append(
                        f"Naive inbound #{protocol['inbound_id']} failed read-only TLS/SNI probe on its internal port after 30 seconds: {last_error}"
                    )
    if caddy.get("found"):
        text = fs.read_text(str(caddy["path"])).lower()
        selected_cert = manifest["certificates"]["cert_path"].lower()
        selected_key = manifest["certificates"]["key_path"].lower()
        has_selected_pair = selected_cert in text and selected_key in text
        for protocol in manifest.get("protocols", []):
            if protocol.get("protocol") != "naive" or protocol.get("exposure") != "tcp_sni":
                continue
            names = protocol.get("sni_names") or [protocol.get("domain", "")]
            managed_frontend = any(
                int(route.get("inbound_id") or 0) == int(protocol.get("inbound_id") or 0)
                and route.get("strategy") == "naive_managed"
                and route.get("status") == "ready"
                for route in (manifest.get("decoys", {}).get("extended_routes") or [])
            )
            if not has_selected_pair and not managed_frontend and not all(
                str(name).lower() in text for name in names
            ):
                errors.append(
                    f"read-only Naive Caddyfile does not visibly cover the planned SNI for inbound #{protocol['inbound_id']}; update Naive in LucX, because this tool will never edit its Caddyfile"
                )
    return errors


def routing_audit_snapshot(audit: Audit) -> dict[str, Any]:
    """Снимок маршрутов и метаданных исходных Naive-файлов без их содержимого."""
    source_fields = ("path", "sha256", "kind", "mode", "uid", "gid")
    sources = (audit.naive_caddyfile or {}).get("files") or []
    return {
        "inbounds": {
            str(item.id): source_routing_fingerprint(item)
            for item in sorted(audit.inbounds, key=lambda item: item.id) if item.enable
        },
        "naive_files": sorted(
            ({field: item.get(field) for field in source_fields} for item in sources),
            key=lambda item: str(item["path"] or ""),
        ),
    }


def validate_routing_snapshot(audit: Audit, snapshot: dict[str, Any]) -> list[str]:
    current = routing_audit_snapshot(audit)
    errors: list[str] = []
    if current["inbounds"] != snapshot.get("inbounds"):
        errors.append("Маршруты LucX изменились после staging; нужен новый аудит и план")
    if current["naive_files"] != snapshot.get("naive_files"):
        errors.append("Исходный Naive Caddyfile или его метаданные изменились после staging; запись заблокирована")
    return errors


def validate_audit_against_manifest(
    audit: Audit,
    manifest: dict[str, Any],
    *,
    allow_pending_publication: bool = False,
) -> list[str]:
    errors: list[str] = []
    if "routing_snapshot" in manifest:
        snapshot = manifest["routing_snapshot"]
        if not isinstance(snapshot, dict):
            errors.append("Снимок маршрутов повреждён; нужен новый аудит и план")
        else:
            errors.extend(validate_routing_snapshot(audit, snapshot))
    if not audit.supported_os:
        errors.append(f"target must be Debian 12 or 13, found {audit.os_id} {audit.os_version}")
    if not audit.db_schema_supported:
        errors.append("LucX database schema is not supported for safe read-only discovery")
    if manifest.get("firewall", {}).get("mode") == "strict_allowlist":
        configured_ssh = {
            int(port)
            for port in (manifest["network"].get("ssh_ports") or [manifest["network"]["ssh_port"]])
        }
        missing_ssh = sorted(set(audit.ssh_ports) - configured_ssh)
        if missing_ssh:
            errors.append(
                f"strict firewall omits detected sshd ports {missing_ssh}; configured allowlist is {sorted(configured_ssh)}"
            )
    expected_panel_domain = manifest["lucx"]["panel"]["domain"].lower()
    actual_panel_domain = audit.settings.get("webDomain", "").lower()
    sync_domains = bool(
        (manifest.get("lucx", {}).get("settings_management") or {}).get("sync_domains")
    )
    if actual_panel_domain != expected_panel_domain and not (
        allow_pending_publication and sync_domains
    ):
        errors.append(
            f"LucX webDomain is {actual_panel_domain or '<empty>'}, but the manifest requires {expected_panel_domain}; save the new domain in LucX first"
        )
    try:
        actual_web_port = int(audit.settings.get("webPort", ""))
    except ValueError:
        actual_web_port = 0
    if actual_web_port != int(manifest["lucx"]["panel"]["internal_port"]):
        errors.append(
            f"LucX webPort is {actual_web_port or '<invalid>'}, but the manifest requires {manifest['lucx']['panel']['internal_port']}"
        )
    expected_panel_path = str(manifest["lucx"]["panel"].get("path_prefix") or "/")
    actual_panel_path = str(audit.settings.get("webBasePath") or "/")
    sync_panel_path = bool(
        (manifest.get("lucx", {}).get("settings_management") or {}).get("sync_panel_path")
    )
    if actual_panel_path != expected_panel_path and not (
        allow_pending_publication and sync_panel_path
    ):
        errors.append(
            "LucX webBasePath does not match the manifest; synchronize it before applying the public panel route"
        )
    expected_sub_domain = manifest["lucx"]["subscription"]["domain"].lower()
    actual_sub_domain = audit.settings.get("subDomain", "").lower()
    if actual_sub_domain != expected_sub_domain and not (
        allow_pending_publication and sync_domains
    ):
        errors.append(
            f"LucX subDomain is {actual_sub_domain or '<empty>'}, but the manifest requires {expected_sub_domain}; save the new domain in LucX first"
        )
    raw_sub_port = str(audit.settings.get("subPort") or "").strip()
    try:
        actual_sub_port = int(raw_sub_port)
    except ValueError:
        actual_sub_port = 0
    if raw_sub_port and actual_sub_port != int(manifest["lucx"]["subscription"]["internal_port"]):
        errors.append(
            f"LucX subPort is {actual_sub_port or '<invalid>'}, but the manifest requires {manifest['lucx']['subscription']['internal_port']}"
        )
    actual_sub_path = audit.settings.get("subPath", "") or "/sub/"
    if actual_sub_path != manifest["lucx"]["subscription"]["path_prefix"]:
        errors.append(
            f"LucX subPath is {actual_sub_path}, but the manifest requires {manifest['lucx']['subscription']['path_prefix']}"
        )
    discovered = {item.id: item for item in audit.inbounds}
    configured_ids = {int(item["inbound_id"]) for item in manifest.get("protocols", [])}
    unplanned = sorted(item.id for item in audit.inbounds if item.enable and item.id not in configured_ids)
    if unplanned:
        errors.append(
            f"new enabled LucX inbounds are absent from the approved manifest: {unplanned}; create a new interactive plan"
        )
    for configured in manifest.get("protocols", []):
        actual = discovered.get(int(configured["inbound_id"]))
        if actual is None:
            errors.append(f"inbound #{configured['inbound_id']} disappeared after planning")
            continue
        if actual.protocol != configured["protocol"] or actual.port != int(configured["internal_port"]):
            errors.append(
                f"inbound #{actual.id} changed after planning: expected {configured['protocol']}:{configured['internal_port']}, "
                f"found {actual.protocol}:{actual.port}"
            )
        if not actual.enable:
            errors.append(f"inbound #{actual.id} is disabled")
        planned_fingerprint = configured.get("source_routing_fingerprint")
        if planned_fingerprint and planned_fingerprint != source_routing_fingerprint(actual):
            errors.append(f"inbound #{actual.id}: параметры маршрута изменились после планирования; нужен новый аудит")
        expected_domain = str(configured.get("domain") or "").lower()
        approved_public_sync = bool(
            configured.get("sync_public_endpoint")
            and (manifest.get("lucx", {}).get("settings_management") or {}).get(
                "sync_public_endpoints"
            )
        )
        if (
            expected_domain
            and actual.share_addr
            and actual.share_addr.lower() != expected_domain
            and not (
                allow_pending_publication
                and approved_public_sync
                and bool(
                    (manifest.get("lucx", {}).get("settings_management") or {}).get(
                        "sync_domains"
                    )
                )
            )
        ):
            errors.append(
                f"inbound #{actual.id} still publishes {actual.share_addr}, but the manifest requires {expected_domain}; update its share address in LucX first"
            )
        if configured.get("sync_share_addr") and actual.suggested_public_port != int(
            configured["public_port"]
        ) and not allow_pending_publication:
            errors.append(
                f"Naive inbound #{actual.id} publishes port {actual.suggested_public_port}, but the manifest requires {configured['public_port']}"
            )
    non_tls_id = manifest.get("network", {}).get("non_tls_backend_inbound_id")
    if non_tls_id is not None:
        selected = next(
            (item for item in manifest.get("protocols", []) if item.get("inbound_id") == non_tls_id),
            None,
        )
        if selected is None or selected.get("exposure") != "tcp_sni":
            errors.append("non_tls_backend_inbound_id must refer to a tcp_sni inbound")
    return errors


def _parse_ss_tcp_listeners(output: str) -> list[tuple[str, int, str]]:
    listeners: list[tuple[str, int, str]] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        local = fields[3] if fields[0].upper() == "LISTEN" else fields[2]
        process = " ".join(fields[5:] if fields[0].upper() == "LISTEN" else fields[4:])
        host = ""
        port_text = ""
        if local.startswith("[") and "]:" in local:
            host, port_text = local[1:].rsplit("]:" , 1)
        elif ":" in local:
            host, port_text = local.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            continue
        listeners.append((host, port, process))
    return listeners


def _parse_ss_listener_ports(output: str) -> set[int]:
    ports: set[int] = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3] if fields[0].upper() in {"LISTEN", "UNCONN"} else fields[2]
        if local.startswith("[") and "]:" in local:
            port_text = local.rsplit("]:", 1)[1]
        elif ":" in local:
            port_text = local.rsplit(":", 1)[1]
        else:
            continue
        try:
            ports.add(int(port_text))
        except ValueError:
            continue
    return ports


def _direct_decoy_domains(manifest: dict[str, Any]) -> list[str]:
    return managed_decoy_domains(manifest)


def validate_public_bind_conflicts(manifest: dict[str, Any], runner: Runner) -> list[str]:
    if not manifest["components"].get("haproxy") or not runner.available("ss"):
        return []
    result = runner.run(["ss", "-H", "-lntp"], check=False, timeout=10)
    if result.returncode:
        return ["could not inspect current TCP listeners before HAProxy bind"]
    ports = {
        int(manifest["lucx"]["panel"].get("public_port", manifest["network"]["public_tcp_port"])),
        int(manifest["lucx"]["subscription"].get("public_port", manifest["network"]["public_tcp_port"])),
    }
    if manifest["decoys"].get("enabled"):
        ports.add(int(manifest["network"]["public_tcp_port"]))
    ports.update(
        int(item["public_port"])
        for item in manifest.get("protocols", [])
        if item.get("exposure") == "tcp_sni"
    )
    bind = str(manifest["network"]["public_bind_address"])
    wildcard_bind = bind in {"0.0.0.0", "::"}
    errors: list[str] = []
    for host, port, process in _parse_ss_tcp_listeners(result.stdout):
        if port not in ports or "haproxy" in process.lower():
            continue
        host_clean = host.strip("[]")
        wildcard_listener = host_clean in {"*", "0.0.0.0", "::", ""}
        same_address = host_clean == bind
        loopback = False
        try:
            loopback = ipaddress.ip_address(host_clean).is_loopback
        except ValueError:
            pass
        if wildcard_listener or same_address or (wildcard_bind and loopback):
            errors.append(
                f"TCP/{port} cannot be assigned to HAProxy because it is already owned by {process or host_clean}"
            )
    return list(dict.fromkeys(errors))


def validate_generated(
    fs: TargetFS,
    generated: dict[str, GeneratedFile],
    staged: dict[str, Path],
    manifest: dict[str, Any],
    runner: Runner,
) -> list[str]:
    errors: list[str] = []
    validate_manifest(manifest)
    if not fs.is_live:
        return errors

    def check(command: list[str], label: str, timeout: int = 30) -> None:
        try:
            result = runner.run(command, check=False, timeout=timeout)
        except (OSError, TimeoutError) as exc:
            errors.append(f"{label} validation could not run: {exc}")
            return
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            errors.append(f"{label} validation failed: {detail}")

    for command, label in _managed_naive_adapt_commands(manifest, staged):
        check(command, label)

    if "/etc/haproxy/haproxy.cfg" in staged:
        haproxy_test = staged["/etc/haproxy/haproxy.cfg"]
        cloudflare_acl = staged.get("/etc/haproxy/cloudflare-ips.lst")
        staged_cert = staged.get("/etc/lucx-post-configurator/tls/certificate.pem")
        staged_key = staged.get("/etc/lucx-post-configurator/tls/certificate.pem.key")
        if cloudflare_acl is not None or staged_cert is not None or staged_key is not None:
            wrapper = haproxy_test.parent / "haproxy-test.cfg"
            text = haproxy_test.read_text(encoding="utf-8")
            if cloudflare_acl is not None:
                text = text.replace("/etc/haproxy/cloudflare-ips.lst", str(cloudflare_acl))
            if staged_key is not None:
                text = text.replace(
                    "/etc/lucx-post-configurator/tls/certificate.pem.key", str(staged_key)
                )
            if staged_cert is not None:
                text = text.replace(
                    "/etc/lucx-post-configurator/tls/certificate.pem", str(staged_cert)
                )
            wrapper.write_text(text, encoding="utf-8")
            haproxy_test = wrapper
        check(["haproxy", "-c", "-f", str(haproxy_test)], "HAProxy")
    if "/etc/nftables.d/60-lucx-post-configurator.nft" in staged:
        check(["nft", "-c", "-f", str(staged["/etc/nftables.d/60-lucx-post-configurator.nft"])], "nftables")
    if "/usr/local/libexec/lucx-sub-sidecar.py" in staged:
        code = "import pathlib; compile(pathlib.Path(__import__('sys').argv[1]).read_bytes(), __import__('sys').argv[1], 'exec')"
        check(["python3", "-c", code, str(staged["/usr/local/libexec/lucx-sub-sidecar.py"])], "sidecar Python")
    if "/usr/local/sbin/lucx-cloudflare-ips-update" in staged:
        code = "import pathlib; compile(pathlib.Path(__import__('sys').argv[1]).read_bytes(), __import__('sys').argv[1], 'exec')"
        check(
            ["python3", "-c", code, str(staged["/usr/local/sbin/lucx-cloudflare-ips-update"])],
            "Cloudflare updater Python",
        )
    if "/etc/logrotate.d/lucx-x-ui" in staged:
        check(["logrotate", "-d", str(staged["/etc/logrotate.d/lucx-x-ui"])], "logrotate")
    nginx_target = "/etc/nginx/conf.d/60-lucx-decoys.conf"
    if nginx_target in staged:
        wrapper_dir = staged[nginx_target].parent
        wrapper = wrapper_dir / "nginx-test.conf"
        mime = "/etc/nginx/mime.types"
        wrapper.write_text(
            "pid /tmp/lucx-post-nginx-test.pid;\n"
            "error_log stderr;\n"
            "events {}\n"
            f"http {{ include {mime}; include {staged[nginx_target]}; }}\n",
            encoding="utf-8",
        )
        check(["nginx", "-t", "-c", str(wrapper)], "Nginx")
    return errors


def _managed_naive_adapt_commands(
    manifest: dict[str, Any],
    staged: dict[str, Path],
) -> list[tuple[list[str], str]]:
    commands: list[tuple[list[str], str]] = []
    for route in (manifest.get("decoys") or {}).get("extended_routes") or []:
        if route.get("strategy") != "naive_managed" or route.get("status") != "ready":
            continue
        inbound_id = int(route.get("inbound_id") or 0)
        target = f"/etc/lucx-post-configurator/naive/naive-{inbound_id}.caddyfile"
        staged_path = staged.get(target)
        binary_path = str(route.get("binary_path") or "")
        if inbound_id <= 0 or staged_path is None or not binary_path.startswith("/"):
            continue
        commands.append(
            (
                [
                    binary_path,
                    "adapt",
                    "--config",
                    str(staged_path),
                    "--adapter",
                    "caddyfile",
                ],
                f"managed Naive inbound #{inbound_id}",
            )
        )
    return commands


def _managed_naive_live_requirements(
    manifest: dict[str, Any],
) -> tuple[list[str], set[int]]:
    services: list[str] = []
    ports: set[int] = set()
    for route in (manifest.get("decoys") or {}).get("extended_routes") or []:
        if route.get("strategy") != "naive_managed" or route.get("status") != "ready":
            continue
        inbound_id = int(route.get("inbound_id") or 0)
        port = int(route.get("managed_listen_port") or 0)
        if inbound_id > 0:
            services.append(f"lucx-naive-decoy-{inbound_id}.service")
        if 1 <= port <= 65535:
            ports.add(port)
    return sorted(set(services)), ports


def _validate_trusttunnel_firewall_listing(
    manifest: dict[str, Any], listing: str
) -> list[str]:
    if manifest.get("firewall", {}).get("mode") == "strict_allowlist":
        return []
    errors: list[str] = []
    lines = listing.splitlines()
    for port in sorted(_protected_trusttunnel_ports(manifest)):
        for transport, comment in (
            ("TCP", "TrustTunnel internal TCP"),
            ("UDP", "TrustTunnel internal UDP"),
        ):
            if not any(
                comment in line and re.search(rf"(?<!\d){port}(?!\d)", line)
                for line in lines
            ):
                errors.append(
                    f"TrustTunnel internal {transport} firewall drop is missing for port {port}"
                )
    return errors


def rollback_health_status(service_errors: list[str], integrity_errors: list[str], health_errors: list[str]) -> str:
    if service_errors:
        return "files-restored-service-errors"
    if integrity_errors:
        return "files-restored-integrity-errors"
    if health_errors:
        return "files-restored-health-errors"
    return "complete"


def validate_required_acceptance(
    manifest: dict[str, Any],
    decoy_results: list[dict[str, Any]],
    vpn_results: list[dict[str, Any]],
    *,
    audit: Audit | None = None,
    vpn_phase: str = "public",
) -> list[str]:
    if (manifest.get("decoys") or {}).get("require_full_acceptance") is not True:
        return []
    errors: list[str] = []
    if not decoy_acceptance_summary(manifest, decoy_results, audit=audit, phase=vpn_phase)["complete"]:
        errors.append("Обязательная проверка всех сайтов и их публичных портов не завершена")
    vpn = vpn_acceptance_summary(manifest, vpn_results, phase=vpn_phase)
    if not vpn["complete"]:
        errors.append("Обязательная функциональная проверка всех VPN endpoints не завершена")
        errors.extend(vpn["errors"])
    return errors


def validate_live_configuration(
    manifest: dict[str, Any],
    runner: Runner,
    *,
    fs: TargetFS | None = None,
    audit: Audit | None = None,
    decoy_results: list[dict[str, Any]] | None = None,
    vpn_results: list[dict[str, Any]] | None = None,
    vpn_phase: str = "public",
) -> list[str]:
    errors: list[str] = []
    observations: list[dict[str, Any]] = []
    components = manifest["components"]

    def wait_for_stable_xui() -> None:
        """Wait until LucX has one stable main process after a restart."""

        if runner.dry_run or not runner.available("systemctl"):
            return
        deadline = time.monotonic() + 90
        previous_pid = ""
        stable_since = 0.0
        while time.monotonic() < deadline:
            result = runner.run(
                ["systemctl", "show", "x-ui.service", "-p", "ActiveState", "-p", "MainPID"],
                check=False,
                timeout=10,
            )
            values = {}
            for line in result.stdout.splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    values[key] = value.strip()
            pid = values.get("MainPID", "0")
            if result.returncode == 0 and values.get("ActiveState") == "active" and pid not in {"", "0"}:
                if pid != previous_pid:
                    previous_pid = pid
                    stable_since = time.monotonic()
                elif time.monotonic() - stable_since >= 15:
                    return
            else:
                previous_pid = ""
                stable_since = 0.0
            time.sleep(1)
        errors.append("x-ui.service did not remain stable for 15 seconds after activation")

    def command_ok(command: list[str], label: str, timeout: int = 20) -> None:
        result = runner.run(command, check=False, timeout=timeout)
        if result.returncode:
            errors.append(f"{label}: {(result.stderr or result.stdout).strip()}")

    if components.get("haproxy"):
        command_ok(["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"], "HAProxy config")
        command_ok(["systemctl", "is-active", "--quiet", "haproxy.service"], "HAProxy service")
    if components.get("nginx") and manifest["decoys"].get("enabled"):
        command_ok(["nginx", "-t"], "Nginx config")
        command_ok(["systemctl", "is-active", "--quiet", "nginx.service"], "Nginx service")
    naive_services, naive_ports = _managed_naive_live_requirements(manifest)
    for service in naive_services:
        command_ok(
            ["systemctl", "is-active", "--quiet", service],
            f"managed Naive service {service}",
        )
    if components.get("firewall"):
        command_ok(["systemctl", "is-active", "--quiet", "lucx-post-firewall.service"], "firewall service")
        listing = runner.run(["nft", "list", "table", "inet", "lucx_post"], check=False)
        expected_chain = (
            "strict_input"
            if manifest.get("firewall", {}).get("mode") == "strict_allowlist"
            else "protect_internal"
        )
        if listing.returncode or expected_chain not in listing.stdout:
            errors.append("isolated nftables table is not active")
        elif expected_chain == "protect_internal":
            errors.extend(
                _validate_trusttunnel_firewall_listing(manifest, listing.stdout)
            )
        if (manifest.get("cloudflare") or {}).get("enabled") and (
            "cloudflare4" not in listing.stdout or "cloudflare6" not in listing.stdout
        ):
            errors.append("Cloudflare nftables source sets are not active")
    if components.get("sidecar"):
        command_ok(["systemctl", "is-active", "--quiet", "lucx-sub-sidecar.service"], "sidecar service")
    if (manifest.get("cloudflare") or {}).get("enabled"):
        command_ok(
            ["systemctl", "is-active", "--quiet", "lucx-cloudflare-ips-update.timer"],
            "Cloudflare network refresh timer",
        )

    if not runner.available("ss"):
        errors.append("listener health checks require the ss command from iproute2")
    else:
        wait_for_stable_xui()
        tcp_result = runner.run(["ss", "-H", "-lnt"], check=False, timeout=10)
        udp_result = runner.run(["ss", "-H", "-lnu"], check=False, timeout=10)
        if tcp_result.returncode or udp_result.returncode:
            errors.append("could not inspect live TCP/UDP listeners with ss")
        else:
            tcp_ports = _parse_ss_listener_ports(tcp_result.stdout)
            udp_ports = _parse_ss_listener_ports(udp_result.stdout)
            required_tcp = {
                int(manifest["lucx"]["panel"]["internal_port"]),
                int(manifest["lucx"]["subscription"]["internal_port"]),
            }
            if manifest["decoys"].get("enabled"):
                required_tcp.add(int(manifest["decoys"]["listen_port"]))
                if str(manifest["decoys"].get("routing_mode") or "strict") == "extended":
                    required_tcp.add(int(manifest["decoys"]["listen_port"]) + 1)
                    routes = list(manifest["decoys"].get("extended_routes") or [])
                    required_tcp.update(extended_split_ports(manifest, routes).values())
                    required_tcp.update(naive_ports)
            if components.get("sidecar"):
                required_tcp.add(int(manifest["sidecar"]["listen_port"]))
            required_udp: set[int] = set()
            for protocol in manifest.get("protocols", []):
                exposure = protocol.get("exposure")
                if exposure == "none":
                    continue
                if exposure == "tcp_sni":
                    required_tcp.add(int(protocol["internal_port"]))
                    if protocol.get("network") == "both":
                        required_udp.add(int(protocol.get("udp_public_port", protocol["internal_port"])))
                elif exposure == "tcp_direct":
                    required_tcp.add(int(protocol["public_port"]))
                elif exposure == "udp_direct":
                    required_udp.add(int(protocol["public_port"]))
                elif exposure == "tcp_udp_direct":
                    required_tcp.add(int(protocol["public_port"]))
                    required_udp.add(int(protocol["public_port"]))
                for binding in protocol.get("port_bindings") or []:
                    transport = str(binding.get("protocol") or "").upper()
                    if binding.get("port") is not None:
                        port = int(binding["port"])
                        if transport in {"TCP", "TCP_UDP"}:
                            required_tcp.add(port)
                        if transport in {"UDP", "TCP_UDP"}:
                            required_udp.add(port)
                    elif binding.get("port_range"):
                        low, high = (int(value) for value in str(binding["port_range"]).split("-", 1))
                        if transport in {"TCP", "TCP_UDP"} and not any(
                            low <= port <= high for port in tcp_ports
                        ):
                            errors.append(f"no live TCP listener found in configured range {low}-{high}")
                        if transport in {"UDP", "TCP_UDP"} and not any(
                            low <= port <= high for port in udp_ports
                        ):
                            errors.append(f"no live UDP listener found in configured range {low}-{high}")
            # LucX starts Xray and tunnel sidecars asynchronously after its
            # systemd service becomes active. Wait for required listeners
            # instead of taking one early snapshot and rolling back a healthy run.
            missing_tcp = sorted(required_tcp - tcp_ports)
            missing_udp = sorted(required_udp - udp_ports)
            deadline = time.monotonic() + (300 if not runner.dry_run else 0)
            stable_samples = 0
            while (missing_tcp or missing_udp) and time.monotonic() < deadline:
                time.sleep(1)
                tcp_result = runner.run(["ss", "-H", "-lnt"], check=False, timeout=10)
                udp_result = runner.run(["ss", "-H", "-lnu"], check=False, timeout=10)
                if tcp_result.returncode or udp_result.returncode:
                    continue
                tcp_ports = _parse_ss_listener_ports(tcp_result.stdout)
                udp_ports = _parse_ss_listener_ports(udp_result.stdout)
                missing_tcp = sorted(required_tcp - tcp_ports)
                missing_udp = sorted(required_udp - udp_ports)
            while not missing_tcp and not missing_udp and stable_samples < 3:
                time.sleep(2)
                tcp_result = runner.run(["ss", "-H", "-lnt"], check=False, timeout=10)
                udp_result = runner.run(["ss", "-H", "-lnu"], check=False, timeout=10)
                if tcp_result.returncode or udp_result.returncode:
                    stable_samples = 0
                    continue
                tcp_now = _parse_ss_listener_ports(tcp_result.stdout)
                udp_now = _parse_ss_listener_ports(udp_result.stdout)
                missing_tcp = sorted(required_tcp - tcp_now)
                missing_udp = sorted(required_udp - udp_now)
                if missing_tcp or missing_udp:
                    stable_samples = 0
                    deadline = max(deadline, time.monotonic() + 30)
                else:
                    stable_samples += 1
            if missing_tcp:
                errors.append(f"required TCP listeners are absent: {missing_tcp}")
            if missing_udp:
                errors.append(f"required UDP listeners are absent: {missing_udp}")

    if components.get("haproxy"):
        connect_host = str(manifest["network"].get("public_bind_address") or "127.0.0.1")
        if connect_host == "::":
            connect_host = "::1"
        elif connect_host == "0.0.0.0":
            connect_host = "127.0.0.1"
        probes = [
            (
                int(manifest["lucx"]["panel"].get("public_port", manifest["network"]["public_tcp_port"])),
                manifest["lucx"]["panel"]["domain"],
            ),
            (
                int(manifest["lucx"]["subscription"].get("public_port", manifest["network"]["public_tcp_port"])),
                manifest["lucx"]["subscription"]["domain"],
            ),
        ]
        if manifest["decoys"].get("enabled"):
            probes.extend(
                (int(manifest["network"]["public_tcp_port"]), domain)
                for domain in _direct_decoy_domains(manifest)
            )
        for protocol in manifest.get("protocols", []):
            if protocol.get("exposure") == "tcp_sni":
                if str(protocol.get("security") or "").lower() == "reality":
                    # Reality camouflage serverNames are external domains the
                    # backend answers to only for genuine Reality clients.
                    # A local probe with a random SNI must fail; probing them
                    # here would flag healthy Reality inbounds as broken.
                    continue
                probes.extend(
                    (int(protocol["public_port"]), domain)
                    for domain in (protocol.get("sni_names") or [protocol["domain"]])
                )
        for port, domain in dict.fromkeys(probes):
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection(
                    (connect_host, port), timeout=10
                ) as raw_socket:
                    with context.wrap_socket(raw_socket, server_hostname=domain) as tls_socket:
                        der = tls_socket.getpeercert(binary_form=True)
                if not der:
                    raise ssl.SSLError("peer did not return a certificate")
                with tempfile.NamedTemporaryFile("w", encoding="ascii", delete=False) as handle:
                    handle.write(ssl.DER_cert_to_PEM_cert(der))
                    temporary_cert = Path(handle.name)
                try:
                    presented = certificate_metadata(temporary_cert)
                finally:
                    temporary_cert.unlink(missing_ok=True)
                # Protocol TLS may be passed through to an unchanged LucX
                # backend. Its certificate is not the public frontend
                # certificate and can legitimately retain the old SNI.
                managed_frontend_domains = {
                    str(manifest["lucx"]["panel"]["domain"]).lower(),
                    str(manifest["lucx"]["subscription"]["domain"]).lower(),
                }
                if manifest["decoys"].get("enabled"):
                    managed_frontend_domains.update(
                        str(item.get("domain") or "").lower()
                        for item in manifest["decoys"].get("sites", [])
                    )
                protocol_domains = {
                    str(item.get("domain") or "").lower()
                    for item in manifest.get("protocols", [])
                }
                if (
                    domain.lower() in managed_frontend_domains
                    and domain.lower() not in protocol_domains
                    and not any(dnsname_matches(pattern, domain) for pattern in presented["sans"])
                ):
                    errors.append(f"TLS endpoint presents a certificate that does not cover {domain}")
            except (OSError, ValueError, ssl.SSLError) as exc:
                errors.append(f"TLS probe through HAProxy on TCP/{port} failed for {domain}: {exc}")
        if manifest["decoys"].get("enabled"):
            observations = observe_decoy_capabilities(manifest, connect_host, runner=runner, audit=audit, phase=vpn_phase)
            if decoy_results is not None:
                decoy_results.extend(observations)
            errors.extend(validate_decoy_observations(manifest, observations, audit=audit, phase=vpn_phase))
    vpn_observations = observe_vpn_capabilities(
        manifest, runner, observers=getattr(runner, "vpn_observers", None), phase=vpn_phase
    )
    if vpn_results is not None:
        vpn_results.extend(vpn_observations)
    errors.extend(validate_required_acceptance(manifest, observations, vpn_observations,
                                              audit=audit, vpn_phase=vpn_phase))
    for observation in vpn_observations:
        if observation["state"] == "failed":
            errors.append(f"functional public VPN probe failed for inbound #{observation['inbound_id']}")
    # After a confirmed zone migration LucX regenerated the Naive Caddyfile
    # during the x-ui restart. Verify the regenerated file actually covers the
    # planned SNI and certificate pair; a failure here triggers the standard
    # rollback of the whole transaction.
    if fs is not None and audit is not None and any(
        protocol.get("sync_naive_endpoint")
        and protocol.get("exposure") == "tcp_sni"
        for protocol in manifest.get("protocols", [])
        if protocol.get("protocol") == "naive"
    ):
        for protocol in manifest.get("protocols", []):
            if protocol.get("protocol") != "naive" or protocol.get("exposure") != "tcp_sni":
                continue
            names = [str(value).lower() for value in (protocol.get("sni_names") or [protocol.get("domain", "")])]
            selected_cert = str(manifest["certificates"]["cert_path"]).lower()
            selected_key = str(manifest["certificates"]["key_path"]).lower()
            regenerated_ok = False
            last_detail = ""
            for candidate in (audit.naive_caddyfile or {}).get("files") or []:
                try:
                    text = fs.read_text(str(candidate["path"])).lower()
                except (OSError, ValueError):
                    last_detail = f"cannot read {candidate['path']}"
                    continue
                has_pair = selected_cert in text and selected_key in text
                has_sni = any(str(value).lower() in text for value in names)
                if has_pair and has_sni:
                    regenerated_ok = True
                    break
                last_detail = f"{candidate['path']}: pair={has_pair} sni={has_sni}"
            if not regenerated_ok:
                errors.append(
                    "LucX did not regenerate the Naive Caddyfile for the new zone "
                    f"(inbound #{protocol['inbound_id']}; {last_detail})"
                )
    # After a confirmed zone migration every synced TLS tunnel must actually
    # accept the new SNI on its own backend port. TrustTunnel strictly rejects
    # ClientHello whose SNI differs from its configured hostname, so a plain
    # probe against the shared 443 is replaced by a direct backend probe here.
    if fs is not None and runner is not None:
        synced = [
            protocol
            for protocol in manifest.get("protocols", [])
            if protocol.get("sync_naive_endpoint")
            and str(protocol.get("security") or "").strip().lower() != "reality"
            and int(protocol.get("public_port") or 443) == 443
            and str(protocol.get("exposure") or "") == "tcp_sni"
        ]
        connect_host = "127.0.0.1"
        for protocol in synced:
            inbound_id = int(protocol["inbound_id"])
            listener = None
            for binding in protocol.get("port_bindings") or []:
                if str(binding.get("protocol") or "").lower() == "tcp":
                    listener = int(binding.get("port") or 0)
                    break
            if not listener:
                continue
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            last_error: Exception | None = None
            for _ in range(10):
                try:
                    with socket.create_connection(
                        (connect_host, listener), timeout=6
                    ) as raw_socket:
                        with context.wrap_socket(
                            raw_socket, server_hostname=protocol["domain"]
                        ):
                            pass
                    last_error = None
                    break
                except (OSError, ValueError, ssl.SSLError) as exc:
                    last_error = exc
                    time.sleep(1)
            if last_error is not None:
                errors.append(
                    f"TLS probe of inbound #{inbound_id} ({protocol.get('protocol')}) "
                    f"on backend port {listener} failed for the new SNI "
                    f"{protocol['domain']}: {last_error}"
                )
    return errors
