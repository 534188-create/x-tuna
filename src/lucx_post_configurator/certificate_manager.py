from __future__ import annotations

import copy
import os
import re
from typing import Any

from .certificates import find_certificate_candidates, select_certificate
from .engine import Engine
from .models import ConfigurationError, valid_domain
from .renderers import GeneratedFile
from .runner import install_packages
from .transaction import create_backup, load_state, new_run_id, restore_backup


def required_domains(manifest: dict[str, Any]) -> list[str]:
    """Return every DNS name that the managed TLS frontend may present."""

    result: set[str] = set()
    lucx = manifest.get("lucx") or {}
    for name in ("panel", "subscription"):
        domain = str((lucx.get(name) or {}).get("domain") or "").lower().rstrip(".")
        if domain:
            result.add(domain)
    decoys = manifest.get("decoys") or {}
    if decoys.get("enabled"):
        for site in decoys.get("sites") or []:
            domain = str(site.get("domain") or "").lower().rstrip(".")
            if domain:
                result.add(domain)
    return sorted(result)


def certificate_status(engine: Engine) -> dict[str, Any]:
    state = load_state(engine.fs)
    manifest = state["manifest"]
    domains = required_domains(manifest)
    certs = manifest["certificates"]
    candidates = find_certificate_candidates(
        engine.fs,
        domains,
        engine.runner,
        extra_cert_paths=[certs.get("cert_path", "")],
        extra_key_paths=[certs.get("key_path", "")],
    )
    selected = select_certificate(
        engine.fs,
        domains,
        engine.runner,
        extra_cert_paths=[certs.get("cert_path", "")],
        extra_key_paths=[certs.get("key_path", "")],
    )
    return {
        "required_domains": domains,
        "configured_cert_path": certs.get("cert_path", ""),
        "configured_key_path": certs.get("key_path", ""),
        "selected": selected.as_dict() if selected else None,
        "candidates": [candidate.as_dict() for candidate in candidates],
        "needs_issue_or_replacement": selected is None,
    }


def certificate_status_for_manifest(engine: Engine, manifest: dict[str, Any]) -> dict[str, Any]:
    """Find a covering certificate for a not-yet-applied manifest."""

    domains = required_domains(manifest)
    configured = manifest.get("certificates") or {}
    selected = select_certificate(
        engine.fs,
        domains,
        engine.runner,
        extra_cert_paths=[str(configured.get("cert_path") or "")],
        extra_key_paths=[str(configured.get("key_path") or "")],
    )
    return {
        "required_domains": domains,
        "selected": selected.as_dict() if selected else None,
        "needs_issue_or_replacement": selected is None,
    }


def _safe_zone(value: str) -> str:
    zone = value.strip().lower().rstrip(".")
    if not valid_domain(zone):
        raise ConfigurationError("некорректная DNS-зона для сертификата")
    return zone


def _certbot_domains(zone: str, required: list[str]) -> list[str]:
    """Build a certificate order Let's Encrypt will accept.

    A wildcard covers exactly one label level, so explicit subdomains at the
    same level are redundant and rejected by the ACME server. Multi-level
    names under the zone must stay in the order explicitly.
    """

    outside = [name for name in required if name != zone and not name.endswith("." + zone)]
    if outside:
        raise ConfigurationError(
            "выбранная DNS-зона не покрывает домены: " + ", ".join(outside)
        )
    result = [zone, f"*.{zone}"]
    suffix = "." + zone
    for name in required:
        if name == zone:
            continue
        rest = name[: -len(suffix)]
        if "." in rest:
            result.append(name)
    return list(dict.fromkeys(result))


def issue_certbot_cloudflare(
    engine: Engine,
    *,
    zone: str,
    api_token: str | None,
    global_api_key: str | None = None,
    cloudflare_email: str = "",
    email: str = "",
    manifest_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Issue a wildcard/SAN certificate without placing the token in argv or logs."""

    if not engine.fs.is_live:
        raise RuntimeError("выпуск сертификата разрешен только в живой системе")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("выпуск сертификата требует root")
    zone = _safe_zone(zone)
    if email and ("\x00" in email or "\r" in email or "\n" in email or "@" not in email):
        raise ConfigurationError("некорректный email Certbot")
    if cloudflare_email and ("\x00" in cloudflare_email or "\r" in cloudflare_email or "\n" in cloudflare_email or "@" not in cloudflare_email):
        raise ConfigurationError("некорректный email Cloudflare")

    state = load_state(engine.fs)
    manifest = copy.deepcopy(manifest_override or state["manifest"])
    domains = required_domains(manifest)
    requested = _certbot_domains(zone, domains)
    credential_target = f"/etc/letsencrypt/lucx-cloudflare-{re.sub(r'[^a-z0-9.-]', '-', zone)}.ini"
    credential_path = engine.fs.path(credential_target)

    token = api_token or ""
    global_key = global_api_key or ""
    if token and global_key:
        raise ConfigurationError("выберите API Token или Global API Key, а не оба режима")
    for value, label in ((token, "API token"), (global_key, "Global API Key")):
        if value and any(character in value for character in ("\x00", "\r", "\n")):
            raise ConfigurationError(f"Cloudflare {label} содержит недопустимые символы")
    if global_key and not cloudflare_email:
        raise ConfigurationError("для Global API Key требуется email аккаунта Cloudflare")
    if not token and not global_key and not credential_path.is_file():
        raise ConfigurationError("нужен API Token, Global API Key или существующий credential-файл")

    install_packages(["certbot", "python3-certbot-dns-cloudflare"], engine.runner)
    generated: dict[str, GeneratedFile] = {}
    if token or global_key:
        credential_lines = []
        if token:
            credential_lines.append(f"dns_cloudflare_api_token = {token}")
        else:
            credential_lines.extend(
                [
                    f"dns_cloudflare_email = {cloudflare_email}",
                    f"dns_cloudflare_api_key = {global_key}",
                ]
            )
        generated[credential_target] = GeneratedFile(
            ("\n".join(credential_lines) + "\n").encode("utf-8"),
            mode=0o600,
            component="certificate-credentials",
        )
    backup = create_backup(
        engine.fs,
        generated,
        new_run_id() + "-certificate",
        extra_targets=[] if generated else [credential_target],
    )
    if token or global_key:
        engine.fs.atomic_write(credential_target, generated[credential_target].content, mode=0o600)

    command = [
        "certbot",
        "certonly",
        "--dns-cloudflare",
        "--dns-cloudflare-credentials",
        credential_target,
        "--dns-cloudflare-propagation-seconds",
        "30",
        "--non-interactive",
        "--agree-tos",
        "--cert-name",
        zone,
    ]
    if email:
        command.extend(["--email", email])
    else:
        command.append("--register-unsafely-without-email")
    for domain in requested:
        command.extend(["-d", domain])
    try:
        engine.runner.run(command, timeout=900)
        candidate = select_certificate(
            engine.fs,
            domains,
            engine.runner,
            extra_cert_paths=[f"/etc/letsencrypt/live/{zone}/fullchain.pem"],
        )
        if candidate is None:
            raise RuntimeError("Certbot завершился, но подходящая пара сертификат/ключ не найдена")
    except Exception:
        restore_backup(engine.fs, backup)
        raise

    updated = copy.deepcopy(manifest)
    updated["certificates"]["cert_path"] = candidate.cert_path
    updated["certificates"]["key_path"] = candidate.key_path
    updated["certificates"]["renewal"].update(
        {"enabled": True, "provider": "certbot", "primary_domain": zone}
    )
    updated["components"]["tls_hook"] = True
    updated["lucx"].setdefault("settings_management", {}).update(
        {"sync_certificate_paths": True, "user_confirmed": True}
    )
    return {
        "zone": zone,
        "requested_domains": requested,
        "candidate": candidate.as_dict(),
        "credential_path": credential_target,
        "credential_backup": str(backup.directory),
        "manifest": updated,
    }
