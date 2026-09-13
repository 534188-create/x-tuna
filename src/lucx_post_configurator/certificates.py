from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import re
import ssl
from pathlib import Path
from typing import Iterable

from .runner import Runner
from .targetfs import TargetFS


@dataclasses.dataclass(slots=True)
class CertificateCandidate:
    cert_path: str
    key_path: str
    sans: list[str]
    expires_at: str
    seconds_remaining: float
    wildcard: bool
    key_matches: bool
    source: str
    renewal_name: str = ""

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


def dnsname_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.strip().lower().rstrip(".")
    hostname = hostname.strip().lower().rstrip(".")
    if pattern.startswith("dns:"):
        pattern = pattern[4:].strip().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        # A wildcard covers exactly one label before its suffix.
        return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")
    return pattern == hostname


def _target_path(fs: TargetFS, actual: Path) -> str:
    relative = actual.absolute().relative_to(fs.root)
    return "/" + relative.as_posix()


def _key_candidates(cert: Path) -> list[Path]:
    names = [
        "privkey.pem",
        "key.pem",
        cert.name.replace("fullchain", "privkey"),
        cert.name.replace("fullchain", "key"),
    ]
    stem = cert.parent.name.replace("_ecc", "")
    names.extend([f"{stem}.key", f"{stem}.pem"])
    result: list[Path] = []
    for name in names:
        candidate = cert.parent / name
        if candidate != cert and candidate.is_file() and candidate not in result:
            result.append(candidate)
    for candidate in sorted(cert.parent.glob("*.key")):
        if candidate not in result:
            result.append(candidate)
    return result


def _key_matches(cert: Path, key: Path, fs: TargetFS, runner: Runner) -> bool:
    if not fs.is_live:
        return key.is_file() and key.stat().st_size > 0
    if not runner.available("openssl"):
        return False
    certificate_key = runner.run(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"], check=False)
    private_key = runner.run(["openssl", "pkey", "-in", str(key), "-pubout"], check=False)
    if certificate_key.returncode or private_key.returncode:
        return False
    return hashlib.sha256(certificate_key.stdout.encode()).digest() == hashlib.sha256(private_key.stdout.encode()).digest()


def _decode(cert: Path) -> tuple[list[str], dt.datetime] | None:
    try:
        decoded = ssl._ssl._test_decode_cert(str(cert))  # type: ignore[attr-defined]
        sans = [value.lower() for kind, value in decoded.get("subjectAltName", []) if kind == "DNS"]
        expiry = dt.datetime.fromtimestamp(
            ssl.cert_time_to_seconds(decoded["notAfter"]), tz=dt.timezone.utc
        )
        return sans, expiry
    except (KeyError, OSError, ValueError, ssl.SSLError):
        return None


def acme_renewal_name(cert: Path) -> str:
    """Read acme.sh's primary domain without exposing other account data."""
    for config in sorted(cert.parent.glob("*.conf")):
        try:
            text = config.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = re.search(r"^Le_Domain=(?:'([^']+)'|\"([^\"]+)\"|([^\r\n]+))$", text, re.MULTILINE)
        if match:
            value = next((item for item in match.groups() if item is not None), "").strip()
            if value:
                return value
    domain_stem = cert.parent.name.removesuffix("_ecc").replace("_wildcard.", "*.")
    try:
        candidate_roots = [cert.parent.parent.parent / ".acme.sh"]
        for root_dir in candidate_roots:
            if root_dir.is_dir():
                for sub in (root_dir / f"{domain_stem}_ecc", root_dir / domain_stem):
                    if sub.is_dir():
                        for config in sorted(sub.glob("*.conf")):
                            try:
                                text = config.read_text(encoding="utf-8", errors="replace")
                            except OSError:
                                continue
                            match = re.search(r"^Le_Domain=(?:'([^']+)'|\"([^\"]+)\"|([^\r\n]+))$", text, re.MULTILINE)
                            if match:
                                value = next((item for item in match.groups() if item is not None), "").strip()
                                if value:
                                    return value
    except Exception:
        pass
    return domain_stem


def _candidate_cert_paths(fs: TargetFS, extra_paths: Iterable[str]) -> list[tuple[Path, str]]:
    result: list[tuple[Path, str]] = []
    seen: set[Path] = set()

    def add(path: Path, source: str) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            return
        if resolved.is_file() and resolved not in seen:
            try:
                resolved.relative_to(fs.root)
            except ValueError:
                return
            seen.add(resolved)
            result.append((path.absolute(), source))

    def classify(value: str, fallback: str) -> str:
        if "/.acme.sh/" in value or value.startswith("/root/cert/") or "/root/cert/" in value:
            return "acme.sh"
        if value.startswith("/etc/letsencrypt/live/"):
            return "Certbot"
        return fallback

    for value in extra_paths:
        if value and str(value).startswith("/"):
            add(fs.path(value), classify(str(value), "LucX/current manifest"))

    roots = [
        ("/root/.acme.sh", "acme.sh"),
        ("/root/cert", "acme.sh"),
        ("/etc/letsencrypt/live", "Certbot"),
        ("/etc/x-ui", "LucX"),
    ]
    home_root = fs.path("/home")
    if home_root.is_dir():
        for home in home_root.iterdir():
            roots.append((f"/home/{home.name}/.acme.sh", "acme.sh"))
    for target_root, source in roots:
        actual_root = fs.path(target_root)
        if not actual_root.is_dir():
            continue
        for pattern in ("fullchain.pem", "fullchain.cer", "*fullchain*.pem", "*fullchain*.cer"):
            for path in actual_root.glob(f"**/{pattern}"):
                add(path, source)
    return result


def find_certificate_candidates(
    fs: TargetFS,
    domains: Iterable[str],
    runner: Runner,
    *,
    extra_cert_paths: Iterable[str] = (),
    extra_key_paths: Iterable[str] = (),
) -> list[CertificateCandidate]:
    required = sorted({domain.lower().rstrip(".") for domain in domains if domain})
    now = dt.datetime.now(dt.timezone.utc)
    result: list[CertificateCandidate] = []
    for cert, source in _candidate_cert_paths(fs, extra_cert_paths):
        decoded = _decode(cert)
        if not decoded:
            continue
        sans, expiry = decoded
        if not all(any(dnsname_matches(pattern, domain) for pattern in sans) for domain in required):
            continue
        configured_keys = [fs.path(value) for value in extra_key_paths if str(value).startswith("/")]
        for key in [*configured_keys, *_key_candidates(cert)]:
            if not _key_matches(cert, key, fs, runner):
                continue
            result.append(
                CertificateCandidate(
                    cert_path=_target_path(fs, cert),
                    key_path=_target_path(fs, key),
                    sans=sans,
                    expires_at=expiry.isoformat(),
                    seconds_remaining=(expiry - now).total_seconds(),
                    wildcard=any(value.startswith("*.") for value in sans),
                    key_matches=True,
                    source=source,
                    renewal_name=(
                        acme_renewal_name(cert)
                        if source == "acme.sh"
                        else cert.parent.name if source == "Certbot" else ""
                    ),
                )
            )
            break
    result.sort(key=lambda item: (item.seconds_remaining > 86400, item.wildcard, item.seconds_remaining), reverse=True)
    return result


def select_certificate(
    fs: TargetFS,
    domains: Iterable[str],
    runner: Runner,
    *,
    extra_cert_paths: Iterable[str] = (),
    extra_key_paths: Iterable[str] = (),
) -> CertificateCandidate | None:
    candidates = find_certificate_candidates(
        fs, domains, runner, extra_cert_paths=extra_cert_paths, extra_key_paths=extra_key_paths
    )
    return next((candidate for candidate in candidates if candidate.seconds_remaining >= 86400), None)
