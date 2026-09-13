from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .decoy_capabilities import classify_decoy_capabilities
from .runner import Runner, OutputLimitExceeded
from .routing_profiles import routing_fingerprint, public_ingresses
from .models import Audit
from .decoy_content import MAX_BODY_BYTES, verify_site


MAX_RESPONSE_BYTES = 8192
VPNObserver = Callable[[dict[str, Any], Runner], dict[str, Any]]
VPN_PROBE_PHASES = frozenset({"direct", "staging", "public", "rollback"})
BROWSER_PROBE_PHASES = frozenset({"direct", "staging", "public", "rollback"})


@dataclass(frozen=True, slots=True)
class BrowserDialAddress:
    """Адрес временного listener задаётся только кодом, отдельно от endpoint."""
    host: str
    port: int

    def __post_init__(self) -> None:
        if (not isinstance(self.host, str) or "%" in self.host
                or not ipaddress.ip_address(self.host).is_loopback
                or type(self.port) is not int or not 1 <= self.port <= 65535):
            raise ValueError("Некорректный loopback адрес browser-пробы")


BrowserDialProvider = Callable[[dict[str, Any], str], BrowserDialAddress]


def _validate_browser_phase(phase: str) -> None:
    if phase not in BROWSER_PROBE_PHASES:
        raise ValueError("Неизвестная фаза браузерной проверки")


def _observer_supports(observer: Any, protocol: dict[str, Any]) -> bool:
    if not callable(observer):
        return False
    supports = getattr(observer, "supports", None)
    if supports is None:
        # Совместимость с явно переданными кодом одноразовыми observers.
        return True
    try:
        return callable(supports) and supports(copy.deepcopy(protocol)) is True
    except Exception:
        return False


def _validate_vpn_phase(phase: str) -> None:
    if phase not in VPN_PROBE_PHASES:
        raise ValueError("Неизвестная фаза функциональной VPN-проверки")


def _probe_protocol(target: dict[str, Any], phase: str) -> dict[str, Any]:
    protocol = copy.deepcopy(target["protocol"])
    protocol["acceptance_target"] = dict(target["identity"])
    protocol["acceptance_endpoint"] = copy.deepcopy(target["endpoint"])
    protocol["acceptance_phase"] = phase
    return protocol


def _observer_preflight(observer: Any, protocol: dict[str, Any], runner: Runner) -> bool:
    if not _observer_supports(observer, protocol):
        return False
    preflight = getattr(observer, "preflight", None)
    if preflight is None:
        return True
    try:
        return callable(preflight) and preflight(copy.deepcopy(protocol), runner) is True
    except Exception:
        return False


def _strict_acceptance(manifest: dict[str, Any]) -> bool:
    return (manifest.get("decoys") or {}).get("require_full_acceptance") is True


def _acceptance_fingerprint(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _decoy_profile_fingerprint(manifest: dict[str, Any], *, audit: Audit | None = None, phase: str = "public") -> str:
    # Профиль связывает результаты с текущими сайтами, маршрутами и портами.
    port = int((manifest.get("network") or {}).get("public_tcp_port") or 443)
    return _acceptance_fingerprint({"decoys": manifest.get("decoys"),
        "capabilities": _capabilities(manifest, audit=audit, phase=phase),
        "network": manifest.get("network"), "protocols": [routing_fingerprint(item, port)
            for item in manifest.get("protocols") or []]})


def _vpn_targets(manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    targets, errors, inbound_ids, endpoint_ids = [], [], set(), set()
    port = (manifest.get("network") or {}).get("public_tcp_port", 443)
    for protocol in manifest.get("protocols") or []:
        if not isinstance(protocol, dict):
            errors.append("Некорректный профиль обязательной VPN-проверки.")
            continue
        if protocol.get("exposure") == "none" or protocol.get("enable") is False:
            continue
        inbound_id = protocol.get("inbound_id")
        endpoints = protocol.get("public_endpoints")
        if type(inbound_id) is not int or inbound_id <= 0 or inbound_id in inbound_ids:
            errors.append("Отсутствует или повторяется идентификатор VPN inbound.")
            continue
        inbound_ids.add(inbound_id)
        if not isinstance(endpoints, list) or not endpoints:
            errors.append(f"VPN inbound #{inbound_id}: публичные endpoints не подтверждены.")
            continue
        try:
            profile = routing_fingerprint(protocol, port)
        except (TypeError, ValueError):
            errors.append(f"VPN inbound #{inbound_id}: профиль не пригоден для проверки.")
            continue
        host_ids = set()
        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                errors.append(f"VPN inbound #{inbound_id}: некорректный публичный endpoint.")
                continue
            address = endpoint.get("address")
            valid = (endpoint.get("valid", True) is True
                and isinstance(address, str) and bool(re.fullmatch(r"[A-Za-z0-9.:-]+", address))
                and type(endpoint.get("port")) is int and 1 <= endpoint["port"] <= 65535
                and type(endpoint.get("host_id")) is int and endpoint["host_id"] >= 0
                and isinstance(endpoint.get("sni"), str)
                and type(endpoint.get("keep_sni_blank")) is bool
                and endpoint.get("sni_source") in {"blank", "address", "explicit", "inherited"})
            if not valid:
                errors.append(f"VPN inbound #{inbound_id}: публичный endpoint не подтверждён.")
                continue
            if endpoint["host_id"] in host_ids:
                errors.append(f"VPN inbound #{inbound_id}: идентификатор Host повторяется.")
                continue
            host_ids.add(endpoint["host_id"])
            identity = {name: endpoint.get(name) for name in (
                "host_id", "address", "port", "sni", "sni_source", "keep_sni_blank", "http_host")}
            fingerprint = _acceptance_fingerprint(identity)
            key = (inbound_id, fingerprint)
            if key in endpoint_ids:
                errors.append(f"VPN inbound #{inbound_id}: публичный endpoint повторяется.")
                continue
            endpoint_ids.add(key)
            targets.append({"protocol": protocol, "endpoint": endpoint, "identity": {
                "inbound_id": inbound_id, "profile_fingerprint": profile,
                "endpoint_fingerprint": fingerprint}})
    return targets, errors


def required_vpn_probe_errors(manifest: dict[str, Any], runner: Runner) -> list[str]:
    """До commit проверяет наличие адаптеров, не запускает probes или команды."""
    if not _strict_acceptance(manifest):
        return []
    targets, errors = _vpn_targets(manifest)
    observers = getattr(runner, "vpn_observers", {})
    observers = observers if isinstance(observers, Mapping) else {}
    for target in targets:
        if not _observer_preflight(observers.get(target["protocol"].get("protocol")),
                                   _probe_protocol(target, "public"), runner):
            message = f"VPN inbound #{target['identity']['inbound_id']}: нет обязательного функционального адаптера."
            if message not in errors:
                errors.append(message)
    return errors


def _functional_evidence(row: Mapping[str, Any], phase: str = "public") -> bool:
    return (row.get("phase") == phase and row.get("functional") is True
        and row.get("public") is (phase in {"public", "rollback"})
        and row.get("authenticated") is True
        and all(type(row.get(name)) is int and 0 < row[name] <= 2**63 - 1
                for name in ("bytes_sent", "bytes_received")))


def vpn_acceptance_summary(manifest: dict[str, Any], observations: list[dict[str, Any]], *,
                           phase: str = "public") -> dict[str, Any]:
    """Не считает отсутствующие, повторные или устаревшие результаты успехом."""
    _validate_vpn_phase(phase)
    if not _strict_acceptance(manifest):
        expected = [p for p in manifest.get("protocols") or [] if p.get("exposure") != "none"]
        verified = sum(row.get("state") == "healthy" for row in observations)
        return {"complete": verified == len(expected) == len(observations),
                "required_endpoints": len(expected), "verified_endpoints": verified, "errors": []}
    targets, errors = _vpn_targets(manifest)
    verified, consumed = 0, set()
    for target in targets:
        identity = target["identity"]
        matches = [(index, row) for index, row in enumerate(observations)
                   if isinstance(row, Mapping) and all(row.get(k) == v for k, v in identity.items())]
        consumed.update(index for index, _ in matches)
        if len(matches) == 1 and matches[0][1].get("state") == "healthy" and _functional_evidence(matches[0][1], phase):
            verified += 1
        else:
            errors.append(f"VPN inbound #{identity['inbound_id']}: обязательная публичная функциональная проверка не подтверждена.")
    if len(consumed) != len(observations):
        errors.append("Получены лишние или устаревшие результаты VPN-проверок.")
    return {"complete": not errors and verified == len(targets), "required_endpoints": len(targets),
            "verified_endpoints": verified, "errors": errors}


def evaluate_http_response(response: bytes, expected_marker: str | None) -> dict[str, Any]:
    """Маркер принимается только из единственного самостоятельного заголовка."""
    header_block, separator, _ = response.partition(b"\r\n\r\n")
    lines = header_block.split(b"\r\n")
    match = re.fullmatch(rb"HTTP/(?:1\.[01]|2) ([0-9]{3})(?: [^\r\n]*)?", lines[0])
    status = int(match[1]) if match else 0
    invalid = not separator or len(header_block) > MAX_RESPONSE_BYTES or not 200 <= status < 400
    markers = []
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            invalid = True
        if any(char < 32 and char != 9 for char in value) or b"\x7f" in value:
            invalid = True
        if name.lower() == b"x-lucx-decoy":
            markers.append(value.strip(b" \t"))
    if invalid:
        return {"state": "http_error", "status": status, "detail": "invalid HTTP response"}
    if expected_marker is not None:
        name, colon, value = expected_marker.partition(":")
        try:
            expected = value.strip().encode("ascii")
        except UnicodeEncodeError:
            expected = b""
        if name.lower() != "x-lucx-decoy" or not colon or not expected or markers != [expected]:
            return {"state": "http_error", "status": status, "detail": "managed marker is absent or ambiguous"}
        return {"state": "healthy", "status": status, "detail": "managed marker observed"}
    return {"state": "site_observed", "status": status, "detail": "HTTPS response observed"}


def _observe_h2(domain: str, address: str, port: int, expected_marker: str | None,
                timeout: float, use_tls: bool, method: str, verify_tls: bool,
                runner: Runner, *, capture_body: bool = False,
                request_path: str = "/", dial_address: BrowserDialAddress | None = None,
                ca_file: str | None = None) -> dict[str, Any]:
    """Настоящий h2 через установленный curl; адреса передаются только stdin."""
    unavailable = {"state": "not_tested", "status": 0, "detail": "HTTP/2 не проверялся: нужен curl с HTTP2"}
    if runner.dry_run or not runner.available("curl"):
        return unavailable
    deadline = time.monotonic() + timeout
    try:
        execute = runner.run_bounded if capture_body else runner.run
        limits = {"max_output_bytes": MAX_RESPONSE_BYTES + MAX_BODY_BYTES + 1024,
                  "output_encoding": "latin-1"} if capture_body else {}
        version = execute(["curl", "--disable", "--version"], check=False, timeout=min(10, timeout), **limits)
        if version.returncode or not any(
            line.startswith("Features:") and "HTTP2" in line.split() for line in version.stdout.splitlines()
        ):
            return unavailable
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HTTP/2 deadline")
        def quoted(value: str) -> str:
            return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
        resolved = f"[{address}]" if ":" in address else address
        connection_option = "resolve = " + quoted(f"{domain}:{port}:{resolved}")
        if dial_address is not None:
            host = f"[{dial_address.host}]" if ":" in dial_address.host else dial_address.host
            connection_option = "connect-to = " + quoted(f"{domain}:{port}:{host}:{dial_address.port}")
        config = [
            "url = " + quoted(f"{'https' if use_tls else 'http'}://{domain}:{port}{request_path}"),
            connection_option,
            "output = " + quoted("-" if capture_body else os.devnull),
            'dump-header = "-"',
            'write-out = "\\nLUCX_HTTP_VERSION:%{http_version}"',
            f"max-time = {remaining}",
            'user-agent = "lucx-post-configurator-health"',
            'header = "Accept: text/html,*/*;q=0.1"',
        ]
        if method == "HEAD":
            if capture_body:
                # CUSTOMREQUEST меняет метод без CURLOPT_NOBODY: curl читает
                # поток до END_STREAM и не скрывает поздние DATA. Размер GET-
                # представления в Content-Length не является телом HEAD.
                config.extend(['request = "HEAD"', "ignore-content-length"])
            else:
                config.append("head")
        if capture_body:
            config.append(f"max-filesize = {MAX_BODY_BYTES}")
        if not verify_tls:
            config.append("insecure")
        if ca_file is not None:
            config.append("cacert = " + quoted(ca_file))
        result = execute([
            "curl", "--disable", "--silent", "--noproxy", "*", "--proto", "=http,https",
            "--http2" if use_tls else "--http2-prior-knowledge", "--config", "-",
        ], check=False, timeout=remaining, input_text="\n".join(config) + "\n", **limits)
    except (OSError, ValueError, subprocess.TimeoutExpired, OutputLimitExceeded):
        return {"state": "http_error", "status": 0, "detail": "HTTP/2 probe execution failed"}
    if result.returncode:
        return {"state": "tls_error" if result.returncode in {35, 51, 60} else "http_error",
                "status": 0, "detail": f"HTTP/2 curl failed (code {result.returncode})"}
    headers, separator, wire_version = result.stdout.rpartition("\nLUCX_HTTP_VERSION:")
    if not separator or wire_version.strip() != "2":
        return {"state": "http_error", "status": 0, "detail": "HTTP/2 was not negotiated"}
    # Нормализуем только заголовки. latin-1 сохраняет все байты тела curl.
    boundary = re.search(r"\r?\n\r?\n", headers)
    if boundary is None:
        return {"state": "http_error", "status": 0, "detail": "HTTP/2 response headers are incomplete"}
    head = headers[:boundary.start()].replace("\r\n", "\n").replace("\n", "\r\n")
    body = headers[boundary.end():]
    encoding = "latin-1" if capture_body else "utf-8"
    normalized = head.encode(encoding) + b"\r\n\r\n" + body.encode(encoding)
    if not normalized.startswith(b"HTTP/2 "):
        return {"state": "http_error", "status": 0, "detail": "HTTP/2 response headers are absent"}
    if capture_body:
        return {"response": normalized}
    return evaluate_http_response(normalized, expected_marker)


def _strict_h1_response(domain: str, address: str, port: int, path: str, method: str,
                        timeout: float, use_tls: bool, verify_tls: bool, *,
                        dial_address: BrowserDialAddress | None = None,
                        ca_file: str | None = None) -> bytes:
    deadline = time.monotonic() + timeout
    limit = MAX_RESPONSE_BYTES + MAX_BODY_BYTES
    authority = domain if port == (443 if use_tls else 80) else f"{domain}:{port}"
    destination = (address, port) if dial_address is None else (dial_address.host, dial_address.port)
    with socket.create_connection(destination, timeout=timeout) as raw_socket:
        stream = raw_socket
        def remaining_time() -> float:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTP probe deadline")
            return remaining
        if use_tls:
            context = ssl.create_default_context()
            if ca_file is not None:
                context.load_verify_locations(cafile=ca_file)
            context.set_alpn_protocols(["http/1.1"])
            if not verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            raw_socket.settimeout(remaining_time())
            stream = context.wrap_socket(raw_socket, server_hostname=domain)
        try:
            stream.settimeout(remaining_time())
            stream.sendall((f"{method} {path} HTTP/1.1\r\nHost: {authority}\r\n"
                            "User-Agent: lucx-post-configurator-health\r\n"
                            "Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii"))
            response = bytearray()
            while len(response) <= limit:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("HTTP probe deadline")
                stream.settimeout(remaining)
                chunk = stream.recv(min(4096, limit + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
            return bytes(response)
        finally:
            if use_tls:
                stream.close()


def _observe_strict_content(domain: str, address: str, port: int, marker: str | None,
                            timeout: float, use_tls: bool, method: str, version: str,
                            verify_tls: bool, runner: Runner, *,
                            dial_address: BrowserDialAddress | None = None,
                            ca_file: str | None = None) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    def request(path: str, remaining: float, request_method: str = "GET") -> bytes:
        remaining = min(remaining, deadline - time.monotonic())
        if remaining <= 0:
            raise TimeoutError("HTTP content deadline")
        if version == "h2":
            observed = _observe_h2(domain, address, port, None, remaining, use_tls,
                                   request_method, verify_tls, runner, capture_body=True, request_path=path,
                                   dial_address=dial_address, ca_file=ca_file)
            if "response" not in observed:
                raise ValueError("HTTP/2 content probe failed")
            return observed["response"]
        return _strict_h1_response(domain, address, port, path, request_method, remaining, use_tls, verify_tls,
                                   dial_address=dial_address, ca_file=ca_file)
    try:
        if runner.dry_run:
            return {"state":"not_tested", "status":0, "detail":"Содержимое сайта не проверялось в dry-run"}
        if version == "h2":
            initial = _observe_h2(domain, address, port, marker, deadline - time.monotonic(), use_tls, method,
                                  verify_tls, runner, capture_body=True, dial_address=dial_address, ca_file=ca_file)
            if "response" not in initial:
                return initial
            response = initial["response"]
        else:
            response = request("/", timeout, method)
        header_result = evaluate_http_response(response, marker)
        if header_result["state"] != "healthy":
            return header_result
        result = verify_site(response, method, f"{'https' if use_tls else 'http'}://{domain}:{port}/", request, timeout, deadline=deadline)
        return {**result, "status": header_result["status"],
                "detail":"Содержимое сайта проверено" if result["state"] == "healthy" else "Содержимое или ресурсы сайта не подтверждены"}
    except (OSError, ValueError, subprocess.TimeoutExpired, OutputLimitExceeded):
        return {"state":"http_error", "status":0, "detail":"Проверка содержимого сайта не завершена"}


def observe_decoy(domain: str, address: str, port: int, expected_marker: str | None,
                  timeout: float = 10.0, *, use_tls: bool = True, method: str = "GET",
                  http_version: str = "h1", verify_tls: bool = True,
                  runner: Runner | None = None, strict_content: bool = False,
                  phase: str = "public", dial_address: BrowserDialAddress | None = None,
                  ca_file: str | None = None) -> dict[str, Any]:
    if method not in {"GET", "HEAD"} or http_version not in {"h1", "h2"}:
        return {"state": "http_error", "status": 0, "detail": "unsupported HTTP probe"}
    try:
        _validate_browser_phase(phase)
        if dial_address is not None:
            if phase not in {"direct", "staging"} or type(dial_address) is not BrowserDialAddress:
                raise ValueError("Недопустимое переназначение browser-пробы")
            if use_tls and not verify_tls:
                raise ValueError("Временная TLS-проба требует проверки сертификата и имени")
        elif phase in {"direct", "staging"}:
            raise ValueError("Не задан адрес временной browser-пробы")
        if ca_file is not None and (phase not in {"direct", "staging"}
                or not isinstance(ca_file, str) or not os.path.isabs(ca_file)
                or any(ord(char) < 32 or ord(char) == 127 for char in ca_file)):
            raise ValueError("Недопустимый кодовый CA browser-пробы")
        if not re.fullmatch(r"[A-Za-z0-9.-]+", domain) or not 0 < int(port) < 65536:
            raise ValueError("invalid destination")
        ipaddress.ip_address(address)
        if not verify_tls and not ipaddress.ip_address(address).is_loopback:
            raise ValueError("internal TLS policy requires loopback")
    except ValueError:
        return {"state": "http_error", "status": 0, "detail": "invalid probe destination or TLS policy"}
    if runner is not None and runner.dry_run:
        return {"state": "not_tested", "status": 0, "detail": "Браузерная проверка не выполнялась в dry-run"}
    if strict_content:
        return _observe_strict_content(domain, address, int(port), expected_marker, timeout,
                                       use_tls, method, http_version, verify_tls, runner or Runner(),
                                       dial_address=dial_address, ca_file=ca_file)
    if http_version == "h2":
        return _observe_h2(domain, address, port, expected_marker, timeout, use_tls, method,
                           verify_tls, runner or Runner(), dial_address=dial_address, ca_file=ca_file)
    try:
        destination = (address, int(port)) if dial_address is None else (dial_address.host, dial_address.port)
        with socket.create_connection(destination, timeout=timeout) as raw_socket:
            stream: Any = raw_socket
            if use_tls:
                context = ssl.create_default_context()
                if ca_file is not None:
                    context.load_verify_locations(cafile=ca_file)
                context.set_alpn_protocols(["http/1.1"])
                if not verify_tls:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                stream = context.wrap_socket(raw_socket, server_hostname=domain)
            try:
                authority = domain if int(port) == (443 if use_tls else 80) else f"{domain}:{port}"
                stream.sendall((f"{method} / HTTP/1.1\r\nHost: {authority}\r\n"
                    "User-Agent: lucx-post-configurator-health\r\n"
                    "Accept: text/html,*/*;q=0.1\r\nConnection: close\r\n\r\n").encode("ascii"))
                response = bytearray()
                while len(response) < MAX_RESPONSE_BYTES:
                    chunk = stream.recv(min(2048, MAX_RESPONSE_BYTES - len(response)))
                    if not chunk:
                        break
                    response.extend(chunk)
                    if b"\r\n\r\n" in response:
                        break
            finally:
                if use_tls:
                    stream.close()
    except (OSError, ssl.SSLError, ValueError):
        return {"state": "tls_error" if use_tls else "http_error", "status": 0,
                "detail": "TLS/HTTP probe failed"}
    result = evaluate_http_response(bytes(response), expected_marker)
    if bytes(response).startswith(b"HTTP/2"):
        return {"state": "http_error", "status": 0, "detail": "invalid HTTP/1 response"}
    return result


def _capabilities(manifest: dict[str, Any], *, audit: Audit | None = None, phase: str = "public") -> list[dict[str, Any]]:
    decoys = manifest.get("decoys") or {}
    configured = list(decoys.get("capabilities") or [])
    candidate_probe = (phase == 'staging' or
                       phase in {'public', 'rollback'} and _strict_acceptance(manifest))
    classified = (classify_decoy_capabilities(manifest, audit=audit, for_staging=True)
                  if candidate_probe else classify_decoy_capabilities(manifest, audit=audit))
    by_domain = {str(item.get("domain") or "").lower(): item for item in classified}
    baseline = ({str(item['domain']).lower(): item for item in classify_decoy_capabilities(manifest, audit=audit)}
                if candidate_probe else {})
    # Сохранённый запрет не повышается до managed из-за отсутствующего route.
    for item in configured:
        domain = str(item.get("domain") or "").lower()
        # Сохранённый производный запрет этого же кандидата разрешает лишь
        # read-only пробу, не commit. Отличающееся ограничение остаётся запретом.
        if (candidate_probe and by_domain.get(domain, {}).get('status') == 'extended_candidate'
                and item == baseline.get(domain)):
            continue
        if domain not in by_domain or not item.get("managed") or item.get("probe_mode") == "none":
            by_domain[domain] = item
    for site in decoys.get("sites") or []:
        domain = str(site.get("domain") or "").lower()
        if domain and domain not in by_domain:
            by_domain[domain] = {"domain": domain, "managed": False, "probe_mode": "none", "status": "missing"}
    return list(by_domain.values())


def decoy_probe_targets(manifest: dict[str, Any], public_address: str, *, audit: Audit | None = None,
                        phase: str = "public") -> list[dict[str, Any]]:
    decoys = manifest.get("decoys") or {}
    extended = str(decoys.get("routing_mode") or "strict") == "extended"
    public_port = int(manifest["network"]["public_tcp_port"])
    targets: list[dict[str, Any]] = []
    for item in _capabilities(manifest, audit=audit, phase=phase):
        if not item.get("managed") or str(item.get("probe_mode") or "none") == "none":
            continue
        domain = str(item["domain"])
        ports = {public_port}
        if _strict_acceptance(manifest):
            for protocol in manifest.get("protocols") or []:
                for port, name, kind in public_ingresses(protocol, public_port):
                    if kind == "site" and name == domain:
                        ports.add(port)
        targets.extend({"domain": domain, "path": "public_tls", "address": public_address,
                        "port": port, "tls": True} for port in sorted(ports))
        if extended:
            host = str(decoys.get("listen_host") or "127.0.0.1")
            port = int(decoys.get("listen_port") or 8444)
            targets.extend([
                {"domain": domain, "path": "internal_tls", "address": host, "port": port, "tls": True},
                {"domain": domain, "path": "internal_h2c", "address": host, "port": port + 1, "tls": False},
            ])
    return targets


def _target_matrix(target: dict[str, Any]) -> list[tuple[str, str]]:
    versions = ("h2",) if target["path"] == "internal_h2c" else ("h1", "h2")
    return [(method, version) for method in ("GET", "HEAD") for version in versions]


def observe_decoy_capabilities(manifest: dict[str, Any], address: str, *, timeout: float = 10.0,
                               runner: Runner | None = None, audit: Audit | None = None,
                               phase: str = "public", dial_target_provider: BrowserDialProvider | None = None,
                               ca_file: str | None = None) -> list[dict[str, Any]]:
    """Фаза и provider задаются вызывающим кодом, никогда полями manifest."""
    _validate_browser_phase(phase)
    temporary = phase in {"direct", "staging"}
    if not temporary and (dial_target_provider is not None or ca_file is not None):
        raise ValueError("Публичная и rollback-проверки не допускают browser override")
    capabilities = _capabilities(manifest, audit=audit, phase=phase)
    by_domain = {str(item["domain"]): item for item in capabilities}
    results = []
    for target in decoy_probe_targets(manifest, address, audit=audit, phase=phase):
        domain = str(target["domain"])
        dial_address = None
        if temporary:
            try:
                if callable(dial_target_provider):
                    dial_address = dial_target_provider(copy.deepcopy(target), phase)
                if type(dial_address) is not BrowserDialAddress:
                    raise ValueError("Нет подтверждённого адреса временной browser-пробы")
            except Exception:
                dial_address = None
        for method, version in _target_matrix(target):
            if temporary and dial_address is None:
                result = {"state": "not_tested", "status": 0,
                          "detail": "Не подтверждён адрес временной browser-пробы"}
            else:
                result = observe_decoy(domain, str(target["address"]), int(target["port"]),
                    f"X-LucX-Decoy: {domain}", timeout, use_tls=bool(target["tls"]), method=method,
                    http_version=version, verify_tls=temporary or target["path"] == "public_tls", runner=runner,
                    strict_content=_strict_acceptance(manifest), phase=phase,
                    dial_address=dial_address, ca_file=ca_file)
            results.append({"domain": domain, "capability_status": by_domain[domain].get("status", "missing"),
                "managed": True, "phase": phase, "path": target["path"], "port": target["port"], "method": method, "http_version": version,
                "tls_verified": bool(target["tls"]) and (temporary or target["path"] == "public_tls") and result["state"] == "healthy",
                "state": result["state"], "http_status": int(result.get("status") or 0), "detail": result["detail"],
                **{key:result[key] for key in ("content_verified", "body_absence_verified", "resources_complete", "resource_count", "verified_resources", "resource_scope") if key in result}})
    for item in capabilities:
        if item.get("managed") and str(item.get("probe_mode") or "none") != "none":
            continue
        results.append({"domain": item["domain"], "capability_status": item.get("status", "missing"),
            "managed": False, "phase": phase, "path": "none", "state": "skipped", "http_status": 0,
            "detail": "Браузерный сайт не проверялся: VPN владеет SNI или нет безопасного маршрута"})
    if _strict_acceptance(manifest):
        fingerprint = _decoy_profile_fingerprint(manifest, audit=audit, phase=phase)
        for result in results:
            result["profile_fingerprint"] = fingerprint
    return results


def _content_receipt_verified(row: dict[str, Any]) -> bool:
    return row.get("content_verified") is True and (
        (row.get("method") == "HEAD" and row.get("body_absence_verified") is True) or
        (row.get("method") == "GET" and row.get("resources_complete") is True and type(row.get("resource_count")) is int
         and type(row.get("verified_resources")) is int
         and row["resource_count"] == row["verified_resources"] >= 0))


def _browser_tls_required(path: Any, phase: str) -> bool:
    return path == "public_tls" or (phase in {"direct", "staging"} and path == "internal_tls")


def decoy_acceptance_summary(manifest: dict[str, Any], observations: list[dict[str, Any]], *,
                             audit: Audit | None = None, phase: str = "public") -> dict[str, Any]:
    _validate_browser_phase(phase)
    if not (manifest.get("decoys") or {}).get("enabled"):
        return {"complete": phase != "staging" and (not _strict_acceptance(manifest) or not observations),
                "requested_sites": 0, "verified_sites": 0, "phase": phase,
                **({"matrix_complete": not observations, "candidate_verified": False} if phase == "staging" else {})}
    requested = {str(item["domain"]) for item in _capabilities(manifest, audit=audit, phase=phase)}
    expected: dict[str, set[tuple[str, int, str, str]]] = {}
    for target in decoy_probe_targets(manifest, "127.0.0.1", audit=audit, phase=phase):
        expected.setdefault(target["domain"], set()).update(
            (target["path"], target["port"], method, version) for method, version in _target_matrix(target))
    verified = set()
    fingerprint = _decoy_profile_fingerprint(manifest, audit=audit, phase=phase) if _strict_acceptance(manifest) else None
    for domain in requested:
        rows = [item for item in observations if isinstance(item, Mapping) and item.get("domain") == domain]
        identities = [(item.get("path"), item.get("port"), item.get("method"), item.get("http_version")) for item in rows]
        if (expected.get(domain) and expected[domain] == set(identities) and len(identities) == len(set(identities))
                and all(item.get("state") == "healthy" and
                    (not _browser_tls_required(item.get("path"), phase) or item.get("tls_verified") is True) and
                    item.get("phase", phase if fingerprint is None else None) == phase and
                    (fingerprint is None or (item.get("profile_fingerprint") == fingerprint
                                             and _content_receipt_verified(item))) for item in rows)):
            verified.add(domain)
    complete = requested == verified and all(isinstance(item, Mapping) and item.get("domain") in requested
                                             for item in observations)
    # Матрица staging ещё не связана с конкретными bytes/material/run кандидата.
    return {"complete": complete and phase != "staging", "phase": phase,
            "requested_sites": len(requested), "verified_sites": len(verified),
            **({"matrix_complete": complete, "candidate_verified": False} if phase == "staging" else {})}


def observe_vpn_capabilities(manifest: dict[str, Any], runner: Runner, *,
                             observers: Mapping[str, VPNObserver] | None = None,
                             phase: str = "public") -> list[dict[str, Any]]:
    """Штатные observers подключаются кодом; manifest не задаёт команды или credentials."""
    _validate_vpn_phase(phase)
    if observers is None:
        registered = getattr(runner, "vpn_observers", {})
        observers = registered if isinstance(registered, Mapping) else {}
    if _strict_acceptance(manifest):
        results = []
        targets, _ = _vpn_targets(manifest)
        for target in targets:
            identity = target["identity"]
            state, evidence = "not_tested", {}
            observer = observers.get(target["protocol"].get("protocol"))
            protocol = _probe_protocol(target, phase)
            if _observer_supports(observer, protocol) and not runner.dry_run:
                try:
                    observed = observer(protocol, runner)
                    if isinstance(observed, Mapping) and all(observed.get(k) == v for k, v in identity.items()):
                        if observed.get("state") == "healthy" and _functional_evidence(observed, phase):
                            state = "healthy"
                            evidence = {k: observed[k] for k in (
                                "functional", "public", "authenticated", "bytes_sent", "bytes_received")}
                        elif observed.get("state") == "failed":
                            state = "failed"
                except Exception:
                    state = "failed"
            results.append({**identity, **evidence, "phase": phase, "state": state,
                "detail": "Функциональная VPN-проверка подтверждена для указанной фазы" if state == "healthy" else
                          "Функциональная VPN-проверка завершилась ошибкой" if state == "failed" else "VPN не проверялся"})
        return results
    results = []
    for protocol in manifest.get("protocols") or []:
        if protocol.get("exposure") == "none":
            continue
        kind = str(protocol.get("protocol") or "unknown")
        state = "not_tested"
        observer = (observers or {}).get(kind)
        if observer is not None:
            try:
                observed = observer(copy.deepcopy(protocol), runner)
                if observed.get("functional") is True and observed.get("public") is True:
                    state = str(observed.get("state") or "not_tested")
                    if state not in {"healthy", "failed", "not_tested"}:
                        state = "not_tested"
            except Exception:
                state = "failed"
        results.append({"inbound_id": int(protocol.get("inbound_id") or 0), "protocol": kind, "state": state,
            "detail": "VPN проверен функционально через публичный маршрут" if state == "healthy" else
                      "Функциональная VPN-проверка завершилась ошибкой" if state == "failed" else "VPN не проверялся"})
    return results


def validate_decoy_observations(manifest: dict[str, Any], observations: list[dict[str, Any]], *,
                                audit: Audit | None = None, phase: str = "public") -> list[str]:
    _validate_browser_phase(phase)
    errors = []
    fingerprint = _decoy_profile_fingerprint(manifest, audit=audit, phase=phase) if _strict_acceptance(manifest) else None
    for target in decoy_probe_targets(manifest, "127.0.0.1", audit=audit, phase=phase):
        for method, version in _target_matrix(target):
            rows = [item for item in observations if isinstance(item, Mapping) and item.get("domain") == target["domain"]
                and item.get("path") == target["path"] and item.get("method") == method
                and item.get("http_version") == version and item.get("port") == target["port"]]
            if len(rows) != 1 or rows[0].get("state") != "healthy" or (
                rows[0].get("phase", phase if fingerprint is None else None) != phase
            ) or (
                _browser_tls_required(target["path"], phase) and rows[0].get("tls_verified") is not True
            ) or (
                fingerprint is not None and (rows[0].get("profile_fingerprint") != fingerprint
                                             or not _content_receipt_verified(rows[0]))
            ):
                errors.append(f"managed decoy probe incomplete or failed: {target['path']} {method} {version}")
    if (fingerprint is not None or phase == "staging") and not decoy_acceptance_summary(
            manifest, observations, audit=audit, phase=phase)["complete"]:
        errors.append("Браузерная приёмка неполна либо не привязана к проверяемому кандидату")
    return errors
