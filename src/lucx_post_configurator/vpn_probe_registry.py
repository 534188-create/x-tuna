"""Кодовый реестр проб установленной конфигурации, без установки инструментов."""
from __future__ import annotations

import sys
import copy
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .runner import Runner
from .discovery import audit_system
from .models import Audit
from .naive_native import NativeNaiveSource
from .naive_probe_source import LucXNaiveCredentialSource
from .naive_probes import NAIVE_SHA256, NaiveProbeContext, NaiveVPNObserver, _native_echo_address
from .targetfs import TargetFS
from .vpn_probe_source import LucXXrayCredentialSource
from .vpn_probes import XRAY_SHA256, XrayProbeContext, XrayVPNObserver

XRAY_PROBE_PATH = '/usr/local/libexec/x-tuna-probes/xray'
NAIVE_PROBE_PATH = '/usr/local/libexec/x-tuna-probes/naive'


class _InstalledObservers(dict):
    """Отличает штатные источники текущего scope от явно заданных кодом проб."""

    def __init__(self, owned):
        super().__init__(owned)
        self.owned = dict(owned)


class _InstalledNaiveObserver:
    """Ленивый read-only источник: регистрация не читает DB и не открывает сокеты."""

    def __init__(self, fs: TargetFS, manifest: dict, audit: Audit | None):
        self._fs, self._manifest, self._audit = fs, copy.deepcopy(manifest), copy.deepcopy(audit)
        self._started = False
        self._observer = None

    def _get(self):
        if not self._started:
            self._started = True
            try:
                manifest = self._manifest
                db_path = manifest['lucx']['db_path']
                audit = self._audit if self._audit is not None else audit_system(self._fs.root, db_path)
                if type(audit) is not Audit or type(audit.public_addresses) is not list:
                    raise ValueError('Не подтверждён адрес echo')
                addresses = [address for address in audit.public_addresses if _native_echo_address(address)]
                if not addresses:
                    raise ValueError('Не подтверждён адрес echo')
                auth = LucXNaiveCredentialSource(self._fs, db_path, manifest, audit)
                native = NativeNaiveSource(self._fs, manifest, audit, auth)
                context = NaiveProbeContext(Path(NAIVE_PROBE_PATH), NAIVE_SHA256, auth,
                    addresses[0], 0, shared_tcp_port=manifest['network']['public_tcp_port'],
                    native_binding_provider=native)
                self._observer = NaiveVPNObserver(context)
            except Exception:  # noqa: BLE001 — отчёт не содержит DB, TLS или process errors.
                self._observer = None
        return self._observer

    def supports(self, protocol):
        observer = self._get()
        return observer is not None and observer.supports(protocol)

    def preflight(self, protocol, runner):
        observer = self._get()
        return observer is not None and observer.preflight(protocol, runner)

    def __call__(self, protocol, runner):
        observer = None if runner.dry_run else self._get()
        if observer is None:
            observer = NaiveVPNObserver(NaiveProbeContext(Path(NAIVE_PROBE_PATH), NAIVE_SHA256,
                lambda value: None, '127.0.0.1', 0))
        return observer(protocol, runner)


@contextmanager
def installed_vpn_probes(fs: TargetFS, runner: Runner,
                         manifest: dict[str, Any], *, audit: Audit | None = None) -> Iterator[None]:
    """Публичная диагностика; staging требует отдельного проверенного dial provider."""
    if not fs.is_live or runner.dry_run or sys.platform != 'linux':
        yield
        return
    absent = object()
    original = getattr(runner, 'vpn_observers', absent)
    port = (manifest.get('network') or {}).get('public_tcp_port', 443)
    source = LucXXrayCredentialSource(fs, (manifest.get('lucx') or {}).get('db_path', ''), port)
    echo_audit = [copy.deepcopy(audit)]
    def echo_address():
        from .vpn_probe_backend import valid_echo_address
        if echo_audit[0] is None:
            echo_audit[0] = audit_system(fs.root, (manifest.get('lucx') or {}).get('db_path', ''))
        current = echo_audit[0]
        addresses = current.public_addresses if type(current) is Audit else []
        if type(addresses) is list:
            for address in addresses:
                if valid_echo_address(address):
                    return address
        raise ValueError('Не подтверждён собственный адрес Xray echo')
    observer = XrayVPNObserver(XrayProbeContext(binary_path=Path(XRAY_PROBE_PATH),
        binary_sha256=XRAY_SHA256, credential_provider=source,
        echo_address='127.0.0.1', echo_port=0, shared_tcp_port=port,
        echo_address_provider=echo_address))
    registered = {'vless': observer, 'vmess': observer}
    if any(isinstance(protocol, dict) and protocol.get('protocol') == 'naive'
           and protocol.get('enable') is not False for protocol in manifest.get('protocols', [])):
        registered['naive'] = _InstalledNaiveObserver(fs, manifest, audit)
    registered = _InstalledObservers(registered)
    if isinstance(original, Mapping):
        # Вложенный rollback заново создаёт источники восстановленного manifest.
        # Явные code-owned overrides сохраняются; observers внешнего scope — нет.
        inherited = original.items()
        if type(original) is _InstalledObservers:
            inherited = ((key, value) for key, value in original.items()
                         if value is not original.owned.get(key, absent))
        registered.update(inherited)
    runner.vpn_observers = registered
    try:
        yield
    finally:
        if original is absent:
            del runner.vpn_observers
        else:
            runner.vpn_observers = original
