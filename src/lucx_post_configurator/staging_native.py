"""Приватный DTO native staging и live fences полного Naive cohort.

Декодирование подтверждает лишь форму DTO. Родитель обязан вызвать verify
перед запуском дочерней приёмки и после её завершения; DTO не заменяет source proof.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, fields
from types import MappingProxyType

from .models import Audit
from .naive_native import NativeNaiveSource
from .naive_probe_source import LucXNaiveCredentialSource
from .naive_probes import NativeBackendBinding, _native_echo_address, _native_valid
from .routing_profiles import routing_fingerprint

_ERROR = 'Набор native staging не подтверждён'
_MAX_COHORT = 128
_MAX_PAYLOAD = 16 * 1024 * 1024
_INTEGER_FIELDS = {'caddy_pid', 'xray_pid', 'bridge_port', 'backend_port'}
_FIELDS = {item.name for item in fields(NativeBackendBinding)}


def _protocols(manifest):
    if type(manifest) is not dict or type(manifest.get('network')) is not dict:
        raise ValueError(_ERROR)
    port = manifest['network'].get('public_tcp_port')
    rows = manifest.get('protocols')
    if (type(port) is not int or not 1 <= port <= 65535 or type(rows) is not list
            or not 1 <= len(rows) <= 4096):
        raise ValueError(_ERROR)
    result, seen = {}, set()
    for item in rows:
        if type(item) is not dict or type(item.get('enable', True)) is not bool:
            raise ValueError(_ERROR)
        if not item.get('enable', True):
            continue
        number = item.get('inbound_id')
        if type(number) is not int or number <= 0 or number in seen:
            raise ValueError(_ERROR)
        seen.add(number)
        if item.get('protocol') == 'naive':
            if type(item.get('internal_port')) is not int or not 1 <= item['internal_port'] <= 65535:
                raise ValueError(_ERROR)
            result[number] = item
    if not 1 <= len(result) <= _MAX_COHORT:
        raise ValueError(_ERROR)
    return result, port


def _payload(payload):
    if (type(payload) is not dict or set(payload) != {'echo_address', 'bindings'}
            or type(payload['echo_address']) is not str or len(payload['echo_address']) > 64
            or not _native_echo_address(payload['echo_address'])
            or type(payload['bindings']) is not list or not 1 <= len(payload['bindings']) <= _MAX_COHORT):
        raise ValueError(_ERROR)
    bindings = {}
    for row in payload['bindings']:
        if (type(row) is not dict or set(row) != {'inbound_id', 'binding'}
                or type(row['inbound_id']) is not int or row['inbound_id'] <= 0
                or row['inbound_id'] in bindings or type(row['binding']) is not dict
                or set(row['binding']) != _FIELDS):
            raise ValueError(_ERROR)
        data = row['binding']
        for name, value in data.items():
            kind = int if name in _INTEGER_FIELDS else bool if name == 'probe_resistance' else str
            if type(value) is not kind or kind is str and len(value.encode('utf-8')) > 65536:
                raise ValueError(_ERROR)
        binding = NativeBackendBinding(**data)
        if not _native_valid(binding):
            raise ValueError(_ERROR)
        bindings[row['inbound_id']] = binding
    if len({binding.auth_policy_fingerprint for binding in bindings.values()}) != 1:
        raise ValueError(_ERROR)
    return MappingProxyType(bindings), payload['echo_address']


def decode_native_payload(payload, manifest) -> tuple[Mapping[int, NativeBackendBinding], str]:
    """Чистая проверка точного cohort; не обращается к live source и не запускает процесс."""
    try:
        bindings, address = _payload(payload)
        protocols, shared = _protocols(manifest)
        if set(bindings) != set(protocols):
            raise ValueError(_ERROR)
        for number, protocol in protocols.items():
            binding = bindings[number]
            names = protocol.get('sni_names')
            if type(names) is not list or not names or any(type(name) is not str for name in names):
                raise ValueError(_ERROR)
            sni = protocol.get('domain') if protocol.get('domain') in names else names[0] if len(names) == 1 else ''
            if (binding.profile_fingerprint != routing_fingerprint(protocol, shared)
                    or binding.backend_port != protocol['internal_port'] or binding.backend_sni != sni):
                raise ValueError(_ERROR)
        return bindings, address
    except Exception:  # noqa: BLE001 — DTO и parser ошибки не раскрывают приватные значения.
        raise ValueError(_ERROR) from None


def native_payload_digest(payload) -> str:
    """Канонический JSON digest; свежесть материалов проверяется только verify."""
    try:
        _payload(payload)
        encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True, allow_nan=False).encode('ascii')
        if len(encoded) > _MAX_PAYLOAD:
            raise ValueError(_ERROR)
        return hashlib.sha256(encoded).hexdigest()
    except Exception:  # noqa: BLE001 — ничего из приватного DTO в сообщении.
        raise ValueError(_ERROR) from None


@dataclass(slots=True, repr=False)
class _State:
    failed: bool = False
    lock: object = field(default_factory=threading.RLock)


@dataclass(frozen=True, slots=True, repr=False)
class NativeStagingSet:
    bindings: Mapping[int, NativeBackendBinding]
    echo_address: str
    _manifest: dict = field(repr=False)
    _auth: LucXNaiveCredentialSource = field(repr=False)
    _source: NativeNaiveSource = field(repr=False)
    _state: _State = field(default_factory=_State, init=False, repr=False)

    def __post_init__(self):
        if (type(self._auth) is not LucXNaiveCredentialSource
                or type(self._source) is not NativeNaiveSource or self._source._auth is not self._auth
                or not isinstance(self.bindings, Mapping) or type(self._manifest) is not dict):
            raise ValueError(_ERROR)
        object.__setattr__(self, '_manifest', copy.deepcopy(self._manifest))
        object.__setattr__(self, 'bindings', MappingProxyType(dict(self.bindings)))

    @classmethod
    def capture(cls, fs, manifest, audit):
        try:
            manifest = copy.deepcopy(manifest)
            audit = copy.deepcopy(audit)
            protocols, _ = _protocols(manifest)
            if type(audit) is not Audit or type(audit.public_addresses) is not list:
                raise ValueError(_ERROR)
            addresses = [address for address in audit.public_addresses
                         if type(address) is str and _native_echo_address(address)]
            if not addresses:
                raise ValueError(_ERROR)
            auth = LucXNaiveCredentialSource(fs, manifest['lucx']['db_path'], manifest, audit)
            source = NativeNaiveSource(fs, manifest, audit, auth)
            bindings = {number: source(protocol) for number, protocol in protocols.items()}
            instance = cls(MappingProxyType(bindings), addresses[0], manifest, auth, source)
            instance.verify(manifest)
            return instance
        except Exception:  # noqa: BLE001 — Linux/TLS/DB ошибки остаются внутри источников.
            raise ValueError(_ERROR) from None

    def verify(self, manifest) -> None:
        """Полный live fence до/после child; любое расхождение закрывает набор навсегда."""
        with self._state.lock:
            try:
                if self._state.failed:
                    raise ValueError(_ERROR)
                protocols, shared = _protocols(manifest)
                original, original_shared = _protocols(self._manifest)
                if set(protocols) != set(self.bindings) or shared != original_shared:
                    raise ValueError(_ERROR)
                deadline = time.monotonic() + 30
                for number, protocol in protocols.items():
                    binding = self.bindings[number]
                    if (not _native_valid(binding) or time.monotonic() >= deadline
                            or routing_fingerprint(protocol, shared) != binding.profile_fingerprint
                            or protocol.get('source_routing_fingerprint') != original[number].get('source_routing_fingerprint')):
                        raise ValueError(_ERROR)
                    credential = self._auth(protocol)
                    if (credential is None or credential.profile_fingerprint != binding.profile_fingerprint
                            or credential.policy_fingerprint != binding.auth_policy_fingerprint
                            or self._source(protocol) != binding or time.monotonic() >= deadline):
                        raise ValueError(_ERROR)
                # Также проверяем форму будущего child DTO и единую policy всего cohort.
                decode_native_payload(self._payload(), manifest)
            except Exception:  # noqa: BLE001 — sticky отказ, без приватных данных в исключении.
                self._state.failed = True
                raise ValueError(_ERROR) from None

    def _payload(self):
        return {'echo_address': self.echo_address, 'bindings': [
            {'inbound_id': number, 'binding': asdict(binding)}
            for number, binding in sorted(self.bindings.items())]}

    def private_payload(self):
        with self._state.lock:
            self.verify(self._manifest)
            return self._payload()

    def credential(self, protocol):
        with self._state.lock:
            try:
                self.verify(self._manifest)
                binding = self.binding(protocol)
                credential = self._auth(protocol)
                if (binding is None or credential is None
                        or credential.profile_fingerprint != binding.profile_fingerprint
                        or credential.policy_fingerprint != binding.auth_policy_fingerprint):
                    raise ValueError(_ERROR)
                return credential
            except Exception:  # noqa: BLE001 — никаких credentials наружу при ошибке.
                self._state.failed = True
                return None

    def binding(self, protocol):
        with self._state.lock:
            try:
                self.verify(self._manifest)
                if type(protocol) is not dict or type(protocol.get('inbound_id')) is not int:
                    raise ValueError(_ERROR)
                binding = self.bindings.get(protocol['inbound_id'])
                if (binding is None or self._source(protocol) != binding
                        or routing_fingerprint(protocol, self._manifest['network']['public_tcp_port'])
                            != binding.profile_fingerprint):
                    raise ValueError(_ERROR)
                return binding
            except Exception:  # noqa: BLE001 — отсутствие актуального proof.
                self._state.failed = True
                return None


def capture(fs, manifest, audit) -> NativeStagingSet:
    return NativeStagingSet.capture(fs, manifest, audit)
