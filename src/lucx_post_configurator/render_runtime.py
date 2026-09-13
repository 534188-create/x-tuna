from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal


@dataclass(frozen=True, slots=True)
class ListenerKey:
    """Identity исходного public-порта либо inbound; роль назначается кодом."""

    role: Literal["public", "split", "decoy_tls", "decoy_h2c", "decoy_plain"]
    identity: int = 0
    ingress_port: int = 0

    def __post_init__(self) -> None:
        if self.role not in {"public", "split", "decoy_tls", "decoy_h2c", "decoy_plain"}:
            raise ValueError("Неизвестная роль listener runtime")
        if type(self.identity) is not int:
            raise ValueError("Identity listener должна быть целым числом")
        if (type(self.ingress_port) is not int or not 0 <= self.ingress_port <= 65535
                or (self.ingress_port != 0 and self.role != "split")):
            raise ValueError("Исходный ingress-порт допустим только для split listener")
        if ((self.role == "public" and not 1 <= self.identity <= 65535)
                or (self.role == "split" and self.identity <= 0)
                or (self.role.startswith("decoy_") and self.identity != 0)):
            raise ValueError("Identity не соответствует роли listener")

    def __repr__(self) -> str:
        ingress = f", ingress_port={self.ingress_port}" if self.ingress_port else ""
        return f"ListenerKey(role={self.role!r}, identity={self.identity!r}{ingress})"


@dataclass(frozen=True, slots=True)
class SocketAddress:
    """Только конкретный loopback IP и целочисленный TCP-порт."""

    host: str
    port: int

    def __post_init__(self) -> None:
        if type(self.host) is not str or type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("Некорректный адрес listener runtime")
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise ValueError("Listener runtime требует конкретный loopback IP") from exc
        if not address.is_loopback or "%" in self.host:
            raise ValueError("Listener runtime требует конкретный loopback IP")
        object.__setattr__(self, "host", str(address))

    @property
    def authority(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


def _safe_path(value: str) -> bool:
    return (type(value) is str and re.fullmatch(r"/[A-Za-z0-9_./-]+", value) is not None
            and all(part not in {"", ".", ".."} for part in value.split("/")[1:]))


def _copy_mapping(value: Mapping) -> dict:
    if not isinstance(value, Mapping):
        # Единый отказ renderer для недопустимого overlay, включая его типы.
        raise ValueError("Runtime ожидает типизированное отображение")  # noqa: TRY004
    result = {}
    for key, item in value.items():
        if key in result:
            raise ValueError("Runtime содержит повторный ключ")
        result[key] = item
    return result


@dataclass(frozen=True, slots=True)
class RenderRuntime:
    """Изолированная подстановка адресов и точных путей; manifest не изменяется.

    Проверка полного набора ролей и принадлежности путей остаётся у renderer,
    который владеет исходным планом. Этот объект не запускает процессы и не
    подтверждает наличие копий материалов либо свободу портов в ОС.
    """

    listeners: Mapping[ListenerKey, SocketAddress]
    paths: Mapping[str, str] = field(default_factory=dict)
    foreground: bool = False
    suppress_system_log: bool = False

    def __post_init__(self) -> None:
        if type(self.foreground) is not bool or type(self.suppress_system_log) is not bool:
            raise ValueError("Флаги runtime должны быть логическими значениями")
        listeners = _copy_mapping(self.listeners)
        if any(type(key) is not ListenerKey or type(value) is not SocketAddress
               for key, value in listeners.items()):
            raise ValueError("Runtime ожидает ListenerKey и SocketAddress")
        if len({value.port for value in listeners.values()}) != len(listeners):
            raise ValueError("Listener-порты runtime должны различаться")
        paths = _copy_mapping(self.paths)
        if any(not _safe_path(source) or not _safe_path(target) for source, target in paths.items()):
            raise ValueError("Runtime содержит небезопасный путь")
        if len(set(paths.values())) != len(paths):
            raise ValueError("Копии разных материалов runtime требуют отдельных путей")
        object.__setattr__(self, "listeners", MappingProxyType(listeners))
        object.__setattr__(self, "paths", MappingProxyType(paths))

    def path(self, source: str) -> str:
        return self.paths.get(source, source)


def runtime_layout(runtime: RenderRuntime) -> dict:
    """Единая identity для binding и IPC; legacy listener сохраняет четыре поля."""
    rows = []
    for key, value in sorted(runtime.listeners.items(),
                             key=lambda pair: (pair[0].role, pair[0].identity, pair[0].ingress_port)):
        row = (key.role, key.identity, value.host, value.port)
        rows.append((*row, key.ingress_port) if key.ingress_port else row)
    return {'listeners': rows, 'paths': dict(runtime.paths), 'foreground': runtime.foreground,
            'suppress_system_log': runtime.suppress_system_log}
