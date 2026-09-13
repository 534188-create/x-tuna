"""Read-only владелец backend→собственный echo; не доказывает выбранный inbound."""
from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import sys
import threading
import time
from pathlib import Path

from .naive_bridge import _actor, _owned, _pin_actor, _same_actor, _tcp_inode
from .staging_processes import _read, parse_tcp_listeners

_ERROR = 'Владелец backend VPN не подтверждён'
XRAY_SERVER_HASHES = frozenset({
    '8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed',
    '64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d',
})


def _check(deadline):
    if time.monotonic() >= deadline:
        raise ValueError(_ERROR)


def _owner(inode: int, deadline: float) -> int:
    """Полный ограниченный поиск; недоступный живой процесс блокирует proof."""
    owners = set()
    count = 0
    with os.scandir('/proc') as processes:
        for entry in processes:
            if not entry.name.isascii() or not entry.name.isdigit():
                continue
            count += 1
            _check(deadline)
            if count > 16384:
                raise ValueError(_ERROR)
            pid = int(entry.name)
            try:
                with os.scandir(entry.path + '/fd') as descriptors:
                    for number, descriptor in enumerate(descriptors, 1):
                        _check(deadline)
                        if number > 4096:
                            raise ValueError(_ERROR)
                        try:
                            if os.readlink(descriptor.path) == f'socket:[{inode}]':
                                owners.add(pid)
                        except FileNotFoundError:
                            continue
            except FileNotFoundError:
                # Только исчезнувший процесс; скрытая таблица fd не допустима.
                if os.path.exists(entry.path):
                    raise ValueError(_ERROR) from None
    if len(owners) != 1:
        raise ValueError(_ERROR)
    return owners.pop()


def _listener_identity(host: str, port: int, deadline: float, *, bridge=False) -> tuple[int, int]:
    found = []
    for suffix, ipv6 in (('tcp', False), ('tcp6', True)):
        table = _read(Path('/proc/net') / suffix, 8 * 1024 * 1024, deadline)
        for listener in parse_tcp_listeners(table, ipv6=ipv6):
            address = ipaddress.ip_address(listener.host)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if listener.port == port and (address == ipaddress.ip_address(host)
                                          or address.is_unspecified):
                found.append((listener, address))
    if len(found) != 1 or bridge and not found[0][1].is_loopback:
        raise ValueError(_ERROR)
    inode = found[0][0].inode
    return _owner(inode, deadline), inode


def _listener_owner(host: str, port: int, deadline: float, *, bridge=False) -> int:
    return _listener_identity(host, port, deadline, bridge=bridge)[0]


def _executable_hash(pid: int, deadline: float) -> str:
    before = _actor(pid, deadline)
    digest, size = hashlib.sha256(), 0
    with open(f'/proc/{pid}/exe', 'rb', buffering=0) as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            _check(deadline)
            if size > 256 * 1024 * 1024:
                raise ValueError(_ERROR)
            digest.update(chunk)
    if not _same_actor(before, _actor(pid, deadline)):
        raise ValueError(_ERROR)
    # Повторное чтение через pin также проверяет fstat дескриптора.
    _pin_actor(pid, digest.hexdigest(), deadline)
    return digest.hexdigest()


def valid_echo_address(address: str) -> bool:
    """Только канонический IPv4 собственного интерфейса; наличие проверяет bind."""
    try:
        value = ipaddress.IPv4Address(address) if type(address) is str else None
        return bool(value is not None and str(value) == address
                    and not (value.is_loopback or value.is_link_local or value.is_multicast
                             or value.is_unspecified or value == ipaddress.IPv4Address('255.255.255.255')))
    except ValueError:
        return False


def _endpoint(value, *, backend=False) -> bool:
    try:
        return (type(value) is tuple and len(value) == 2 and type(value[0]) is str
                and str(ipaddress.ip_address(value[0]) if backend else ipaddress.IPv4Address(value[0])) == value[0]
                and type(value[1]) is int and 1 <= value[1] <= 65535)
    except ValueError:
        return False


class XrayEchoWitness:
    """Две независимые удерживаемые сессии от закреплённого executable.

    Не читает конфиг/credentials и не управляет процессом. Caller завершает
    echo-потоки перед финальным verify; выход из context сохраняет evidence.
    """

    def __init__(self, host: str, port: int, endpoint: tuple[str, int]):
        self._host, self._port, self._endpoint = host, port, endpoint
        self._lock = threading.RLock()
        self._actor = self._listener = None
        self._digest = ''
        self._used: set[int] = set()
        self._entered = self._failed = False

    def __enter__(self):
        with self._lock:
            try:
                if (self._entered or self._failed or sys.platform != 'linux'
                        or not _endpoint((self._host, self._port), backend=True)
                        or not _endpoint(self._endpoint) or not valid_echo_address(self._endpoint[0])):
                    raise ValueError(_ERROR)
                self._entered = True
                deadline = time.monotonic() + 5
                self._listener = _listener_identity(self._host, self._port, deadline)
                pid, _ = self._listener
                self._digest = _executable_hash(pid, deadline)
                if self._digest not in XRAY_SERVER_HASHES:
                    raise ValueError(_ERROR)
                self._actor = _pin_actor(pid, self._digest, deadline)
                self._verify_actor_listener(deadline)
                return self
            except Exception:  # noqa: BLE001 — пути/executable и сведения proc не выходят наружу.
                self._failed = True
                raise ValueError(_ERROR) from None

    def _verify_actor_listener(self, deadline):
        if (self._failed or not self._entered or self._actor is None or self._listener is None
                or not _same_actor(self._actor, _actor(self._listener[0], deadline))
                or _listener_identity(self._host, self._port, deadline) != self._listener):
            raise ValueError(_ERROR)
        _owned(self._actor, self._listener[1], deadline)
        _check(deadline)

    def prove(self, peer: socket.socket) -> bool:
        """Вызывается перед первым echo-byte, пока обе стороны TCP удерживаются."""
        with self._lock:
            if self._failed:
                return False
            try:
                if (not self._entered or len(self._used) >= 2 or peer.family != socket.AF_INET
                        or peer.getsockname() != self._endpoint):
                    raise ValueError(_ERROR)
                remote = peer.getpeername()
                if not _endpoint(remote):
                    raise ValueError(_ERROR)
                deadline = time.monotonic() + 3
                self._verify_actor_listener(deadline)
                inode = _tcp_inode(remote, self._endpoint, deadline)
                if inode in self._used or _owner(inode, deadline) != self._listener[0]:
                    raise ValueError(_ERROR)
                _owned(self._actor, inode, deadline)
                if (peer.getsockname() != self._endpoint or peer.getpeername() != remote
                        or _tcp_inode(remote, self._endpoint, deadline) != inode
                        or _owner(inode, deadline) != self._listener[0]):
                    raise ValueError(_ERROR)
                _owned(self._actor, inode, deadline)
                self._verify_actor_listener(deadline)
                self._used.add(inode)
                return True
            except Exception:  # noqa: BLE001 — fail-closed callback без приватных причин.
                self._failed = True
                return False

    def verify(self) -> None:
        with self._lock:
            try:
                if self._failed or len(self._used) != 2:
                    raise ValueError(_ERROR)
                deadline = time.monotonic() + 5
                self._verify_actor_listener(deadline)
                if not _same_actor(self._actor, _pin_actor(self._listener[0], self._digest, deadline)):
                    raise ValueError(_ERROR)
                self._verify_actor_listener(deadline)
            except Exception:  # noqa: BLE001 — verify допустим после __exit__, ошибка необратима.
                self._failed = True
                raise ValueError(_ERROR) from None

    def __exit__(self, *_args):
        # Дескрипторов и процессов во владении witness нет. Evidence нужно caller
        # после остановки echo, чтобы поздний callback не скрыл sticky failure.
        return False
