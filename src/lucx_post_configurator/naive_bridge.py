"""Приватная корреляция SOCKS handshake; не является receipt общей приёмки.

Linux cBPF выпускает только заголовки и ограниченные служебные bytes.
Пароль upstream остаётся в ядре. Владельцев sockets, nonce-обмен, исходники
и TLS обязан отдельно подтвердить координатор. Из manifest этот API не вызывается.
"""
from __future__ import annotations

import ipaddress
import hashlib
import math
import os
import re
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .staging_processes import _file_identity, _process, _read

_ERROR = 'Путь Naive через SOCKS bridge не подтверждён'


def _connect(host: str, port: int, bridge: int) -> bytes:
    if any(type(value) is not int or not 0 < value < 65536 for value in (port, bridge)):
        raise ValueError(_ERROR)
    address = ipaddress.IPv4Address(host)
    if address.is_unspecified or address.is_multicast:
        raise ValueError(_ERROR)
    return b'\x05\x01\x00\x01' + address.packed + struct.pack('!H', port)


def _bridge_filter(host: str, port: int, bridge: int) -> tuple[tuple[int, int, int, int], ...]:
    """cBPF для SOCK_DGRAM: IPv4 header начинается с offset 0.

    Только loopback IPv4 без IP options/фрагментации. TCP options разрешены.
    Auth LucX: version, длина username, lucx, длина password=24; наружу первые
    два bytes, без username/password. Неизвестная форма полностью отбрасывается.
    См. kernel.org/doc/html/latest/networking/filter.html (sock_filter ABI).
    """
    connect = _connect(host, port, bridge)
    code, labels = [], {}

    def emit(op, value=0):
        code.append((op, 0, 0, value))

    def branch(op, value, yes=None, no=None):
        code.append((op, yes, no, value))

    def require(value, op=0x15):
        branch(op, value, no='drop')

    def label(name):
        labels[name] = len(code)

    def destination():
        emit(0x28, 22)
        require(bridge)

    def origin():
        emit(0x28, 20)
        require(bridge)

    def retain(count):
        emit(0x61, 1)
        emit(0x87)
        emit(0x04, count)
        emit(0x16)

    emit(0x30, 0); require(0x45)
    emit(0x30, 9); require(6)
    emit(0x28, 6); emit(0x54, 0xbfff); require(0)
    for offset in (12, 16):
        emit(0x20, offset); require(0x7f000001)
    emit(0x28, 20); branch(0x15, bridge, yes='ports_ok')
    destination()
    label('ports_ok')
    emit(0x30, 32); emit(0x54, 15); require(0)
    emit(0x30, 32); emit(0x74, 2); emit(0x54, 60); require(20, 0x35)
    emit(0x04, 20); emit(0x02, 1)  # M[1]: начало TCP payload.
    emit(0x28, 2); emit(0x02, 0)
    emit(0x61, 0); emit(0x80); require(0, 0x1d)  # skb len == IP total_len.
    emit(0x61, 1); emit(0x60, 0); emit(0x1c); emit(0x02, 2)
    branch(0x15, 0, yes='control')
    emit(0x30, 33); emit(0x54, 0xf7); require(0x10)  # ACK, возможно PSH.
    emit(0x60, 2)
    for length, name in ((3, 'greet3'), (4, 'greet4'), (31, 'auth'), (2, 'reply'), (10, 'connect')):
        branch(0x15, length, yes=name)
    emit(0x06, 0)
    label('control')
    emit(0x30, 33); branch(0x45, 7, no='drop')  # SYN/FIN/RST, не пустые ACK.
    retain(0)
    for name, size, expected in (('greet3', 3, 0x0501), ('greet4', 4, 0x05020002)):
        label(name); destination(); emit(0x61, 1)
        emit(0x48 if size == 3 else 0x40, 0); require(expected)
        if size == 3:
            emit(0x50, 2); require(2)
        retain(size)
    label('auth'); destination(); emit(0x61, 1)
    emit(0x40, 0); require(0x01046c75)
    emit(0x48, 4); require(0x6378)
    emit(0x50, 6); require(24)
    retain(2)
    label('reply'); origin(); emit(0x61, 1)
    emit(0x48, 0); branch(0x15, 0x0502, yes='reply_ok'); require(0x0100)
    label('reply_ok'); retain(2)
    label('connect'); destination(); emit(0x61, 1)
    for offset, size in ((0, 4), (4, 4), (8, 2)):
        emit(0x40 if size == 4 else 0x48, offset)
        require(int.from_bytes(connect[offset:offset + size], 'big'))
    retain(10)
    label('drop'); emit(0x06, 0)
    result = []
    for index, (op, yes, no, value) in enumerate(code):
        jumps = tuple(labels[item] - index - 1 if isinstance(item, str) else 0 for item in (yes, no))
        if any(not 0 <= jump <= 255 for jump in jumps):
            raise ValueError(_ERROR)
        result.append((op, *jumps, value))
    return tuple(result)


def _attach_filter(stream: socket.socket, instructions) -> None:
    """Установить и заблокировать фильтр до bind packet socket/первого чтения."""
    import ctypes

    class Instruction(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]

    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('instructions', ctypes.POINTER(Instruction))]

    values = (Instruction * len(instructions))(*(Instruction(*item) for item in instructions))
    program = Program(len(values), values)
    stream.setsockopt(socket.SOL_SOCKET, 26, bytes(program))  # SO_ATTACH_FILTER
    stream.setsockopt(socket.SOL_SOCKET, 44, 1)  # SO_LOCK_FILTER


@dataclass(slots=True, repr=False)
class _Flow:
    client_isn: int
    server_isn: int = 0
    stage: int = 0
    client_next: int = 0
    server_next: int = 0
    seen: set[tuple] = field(default_factory=set)


class BridgeSequence:
    """Только полный свежий handshake, включая sequence/ack каждого сообщения.

    Возвращаемый tuple — (client_port, client_ISN, server_ISN), не разрешение
    Engine. Сообщение с теми же CONNECT bytes внутри готового туннеля не proof.
    """

    def __init__(self, host: str, port: int, bridge: int):
        self._connect = _connect(host, port, bridge)
        self._bridge = bridge
        self._flows: dict[int, _Flow] = {}
        self._events = 0

    def observe(self, data: bytes) -> tuple[int, int, int] | None:
        self._events += 1
        if self._events > 1024:
            raise ValueError(_ERROR)
        if (type(data) is not bytes or not 40 <= len(data) <= 90 or data[0] != 0x45
                or data[9] != 6 or data[12:20] != b'\x7f\x00\x00\x01' * 2
                or int.from_bytes(data[6:8], 'big') & 0xbfff):
            return None
        start = 20 + (data[32] >> 4) * 4
        length = int.from_bytes(data[2:4], 'big') - start
        if start < 40 or data[32] & 15 or start > len(data):
            return None
        source, destination, seq, ack = struct.unpack('!HHII', data[20:32])
        reverse = source == self._bridge
        peer = destination if reverse else source
        if not peer or source == destination or (not reverse and destination != self._bridge):
            return None
        flags, payload = data[33], data[start:]
        if (length != len(payload)
                and not (not reverse and length == 31 and payload == b'\x01\x04')):
            return None
        key = (reverse, seq, ack, flags & ~8, length, payload)
        flow = self._flows.get(peer)
        if flow is not None and key in flow.seen:
            return None
        if not reverse and flags == 2 and length == 0 and ack == 0:
            if len(self._flows) >= 128 and peer not in self._flows:
                raise ValueError(_ERROR)
            self._flows[peer] = _Flow(seq, client_next=(seq + 1) % 2**32, seen={key})
            return None
        if flow is None:
            return None
        if flags & 5:
            self._flows.pop(peer, None)
            return None
        if flow.stage == 0:
            valid = reverse and flags == 0x12 and length == 0 and ack == flow.client_next
            if valid:
                flow.server_isn, flow.server_next = seq, (seq + 1) % 2**32
        else:
            wanted = {1: (False, (b'\x05\x01\x02', b'\x05\x02\x00\x02'), (3, 4)),
                      2: (True, (b'\x05\x02',), (2,)),
                      3: (False, (b'\x01\x04',), (31,)),
                      4: (True, (b'\x01\x00',), (2,)),
                      5: (False, (self._connect,), (10,))}.get(flow.stage)
            valid = (wanted is not None and reverse is wanted[0] and payload in wanted[1]
                     and length in wanted[2] and flags & 0xf7 == 0x10
                     and seq == (flow.server_next if reverse else flow.client_next)
                     and ack == (flow.client_next if reverse else flow.server_next))
            if valid:
                if reverse:
                    flow.server_next = (seq + length) % 2**32
                else:
                    flow.client_next = (seq + length) % 2**32
        if not valid:
            self._flows.pop(peer, None)
            return None
        flow.seen.add(key)
        flow.stage += 1
        if flow.stage == 6:
            return peer, flow.client_isn, flow.server_isn
        return None

    def current(self, match: tuple[int, int, int]) -> bool:
        flow = self._flows.get(match[0])
        return bool(flow is not None and flow.stage == 6
                    and (flow.client_isn, flow.server_isn) == match[1:])


def _actor(pid: int, deadline: float):
    if type(pid) is not int or pid <= 1:
        raise ValueError(_ERROR)
    info = _process(pid, deadline)
    if info.state in 'ZXxz':
        raise ValueError(_ERROR)
    ns = os.stat(f'/proc/{pid}/ns/net')
    own_ns = os.stat('/proc/self/ns/net')
    if (ns.st_dev, ns.st_ino) != (own_ns.st_dev, own_ns.st_ino):
        raise ValueError(_ERROR)
    executable = os.stat(f'/proc/{pid}/exe')
    if (not stat.S_ISREG(executable.st_mode) or executable.st_mode & 0o022
            or executable.st_uid != 0 or not 0 < executable.st_size <= 256 * 1024 * 1024
            or not info.same_process(_process(pid, deadline))):
        raise ValueError(_ERROR)
    return info, (ns.st_dev, ns.st_ino), _file_identity(executable)


def _same_actor(before, after):
    return before[0].same_process(after[0]) and before[1:] == after[1:]


def _pin_actor(pid: int, digest: str, deadline: float):
    if type(digest) is not str or not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError(_ERROR)
    before = _actor(pid, deadline)
    hashed, count = hashlib.sha256(), 0
    with open(f'/proc/{pid}/exe', 'rb', buffering=0) as executable:
        if _file_identity(os.fstat(executable.fileno())) != before[2]:
            raise ValueError(_ERROR)
        while chunk := executable.read(1024 * 1024):
            count += len(chunk)
            if count > 256 * 1024 * 1024 or time.monotonic() >= deadline:
                raise ValueError(_ERROR)
            hashed.update(chunk)
        if _file_identity(os.fstat(executable.fileno())) != before[2]:
            raise ValueError(_ERROR)
    if hashed.hexdigest() != digest or not _same_actor(before, _actor(pid, deadline)):
        raise ValueError(_ERROR)
    return before


def _owned(actor, inode: int, deadline: float):
    pid = actor[0].pid
    if not _same_actor(actor, _actor(pid, deadline)):
        raise ValueError(_ERROR)
    found = False
    with os.scandir(f'/proc/{pid}/fd') as files:
        for count, entry in enumerate(files, 1):
            if count > 4096 or time.monotonic() >= deadline:
                raise ValueError(_ERROR)
            try:
                found |= os.readlink(entry.path) == f'socket:[{inode}]'
            except FileNotFoundError:
                continue
    if not found or not _same_actor(actor, _actor(pid, deadline)):
        raise ValueError(_ERROR)


def _tcp_inode(local, remote, deadline: float):
    def key(address, mapped):
        raw = socket.inet_aton(address[0])
        if mapped:
            raw = bytes(10) + b'\xff\xff' + raw
        return ''.join(f'{int.from_bytes(raw[i:i + 4], sys.byteorder):08X}'
                       for i in range(0, len(raw), 4)) + f':{address[1]:04X}'

    matches = []
    for name, mapped in (('tcp', False), ('tcp6', True)):
        wanted = key(local, mapped), key(remote, mapped)
        lines = _read(Path('/proc/net') / name, 8 * 1024 * 1024, deadline).splitlines()
        if not lines or 'local_address' not in lines[0] or len(lines) > 32769:
            raise ValueError(_ERROR)
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 10:
                raise ValueError(_ERROR)
            if (fields[1], fields[2]) == wanted and fields[3] == '01':
                matches.append(int(fields[9]))
    if len(matches) != 1 or matches[0] <= 0:
        raise ValueError(_ERROR)
    return matches[0]


class BridgeCapture:
    """Пассивное наблюдение собственного exchange, без записи конфигов/пакетов.

    Это не источник credentials и не выбор outbound policy. Caller держит свой
    nonce-обмен открытым до prove и отдельно сверяет TLS/source/DB до и после.
    Только текущая netns, IPv4 loopback bridge и прямой IPv4 egress к своему echo.
    """

    def __init__(self, host: str, port: int, bridge: int, *, caddy_pid: int,
                 caddy_sha256: str, xray_pid: int, xray_sha256: str):
        self._sequence = BridgeSequence(host, port, bridge)
        if caddy_pid == xray_pid:
            raise ValueError(_ERROR)
        self._target, self._bridge = (host, port), bridge
        self._pins = ((caddy_pid, caddy_sha256), (xray_pid, xray_sha256))
        self._socket = None
        self._entered = False
        self._failed = False
        self._used = set()

    def __enter__(self):
        if self._entered or sys.platform != 'linux':
            raise ValueError(_ERROR)
        self._entered = True
        self._deadline = time.monotonic() + 60
        self._actors = tuple(_pin_actor(pid, digest, self._deadline) for pid, digest in self._pins)
        stream = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, 0)
        try:
            # protocol=0 не принимает пакеты до bind. Фильтр уже заблокирован
            # к моменту подписки на IPv4; auth никогда не попадает в очередь Python.
            _attach_filter(stream, _bridge_filter(*self._target, self._bridge))
            stream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)
            stream.setsockopt(263, 23, 1)  # SOL_PACKET / PACKET_IGNORE_OUTGOING
            stream.bind(('lo', 0x0800))
            self._socket = stream
            return self
        except BaseException:
            stream.close()
            raise

    def prove(self, peer: socket.socket, *, timeout: float = 2) -> bool:
        """peer — принятое собственным echo соединение, удерживаемое caller."""
        try:
            if (self._failed or self._socket is None or type(timeout) not in {int, float}
                    or not math.isfinite(timeout) or not 0 < timeout <= 5):
                raise ValueError(_ERROR)
            deadline = min(self._deadline, time.monotonic() + timeout)
            local, remote = peer.getsockname(), peer.getpeername()
            if local != self._target or peer.family != socket.AF_INET:
                raise ValueError(_ERROR)
            accepted_inode = os.fstat(peer.fileno()).st_ino
            outbound_inode = _tcp_inode(remote, local, deadline)
            _owned(self._actors[1], outbound_inode, deadline)
            while time.monotonic() < deadline:
                self._socket.settimeout(max(.001, deadline - time.monotonic()))
                data, _, flags, address = self._socket.recvmsg(128)
                if flags & socket.MSG_TRUNC or address[0] != 'lo' or address[2] != 0:
                    raise ValueError(_ERROR)
                match = self._sequence.observe(data)
                if match is None:
                    continue
                source = ('127.0.0.1', match[0])
                target = ('127.0.0.1', self._bridge)
                client_inode = _tcp_inode(source, target, deadline)
                server_inode = _tcp_inode(target, source, deadline)
                identity = (accepted_inode, client_inode, server_inode)
                if any(value in self._used for value in identity) or len(set(identity)) != 3:
                    raise ValueError(_ERROR)
                _owned(self._actors[0], client_inode, deadline)
                _owned(self._actors[1], server_inode, deadline)
                # Старая очередь handshake A не должна подтвердить sockets B
                # после повторного использования tuple. Вычитываем события,
                # поступившие до снимка inode, и повторяем тот же снимок после.
                self._socket.setblocking(False)
                for _ in range(1024):
                    if time.monotonic() >= deadline:
                        raise ValueError(_ERROR)
                    try:
                        extra, _, extra_flags, extra_address = self._socket.recvmsg(128)
                    except BlockingIOError:
                        break
                    if extra_flags & socket.MSG_TRUNC or extra_address[0] != 'lo' or extra_address[2] != 0:
                        raise ValueError(_ERROR)
                    if self._sequence.observe(extra) is not None:
                        raise ValueError(_ERROR)
                else:
                    raise ValueError(_ERROR)
                if (not self._sequence.current(match)
                        or _tcp_inode(source, target, deadline) != client_inode
                        or _tcp_inode(target, source, deadline) != server_inode
                        or _tcp_inode(remote, local, deadline) != outbound_inode):
                    raise ValueError(_ERROR)
                _owned(self._actors[0], client_inode, deadline)
                _owned(self._actors[1], server_inode, deadline)
                _owned(self._actors[1], outbound_inode, deadline)
                _, dropped = struct.unpack('II', self._socket.getsockopt(263, 6, 8))  # PACKET_STATISTICS
                if (dropped or os.fstat(peer.fileno()).st_ino != accepted_inode
                        or peer.getsockname() != local or peer.getpeername() != remote
                        or any(not _same_actor(actor, _actor(actor[0].pid, deadline)) for actor in self._actors)):
                    raise ValueError(_ERROR)
                self._used.update(identity)
                return True
        except (OSError, ValueError, TypeError, IndexError, struct.error):
            self._failed = True
            return False
        self._failed = True
        return False

    def __exit__(self, *args):
        if self._socket is not None:
            self._socket.close()
            self._socket = None
