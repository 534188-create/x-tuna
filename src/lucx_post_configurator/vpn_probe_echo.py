"""Короткоживущий loopback echo для двух ограниченных VPN round-trip."""
from __future__ import annotations

import selectors
import ipaddress
import socket
import threading
import time
from typing import Any, Self
from collections.abc import Callable


class LocalProbeEcho:
    """Не принимает адрес/команду из manifest и никогда не открывает proxy."""

    def __init__(self, *, bind_address: str = '127.0.0.1',
                 verify_peer: Callable[[socket.socket], bool] | None = None) -> None:
        address = ipaddress.ip_address(bind_address)
        if (address.version != 4 or address.is_unspecified or address.is_multicast
                or str(address) != bind_address or bind_address == '255.255.255.255'
                or bind_address != '127.0.0.1' and not callable(verify_peer)
                or verify_peer is not None and not callable(verify_peer)):
            raise ValueError('Не подтверждён собственный адрес или проверяющий маршрут echo')
        self._bind_address = bind_address
        self._verify_peer = verify_peer
        self.verified_connections = 0
        self.verification_failed = False
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.endpoint: tuple[str, int] = ("127.0.0.1", 0)

    def __enter__(self) -> Self:
        if self._listener is not None or self._stop.is_set():
            raise RuntimeError("Контекст echo нельзя использовать повторно")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind((self._bind_address, 0))
            listener.listen(4)
            listener.setblocking(False)
            self.endpoint = listener.getsockname()
            self._listener = listener
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            return self
        except BaseException:
            listener.close()
            raise

    def _serve(self) -> None:
        assert self._listener is not None
        peers: dict[socket.socket, dict[str, Any]] = {}
        accepted, total = 0, 0
        deadline = time.monotonic() + 65
        with selectors.DefaultSelector() as selector:
            selector.register(self._listener, selectors.EVENT_READ)

            def close(peer: socket.socket) -> None:
                selector.unregister(peer)
                peers.pop(peer, None)
                peer.close()

            try:
                while not self._stop.is_set() and time.monotonic() < deadline:
                    for key, events in selector.select(.05):
                        sock = key.fileobj
                        if sock is self._listener:
                            peer, _ = self._listener.accept()
                            accepted += 1
                            if accepted > 8 or len(peers) >= 4 or total >= 65536:
                                peer.close()
                                continue
                            peer.setblocking(False)
                            peers[peer] = {"bytes": 0, "pending": bytearray(), "eof": False, "verified": False}
                            selector.register(peer, selectors.EVENT_READ)
                            continue
                        state = peers[sock]
                        try:
                            if events & selectors.EVENT_READ:
                                room = min(8192, 16384 - state["bytes"], 65536 - total)
                                chunk = sock.recv(room) if room else b""
                                if chunk:
                                    if self._verify_peer is not None and not state['verified']:
                                        try:
                                            verified = self._verify_peer(sock) is True
                                        except Exception:  # noqa: BLE001 — данные владельца socket не выводятся.
                                            verified = False
                                        if not verified:
                                            self.verification_failed = True
                                            self._stop.set()
                                            close(sock)
                                            break
                                        state['verified'] = True
                                        self.verified_connections += 1
                                    state["pending"].extend(chunk)
                                    state["bytes"] += len(chunk)
                                    total += len(chunk)
                                else:
                                    state["eof"] = True
                            if events & selectors.EVENT_WRITE and state["pending"]:
                                sent = sock.send(state["pending"])
                                del state["pending"][:sent]
                            if state["pending"]:
                                selector.modify(sock, selectors.EVENT_WRITE)
                            elif state["eof"] or state["bytes"] >= 16384 or total >= 65536:
                                close(sock)
                            else:
                                selector.modify(sock, selectors.EVENT_READ)
                        except (ConnectionError, OSError):
                            close(sock)
            finally:
                for peer in list(peers):
                    close(peer)
                selector.unregister(self._listener)
                self._listener.close()

    def __exit__(self, *args: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3 if self._verify_peer else 1)
            if self._thread.is_alive():
                raise RuntimeError("Echo-listener не завершился")
