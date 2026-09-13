from __future__ import annotations

import threading
import time
import sys
from collections.abc import Callable
from types import TracebackType
from typing import Any, TypeVar


T = TypeVar("T")
OutputFn = Callable[[str], None]
ClockFn = Callable[[], float]
WaitFn = Callable[[threading.Event, float], bool]


def _elapsed(value: float) -> str:
    seconds = max(0, int(value))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


class ProgressDisplay:
    """Line-based progress with honest totals or an elapsed-time heartbeat."""

    def __init__(
        self,
        output_fn: OutputFn,
        title: str,
        *,
        total: int | None = None,
        interval: float = 1.0,
        clock: ClockFn = time.monotonic,
        wait_fn: WaitFn | None = None,
    ) -> None:
        if total is not None and total <= 0:
            raise ValueError("progress total must be positive")
        self.output_fn = output_fn
        self.title = str(title).strip() or "Операция"
        self.total = total
        self.interval = max(0.1, float(interval))
        self.clock = clock
        self.wait_fn = wait_fn or (lambda event, timeout: event.wait(timeout))
        self._started = 0.0
        self._current = 0
        self._label = self.title
        self._spinner = 0
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._rendered = False
        self._interactive = output_fn is print and sys.stdout.isatty()

    def _write(self, line: str) -> None:
        with self._lock:
            if self._interactive:
                # Do not emit a new line for every spinner frame.
                sys.stdout.write("\r\033[2K" + line)
                sys.stdout.flush()
            else:
                self.output_fn(line)
            self._rendered = True

    def _elapsed(self) -> str:
        return _elapsed(self.clock() - self._started)

    def _heartbeat_line(self) -> str:
        if self.total is not None:
            current = min(max(0, self._current), self.total)
            percent = round(current * 100 / self.total)
            filled = round(current * 18 / self.total)
            bar = "█" * filled + "░" * (18 - filled)
            return (
                f"[{bar}] {current}/{self.total}  {percent}% — {self._label}; "
                f"прошло {self._elapsed()}"
            )
        marker = "|/-\\"[self._spinner % 4]
        self._spinner += 1
        return f"[{marker}] {self._label}; прошло {self._elapsed()}"

    def _heartbeat_loop(self) -> None:
        while not self.wait_fn(self._stop, self.interval):
            self._write(self._heartbeat_line())

    def __enter__(self) -> "ProgressDisplay":
        self._started = self.clock()
        self._stop.clear()
        self._write(self._heartbeat_line())
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            name="lucx-tui-progress",
            daemon=True,
        )
        self._thread.start()
        return self

    def phase(self, current: int, label: str) -> None:
        if current < 0:
            raise ValueError("progress phase cannot be negative")
        if self.total is not None and current > self.total:
            raise ValueError("progress phase exceeds total")
        self._current = current
        self._label = str(label).strip() or self.title
        self._write(self._heartbeat_line())

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=min(1.0, self.interval + 0.1))
        state = "завершено" if exc_type is None else "ошибка"
        if self._interactive:
            sys.stdout.write("\r\033[2K" + f"{self.title}: {state}; прошло {self._elapsed()}\n")
            sys.stdout.flush()
        else:
            self._write(f"{self.title}: {state}; прошло {self._elapsed()}")
        return False

    def run(self, operation: Callable[[], T]) -> T:
        with self:
            return operation()
