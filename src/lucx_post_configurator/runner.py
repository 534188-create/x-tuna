from __future__ import annotations

import dataclasses
import codecs
import os
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any


@dataclasses.dataclass(slots=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


class CommandError(RuntimeError):
    def __init__(self, result: CommandResult) -> None:
        self.result = result
        rendered = " ".join(result.args)
        detail = (result.stderr or result.stdout).strip()
        super().__init__(f"command failed ({result.returncode}): {rendered}: {detail}")


class OutputLimitExceeded(RuntimeError):
    """Вывод процесса превысил лимит; его содержимое не входит в ошибку."""


class Runner:
    def __init__(self, *, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.history: list[list[str]] = []

    def available(self, command: str) -> bool:
        return shutil.which(command) is not None

    def run_bounded(self, args: Sequence[str | Path], *, max_output_bytes: int,
                    check: bool = True, timeout: float = 30,
                    env: dict[str, str] | None = None,
                    input_text: str | None = None, output_encoding: str = "utf-8",
                    isolate_process_group: bool = False,
                    inherit_env: bool = True) -> CommandResult:
        """Ограничивает суммарный stdout/stderr и время, включая отправку stdin."""
        if type(max_output_bytes) is not int or max_output_bytes <= 0 or timeout <= 0:
            raise ValueError("Некорректный лимит процесса")
        codecs.lookup(output_encoding)
        command = [str(value) for value in args]
        self.history.append(command)
        if self.dry_run:
            return CommandResult(command, 0, "", "")
        if isolate_process_group and os.name != "posix":
            raise ValueError("Изоляция группы процессов доступна только в POSIX")
        merged_env = os.environ.copy() if inherit_env else {}
        if not inherit_env and os.name == "nt" and "SystemRoot" in os.environ:
            merged_env["SystemRoot"] = os.environ["SystemRoot"]
        merged_env.setdefault("LC_ALL", "C.UTF-8")
        merged_env.setdefault("LANG", "C.UTF-8")
        if env:
            merged_env.update(env)
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=merged_env,
                                   start_new_session=isolate_process_group)
        buffers = [bytearray(), bytearray()]
        lock, exceeded = threading.Lock(), threading.Event()
        started = time.monotonic()

        def drain(stream: Any, index: int) -> None:
            try:
                while chunk := stream.read(4096):
                    with lock:
                        if sum(map(len, buffers)) + len(chunk) > max_output_bytes:
                            exceeded.set()
                            return
                        buffers[index].extend(chunk)
            finally:
                stream.close()

        def feed() -> None:
            try:
                process.stdin.write((input_text or "").encode("utf-8"))
                process.stdin.flush()
            except (OSError, ValueError):
                pass
            finally:
                process.stdin.close()

        threads = [threading.Thread(target=drain, args=(process.stdout, 0), daemon=True),
                   threading.Thread(target=drain, args=(process.stderr, 1), daemon=True),
                   threading.Thread(target=feed, daemon=True)]
        for thread in threads:
            thread.start()
        failure: Exception | None = None

        def stop_group() -> None:
            if isolate_process_group:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

        try:
            while process.poll() is None or any(thread.is_alive() for thread in threads):
                if process.poll() is not None:
                    # Worker мог завершиться, оставив потомков с открытыми каналами.
                    stop_group()
                if exceeded.is_set():
                    failure = OutputLimitExceeded("Вывод процесса превысил допустимый размер")
                    break
                if time.monotonic() - started >= timeout:
                    failure = subprocess.TimeoutExpired(command, timeout)
                    break
                time.sleep(0.005)
            if exceeded.is_set():
                failure = OutputLimitExceeded("Вывод процесса превысил допустимый размер")
        finally:
            stop_group()
            if process.poll() is None:
                process.kill()
            process.wait()
            for thread in threads:
                thread.join(timeout=0.2)
        if failure is not None:
            raise failure
        result = CommandResult(command, process.returncode,
                               buffers[0].decode(output_encoding, "replace"),
                               buffers[1].decode(output_encoding, "replace"))
        if check and result.returncode:
            raise CommandError(result)
        return result

    def run(
        self,
        args: Sequence[str | Path],
        *,
        check: bool = True,
        timeout: int = 30,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        command = [str(value) for value in args]
        self.history.append(command)
        if self.dry_run:
            return CommandResult(command, 0, "", "")
        merged_env = os.environ.copy()
        merged_env.setdefault("LC_ALL", "C.UTF-8")
        merged_env.setdefault("LANG", "C.UTF-8")
        if env:
            merged_env.update(env)
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input_text,
            timeout=timeout,
            env=merged_env,
        )
        result = CommandResult(command, completed.returncode, completed.stdout, completed.stderr)
        if check and result.returncode != 0:
            raise CommandError(result)
        return result


def missing_packages(packages: list[str], runner: Runner) -> list[str]:
    missing: list[str] = []
    if not runner.available("dpkg-query"):
        return packages
    for package in packages:
        result = runner.run(
            ["dpkg-query", "-W", "-f=${Status}", package], check=False, timeout=10
        )
        if result.returncode != 0 or "install ok installed" not in result.stdout:
            missing.append(package)
    return missing


def install_packages(
    packages: list[str], runner: Runner, *, missing: list[str] | None = None
) -> list[str]:
    missing = missing_packages(packages, runner) if missing is None else list(missing)
    if not missing:
        return []
    runner.run(["apt-get", "update"], timeout=300, env={"DEBIAN_FRONTEND": "noninteractive"})
    runner.run(
        ["apt-get", "install", "-y", "--no-install-recommends", *missing],
        timeout=600,
        env={"DEBIAN_FRONTEND": "noninteractive"},
    )
    return missing
