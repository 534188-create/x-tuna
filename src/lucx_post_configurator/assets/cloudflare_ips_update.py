#!/usr/bin/env python3
"""Atomically synchronize the HAProxy origin ACL with official Cloudflare lists."""

from __future__ import annotations

import fcntl
import ipaddress
import os
import pathlib
import subprocess
import tempfile
import urllib.request


IPV4_URL = "https://www.cloudflare.com/ips-v4"
IPV6_URL = "https://www.cloudflare.com/ips-v6"
ACL_PATH = pathlib.Path("/etc/haproxy/cloudflare-ips.lst")
HAPROXY_CONFIG = "/etc/haproxy/haproxy.cfg"
LOCK_PATH = "/run/lock/lucx-cloudflare-ips-update.lock"
MINIMUM_COUNTS = {4: 10, 6: 5}
MAXIMUM_COUNT = 1000


def download(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "lucx-post-configurator/1 cloudflare-origin-update"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError(f"official Cloudflare list returned HTTP {response.status}")
        if response.headers.get_content_type() not in {"text/plain", "application/octet-stream"}:
            raise RuntimeError("official Cloudflare list has an unexpected content type")
        data = response.read(256 * 1024 + 1)
    if len(data) > 256 * 1024:
        raise RuntimeError("official Cloudflare list is unexpectedly large")
    return data.decode("ascii")


def parse(text: str, version: int) -> list[str]:
    result: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for raw in text.splitlines():
        value = raw.strip()
        if not value:
            continue
        network = ipaddress.ip_network(value, strict=True)
        if network.version != version:
            raise RuntimeError(f"mixed address family in Cloudflare IPv{version} list")
        if network.is_private or network.is_loopback or network.is_multicast or network.is_unspecified:
            raise RuntimeError(f"non-public address in Cloudflare IPv{version} list")
        result.add(network)
    if not MINIMUM_COUNTS[version] <= len(result) <= MAXIMUM_COUNT:
        raise RuntimeError(f"unexpected Cloudflare IPv{version} network count: {len(result)}")
    return [
        str(network)
        for network in sorted(result, key=lambda item: (int(item.network_address), item.prefixlen))
    ]


def atomic_write(path: pathlib.Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def run(command: list[str], input_text: str | None = None) -> None:
    result = subprocess.run(
        command,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(detail or f"command failed: {command[0]}")


def nft_update(ipv4: list[str], ipv6: list[str]) -> None:
    script = (
        "flush set inet lucx_post cloudflare4\n"
        "add element inet lucx_post cloudflare4 { " + ", ".join(ipv4) + " }\n"
        "flush set inet lucx_post cloudflare6\n"
        "add element inet lucx_post cloudflare6 { " + ", ".join(ipv6) + " }\n"
    )
    run(["/usr/sbin/nft", "-c", "-f", "-"], script)
    run(["/usr/sbin/nft", "-f", "-"], script)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("Cloudflare ACL update requires root")
    pathlib.Path(LOCK_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(LOCK_PATH, "a+", encoding="ascii") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        ipv4 = parse(download(IPV4_URL), 4)
        ipv6 = parse(download(IPV6_URL), 6)
        candidate = ("\n".join(ipv4 + ipv6) + "\n").encode("ascii")
        previous = ACL_PATH.read_bytes() if ACL_PATH.is_file() else None
        changed = previous != candidate
        previous4: list[str] = []
        previous6: list[str] = []
        if previous is not None:
            previous_text = previous.decode("ascii")
            previous4 = parse(
                "\n".join(
                    value for value in previous_text.splitlines()
                    if value and ipaddress.ip_network(value).version == 4
                ),
                4,
            )
            previous6 = parse(
                "\n".join(
                    value for value in previous_text.splitlines()
                    if value and ipaddress.ip_network(value).version == 6
                ),
                6,
            )
        if changed:
            atomic_write(ACL_PATH, candidate)
        try:
            run(["/usr/sbin/haproxy", "-c", "-f", HAPROXY_CONFIG])
            nft_update(ipv4, ipv6)
            if changed:
                run(["/usr/bin/systemctl", "reload", "haproxy.service"])
        except Exception:
            if previous4 and previous6:
                try:
                    nft_update(previous4, previous6)
                except Exception:
                    pass
            if previous is None:
                try:
                    ACL_PATH.unlink()
                except FileNotFoundError:
                    pass
            else:
                atomic_write(ACL_PATH, previous)
                subprocess.run(
                    ["/usr/bin/systemctl", "reload", "haproxy.service"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
            raise
        status = "updated" if changed else "verified"
        print(f"Cloudflare ACL {status}: IPv4={len(ipv4)} IPv6={len(ipv6)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
