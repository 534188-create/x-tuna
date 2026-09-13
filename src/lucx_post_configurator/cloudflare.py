from __future__ import annotations

import ipaddress
import urllib.request
from typing import Iterable


CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6"
# Cloudflare's documented HTTPS proxy ports.  CIDR ranges are deliberately
# downloaded at runtime; the small port allowlist is a protocol constraint and
# is validated before a manifest can be applied.
CLOUDFLARE_HTTPS_PORTS = (443, 2053, 2083, 2087, 2096, 8443)
CLOUDFLARE_PORTS_DOC = "https://developers.cloudflare.com/fundamentals/reference/network-ports/"
MINIMUM_COUNTS = {4: 10, 6: 5}
MAXIMUM_COUNT = 1000


class CloudflareNetworkError(RuntimeError):
    pass


def parse_networks(text: str, version: int) -> list[str]:
    networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for raw in text.splitlines():
        value = raw.strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise CloudflareNetworkError(f"invalid Cloudflare IPv{version} CIDR") from exc
        if network.version != version:
            raise CloudflareNetworkError(f"mixed address family in Cloudflare IPv{version} list")
        if network.is_private or network.is_loopback or network.is_multicast or network.is_unspecified:
            raise CloudflareNetworkError(f"non-public address in Cloudflare IPv{version} list")
        networks.add(network)
    if not MINIMUM_COUNTS[version] <= len(networks) <= MAXIMUM_COUNT:
        raise CloudflareNetworkError(
            f"unexpected Cloudflare IPv{version} network count: {len(networks)}"
        )
    return [
        str(network)
        for network in sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen))
    ]


def validate_networks(values: Iterable[str]) -> dict[str, list[str]]:
    grouped = {4: [], 6: []}
    for value in values:
        try:
            network = ipaddress.ip_network(str(value), strict=True)
        except ValueError as exc:
            raise CloudflareNetworkError("invalid stored Cloudflare CIDR") from exc
        grouped[network.version].append(str(network))
    return {
        "ipv4": parse_networks("\n".join(grouped[4]), 4),
        "ipv6": parse_networks("\n".join(grouped[6]), 6),
    }


def _download(url: str, timeout: int) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "lucx-post-configurator/1 cloudflare-origin-update"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise CloudflareNetworkError(f"Cloudflare list returned HTTP {response.status}")
            content_type = response.headers.get_content_type()
            if content_type not in {"text/plain", "application/octet-stream"}:
                raise CloudflareNetworkError("unexpected Cloudflare list content type")
            data = response.read(256 * 1024 + 1)
    except CloudflareNetworkError:
        raise
    except Exception as exc:
        raise CloudflareNetworkError("could not download official Cloudflare network list") from exc
    if len(data) > 256 * 1024:
        raise CloudflareNetworkError("Cloudflare network list is unexpectedly large")
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CloudflareNetworkError("Cloudflare network list is not ASCII") from exc


def fetch_cloudflare_networks(timeout: int = 15) -> dict[str, list[str]]:
    return {
        "ipv4": parse_networks(_download(CLOUDFLARE_IPV4_URL, timeout), 4),
        "ipv6": parse_networks(_download(CLOUDFLARE_IPV6_URL, timeout), 6),
    }
