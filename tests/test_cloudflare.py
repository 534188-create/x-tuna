from __future__ import annotations

import unittest
from unittest import mock

from lucx_post_configurator import cloudflare


class CloudflareTests(unittest.TestCase):
    def test_network_lists_are_validated_by_family_and_public_scope(self) -> None:
        with mock.patch.dict(cloudflare.MINIMUM_COUNTS, {4: 1, 6: 1}):
            self.assertEqual(cloudflare.parse_networks("8.8.8.0/24\n", 4), ["8.8.8.0/24"])
            self.assertEqual(
                cloudflare.parse_networks("2606:4700::/32\n", 6),
                ["2606:4700::/32"],
            )
            with self.assertRaises(cloudflare.CloudflareNetworkError):
                cloudflare.parse_networks("127.0.0.0/8\n", 4)
            with self.assertRaises(cloudflare.CloudflareNetworkError):
                cloudflare.parse_networks("2606:4700::/32\n", 4)

    def test_incomplete_download_is_rejected(self) -> None:
        with self.assertRaisesRegex(cloudflare.CloudflareNetworkError, "count"):
            cloudflare.parse_networks("8.8.8.0/24\n", 4)


if __name__ == "__main__":
    unittest.main()
