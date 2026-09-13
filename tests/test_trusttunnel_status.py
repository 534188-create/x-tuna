from __future__ import annotations

import unittest

from lucx_post_configurator.models import Audit, Inbound, default_manifest
from lucx_post_configurator.runner import CommandResult
from lucx_post_configurator.trusttunnel_status import observe_trusttunnel


class FakeRunner:
    def __init__(self, result: CommandResult | None = None, *, available: bool = True) -> None:
        self.result = result
        self.command_available = available

    def available(self, command: str) -> bool:
        return self.command_available and command == "ss"

    def run(self, args, **_kwargs) -> CommandResult:
        if self.result is None:
            raise AssertionError("unexpected listener command")
        return self.result


class TrustTunnelStatusTests(unittest.TestCase):
    def test_ipv6_loopback_does_not_prove_ipv4_inbound_listener(self) -> None:
        audit = Audit(db_schema_supported=True, inbounds=[Inbound(7, "trusttunnel", "existing", True, "127.0.0.1", 19443)])
        result = observe_trusttunnel(audit, FakeRunner(CommandResult(
            ["ss", "-H", "-lnt"], 0, "LISTEN 0 4096 [::1]:19443 [::]:*\n", "")))
        self.assertEqual(result.observed_listener_inbound_ids, [])

    def test_wildcard_ipv4_socket_covers_loopback_inbound(self) -> None:
        audit = Audit(db_schema_supported=True, inbounds=[Inbound(7, "trusttunnel", "existing", True, "127.0.0.1", 19443)])
        result = observe_trusttunnel(audit, FakeRunner(CommandResult(
            ["ss", "-H", "-lnt"], 0, "LISTEN 0 4096 0.0.0.0:19443 0.0.0.0:*\n", "")))
        self.assertEqual(result.observed_listener_inbound_ids, [7])

    def test_live_lucx_is_observed_when_optional_backend_is_disabled(self) -> None:
        manifest = default_manifest()
        manifest["components"]["trusttunnel_backend"] = False
        audit = Audit(
            db_schema_supported=True,
            inbounds=[
                Inbound(
                    id=7,
                    protocol="trusttunnel",
                    remark="existing",
                    enable=True,
                    listen="::1",
                    port=19443,
                    network="tcp",
                    alpn=["h2"],
                )
            ],
        )

        result = observe_trusttunnel(
            audit,
            FakeRunner(
                CommandResult(
                    ["ss", "-H", "-lnt"],
                    0,
                    'LISTEN 0 4096 [::1]:19443 [::]:* users:(("endpoint",pid=1,fd=3))\n',
                    "",
                )
            ),
            optional_backend_enabled=manifest["components"]["trusttunnel_backend"],
        )

        self.assertEqual(result.discovery_state, "observed")
        self.assertEqual(result.listener_state, "observed")
        self.assertEqual(result.protocol_probe_state, "not_checked")
        self.assertEqual(result.enabled_inbounds, 1)
        self.assertEqual(result.observed_listener_inbound_ids, [7])
        self.assertFalse(result.optional_backend_enabled)
        self.assertFalse(result.ready)

    def test_unavailable_listener_snapshot_is_not_reported_as_error(self) -> None:
        audit = Audit(
            db_schema_supported=True,
            inbounds=[Inbound(8, "trusttunnel", "existing", True, "127.0.0.1", 20443)],
        )

        result = observe_trusttunnel(audit, FakeRunner(available=False))

        self.assertEqual(result.discovery_state, "observed")
        self.assertEqual(result.listener_state, "not_checked")
        self.assertEqual(result.errors, [])

    def test_listener_failure_is_separate_from_unchecked_protocol(self) -> None:
        audit = Audit(
            db_schema_supported=True,
            inbounds=[Inbound(9, "trust-tunnel", "existing", True, "127.0.0.1", 21443)],
        )

        result = observe_trusttunnel(
            audit,
            FakeRunner(CommandResult(["ss", "-H", "-lnt"], 1, "", "private detail")),
        )

        self.assertEqual(result.listener_state, "error")
        self.assertEqual(result.protocol_probe_state, "not_checked")
        self.assertEqual(result.errors, ["не удалось прочитать TCP listeners через ss"])


if __name__ == "__main__":
    unittest.main()
