from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from helpers import make_target
from lucx_post_configurator.engine import Engine
from lucx_post_configurator.runner import Runner


class TrustTunnelEngineStatusTests(unittest.TestCase):
    def test_readonly_status_without_state_preserves_all_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_target(root)
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            engine = Engine(root, runner=Runner(dry_run=True))
            result = engine.trusttunnel_status()
            self.assertEqual(result.discovery_state, "observed")
            self.assertEqual(result.protocol_probe_state, "not_checked")
            self.assertFalse(result.optional_backend_enabled)
            self.assertEqual(before, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()})
            self.assertFalse(any(command[0] in {"systemctl", "apt", "nft"} for command in engine.runner.history))

    def test_absent_candidate_never_runs_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = Engine(directory, runner=Runner(dry_run=True))
            result = engine.probe_trusttunnel_candidate(binary=str(Path(directory) / "absent"), loopback_port=26444)
            self.assertFalse(result.ready)
            self.assertEqual(engine.runner.history, [])


if __name__ == "__main__":
    unittest.main()
