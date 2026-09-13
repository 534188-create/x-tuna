from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lucx_post_configurator.engine import Engine
from lucx_post_configurator.network_tuning import (
    RECOMMENDED_SYSCTL_SETTINGS,
    SYSCTL_BBR_PATH,
    apply_network_tuning,
    get_network_tuning_status,
    render_sysctl_bbr_conf,
    revert_network_tuning,
)
from lucx_post_configurator.runner import CommandResult, Runner
from lucx_post_configurator.targetfs import TargetFS


class NetworkTuningTests(unittest.TestCase):
    def test_render_sysctl_bbr_conf(self) -> None:
        rendered = render_sysctl_bbr_conf()
        self.assertIn("net.core.default_qdisc = fq", rendered)
        self.assertIn("net.ipv4.tcp_congestion_control = bbr", rendered)
        self.assertIn("net.core.rmem_max = 67108864", rendered)
        self.assertIn("net.ipv4.tcp_rmem = 4096 87380 67108864", rendered)

    def test_get_network_tuning_status_unoptimized(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            fs = TargetFS(tempdir)
            runner = Runner(dry_run=True)
            status = get_network_tuning_status(runner, fs)
            self.assertFalse(status["config_file_present"])
            self.assertFalse(status["is_fully_optimized"])
            self.assertEqual(status["config_file_path"], SYSCTL_BBR_PATH)

    def test_apply_and_revert_network_tuning(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            fs = TargetFS(tempdir)
            runner = Runner(dry_run=True)

            # Apply
            apply_res = apply_network_tuning(runner, fs)
            self.assertTrue(apply_res["ok"])
            self.assertTrue(fs.exists(SYSCTL_BBR_PATH))

            content = fs.read_text(SYSCTL_BBR_PATH)
            self.assertIn("net.ipv4.tcp_congestion_control = bbr", content)
            self.assertIn("net.core.default_qdisc = fq", content)

            # Revert
            revert_res = revert_network_tuning(runner, fs)
            self.assertTrue(revert_res["ok"])
            self.assertTrue(revert_res["removed"])
            self.assertFalse(fs.exists(SYSCTL_BBR_PATH))

    def test_engine_delegation(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            engine = Engine(root=tempdir, runner=Runner(dry_run=True))
            status = engine.get_network_tuning_status()
            self.assertIn("bbr_supported", status)
            self.assertIn("recommended_values", status)

            apply_res = engine.apply_network_tuning()
            self.assertTrue(apply_res["ok"])
            self.assertTrue(engine.fs.exists(SYSCTL_BBR_PATH))

            revert_res = engine.revert_network_tuning()
            self.assertTrue(revert_res["ok"])
            self.assertFalse(engine.fs.exists(SYSCTL_BBR_PATH))
