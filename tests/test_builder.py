from __future__ import annotations

import base64
import hashlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path

from helpers import make_target


PROJECT = Path(__file__).parents[1]


class BuilderTests(unittest.TestCase):
    def test_build_is_deterministic_and_payload_matches(self) -> None:
        command = [sys.executable, str(PROJECT / "tools/build_installer.py")]
        subprocess.run(command, cwd=PROJECT, check=True, capture_output=True, text=True)
        first = (PROJECT / "dist/lucx-post-configure.sh").read_bytes()
        subprocess.run(command, cwd=PROJECT, check=True, capture_output=True, text=True)
        second = (PROJECT / "dist/lucx-post-configure.sh").read_bytes()
        self.assertEqual(first, second)
        marker = b"__LUCX_POST_CONFIGURATOR_PAYLOAD__\n"
        self.assertEqual(first.count(marker), 1)
        payload = base64.b64decode(b"".join(first.rsplit(marker, 1)[1].split()), validate=True)
        self.assertIn(hashlib.sha256(payload).hexdigest().encode(), first)
        self.assertNotIn(b"hy" + b"dra", payload.lower())
        with tempfile.TemporaryDirectory() as temporary:
            with zipfile.ZipFile(BytesIO(payload)) as archive:
                archive.extractall(temporary)
            env = __import__("os").environ.copy()
            env["PYTHONPATH"] = temporary
            completed = subprocess.run(
                [sys.executable, "-m", "lucx_post_configurator", "--help"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("--reconfigure", completed.stdout)
            self.assertIn("--decoy-routing-mode", completed.stdout)
            self.assertIn("--trusttunnel-backend-probe", completed.stdout)
            self.assertTrue(
                (Path(temporary) / "lucx_post_configurator/trusttunnel_backend.py").is_file()
            )
            self.assertTrue((Path(temporary) / "lucx_post_configurator/assets/lucx_sub_sidecar.py").is_file())
            self.assertTrue(
                (Path(temporary) / "lucx_post_configurator/assets/cloudflare_ips_update.py").is_file()
            )

            artifact_check = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    """
import importlib
from lucx_post_configurator.models import default_manifest
from lucx_post_configurator.migrations import migrate_manifest
from lucx_post_configurator.decoy_capabilities import classify_decoy_capabilities
from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
from lucx_post_configurator.planner import build_plan

for name in (
    'migrations', 'decoy_capabilities', 'extended_decoys', 'integrity', 'decoy_health',
    'diagnostics', 'status', 'naive_frontend', 'questionnaire', 'tui',
):
    importlib.import_module('lucx_post_configurator.' + name)

legacy = default_manifest()
legacy['schema_version'] = 1
legacy['decoys'].pop('capabilities', None)
legacy.pop('integrity', None)
manifest = migrate_manifest(legacy)
manifest['lucx']['panel']['domain'] = 'panel.example.com'
manifest['lucx']['subscription']['domain'] = 'sub.example.com'
manifest['certificates']['cert_path'] = '/cert/fullchain.pem'
manifest['certificates']['key_path'] = '/cert/privkey.pem'
manifest['protocols'] = [
    {
        'inbound_id': 1, 'protocol': 'vless', 'remark': 'vless',
        'domain': 'owned.example.com', 'internal_host': '127.0.0.1',
        'internal_port': 10001, 'public_port': 443, 'network': 'tcp',
        'exposure': 'tcp_sni', 'security': 'tls',
        'sni_names': ['owned.example.com'], 'port_bindings': [],
    },
    {
        'inbound_id': 2, 'protocol': 'awg', 'remark': 'awg',
        'domain': 'awg.example.com', 'internal_host': '127.0.0.1',
        'internal_port': 8443, 'public_port': 8443, 'network': 'udp',
        'exposure': 'udp_direct', 'security': '',
        'sni_names': [], 'port_bindings': [],
    },
]
manifest['decoys']['capabilities'] = classify_decoy_capabilities(manifest)
assert manifest['schema_version'] == 3
assert {x['status'] for x in manifest['decoys']['capabilities']} == {
    'blocked_sni_collision', 'udp_with_tcp_decoy', 'direct_tcp_decoy'
}
assert build_plan(manifest)['actions']
assert classify_extended_decoy_routes(manifest)
print('artifact-v3-ok')
""",
                ],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(artifact_check.returncode, 0, artifact_check.stderr)
            self.assertIn("artifact-v3-ok", artifact_check.stdout)

            fake_root = Path(temporary) / "target"
            make_target(fake_root)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "lucx_post_configurator",
                    "--audit",
                    "--root",
                    str(fake_root),
                ],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn('"supported_os": true', completed.stdout)
            self.assertNotIn("must-not-leak", completed.stdout)

            (fake_root / "etc/os-release").write_text(
                'ID=debian\nVERSION_ID="13"\n', encoding="utf-8"
            )
            debian_13 = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "lucx_post_configurator",
                    "--audit",
                    "--root",
                    str(fake_root),
                ],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(debian_13.returncode, 0, debian_13.stderr)
            self.assertIn('"os_version": "13"', debian_13.stdout)


if __name__ == "__main__":
    unittest.main()
