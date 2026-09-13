from __future__ import annotations

import io
import hashlib
import json
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

from lucx_post_configurator.certificate_manager import required_domains
from lucx_post_configurator.cli import main as cli_main
from lucx_post_configurator.diagnostics import stable_fingerprint
from lucx_post_configurator.engine import (
    ApplyError,
    Engine,
    _ephemeral_routing_material,
    _managed_naive_services_from_targets,
)
from lucx_post_configurator.models import Audit, default_manifest
from lucx_post_configurator.planner import build_plan
from lucx_post_configurator.renderers import GeneratedFile
from lucx_post_configurator.repair import _dynamic_changes, repair_apply, repair_check
from lucx_post_configurator.runner import CommandResult, Runner
from lucx_post_configurator.self_install import POST_UPDATE_SERVICE, REPAIR_WRAPPER
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.tui import run_tui
from lucx_post_configurator import updates as updates_module
from lucx_post_configurator import self_install as self_install_module
from lucx_post_configurator.updates import _safe_extract_tar, _validated_https_url

from helpers import make_target


class ManagementFeatureTests(unittest.TestCase):
    def test_github_proxy_templates_are_validated_and_appended(self) -> None:
        attempts = updates_module._source_attempts(
            "github",
            github_proxy_templates=[
                "https://proxy.example/download?url={url}",
                "https://mirror.example/?target={url}",
            ],
        )
        self.assertEqual(attempts[0][0], "gh-proxy")
        self.assertEqual(attempts[1][0], "github")
        self.assertEqual([item[0] for item in attempts[2:]], ["github-proxy-1", "github-proxy-2"])
        with self.assertRaises(RuntimeError):
            updates_module._source_attempts(
                "github", github_proxy_templates=["http://proxy.example/?url={url}"]
            )

    def test_auto_update_tries_gh_proxy_before_direct_github(self) -> None:
        attempts = updates_module._source_attempts("auto")
        self.assertEqual(attempts[0][0], "gh-proxy")
        self.assertEqual(attempts[1][0], "github")
        self.assertTrue(attempts[0][1].startswith(updates_module.GITHUB_PROXY_BASE))
    def test_trusttunnel_client_random_is_ephemeral_and_hash_bound_to_the_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            import json
            import sqlite3

            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO inbounds(id,protocol,remark,enable,listen,port,settings,stream_settings,share_addr,share_addr_strategy) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        7,
                        "trusttunnel",
                        "Trust",
                        1,
                        "127.0.0.1",
                        19443,
                        json.dumps({"clientRandomPrefix": "deadbeef/ffffffff"}),
                        "{}",
                        "trust.example.com",
                        "custom",
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            manifest = default_manifest()
            manifest["lucx"]["db_path"] = "/etc/x-ui/x-ui.db"
            manifest["decoys"]["extended_routes"] = [
                {
                    "inbound_id": 7,
                    "strategy": "trusttunnel_clienthello_split",
                    "status": "ready",
                    "clienthello_match_fingerprint": stable_fingerprint(
                        "deadbeef/ffffffff"
                    ),
                }
            ]

            material = _ephemeral_routing_material(Engine(root).fs, Audit(), manifest)

            self.assertEqual(material, {7: {"clienthello_hex_prefix": "DEADBEEF"}})
            self.assertNotIn("deadbeef", str(manifest).lower())
    def test_only_exact_managed_naive_unit_targets_become_service_names(self) -> None:
        self.assertEqual(
            _managed_naive_services_from_targets(
                [
                    "/etc/lucx-post-configurator/naive/naive-7.caddyfile",
                    "/etc/systemd/system/lucx-naive-decoy-7.service",
                    "/etc/systemd/system/lucx-naive-decoy-not-a-number.service",
                    "/etc/systemd/system/haproxy.service",
                ]
            ),
            ["lucx-naive-decoy-7.service"],
        )
    @staticmethod
    def _managed_naive_manifest() -> dict:
        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.com"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.com"
        manifest["certificates"]["cert_path"] = "/cert/fullchain.pem"
        manifest["certificates"]["key_path"] = "/cert/privkey.pem"
        manifest["protocols"] = [
            {
                "inbound_id": 7,
                "protocol": "naive",
                "remark": "Naive",
                "domain": "naive.example.com",
                "internal_host": "127.0.0.1",
                "internal_port": 47863,
                "public_port": 443,
                "network": "tcp",
                "exposure": "tcp_sni",
                "security": "tls",
                "sni_names": ["naive.example.com"],
                "port_bindings": [],
            }
        ]
        manifest["decoys"].update(
            {
                "enabled": True,
                "routing_mode": "extended",
                "extended_user_confirmed": True,
                "sites": [
                    {
                        "domain": "naive.example.com",
                        "root": "/var/www/lucx-decoys/naive.example.com",
                    }
                ],
                "extended_routes": [
                    {
                        "inbound_id": 7,
                        "domain": "naive.example.com",
                        "strategy": "naive_managed",
                        "status": "ready",
                        "managed_listen_port": 26443,
                        "binary_path": "/usr/local/x-ui/bin/caddy-naive-linux-amd64",
                        "source_caddyfile": "/usr/local/x-ui/bin/tunnel/naive-7.caddyfile",
                        "source_caddyfile_sha256": "a" * 64,
                    }
                ],
            }
        )
        manifest["components"].update(
            {
                "haproxy": True,
                "nginx": True,
                "extended_tls_split": True,
                "naive_frontend": True,
            }
        )
        return manifest

    def test_plan_lists_managed_naive_targets_but_never_the_original_caddyfile(self) -> None:
        plan = build_plan(self._managed_naive_manifest())

        action = next(
            item for item in plan["actions"] if item["component"] == "naive_frontend"
        )
        self.assertEqual(
            action["targets"],
            [
                "/usr/local/libexec/lucx-naive-sync.py",
                "/etc/lucx-post-configurator/naive/naive-7.caddyfile",
                "/etc/systemd/system/lucx-naive-decoy-7.service",
                "/etc/systemd/system/lucx-naive-sync-7.path",
                "/etc/systemd/system/lucx-naive-sync-7.service",
            ],
        )
        self.assertEqual(
            action["services"],
            ["lucx-naive-decoy-7.service", "lucx-naive-sync-7.path"],
        )
        self.assertNotIn(
            "/usr/local/x-ui/bin/tunnel/naive-7.caddyfile",
            {target for item in plan["actions"] for target in item.get("targets") or []},
        )

    def test_naive_source_is_loaded_ephemerally_from_the_exact_audited_file(self) -> None:
        source = "example.com {\n route {\n  forward_proxy {\n   basic_auth user secret\n  }\n }\n}\n"
        digest = hashlib.sha256(source.encode()).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "usr/local/x-ui/bin/tunnel/naive-7.caddyfile"
            target.parent.mkdir(parents=True)
            target.write_bytes(source.encode("utf-8"))
            audit = Audit(
                naive_caddyfile={
                    "files": [
                        {
                            "path": "/usr/local/x-ui/bin/tunnel/naive-7.caddyfile",
                            "sha256": digest,
                        }
                    ]
                }
            )
            manifest = default_manifest()
            manifest["decoys"]["extended_routes"] = [
                {
                    "inbound_id": 7,
                    "strategy": "naive_managed",
                    "status": "ready",
                    "source_caddyfile": "/usr/local/x-ui/bin/tunnel/naive-7.caddyfile",
                    "source_caddyfile_sha256": digest,
                }
            ]

            material = _ephemeral_routing_material(Engine(root).fs, audit, manifest)

            self.assertEqual(material[7]["naive_caddyfile_text"], source)
            self.assertEqual(material[7]["naive_source_metadata"], audit.naive_caddyfile["files"][0])
            self.assertEqual(target.read_bytes(), source.encode("utf-8"))
            target.write_bytes((source + "# changed\n").encode("utf-8"))
            with self.assertRaisesRegex(ApplyError, "changed after audit"):
                _ephemeral_routing_material(Engine(root).fs, audit, manifest)

    def test_activation_starts_internal_naive_frontend_before_haproxy(self) -> None:
        runner = Runner(dry_run=True)
        engine = Engine(".", runner=runner)
        generated = {
            "/etc/nginx/conf.d/60-lucx-decoys.conf": GeneratedFile(
                b"", component="nginx"
            ),
            "/etc/systemd/system/lucx-naive-decoy-7.service": GeneratedFile(
                b"", component="naive_frontend"
            ),
            "/etc/haproxy/haproxy.cfg": GeneratedFile(b"", component="haproxy"),
        }

        engine._activate(generated, "resolvconf")

        history = runner.history
        naive_restart = history.index(
            ["systemctl", "restart", "lucx-naive-decoy-7.service"]
        )
        haproxy_restart = history.index(
            ["systemctl", "reload-or-restart", "haproxy.service"]
        )
        self.assertLess(naive_restart, haproxy_restart)
        self.assertIn(["systemctl", "daemon-reload"], history)

    def test_failed_apply_rollback_restores_external_ingress_before_internal_services(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = Runner(dry_run=True)
            engine = Engine(temporary, runner=runner)
            engine.fs.atomic_write_text("/etc/haproxy/haproxy.cfg", "restored\n")
            engine.fs.atomic_write_text(
                "/etc/nginx/conf.d/60-lucx-decoys.conf", "restored\n"
            )
            engine.fs.atomic_write_text(
                "/etc/systemd/system/lucx-naive-decoy-7.service", "restored\n"
            )
            generated = {
                "/etc/haproxy/haproxy.cfg": GeneratedFile(b"", component="haproxy"),
                "/etc/nginx/conf.d/60-lucx-decoys.conf": GeneratedFile(
                    b"", component="nginx"
                ),
                "/etc/systemd/system/lucx-naive-decoy-7.service": GeneratedFile(
                    b"", component="naive_frontend"
                ),
            }

            self.assertEqual(engine._reactivate_after_restore(generated, "resolvconf", []), [])

            history = runner.history
            external = history.index(
                ["systemctl", "reload-or-restart", "haproxy.service"]
            )
            nginx = history.index(
                ["systemctl", "reload-or-restart", "nginx.service"]
            )
            naive = history.index(
                ["systemctl", "restart", "lucx-naive-decoy-7.service"]
            )
            self.assertLess(external, nginx)
            self.assertLess(external, naive)

    def test_certificate_scope_excludes_protocol_reality_sni(self) -> None:
        manifest = default_manifest()
        manifest["lucx"]["panel"]["domain"] = "panel.example.com"
        manifest["lucx"]["subscription"]["domain"] = "sub.example.com"
        manifest["protocols"] = [
            {
                "exposure": "tcp_sni",
                "sni_names": ["www.google.com", "api.example.com"],
            }
        ]
        manifest["decoys"].update(
            {
                "enabled": True,
                "sites": [{"domain": "api.example.com", "root": "/var/www/decoy/api"}],
            }
        )
        self.assertEqual(
            required_domains(manifest),
            ["api.example.com", "panel.example.com", "sub.example.com"],
        )

    def test_repair_change_report_is_keyed_by_inbound_id(self) -> None:
        before = {"protocols": [{"inbound_id": 7, "protocol": "naive", "internal_port": 1000}]}
        after = {"protocols": [{"inbound_id": 7, "protocol": "naive", "internal_port": 2000}]}
        self.assertEqual(
            _dynamic_changes(before, after),
            [{"inbound_id": 7, "protocol": "naive", "changed_fields": ["internal_port"]}],
        )

    def test_repair_change_report_includes_extended_strategy_changes(self) -> None:
        before = {
            "protocols": [{"inbound_id": 7, "protocol": "naive"}],
            "decoys": {
                "extended_routes": [
                    {
                        "inbound_id": 7,
                        "strategy": "naive_native",
                        "status": "ready",
                        "source_caddyfile_sha256": "a" * 64,
                    }
                ]
            },
        }
        after = {
            "protocols": [{"inbound_id": 7, "protocol": "naive"}],
            "decoys": {
                "extended_routes": [
                    {
                        "inbound_id": 7,
                        "strategy": "naive_managed",
                        "status": "ready",
                        "source_caddyfile_sha256": "b" * 64,
                    }
                ]
            },
        }

        self.assertEqual(
            _dynamic_changes(before, after),
            [
                {
                    "inbound_id": 7,
                    "protocol": "naive",
                    "changed_fields": [
                        "decoy_strategy",
                        "source_caddyfile_sha256",
                    ],
                }
            ],
        )

    def test_repair_change_report_includes_trusttunnel_match_fingerprint_change(self) -> None:
        before = {
            "protocols": [
                {
                    "inbound_id": 9,
                    "protocol": "trusttunnel",
                    "clienthello_match_fingerprint": "sha256:old",
                }
            ]
        }
        after = {
            "protocols": [
                {
                    "inbound_id": 9,
                    "protocol": "trusttunnel",
                    "clienthello_match_fingerprint": "sha256:new",
                }
            ]
        }

        self.assertEqual(
            _dynamic_changes(before, after),
            [
                {
                    "inbound_id": 9,
                    "protocol": "trusttunnel",
                    "changed_fields": ["clienthello_match_fingerprint"],
                }
            ],
        )

    def test_repair_change_report_treats_missing_optional_matcher_as_empty(self) -> None:
        before = {"protocols": [{"inbound_id": 1, "protocol": "vmess"}]}
        after = {
            "protocols": [
                {
                    "inbound_id": 1,
                    "protocol": "vmess",
                    "clienthello_match_fingerprint": "",
                }
            ]
        }
        self.assertEqual(_dynamic_changes(before, after), [])

    def test_explicit_repair_rebaselines_expected_post_update_integrity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = default_manifest()
            manifest["integrity"] = {
                "protected_lucx": {"old": True},
                "naive_caddyfile": {"old": True},
            }
            engine = SimpleNamespace(
                fs=Engine(temporary).fs,
                audit=mock.Mock(return_value=Audit(db_schema_supported=True)),
                apply=mock.Mock(return_value={"status": "complete", "warnings": []}),
                prepare_operation=lambda m, audit=None: m,
            )
            with (
                mock.patch(
                    "lucx_post_configurator.repair.load_state",
                    return_value={"manifest": manifest},
                ),
                mock.patch(
                    "lucx_post_configurator.repair.capture_integrity",
                    return_value={"protected_lucx": {"new": True}, "naive_caddyfile": {}},
                ),
                mock.patch(
                    "lucx_post_configurator.repair.compare_integrity",
                    return_value=["inbound #1 port changed"],
                ),
                mock.patch(
                    "lucx_post_configurator.repair.refresh_manifest_from_audit",
                    return_value=(manifest, ["маршрут перечитан"]),
                ),
            ):
                report = repair_apply(engine)  # type: ignore[arg-type]

            self.assertEqual(engine.apply.call_count, 1)
            self.assertIn("маршрут перечитан", report["warnings"])
            self.assertTrue(
                any("inbound #1 port changed" in item for item in report["warnings"])
            )

    def test_tui_exits_without_touching_engine(self) -> None:
        output: list[str] = []
        self.assertEqual(
            run_tui(object(), input_fn=lambda _prompt: "0", output_fn=output.append),  # type: ignore[arg-type]
            0,
        )
        self.assertTrue(any("LucX post-configurator" in line for line in output))

    def test_persistent_repair_service_retries_and_wrapper_maps_legacy_commands(self) -> None:
        self.assertIn(b"Restart=on-failure", POST_UPDATE_SERVICE)
        self.assertIn(b"--repair-check", REPAIR_WRAPPER)
        self.assertIn(b"--repair-apply", REPAIR_WRAPPER)

    def test_self_install_provides_persistent_detached_update_worker_template(self) -> None:
        self.assertTrue(
            hasattr(self_install_module, "UPDATE_WORKER_UNIT"),
            "self-install does not provide the unit used by the detached launcher",
        )
        unit = self_install_module.UPDATE_WORKER_UNIT
        self.assertIn(b"ExecStart=/usr/local/sbin/lucx-post-configure --update-worker", unit)
        self.assertIn(b"--update-job-id %i", unit)
        self.assertIn(b"TimeoutStartSec=2700", unit)
        self.assertNotIn(b"PartOf=x-ui.service", unit)

    def test_self_install_provides_x_tuna_tui_command(self) -> None:
        self.assertEqual(self_install_module.X_TUNA_COMMAND, "/usr/local/sbin/x-tuna")
        self.assertIn(
            b"exec /usr/local/sbin/lucx-post-configure",
            self_install_module.X_TUNA_WRAPPER,
        )

    def test_custom_mirror_requires_plain_https_url(self) -> None:
        self.assertEqual(
            _validated_https_url("https://mirror.example.com/lucx.tar.gz"),
            "https://mirror.example.com/lucx.tar.gz",
        )
        for value in ("http://mirror.example.com/a.tar", "https://user@mirror.example.com/a.tar"):
            with self.assertRaises(RuntimeError):
                _validated_https_url(value)

    def test_update_tar_is_manually_extracted_and_path_traversal_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            good = root / "good.tar.gz"
            payload = b"#!/bin/bash\necho safe\n"
            with tarfile.open(good, "w:gz") as archive:
                item = tarfile.TarInfo("lucx-dist/update.sh")
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
            update = _safe_extract_tar(good, root / "good")
            self.assertEqual(update.read_bytes(), payload)

            bad = root / "bad.tar.gz"
            with tarfile.open(bad, "w:gz") as archive:
                item = tarfile.TarInfo("../escape/update.sh")
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
            with self.assertRaises(RuntimeError):
                _safe_extract_tar(bad, root / "bad")

    def test_lucx_update_is_launched_as_detached_systemd_worker(self) -> None:
        """Stopping x-ui must not kill the updater or skip post-update repair."""

        self.assertTrue(
            hasattr(updates_module, "_launch_update_worker"),
            "LucX update still has no process independent from the TUI/x-ui cgroup",
        )
        runner = Runner(dry_run=True)
        job_id = "20260901T091114Z-629799"

        updates_module._launch_update_worker(runner, job_id)

        self.assertEqual(
            runner.history,
            [
                [
                    "systemctl",
                    "start",
                    "--no-block",
                    f"lucx-post-update@{job_id}.service",
                ]
            ],
        )

    @unittest.skipUnless(__import__("importlib.util").util.find_spec("fcntl"), "fcntl is unavailable on Windows")
    def test_lock_error_identifies_active_owner_when_metadata_is_available(self) -> None:
        class LiveTestFS(TargetFS):
            @property
            def is_live(self) -> bool:
                return True

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            engine = Engine(root, runner=Runner(dry_run=True))
            engine.fs = LiveTestFS(root)
            lock = engine.fs.path("/run/lock/lucx-post-configurator.lock")
            lock.parent.mkdir(parents=True, exist_ok=True)
            metadata = engine.fs.path("/run/lock/lucx-post-configurator.lock.json")
            metadata.write_text(
                json.dumps({"pid": 1, "operation": "repair"}), encoding="utf-8"
            )
            import fcntl
            with lock.open("a+") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                with self.assertRaisesRegex(ApplyError, "другая операция"):
                    with engine._exclusive_lock():
                        pass
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def test_detached_worker_runs_official_updater_before_transactional_repair(self) -> None:
        self.assertTrue(
            hasattr(updates_module, "run_update_worker"),
            "detached systemd job has no worker that owns updater and repair",
        )
        with tempfile.TemporaryDirectory() as temporary:
            engine = Engine(temporary, runner=Runner(dry_run=True))
            job_id = "20260901T091114Z-629799"
            job_dir = engine.fs.path(
                f"/var/lib/lucx-post-configurator/update-jobs/{job_id}"
            )
            script = job_dir / "source/update.sh"
            script.parent.mkdir(parents=True)
            script.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            (job_dir / "job.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "job_id": job_id,
                        "update_script": "source/update.sh",
                        "install_source": "yandex",
                        "source": "sourcecraft",
                    }
                ),
                encoding="utf-8",
            )
            engine.fs.atomic_write_text(
                "/var/lib/lucx-post-configurator/pending-post-update-repair",
                job_id + "\n",
                mode=0o600,
            )

            def completed_repair(_engine: Engine) -> dict:
                self.assertEqual(engine.runner.history[0], ["bash", str(script)])
                return {"run_id": "repair-transaction"}

            with (
                mock.patch(
                    "lucx_post_configurator.updates._require_safe_automatic_update_adapter",
                    return_value=None,
                ),
                mock.patch(
                    "lucx_post_configurator.updates.repair_apply",
                    side_effect=completed_repair,
                ) as repair,
            ):
                result = updates_module.run_update_worker(engine, job_id)

            repair.assert_called_once_with(engine)
            self.assertEqual(result["status"], "complete")
            status = json.loads(
                engine.fs.read_text(
                    "/var/lib/lucx-post-configurator/update-status.json"
                )
            )
            self.assertEqual(status["state"], "complete")
            self.assertEqual(status["repair_run_id"], "repair-transaction")
            self.assertEqual(status["phase_current"], 3)
            self.assertEqual(status["phase_total"], 3)
            self.assertIn("started_at", status)
            self.assertIn("updated_at", status)
            self.assertFalse(script.exists())
            self.assertTrue((job_dir / "job.json").is_file())

    def test_update_status_projection_exposes_phases_but_redacts_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            engine = Engine(temporary, runner=Runner(dry_run=True))
            engine.fs.atomic_write_text(
                "/var/lib/lucx-post-configurator/update-status.json",
                json.dumps(
                    {
                        "schema_version": 1,
                        "job_id": "20260901T091114Z-629799",
                        "source": "sourcecraft",
                        "state": "running_repair",
                        "phase_current": 3,
                        "phase_total": 3,
                        "phase_label": "Восстановление маршрутов",
                        "started_at": "2026-09-01T09:11:14+00:00",
                        "updated_at": "2026-09-01T09:12:14+00:00",
                        "backup": "/var/backups/lucx-safe",
                        "password": "must-never-be-returned",
                        "raw_output": "secret command output",
                    }
                ),
                mode=0o600,
            )

            projected = updates_module.update_source_status(engine)["job_status"]

            self.assertEqual(projected["state"], "running_repair")
            self.assertEqual(projected["phase_current"], 3)
            self.assertEqual(projected["phase_total"], 3)
            self.assertEqual(projected["backup"], "/var/backups/lucx-safe")
            self.assertNotIn("password", projected)
            self.assertNotIn("raw_output", projected)

    def test_failed_update_without_pending_marker_is_marked_historical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            engine = Engine(temporary, runner=Runner(dry_run=True))
            engine.fs.atomic_write_text(
                "/var/lib/lucx-post-configurator/update-status.json",
                json.dumps({
                    "schema_version": 1,
                    "job_id": "20260901T091114Z-629799",
                    "state": "failed",
                    "error": "старое повреждение",
                }),
                mode=0o600,
            )
            result = updates_module.update_source_status(engine)["job_status"]
            self.assertTrue(result["historical"])

    def test_repair_check_uses_bounded_validation_without_live_waits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            engine = Engine(temporary, runner=Runner(dry_run=True))
            engine.validate_installed = mock.Mock(
                return_value={"ok": True, "errors": [], "changed_managed_files": []}
            )
            engine.audit = mock.Mock(
                return_value=mock.Mock(
                    db_schema_supported=True,
                    services={},
                    naive_caddyfile={},
                )
            )
            engine.plan = mock.Mock(return_value={})
            manifest = {
                "schema_version": 3,
                "lucx": {
                    "db_path": "/etc/x-ui/x-ui.db",
                    "panel": {"internal_port": 1},
                    "subscription": {"internal_port": 2},
                },
                "integrity": {},
                "decoys": {},
            }
            state = {"manifest": manifest, "integrity": {}, "run_id": "test"}
            with mock.patch("lucx_post_configurator.repair.load_state", return_value=state):
                with mock.patch("lucx_post_configurator.repair.refresh_manifest_from_audit", return_value=(manifest, [])):
                    with mock.patch("lucx_post_configurator.repair.capture_integrity", return_value={}):
                        repair_check(engine)
            engine.validate_installed.assert_called_once_with(include_live=False)

    def test_failed_detached_updater_leaves_marker_and_does_not_run_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = Runner(dry_run=True)
            engine = Engine(temporary, runner=runner)
            job_id = "20260901T091114Z-629799"
            job_dir = engine.fs.path(
                f"/var/lib/lucx-post-configurator/update-jobs/{job_id}"
            )
            script = job_dir / "source/update.sh"
            script.parent.mkdir(parents=True)
            script.write_text("#!/bin/bash\nexit 17\n", encoding="utf-8")
            (job_dir / "job.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "job_id": job_id,
                        "update_script": "source/update.sh",
                        "install_source": "yandex",
                        "source": "sourcecraft",
                    }
                ),
                encoding="utf-8",
            )
            engine.fs.atomic_write_text(
                "/var/lib/lucx-post-configurator/pending-post-update-repair",
                job_id + "\n",
                mode=0o600,
            )
            runner.run = mock.Mock(
                return_value=CommandResult(["bash", str(script)], 17, "", "updater failed")
            )

            with (
                mock.patch(
                    "lucx_post_configurator.updates._require_safe_automatic_update_adapter",
                    return_value=None,
                ),
                mock.patch("lucx_post_configurator.updates.repair_apply") as repair,
                self.assertRaisesRegex(RuntimeError, "официальный обновлятор"),
            ):
                updates_module.run_update_worker(engine, job_id)

            repair.assert_not_called()
            self.assertTrue(
                engine.fs.exists(
                    "/var/lib/lucx-post-configurator/pending-post-update-repair"
                )
            )
            status = json.loads(
                engine.fs.read_text(
                    "/var/lib/lucx-post-configurator/update-status.json"
                )
            )
            self.assertEqual(status["state"], "failed")

    def test_update_stages_persistent_job_and_returns_after_systemd_accepts_it(self) -> None:
        class LiveTestFS(TargetFS):
            @property
            def is_live(self) -> bool:
                return True

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            runner = Runner(dry_run=True)
            engine = Engine(root, runner=runner)
            engine.fs = LiveTestFS(root)
            manifest = default_manifest()
            manifest["lucx"]["db_path"] = "/etc/x-ui/x-ui.db"

            def fake_download(_engine: Engine, _url: str, destination: Path) -> None:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"archive" * 256)

            def fake_extract(_archive: Path, destination: Path) -> Path:
                script = destination / "lucx/update.sh"
                script.parent.mkdir(parents=True, exist_ok=True)
                script.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
                return script

            with (
                mock.patch(
                    "lucx_post_configurator.updates._require_safe_automatic_update_adapter",
                    return_value=None,
                ),
                mock.patch(
                    "lucx_post_configurator.updates.repair_check",
                    return_value={"repair_required": False},
                ),
                mock.patch(
                    "lucx_post_configurator.updates.install_self",
                    return_value={"installed": []},
                ),
                mock.patch(
                    "lucx_post_configurator.updates.load_state",
                    return_value={"manifest": manifest},
                ),
                mock.patch(
                    "lucx_post_configurator.updates._download_archive",
                    side_effect=fake_download,
                ),
                mock.patch(
                    "lucx_post_configurator.updates._safe_extract_tar",
                    side_effect=fake_extract,
                ),
                mock.patch(
                    "lucx_post_configurator.updates.repair_apply",
                    return_value={"run_id": "foreground-repair-must-not-run"},
                ) as foreground_repair,
            ):
                result = updates_module.update_lucx(
                    engine,
                    source="sourcecraft",
                    self_source="unused-in-test",
                )

            self.assertEqual(result["status"], "started")
            foreground_repair.assert_not_called()
            self.assertTrue(
                any(
                    command[:3] == ["systemctl", "start", "--no-block"]
                    for command in runner.history
                )
            )
            self.assertFalse(any(command[0] == "bash" for command in runner.history))
            descriptor = engine.fs.path(
                f"/var/lib/lucx-post-configurator/update-jobs/{result['job_id']}/job.json"
            )
            self.assertTrue(descriptor.is_file())

    def test_hidden_cli_worker_entrypoint_dispatches_persistent_update_job(self) -> None:
        job_id = "20260901T091114Z-629799"
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch(
                    "lucx_post_configurator.cli._require_live_root",
                    return_value=None,
                ),
                mock.patch(
                    "lucx_post_configurator.cli.run_update_worker",
                    return_value={"status": "complete", "job_id": job_id},
                ) as worker,
                mock.patch("lucx_post_configurator.cli._emit") as emit,
            ):
                try:
                    result = cli_main(
                        [
                            "--update-worker",
                            "--update-job-id",
                            job_id,
                            "--root",
                            temporary,
                        ]
                    )
                except SystemExit as exc:
                    self.fail(f"worker CLI arguments are not implemented: {exc}")

        self.assertEqual(result, 0)
        worker.assert_called_once()
        emit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
