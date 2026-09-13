from __future__ import annotations

import copy
import hashlib
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import PropertyMock, patch

from test_transport_routing_regressions import topology

from lucx_post_configurator.models import Audit, Inbound, default_manifest
from lucx_post_configurator.questionnaire import _inbound_routing_metadata
from lucx_post_configurator.renderers import render_haproxy
from lucx_post_configurator.routing_profiles import source_routing_fingerprint
from lucx_post_configurator.validation import validate_audit_against_manifest


class RoutingFreshnessTests(unittest.TestCase):
    def test_native_connect_material_requires_canonical_source_and_preserves_file(self):
        from lucx_post_configurator.engine import ApplyError, _ephemeral_routing_material
        from lucx_post_configurator.extended_decoys import classify_extended_decoy_routes
        source = '''{
 admin off
 auto_https off
 servers {
  protocols h1 h2
 }
}
:18443 {
 bind 127.0.0.1
 tls /cert/original.pem /cert/original.key
 route {
  forward_proxy {
   basic_auth synthetic-user synthetic-secret
   hide_ip
   hide_via
   probe_resistance
   upstream socks5://lucx:abcdefghijklmnopqrstuvwx@127.0.0.1:19444
  }
 }
}
'''
        for valid in (True, False):
            with tempfile.TemporaryDirectory() as temporary, self.subTest(valid=valid):
                fs, manifest, audit, path = self._connect_source_fixture(temporary)
                payload = (source if valid else source.replace('auto_https off', 'auto_https disable_redirects')).encode()
                path.write_bytes(payload)
                audit.naive_caddyfile['files'][0]['sha256'] = hashlib.sha256(payload).hexdigest()
                manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(manifest, audit)
                before, original = path.stat(), copy.deepcopy((manifest, audit))
                if valid:
                    material = _ephemeral_routing_material(fs, audit, manifest)
                    self.assertEqual(material[7]['naive_caddyfile_text'], source)
                    self.assertEqual(material[7]['naive_source_metadata'], audit.naive_caddyfile['files'][0])
                else:
                    with self.assertRaises(ApplyError):
                        _ephemeral_routing_material(fs, audit, manifest)
                self.assertEqual((manifest, audit), original)
                self.assertEqual(path.read_bytes(), payload)
                after = path.stat()
                for field in ('st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_mtime_ns', 'st_ctime_ns'):
                    self.assertEqual(getattr(before, field), getattr(after, field))

    def test_strict_naive_passthrough_does_not_load_new_connect_material(self):
        from test_naive_connect_frontend import candidate_fixture
        from lucx_post_configurator.engine import _ephemeral_routing_material
        from lucx_post_configurator.models import validate_manifest
        from lucx_post_configurator.targetfs import TargetFS
        manifest, audit, _ = candidate_fixture()
        manifest['decoys'].update(routing_mode='strict', enabled=False, extended_routes=[])
        manifest['components']['extended_tls_split'] = False
        validate_manifest(manifest)
        self.assertNotIn('lucx_naive_split', render_haproxy(manifest))
        with tempfile.TemporaryDirectory() as temporary:
            with patch('lucx_post_configurator.naive_probe_source._capture',
                       side_effect=AssertionError('strict passthrough must not read source')) as capture:
                self.assertEqual(_ephemeral_routing_material(TargetFS(temporary), audit, manifest), {})
                capture.assert_not_called()

    def _connect_source_fixture(self, temporary):
        from test_naive_connect_frontend import SOURCE, candidate_fixture

        from lucx_post_configurator.extended_decoys import (
            classify_extended_decoy_routes,
        )
        from lucx_post_configurator.targetfs import TargetFS
        fs = TargetFS(temporary)
        manifest, audit, _ = candidate_fixture()
        metadata = audit.naive_caddyfile['files'][0]
        path = fs.path(metadata['path'])
        path.parent.mkdir(parents=True)
        path.write_text(SOURCE, encoding='utf-8', newline='')
        path.chmod(0o600)
        info = path.lstat()
        metadata.update(mode=info.st_mode & 0o7777, uid=info.st_uid, gid=info.st_gid)
        manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(manifest, audit)
        self.assertEqual(manifest['decoys']['extended_routes'][0]['strategy'], 'naive_connect_h2')
        return fs, manifest, audit, path

    def test_connect_material_uses_exact_read_only_capture_with_or_without_cache(self):
        from lucx_post_configurator.engine import _ephemeral_routing_material
        from lucx_post_configurator.targetfs import TargetFS
        with tempfile.TemporaryDirectory() as temporary:
            fs, manifest, audit, path = self._connect_source_fixture(temporary)
            before = path.lstat()
            payload = path.read_bytes()
            for cached in (True, False):
                if not cached:
                    manifest['decoys']['extended_routes'] = []
                original = copy.deepcopy(manifest)
                with self.subTest(cached=cached), patch.object(TargetFS, 'read_bytes',
                        side_effect=AssertionError('new candidate must use bounded capture')):
                    material = _ephemeral_routing_material(fs, audit, manifest)
                self.assertEqual(set(material), {7})
                self.assertEqual(material[7]['naive_caddyfile_text'], payload.decode('utf-8'))
                self.assertEqual(material[7]['naive_source_metadata'], audit.naive_caddyfile['files'][0])
                self.assertEqual(manifest, original)
            after = path.lstat()
            self.assertEqual(path.read_bytes(), payload)
            for field in ('st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_mtime_ns', 'st_ctime_ns'):
                self.assertEqual(getattr(before, field), getattr(after, field))

    def test_connect_material_rejects_missing_duplicate_and_drifted_source(self):
        from lucx_post_configurator.engine import (
            ApplyError,
            _ephemeral_routing_material,
        )
        mutations = [lambda a, p: a.naive_caddyfile.update(files=[]),
                     lambda a, p: a.naive_caddyfile['files'].append(copy.deepcopy(a.naive_caddyfile['files'][0])),
                     lambda a, p: p.write_bytes(p.read_bytes() + b'# changed'),
                     lambda a, p: p.unlink()]
        for field, value in (('mode', 0), ('uid', 123456), ('gid', 123456), ('kind', 'symlink'),
                             ('sha256', '0' * 64), ('path', '/etc/other/naive-7.caddyfile')):
            mutations.append(lambda a, p, f=field, v=value: a.naive_caddyfile['files'][0].update({f: v}))
        for index, mutate in enumerate(mutations):
            with tempfile.TemporaryDirectory() as temporary, self.subTest(index=index):
                fs, manifest, audit, path = self._connect_source_fixture(temporary)
                mutate(audit, path)
                with self.assertRaises(ApplyError):
                    _ephemeral_routing_material(fs, audit, manifest)

    def test_connect_material_rejects_forged_or_partial_cached_routes(self):
        from lucx_post_configurator.engine import (
            ApplyError,
            _ephemeral_routing_material,
        )
        with tempfile.TemporaryDirectory() as temporary:
            fs, original, audit, _ = self._connect_source_fixture(temporary)
            variants = []
            for field, value in (('status', 'ready'), ('strategy', 'naive_native'),
                                 ('backend_sni', 'other.example.test')):
                manifest = copy.deepcopy(original)
                manifest['decoys']['extended_routes'][0][field] = value
                variants.append(manifest)
            manifest = copy.deepcopy(original)
            manifest['decoys']['extended_routes'].append(copy.deepcopy(manifest['decoys']['extended_routes'][0]))
            variants.append(manifest)
            manifest = copy.deepcopy(original)
            manifest['decoys']['extended_routes'][0]['source_identity'].pop('mode')
            variants.append(manifest)
            for index, manifest in enumerate(variants):
                with self.subTest(index=index), self.assertRaises(ApplyError):
                    _ephemeral_routing_material(fs, audit, manifest)

    def test_connect_material_checks_real_metadata_even_after_cache_refresh(self):
        from lucx_post_configurator.engine import (
            ApplyError,
            _ephemeral_routing_material,
        )
        from lucx_post_configurator.extended_decoys import (
            classify_extended_decoy_routes,
        )
        for field in ('mode', 'uid', 'gid'):
            with tempfile.TemporaryDirectory() as temporary, self.subTest(field=field):
                fs, manifest, audit, _ = self._connect_source_fixture(temporary)
                audit.naive_caddyfile['files'][0][field] += 1
                manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(manifest, audit)
                self.assertEqual(manifest['decoys']['extended_routes'][0]['strategy'], 'naive_connect_h2')
                with self.assertRaises(ApplyError):
                    _ephemeral_routing_material(fs, audit, manifest)

    def test_connect_material_rejects_missing_member_of_mixed_cache(self):
        from lucx_post_configurator.engine import (
            ApplyError,
            _ephemeral_routing_material,
        )
        from lucx_post_configurator.extended_decoys import (
            classify_extended_decoy_routes,
        )
        with tempfile.TemporaryDirectory() as temporary:
            fs, manifest, audit, _ = self._connect_source_fixture(temporary)
            manifest['protocols'].append(topology('ws', inbound_id=8, domain='other.example.test',
                internal_port=19443, sni_names=['other.example.test'],
                transport_hosts=['other.example.test'])['protocols'][0])
            routes = classify_extended_decoy_routes(manifest, audit)
            for missing in (0, 1):
                manifest['decoys']['extended_routes'] = [route for index, route in enumerate(routes) if index != missing]
                with self.subTest(missing=missing), self.assertRaises(ApplyError):
                    _ephemeral_routing_material(fs, audit, manifest)

    def test_connect_material_cannot_trust_audited_capabilities_over_source_parser(self):
        from lucx_post_configurator.engine import (
            ApplyError,
            _ephemeral_routing_material,
        )
        from lucx_post_configurator.extended_decoys import (
            classify_extended_decoy_routes,
        )
        for replacement in ('upstream https://upstream.example.test', 'probe_resistance',
                            'basic_auth {$SYNTHETIC_USER} synthetic-pass'):
            with tempfile.TemporaryDirectory() as temporary, self.subTest(replacement=replacement):
                fs, manifest, audit, path = self._connect_source_fixture(temporary)
                text = path.read_text(encoding='utf-8')
                text = text.replace('basic_auth synthetic-user synthetic-secret',
                                    'basic_auth synthetic-user synthetic-secret\n ' + replacement)
                path.write_text(text, encoding='utf-8', newline='')
                audit.naive_caddyfile['files'][0]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                manifest['decoys']['extended_routes'] = classify_extended_decoy_routes(manifest, audit)
                with self.assertRaises(ApplyError):
                    _ephemeral_routing_material(fs, audit, manifest)

    def test_connect_material_rejects_symlink_even_with_matching_audit_hash(self):
        from lucx_post_configurator.engine import (
            ApplyError,
            _ephemeral_routing_material,
        )
        with tempfile.TemporaryDirectory() as temporary:
            fs, manifest, audit, path = self._connect_source_fixture(temporary)
            target = path.with_suffix('.actual')
            path.rename(target)
            try:
                os.symlink(target, path)
            except OSError:
                self.skipTest('Нет разрешения на создание локального symlink')
            with self.assertRaises(ApplyError):
                _ephemeral_routing_material(fs, audit, manifest)

    def test_drift_during_staged_validation_prevents_managed_commit(self):
        from helpers import make_target

        from lucx_post_configurator.engine import ApplyError, Engine
        from lucx_post_configurator.renderers import GeneratedFile
        from lucx_post_configurator.runner import Runner
        from lucx_post_configurator.targetfs import TargetFS

        manifest = topology("grpc")
        manifest["components"] = {key: False for key in manifest["components"]}
        manifest["components"].update(haproxy=True, nginx=True, extended_tls_split=True)
        manifest["dns"]["enabled"] = False
        manifest["cloudflare"]["enabled"] = False
        audit = Audit(supported_os=True, db_schema_supported=True,
            settings={"webDomain": "panel.example.test", "webPort": "2083",
                      "subDomain": "sub.example.test", "subPort": "2096"},
            inbounds=[Inbound(id=7, protocol="vless", remark="", enable=True,
                              listen="127.0.0.1", port=18443, transport="grpc")])
        # После staging панель легально меняет транспорт, но старый план уже непригоден.
        def change_transport(*args, **kwargs):
            audit.inbounds[0].transport = "xhttp"
            engine.fs.atomic_write_text(target, "external edit during staging\n")
            return []

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            make_target(root)
            engine = Engine(root, runner=Runner(dry_run=True))
            target = "/etc/haproxy/haproxy.cfg"
            engine.fs.atomic_write_text(target, "previous configuration\n")
            stack.enter_context(patch.object(TargetFS, "is_live", new_callable=PropertyMock, return_value=True))
            stack.enter_context(patch.object(engine, "audit", side_effect=lambda *_: copy.deepcopy(audit)))
            stack.enter_context(patch.object(engine, "_activate"))
            restore_services = stack.enter_context(patch.object(engine, "_reactivate_after_restore", return_value=[]))
            stack.enter_context(patch.object(engine, "_register_acme_hook", side_effect=lambda m, complete=None: (complete() if complete else None) or []))
            stack.enter_context(patch("lucx_post_configurator.engine._managed_decoy_directories", return_value={}))
            for name in ("validate_public_bind_conflicts", "validate_certificate", "validate_lucx_tls_coverage", "validate_live_configuration"):
                stack.enter_context(patch("lucx_post_configurator.engine." + name, return_value=[]))
            stack.enter_context(patch("lucx_post_configurator.engine.render_files",
                return_value={target: GeneratedFile(b"new configuration\n", component="haproxy")}))
            stack.enter_context(patch("lucx_post_configurator.engine.validate_generated", side_effect=change_transport))
            commit = stack.enter_context(patch("lucx_post_configurator.engine.commit_managed_transition", wraps=__import__(
                "lucx_post_configurator.transaction", fromlist=["commit_managed_transition"]).commit_managed_transition))
            with self.assertRaisesRegex(ApplyError, "staging|commit"):
                engine._apply_locked(manifest)
            commit.assert_not_called()
            restore_services.assert_not_called()
            self.assertEqual(engine.fs.read_bytes(target), b"external edit during staging\n")

    def test_native_naive_material_is_read_from_exact_audited_source(self):
        from lucx_post_configurator.engine import _ephemeral_routing_material
        from lucx_post_configurator.targetfs import TargetFS

        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            path = "/usr/local/x-ui/bin/tunnel/naive-7.caddyfile"
            payload = b"synthetic read-only source\n"
            fs.atomic_write_text(path, payload.decode())
            digest = hashlib.sha256(payload).hexdigest()
            metadata = {"path": path, "sha256": digest, "capabilities": {"native_decoy": True}}
            audit = Audit(naive_caddyfile={"files": [metadata], "binary_path": "/usr/local/bin/caddy-naive"})
            manifest = {"decoys": {"extended_routes": [{"inbound_id": 7,
                "strategy": "naive_native", "status": "ready", "source_caddyfile": path,
                "source_caddyfile_sha256": digest}]}}
            material = _ephemeral_routing_material(fs, audit, manifest)[7]
            self.assertEqual(material["naive_caddyfile_text"], payload.decode())
            self.assertEqual(material["naive_source_metadata"], metadata)
            self.assertEqual(material["naive_binary_path"], "/usr/local/bin/caddy-naive")
            self.assertEqual(fs.read_bytes(path), payload)

    def test_staging_snapshot_detects_new_inbound_and_naive_source_drift(self):
        source = {"path": "/usr/local/x-ui/bin/tunnel/naive-7.caddyfile",
                  "sha256": "a" * 64, "kind": "file", "mode": 384, "uid": 0, "gid": 0}
        actual = Inbound(id=7, protocol="naive", remark="", enable=True,
                         listen="127.0.0.1", port=18443)
        audit = Audit(supported_os=True, db_schema_supported=True, inbounds=[actual],
            settings={"webDomain": "panel.example.test", "webPort": "2083",
                      "subDomain": "sub.example.test", "subPort": "2096"},
            naive_caddyfile={"files": [source]})
        manifest = default_manifest(audit)
        manifest["protocols"] = [{"inbound_id": 7, "protocol": "naive",
            "internal_port": 18443, "public_port": 443, "domain": "", "exposure": "tcp_sni"}]
        manifest["routing_snapshot"] = {
            "inbounds": {"7": source_routing_fingerprint(actual)},
            "naive_files": [dict(source)],
        }
        self.assertEqual(validate_audit_against_manifest(audit, manifest), [])
        for field, value in {"sha256": "b" * 64, "kind": "symlink", "mode": 420,
                             "uid": 1, "gid": 1}.items():
            changed = copy.deepcopy(audit)
            changed.naive_caddyfile["files"][0][field] = value
            with self.subTest(field=field):
                self.assertTrue(validate_audit_against_manifest(changed, manifest))
        audit.inbounds.append(Inbound(id=8, protocol="trojan", remark="", enable=True,
                                      listen="127.0.0.1", port=19443))
        self.assertTrue(validate_audit_against_manifest(audit, manifest))

    def test_cached_route_rejects_every_routing_change(self):
        changes = {
            "transport_mode": "stream-one",
            "alpn": ["http/1.1"],
            "public_port": 8443,
            "port_bindings": [{"protocol": "TCP", "port": 27443}],
            "udp_over_tcp": True,
            "exposure": "tcp_direct",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                manifest = topology("xhttp", transport_mode="packet-up")
                manifest["protocols"][0][field] = value
                with self.assertRaises(ValueError):
                    render_haproxy(manifest)

    def test_cached_route_without_fingerprint_requires_new_plan(self):
        manifest = topology()
        manifest["decoys"]["extended_routes"][0].pop("routing_fingerprint", None)
        with self.assertRaises(ValueError):
            render_haproxy(manifest)

    def test_audited_transport_changes_invalidate_planned_route(self):
        changes = {
            "transport": "grpc", "transport_path": "/changed",
            "transport_mode": "stream-one", "alpn": ["http/1.1"],
            "transport_hosts": ["other.example.test"],
            "server_names": ["other.example.test"], "security": "reality",
            "network": "udp", "listen": "127.0.0.2",
            "port_bindings": [{"protocol": "UDP", "port": 18443}],
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                actual = Inbound(id=7, protocol="vless", remark="VPN", enable=True,
                    listen="127.0.0.1", port=18443, share_addr="vpn.example.test",
                    suggested_public_port=443, network="tcp", security="tls",
                    transport="xhttp", transport_path="/vpn", transport_mode="packet-up",
                    transport_hosts=["vpn.example.test"], server_names=["vpn.example.test"],
                    alpn=["h2", "http/1.1"])
                audit = Audit(supported_os=True, db_schema_supported=True, inbounds=[actual],
                    settings={"webDomain": "panel.example.test", "webPort": "2083",
                              "subDomain": "sub.example.test", "subPort": "2096"})
                manifest = default_manifest(audit)
                manifest["protocols"] = [dict(inbound_id=7, protocol="vless",
                    internal_port=18443, public_port=443, domain="vpn.example.test",
                    exposure="tcp_sni", network="tcp", security="tls",
                    **_inbound_routing_metadata(actual))]
                self.assertEqual(validate_audit_against_manifest(audit, manifest), [])
                setattr(actual, field, value)
                self.assertTrue(validate_audit_against_manifest(audit, manifest))

    def test_renderer_rejects_tampered_cache_even_with_original_fingerprint(self):
        manifest = topology("xhttp", transport_mode="packet-up")
        original = copy.deepcopy(manifest)
        manifest["decoys"]["extended_routes"][0]["alpn"] = ["http/1.1"]
        with self.assertRaises(ValueError):
            render_haproxy(manifest)
        self.assertIn("backend", render_haproxy(original))
