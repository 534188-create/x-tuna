from __future__ import annotations

import datetime as dt
import tempfile
import unittest
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from lucx_post_configurator.certificates import dnsname_matches, find_certificate_candidates, select_certificate
from lucx_post_configurator.runner import Runner
from lucx_post_configurator.targetfs import TargetFS


def make_certificate(cert: Path, key_path: Path, sans: list[str], days: int) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(value) for value in sans]), critical=False)
    )
    certificate = builder.sign(key, hashes.SHA256())
    cert.parent.mkdir(parents=True, exist_ok=True)
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


class CertificateDiscoveryTests(unittest.TestCase):
    def test_wildcard_matches_one_subdomain_label(self) -> None:
        self.assertTrue(dnsname_matches("*.example.test", "test10.example.test"))
        self.assertFalse(dnsname_matches("*.example.test", "deep.test10.example.test"))
        self.assertFalse(dnsname_matches("*.example.test", "example.test"))
    def test_cloudflare_global_api_key_credentials_are_supported(self) -> None:
        from lucx_post_configurator.certificate_manager import _safe_zone, _certbot_domains

        self.assertEqual(_safe_zone("Example.COM."), "example.com")
        self.assertEqual(
            _certbot_domains("example.com", ["panel.example.com"]),
            ["example.com", "*.example.com"],
        )

    def test_certbot_order_omits_wildcard_covered_subdomains(self) -> None:
        from lucx_post_configurator.certificate_manager import _certbot_domains

        self.assertEqual(
            _certbot_domains(
                "example.com",
                [
                    "panel.example.com",
                    "sub.example.com",
                    "test1.example.com",
                    "deep.api.example.com",
                ],
            ),
            ["example.com", "*.example.com", "deep.api.example.com"],
        )

    def test_certbot_order_does_not_duplicate_zone_names(self) -> None:
        from lucx_post_configurator.certificate_manager import _certbot_domains

        self.assertEqual(
            _certbot_domains("example.com", ["example.com", "*.example.com"]),
            ["example.com", "*.example.com"],
        )

    def test_certbot_order_rejects_domains_outside_zone(self) -> None:
        from lucx_post_configurator.certificate_manager import _certbot_domains
        from lucx_post_configurator.models import ConfigurationError

        with self.assertRaises(ConfigurationError):
            _certbot_domains("example.com", ["other.example.org"])
    def test_selects_longest_lived_covering_wildcard_and_stable_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            acme = root / "root/.acme.sh/example.com_ecc"
            make_certificate(
                acme / "fullchain.cer",
                acme / "example.com.key",
                ["example.com", "*.example.com"],
                90,
            )
            (acme / "example.com.conf").write_text(
                "Le_Domain='*.example.com'\nLe_Alt='example.com'\n",
                encoding="utf-8",
            )
            fs = TargetFS(root)
            candidate = select_certificate(
                fs,
                ["panel.example.com", "sub.example.com", "example.com"],
                Runner(dry_run=True),
            )
            self.assertIsNotNone(candidate)
            assert candidate is not None
            self.assertTrue(candidate.wildcard)
            self.assertEqual(candidate.cert_path, "/root/.acme.sh/example.com_ecc/fullchain.cer")
            self.assertEqual(candidate.key_path, "/root/.acme.sh/example.com_ecc/example.com.key")
            self.assertEqual(candidate.renewal_name, "*.example.com")

    def test_extra_acme_path_is_still_classified_as_acme(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            acme = root / "root/.acme.sh/example.com_ecc"
            make_certificate(
                acme / "fullchain.cer",
                acme / "example.com.key",
                ["*.example.com"],
                90,
            )
            candidate = select_certificate(
                TargetFS(root),
                ["panel.example.com"],
                Runner(dry_run=True),
                extra_cert_paths=["/root/.acme.sh/example.com_ecc/fullchain.cer"],
            )
            self.assertIsNotNone(candidate)
            assert candidate is not None
            self.assertEqual(candidate.source, "acme.sh")

    def test_rejects_certificate_that_does_not_cover_every_domain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            acme = root / "root/.acme.sh/example.com_ecc"
            make_certificate(
                acme / "fullchain.cer",
                acme / "example.com.key",
                ["*.example.com"],
                90,
            )
            candidates = find_certificate_candidates(
                TargetFS(root),
                ["panel.example.com", "other.example.net"],
                Runner(dry_run=True),
            )
            self.assertEqual(candidates, [])

    def test_certbot_live_symlink_path_is_returned_instead_of_archive_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "etc/letsencrypt/archive/example.com"
            live = root / "etc/letsencrypt/live/example.com"
            make_certificate(
                archive / "fullchain1.pem",
                archive / "privkey1.pem",
                ["*.example.com"],
                60,
            )
            live.mkdir(parents=True)
            try:
                os.symlink("../../archive/example.com/fullchain1.pem", live / "fullchain.pem")
                os.symlink("../../archive/example.com/privkey1.pem", live / "privkey.pem")
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            candidate = select_certificate(
                TargetFS(root), ["panel.example.com"], Runner(dry_run=True)
            )
            self.assertIsNotNone(candidate)
            assert candidate is not None
            self.assertEqual(candidate.cert_path, "/etc/letsencrypt/live/example.com/fullchain.pem")
    def test_acme_certificate_in_root_cert_is_discovered_and_classified_as_acme(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cert_dir = root / "root/cert/example.test"
            acme_dir = root / "root/.acme.sh/example.test_ecc"
            acme_dir.mkdir(parents=True, exist_ok=True)
            (acme_dir / "example.test.conf").write_text("Le_Domain='example.test'\nLe_RealFullChainPath='/root/cert/example.test/fullchain.pem'\n")
            make_certificate(
                cert_dir / "fullchain.pem",
                cert_dir / "privkey.pem",
                ["example.test", "*.example.test"],
                60,
            )
            candidates = find_certificate_candidates(
                TargetFS(root),
                ["panel.example.test", "sub.example.test"],
                Runner(dry_run=True),
            )
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].source, "acme.sh")
            self.assertEqual(candidates[0].renewal_name, "example.test")
            self.assertEqual(candidates[0].cert_path, "/root/cert/example.test/fullchain.pem")
            self.assertEqual(candidates[0].key_path, "/root/cert/example.test/privkey.pem")


if __name__ == "__main__":
    unittest.main()
