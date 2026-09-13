from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.check_documentation import check
from tools.scan_secrets import scan


class ReleaseToolTests(unittest.TestCase):
    def test_secret_scan_excludes_local_development_environments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (".venv-dev", ".venv", "venv", "work"):
                dependency = root / name / "vendor.py"
                dependency.parent.mkdir()
                dependency.write_text("tool --" + "password " + "x" * 24, encoding="utf-8")
            self.assertEqual(scan(root), [])

    def test_secret_scan_rejects_operational_domain_literals_without_printing_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            domain = "private" + ".invalid"
            (root / "probe.py").write_text('hostname = "' + domain + '"\n', encoding="utf-8")
            result = scan(root)
            self.assertTrue(result)
            self.assertNotIn(domain, "\n".join(result))

    def test_secret_scan_accepts_synthetic_examples_and_rejects_real_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe = root / "safe.md"
            safe.write_text(
                "password=example\nsubId=\"subscription-example\"\n",
                encoding="utf-8",
            )
            self.assertEqual(scan(root), [])

            unsafe = root / "unsafe.py"
            flag = "-" + "pw"
            unsafe.write_text("ssh " + flag + " " + ("x" * 24) + "\n", encoding="utf-8")
            self.assertTrue(scan(root))

    def test_documentation_checker_accepts_local_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "README.md").write_text(
                "# Проект\n\n[Документ](docs.md)\n", encoding="utf-8"
            )
            (root / "docs.md").write_text("# Документ\n", encoding="utf-8")
            (root / "docs" / "PROJECT_DEVELOPMENT_CONTEXT_RU.md").write_text(
                "\n".join(
                    [
                        "## Паспорт проекта",
                        "## Цели и границы",
                        "## Неподвижные инварианты",
                        "## Карта репозитория",
                        "## Жизненный цикл применения",
                        "## Подписки",
                        "## Обновление LucX и восстановление",
                        "## Тестовые ворота",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(check(root), [])

    def test_documentation_checker_requires_complete_development_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            context = root / "docs" / "PROJECT_DEVELOPMENT_CONTEXT_RU.md"
            context.write_text(
                "\n".join(
                    [
                        "## Паспорт проекта",
                        "## Цели и границы",
                        "## Неподвижные инварианты",
                        "## Карта репозитория",
                        "## Жизненный цикл применения",
                        "## Подписки",
                        "## Обновление LucX и восстановление",
                        "## Тестовые ворота",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(check(root), [])

            context.write_text("# Неполный документ\n", encoding="utf-8")
            self.assertTrue(check(root))


if __name__ == "__main__":
    unittest.main()
