from __future__ import annotations

import unittest

from lucx_post_configurator.progress import ProgressDisplay


class ProgressDisplayTests(unittest.TestCase):
    def test_known_work_prints_real_fraction_and_percentage(self) -> None:
        output: list[str] = []
        with ProgressDisplay(
            output.append,
            "Проверка",
            total=9,
            interval=3600,
            clock=lambda: 100.0,
        ) as progress:
            progress.phase(6, "Проверка HAProxy")

        rendered = "\n".join(output)
        self.assertIn("6/9", rendered)
        self.assertIn("67%", rendered)
        self.assertIn("Проверка HAProxy", rendered)
        self.assertIn("завершено", rendered)

    def test_unknown_work_has_heartbeat_and_elapsed_but_no_percentage(self) -> None:
        output: list[str] = []
        with ProgressDisplay(
            output.append,
            "Выпуск сертификата",
            interval=3600,
            clock=lambda: 200.0,
        ):
            pass

        rendered = "\n".join(output)
        self.assertIn("Выпуск сертификата", rendered)
        self.assertIn("прошло 00:00", rendered)
        self.assertNotIn("%", rendered)

    def test_exception_is_reported_and_reraised(self) -> None:
        output: list[str] = []

        def fail() -> None:
            raise RuntimeError("secret detail")

        with self.assertRaises(RuntimeError):
            ProgressDisplay(
                output.append,
                "Операция",
                interval=3600,
                clock=lambda: 300.0,
            ).run(fail)

        rendered = "\n".join(output)
        self.assertIn("ошибка", rendered)
        self.assertNotIn("secret detail", rendered)


if __name__ == "__main__":
    unittest.main()
