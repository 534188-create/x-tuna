#!/usr/bin/env python3
"""Проверяет UTF-8 Markdown и локальные ссылки документации."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


LINK_RE = re.compile(r"\]\(([^)#]+)(?:#[^)]+)?\)")
ENGLISH_HEADINGS = re.compile(r"^#{1,6}\s+(?:The |This |Architecture|Development|Acceptance|Target |Global )", re.I)
CONTEXT_PATH = "docs/PROJECT_DEVELOPMENT_CONTEXT_RU.md"


def check(root: Path) -> list[str]:
    errors: list[str] = []
    context = root / CONTEXT_PATH
    if not context.is_file():
        errors.append(f"{context}: отсутствует основной контекст разработки")
    else:
        context_text = context.read_text(encoding="utf-8")
        required_sections = (
            "## Паспорт проекта",
            "## Цели и границы",
            "## Неподвижные инварианты",
            "## Карта репозитория",
            "## Жизненный цикл применения",
            "## Подписки",
            "## Обновление LucX и восстановление",
            "## Тестовые ворота",
        )
        for section in required_sections:
            if section not in context_text:
                errors.append(f"{context}: отсутствует раздел: {section}")
    for path in sorted(root.rglob("*.md")):
        if any(part in {".git", "__pycache__", ".reference", "dist", "outputs", "work", "superpowers"} for part in path.relative_to(root).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"{path}: не UTF-8")
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            if ENGLISH_HEADINGS.search(line):
                errors.append(f"{path}:{line_number}: англоязычный заголовок")
            for target in LINK_RE.findall(line):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                target_path = (path.parent / target).resolve()
                if not target_path.exists():
                    errors.append(f"{path}:{line_number}: ссылка не найдена: {target}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Проверка русской документации и локальных ссылок")
    parser.add_argument("root", nargs="?", default=".", help="корень репозитория")
    args = parser.parse_args(argv)
    errors = check(Path(args.root).resolve())
    if errors:
        print("Проверка документации не пройдена:")
        print("\n".join(errors))
        return 1
    print("Проверка документации пройдена.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
