#!/usr/bin/env python3
"""Проверяет публикационный состав на очевидные реальные секреты."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SKIP_PARTS = {".git", "__pycache__", ".reference", "dist", "outputs", "work", ".venv-dev", ".venv", "venv"}
SKIP_FILES = {"task_plan.md", "findings.md", "progress.md"}
TEXT_SUFFIXES = {".md", ".py", ".sh", ".toml", ".json", ".yaml", ".yml", ".txt"}
PATTERNS = (
    ("необезличенный домен", re.compile(r"\b(?:hostname|domain|sni)\s*[=:]\s*['\"](?:[a-z0-9-]+\.)+[a-z]{2,}['\"]", re.I)),
    ("закрытый ключ", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("секрет в командной строке", re.compile(r"(?:-pw|--password|--passwd)(?:=|\s+)(?!secret\b|example\b|<)[^\s$<>{}]+", re.I)),
    ("реальный IPv4", re.compile(r"\b(?:72\.56\.52\.228|89\.19\.223\.185)\b")),
    ("идентификатор подписки", re.compile(r"\b(?:subId|sub_id)\s*[:=]\s*['\"][A-Za-z0-9_-]{12,}['\"]")),
    ("токен API", re.compile(r"\b(?:api[_-]?token|cloudflare[_-]?token)\s*[:=]\s*[A-Za-z0-9_-]{20,}", re.I)),
)


def iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.name in SKIP_FILES or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in SKIP_PARTS for part in path.relative_to(root).parts):
            continue
        yield path


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for path in iter_files(root):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            findings.append(f"{path}: файл не является UTF-8 текстом")
            continue
        for line_number, line in enumerate(lines, 1):
            for label, pattern in PATTERNS:
                if pattern.search(line) and "example" not in line.lower():
                    findings.append(f"{path}:{line_number}: {label}")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Проверка репозитория на секреты перед публикацией")
    parser.add_argument("root", nargs="?", default=".", help="корень репозитория")
    args = parser.parse_args(argv)
    findings = scan(Path(args.root).resolve())
    if findings:
        print("Проверка секретов не пройдена:")
        print("\n".join(findings))
        return 1
    print("Проверка секретов пройдена: совпадений не найдено.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
