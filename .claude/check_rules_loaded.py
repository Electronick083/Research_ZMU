#!/usr/bin/env python3
"""Проверка, что все файлы правил проекта подключены импортом в CLAUDE.md.

Запускается хуком SessionStart. Молчит, когда всё в порядке; при расхождении
печатает JSON с предупреждением, которое Claude Code добавляет в контекст.

Правилом считается файл `.claude/memory/*.md` с `type: feedback` во frontmatter.
Такой файл должен быть подключён строкой `@.claude/memory/<имя>.md` в CLAUDE.md,
иначе его текст не попадёт в контекст новой сессии — останется только строка
в индексе MEMORY.md, то есть формулировка без разбора.
"""

import json
import os
import re
import sys
from pathlib import Path


def project_dir() -> Path:
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env and Path(env).is_dir():
        return Path(env)
    # .claude/check_rules_loaded.py -> корень проекта
    return Path(__file__).resolve().parent.parent


def imports_of(claude_md: Path) -> set[str]:
    """Пути из строк `@путь`. Импорты внутри блоков кода парсер Claude Code
    пропускает — здесь та же логика, иначе проверка соврёт."""
    if not claude_md.is_file():
        return set()
    text = claude_md.read_text(encoding="utf-8")
    text = re.sub(r"^```.*?^```", "", text, flags=re.S | re.M)  # fenced blocks
    text = re.sub(r"`[^`\n]*`", "", text)                        # code spans
    return {m.group(1) for m in re.finditer(r"^@(\S+)", text, flags=re.M)}


def is_rule_file(path: Path) -> bool:
    head = path.read_text(encoding="utf-8")[:600]
    return re.search(r"^\s*type:\s*feedback\s*$", head, flags=re.M) is not None


def main() -> int:
    root = project_dir()
    claude_md = root / "CLAUDE.md"
    memory = root / ".claude" / "memory"
    if not memory.is_dir():
        return 0

    imported = imports_of(claude_md)
    # removeprefix, а НЕ lstrip: lstrip("./") срезает любые символы из набора и
    # превращает ".claude/..." в "claude/...", давая ложные срабатывания.
    imported_norm = {p.replace("\\", "/").removeprefix("./") for p in imported}

    problems: list[str] = []

    missing = []
    for f in sorted(memory.glob("*.md")):
        if f.name == "MEMORY.md" or not is_rule_file(f):
            continue
        rel = f".claude/memory/{f.name}"
        if rel not in imported_norm:
            missing.append(rel)
    if missing:
        problems.append(
            "НЕ ПОДКЛЮЧЕНЫ В CLAUDE.md (правила есть на диске, но в контекст не попали):\n"
            + "\n".join(f"  - {m}" for m in missing)
            + "\nПрочитать их инструментом Read ПРЯМО СЕЙЧАС и добавить строку "
              "`@<путь>` в CLAUDE.md."
        )

    broken = [p for p in sorted(imported) if not (root / p).is_file()]
    if broken:
        problems.append(
            "БИТЫЕ ИМПОРТЫ в CLAUDE.md (файла нет на диске, импорт молча не сработал):\n"
            + "\n".join(f"  - {b}" for b in broken)
            + "\nПоправить путь в CLAUDE.md."
        )

    if not claude_md.is_file():
        problems.append(
            "CLAUDE.md В КОРНЕ ПРОЕКТА ОТСУТСТВУЕТ — правила проекта в этой сессии "
            "не загружены. Прочитать .claude/memory/MEMORY.md и файлы правил вручную."
        )

    if not problems:
        return 0

    text = "⚠️ ПРАВИЛА ПРОЕКТА ЗАГРУЖЕНЫ НЕ ПОЛНОСТЬЮ\n\n" + "\n\n".join(problems)
    json.dump(
        {
            "systemMessage": "Правила проекта загружены не полностью — см. контекст",
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": text,
            },
        },
        sys.stdout,
        ensure_ascii=False,
    )
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.exit(main())
