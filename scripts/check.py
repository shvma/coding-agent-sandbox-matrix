#!/usr/bin/env python3
"""Проверки репозитория: конфиг, мастер установки, ссылки, даты.

Запуск: python3 scripts/check.py           — рабочее дерево
        python3 scripts/check.py --history — плюс даты в каждом коммите истории
Без ShellCheck в PATH проверка ShellCheck пропускается; REQUIRE_SHELLCHECK=1 делает её обязательной (так в CI).
"""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETTINGS = ROOT / "claude-sandbox" / "managed-settings.json"
SETTINGS_DOC = ROOT / "claude-sandbox" / "README.md"
DATE = re.compile(r"\b(20\d\d-[01]\d-[0-3]\d)\b")
# Ссылки на файлы этого репозитория: `путь.ext` в обратных кавычках и [текст](путь).
REF_EXT = (".md", ".json", ".sh", ".py", ".yml", ".yaml")
TICK = re.compile(r"`([^`\s]+)`")
LINK = re.compile(r"\]\(([^)\s]+)\)")

failures = []


def fail(msg):
    failures.append(msg)
    print(f"FAIL  {msg}")


def ok(msg):
    print(f"ok    {msg}")


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True).stdout


def leaf_keys(node, prefix=""):
    """Пути ключей до листа; содержимое списков не раскрываем — это значения, а не ключи."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from leaf_keys(v, f"{prefix}.{k}" if prefix else k)
    else:
        yield prefix


def check_settings():
    try:
        data = json.loads(SETTINGS.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"{SETTINGS.relative_to(ROOT)}: невалидный JSON: {e}")
        return
    ok(f"{SETTINGS.relative_to(ROOT)}: валидный JSON")
    doc = SETTINGS_DOC.read_text(encoding="utf-8")
    missing = [k for k in leaf_keys(data) if f"`{k}`" not in doc]
    if missing:
        fail(f"ключи без описания в {SETTINGS_DOC.relative_to(ROOT)}: {', '.join(missing)}")
    else:
        ok(f"каждый ключ managed-settings.json описан в {SETTINGS_DOC.relative_to(ROOT)}")


def check_shell():
    scripts = sorted(ROOT.rglob("*.sh"))
    for s in scripts:
        r = subprocess.run(["bash", "-n", str(s)], capture_output=True, text=True)
        if r.returncode:
            fail(f"{s.relative_to(ROOT)}: bash -n: {r.stderr.strip()}")
        else:
            ok(f"{s.relative_to(ROOT)}: bash -n")
    if not shutil.which("shellcheck"):
        if os.environ.get("REQUIRE_SHELLCHECK") == "1":
            fail("ShellCheck не найден, а REQUIRE_SHELLCHECK=1")
        else:
            print("skip  ShellCheck не найден в PATH")
        return
    r = subprocess.run(["shellcheck", *map(str, scripts)], capture_output=True, text=True)
    if r.returncode:
        fail(f"ShellCheck:\n{r.stdout.strip()}")
    else:
        ok("ShellCheck: замечаний нет")


def tracked_files():
    return [ROOT / p for p in git("ls-files", "--cached", "--others", "--exclude-standard").splitlines()]


def check_refs():
    bad = []
    for md in (p for p in tracked_files() if p.suffix == ".md" and p.exists()):
        text = md.read_text(encoding="utf-8")
        refs = [r for r in TICK.findall(text) if r.endswith(REF_EXT)]
        refs += [r.split("#")[0] for r in LINK.findall(text) if not re.match(r"[a-z]+:", r)]
        for ref in refs:
            if not ref or ref.startswith(("~", "/", "$")):
                continue
            if not ((md.parent / ref).exists() or (ROOT / ref).exists()):
                bad.append(f"{md.relative_to(ROOT)} → {ref}")
    if bad:
        fail("ссылки на несуществующие файлы:\n      " + "\n      ".join(bad))
    else:
        ok("ссылки на файлы репозитория ведут на существующие файлы")


def late_dates(commit_date, files):
    """Даты в тексте позже даты коммита: признак того, что дата коммита не соответствует содержимому."""
    out = []
    for name, text in files:
        for d in set(DATE.findall(text)):
            if d > commit_date:
                out.append(f"{name}: {d}")
    return sorted(out)


def check_dates_worktree():
    head = git("log", "-1", "--format=%cs").strip()
    files = []
    for p in tracked_files():
        if p.exists() and p.is_file():
            try:
                files.append((str(p.relative_to(ROOT)), p.read_text(encoding="utf-8")))
            except UnicodeDecodeError:
                pass
    late = late_dates(max(head, today()), files) if uncommitted() else late_dates(head, files)
    if late:
        fail("даты позже даты коммита:\n      " + "\n      ".join(late))
    else:
        ok(f"даты в тексте не позже {head if not uncommitted() else 'сегодняшнего дня'}")


def check_dates_history():
    bad = []
    for line in git("log", "--format=%H %cs").splitlines():
        sha, cdate = line.split()
        files = []
        for name in git("ls-tree", "-r", "--name-only", sha).splitlines():
            try:
                files.append((name, git("show", f"{sha}:{name}")))
            except (subprocess.CalledProcessError, UnicodeDecodeError):
                pass
        bad += [f"{sha[:7]} ({cdate}) {x}" for x in late_dates(cdate, files)]
    if bad:
        fail("в истории коммит содержит даты позже своей даты:\n      " + "\n      ".join(bad))
    else:
        ok("история: ни один коммит не содержит дат позже своей даты")


def uncommitted():
    return bool(git("status", "--porcelain").strip())


def today():
    from datetime import date
    return date.today().isoformat()


def main():
    check_settings()
    check_shell()
    check_refs()
    check_dates_worktree()
    if "--history" in sys.argv:
        check_dates_history()
    print(f"\n{'FAILED' if failures else 'PASSED'}: {len(failures)} проблем(ы)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
