#!/usr/bin/env python3
"""Проверки репозитория: конфиг, мастер установки, ссылки, даты.

Конфиг: каждый ключ managed-settings.json должен стоять в таблице claude-sandbox/README.md
с тем же значением (для списков — каждый элемент), а не просто упоминаться.

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
    # Строки таблицы README: | `ключ`[, `ключ`] | значение | зачем | источник |
    table = {}
    for line in SETTINGS_DOC.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 2:
            for key in TICK.findall(cells[0]):
                table[key] = cells[1]
    bad = []
    for key in leaf_keys(data):
        value = lookup(data, key)
        if key not in table:
            bad.append(f"{key}: нет строки в таблице")
            continue
        for shown in shown_values(value):
            if shown not in table[key]:
                bad.append(f"{key}: в конфиге {shown}, в README «{table[key][:60]}»")
    if bad:
        fail(f"{SETTINGS_DOC.relative_to(ROOT)} расходится с managed-settings.json:\n      " + "\n      ".join(bad))
    else:
        ok(f"значения всех ключей managed-settings.json совпадают с таблицей {SETTINGS_DOC.relative_to(ROOT)}")


def lookup(data, key):
    for part in key.split("."):
        data = data[part]
    return data


def shown_values(value):
    """Как значение должно быть записано в ячейке: скаляр целиком, список — поэлементно."""
    if not isinstance(value, list):
        return [f"`{json.dumps(value)}`"]
    if not value:
        return ["`[]`"]
    return [f"`{item.get('path') or item.get('name') or json.dumps(item)}`" if isinstance(item, dict)
            else f"`{item}`" for item in value]


def check_shell():
    scripts = sorted(p for p in tracked_files() if p.suffix == ".sh" and p.is_file())
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
            # Пути на машине пользователя и dot-файлы чужих репозиториев (`.mcp.json`) — не ссылки сюда.
            if not ref or ref.startswith(("~", "/", "$")) or (ref.startswith(".") and not ref.startswith(("./", "../"))):
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


def check_results():
    from run import SCHEMA, render, validate
    snapshots = [p for p in tracked_files() if p.name == "raw.json" and
                 p.is_relative_to(ROOT / "results")]
    for path in snapshots:
        try:
            raw = json.loads(path.read_text())
            if raw.get("schema") != SCHEMA:
                print(f"skip  {path.relative_to(ROOT)}: архив schema {raw.get('schema')}, "
                      "текущий редьюсер его не пересчитывает")
                continue
            if validate(raw):
                fail(f"{path.relative_to(ROOT)}: неполный прогон или неожиданные исходы")
            elif path.with_name("matrix.md").read_text() != render(raw):
                fail(f"{path.relative_to(ROOT)}: матрица не соответствует сырым логам")
            else:
                ok(f"{path.relative_to(ROOT)}: исходы и матрица подтверждены сырыми логами")
        except (KeyError, ValueError, OSError) as exc:
            fail(f"{path.relative_to(ROOT)}: {exc}")


def main():
    check_settings()
    check_shell()
    check_refs()
    check_dates_worktree()
    check_results()
    if "--history" in sys.argv:
        check_dates_history()
    print(f"\n{'FAILED' if failures else 'PASSED'}: {len(failures)} проблем(ы)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
