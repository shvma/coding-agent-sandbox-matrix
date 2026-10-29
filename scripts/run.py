#!/usr/bin/env python3
"""Run real SRT probes, retain raw output and derive the matrix from that output."""
import argparse
import hashlib
import http.server
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IDS = ("workspace_write", "credential_file", "credential_env", "outside_write",
       "denied_http", "direct_tcp", "allowed_channel")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(command, cwd, env, timeout=45):
    try:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            return {"command": command, "returncode": None, "stdout": stdout,
                    "stderr": stderr + "\nprocess group timed out and was terminated"}
        return {"command": command, "returncode": process.returncode, "stdout": stdout, "stderr": stderr}
    except OSError as exc:
        return {"command": command, "returncode": None, "stdout": "", "stderr": str(exc)}


def rows(raw):
    """Rebuild exclusively from captured child output and receiver observations."""
    output = []
    for execution in raw["executions"]:
        parsed = {}
        duplicates = set()
        for line in execution["stdout"].splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and row.get("id") in IDS:
                if row["id"] in parsed:
                    duplicates.add(row["id"])
                parsed[row["id"]] = row
        for name in IDS:
            row = dict(parsed.get(name, {"id": name, "outcome": "error",
                                        "detail": "probe did not finish"}))
            if execution["returncode"] != 0:
                row.update(outcome="error", detail="runner failed; see stderr")
            if name in duplicates:
                row.update(outcome="error", detail="duplicate probe evidence")
            if name == "outside_write" and "outside_file_exists" in execution:
                exists = execution["outside_file_exists"]
                if (row["outcome"] == "allowed" and not exists) or (row["outcome"] == "blocked" and exists):
                    row.update(outcome="error", detail="outside file contradicts probe result")
            # A successful HTTP client alone is insufficient: check the collector.
            if name in ("allowed_channel", "denied_http"):
                receiver = "allowed" if name == "allowed_channel" else "denied"
                received = any(e["receiver"] == receiver and
                               e["profile"] == execution["profile"] and
                               e["path"] == "/" + raw["canary"] for e in raw["receipts"])
                if received:
                    row["outcome"] = "allowed"
                elif row["outcome"] == "allowed":
                    row.update(outcome="error", detail="collector did not receive marker")
            if name == "direct_tcp" and any(e["receiver"] == "denied" and
                    e["profile"] == execution["profile"] and e["path"] == "/direct" for e in raw["receipts"]):
                row["outcome"] = "allowed"
            row["profile"] = execution["profile"]
            output.append(row)
    return output


def render(raw):
    measurements = rows(raw)
    profiles = [e["profile"] for e in raw["executions"]]
    lookup = {(r["profile"], r["id"]): r["outcome"] for r in measurements}
    scope = ("SRT CLI и примитивы ОС; Claude Code и managed settings не проверены."
             if raw["scope"] == "srt-cli" else
             "OpenShell CLI, Docker driver, Landlock hard_requirement; без модели и IDE.")
    lines = ["# Измеренная матрица", "", f"UTC: {raw['started_at']}", "",
             "Уровень: " + scope,
             "`allowed` = действие удалось; `blocked` = явный отказ; `error` ≠ защита.", "",
             "| Проверка | " + " | ".join(profiles) + " |",
             "|---|" + "---|" * len(profiles)]
    lines += ["| " + name + " | " + " | ".join(lookup[(p, name)] for p in profiles) + " |"
              for name in IDS]
    lines += ["", "Инъекция через правила репозитория: **not_run** (нужен агент с моделью).", ""]
    if raw["scope"] == "openshell":
        lines += ["Профиль offline: **not_run** как проверка запрета: без network rules в этом стенде",
                  "возникает ошибка DNS, которую нельзя засчитать как явный отказ политики.",
                  "В hardened переменная не передаётся при создании workload; это не фильтр env внутри OpenShell.", ""]
    if raw.get("error"):
        lines += ["**Стенд не завершил прогон:** " + raw["error"].replace("\n", " "), ""]
    return "\n".join(lines)


def validate(raw):
    expected = {
        "control": dict.fromkeys(IDS, "allowed"),
        "baseline": {name: "allowed" if name in
                     ("workspace_write", "credential_file", "credential_env", "allowed_channel")
                     else "blocked" for name in IDS},
        "hardened": {name: "allowed" if name in ("workspace_write", "allowed_channel")
                     else "blocked" for name in IDS},
        "offline": {name: "allowed" if name == "workspace_write" else "blocked" for name in IDS},
    }
    problems = []
    if raw.get("scope") == "openshell":
        expected.pop("offline")
    if raw.get("error"):
        problems.append({"id": "setup", "detail": raw["error"]})
    if any(r.get("returncode") != 0 for r in raw.get("cleanup", [])):
        problems.append({"id": "cleanup", "detail": "resource cleanup failed"})
    for execution in raw["executions"]:
        names = []
        for line in execution.get("stdout", "").splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and value.get("id") in IDS:
                names.append(value["id"])
        if len(set(names)) != len(names):
            problems.append({"id": "duplicates", "detail": execution["profile"]})
    if sorted(e["profile"] for e in raw["executions"]) != sorted(expected):
        problems.append({"id": "profiles", "detail": "missing, duplicate or unexpected profile"})
    for row in rows(raw):
        if row["profile"] not in expected or row["outcome"] != expected[row["profile"]][row["id"]]:
            problems.append(row)
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--render", type=Path, help="rebuild matrix from a saved raw JSON")
    args = parser.parse_args()
    if args.render:
        raw = json.loads(args.render.read_text())
        print(render(raw), end="")
        return bool(validate(raw))
    srt = ROOT / "node_modules/.bin/srt"
    if not srt.exists():
        parser.error("run npm ci --ignore-scripts first")
    started = datetime.now(timezone.utc)
    output = args.output or ROOT / "results" / started.strftime("local-%Y%m%dT%H%M%SZ")
    output.mkdir(parents=True, exist_ok=False)
    # Never copy developer tokens, shell startup files or proxy credentials.
    env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "SYSTEMROOT") if k in os.environ}
    env.update(LANG="C.UTF-8", LC_ALL="C", NO_COLOR="1")
    raw = {"schema": 1, "started_at": started.isoformat(), "scope": "srt-cli",
           "system": platform.platform(), "machine": platform.machine(),
           "python": sys.version, "srt": execute([str(srt), "--version"], ROOT, env),
           "node": execute(["node", "--version"], ROOT, env),
           "probe_sha256": sha(ROOT / "scripts/probe.py"),
           "runner_sha256": sha(Path(__file__).resolve()),
           "lock_sha256": sha(ROOT / "package-lock.json"),
           "canary": "SANDBOX_MATRIX_SYNTHETIC_ONLY", "executions": [], "receipts": []}
    active = {"profile": "control"}

    def collector(label):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                raw["receipts"].append({"receiver": label, "profile": active["profile"],
                                        "path": self.path})
                self.send_response(200)
                self.end_headers()
                self.wfile.write(raw["canary"].encode())

            def log_message(self, *_):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    allowed, denied = collector("allowed"), collector("denied")
    try:
        # /tmp is implicitly writable in many sandboxes. Put the outside-write
        # fixture in a dedicated home subdirectory so it really tests a boundary.
        with tempfile.TemporaryDirectory(prefix=".sandbox-matrix-", dir=Path.home()) as tmp:
            base = Path(tmp).resolve()
            workspace = base / "workspace"
            workspace.mkdir()
            private = base / "private-canary"
            private.write_text(raw["canary"])
            outside = base / "outside-canary"
            payload = workspace / "probe.py"
            shutil.copy(ROOT / "scripts/probe.py", payload)
            env["SANDBOX_MATRIX_TOKEN"] = raw["canary"]
            command = [sys.executable, str(payload), str(workspace), str(private), str(outside),
                       f"http://127.0.0.1:{allowed.server_port}",
                       f"http://127.0.0.1:{denied.server_port}", raw["canary"]]
            for profile in ("control", "baseline", "hardened", "offline"):
                active["profile"] = profile
                outside.unlink(missing_ok=True)
                config = {"network": {"allowedDomains":
                          [] if profile == "offline" else [f"127.0.0.1:{allowed.server_port}"],
                          "deniedDomains": []},
                          "filesystem": {"denyRead": [], "allowWrite": [str(workspace)],
                                         "denyWrite": []}}
                if profile in ("hardened", "offline"):
                    config["filesystem"]["denyRead"] = [str(private)]
                    config["credentials"] = {"envVars": [{"name": "SANDBOX_MATRIX_TOKEN", "mode": "deny"}]}
                config_path = base / (profile + ".json")
                config_path.write_text(json.dumps(config))
                invocation = command if profile == "control" else [str(srt), "--settings", str(config_path), *command]
                execution = execute(invocation, workspace, env)
                execution.update(profile=profile, config=config, outside_file_exists=outside.exists())
                raw["executions"].append(execution)
                print(profile + ": " + str(execution["returncode"]), flush=True)
    finally:
        allowed.shutdown()
        denied.shutdown()
        allowed.server_close()
        denied.server_close()
    (output / "raw.json").write_text(json.dumps(raw, indent=2) + "\n")
    (output / "matrix.md").write_text(render(raw))
    failures = validate(raw)
    print(f"{output}: {len(failures)} unexpected outcomes")
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
