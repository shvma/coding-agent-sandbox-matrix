#!/usr/bin/env python3
"""Run real SRT probes, retain raw output and derive the matrix from that output.

Exit code: 0 — outcomes match the stated policy; 2 — findings (an outcome
differs from the policy expectation, recorded in the matrix); 1 — the stand
itself failed (error outcomes, failed control, setup or cleanup failure).
"""
import argparse
import hashlib
import http.server
import json
import os
import platform
import secrets
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from probe import DEFERRED

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = 2
NETWORK = ("denied_http", "direct_tcp", "dns_udp", "unix_socket", "allowed_channel", "exfil_secret")
FILES = ("workspace_write", "outside_write", *DEFERRED)
IDS = ("workspace_write", "credential_file", "credential_env", "outside_write",
       "denied_http", "direct_tcp", "dns_udp", "unix_socket", "allowed_channel",
       "exfil_secret", *DEFERRED)
# Errors after which only the receiver can tell whether data left: a refused
# connection in a private network namespace, a dropped datagram, a timeout,
# a datagram the kernel refused to address (EDESTADDRREQ in OpenShell).
# Name-resolution errors are not here: the receiver was never addressed.
UNDELIVERED = ("ECONNREFUSED", "ENETUNREACH", "EHOSTUNREACH", "ETIMEDOUT", "EDESTADDRREQ")

A, B = "allowed", "blocked"


def expectations(scope):
    """Policy expectation per profile. Sources are cited in README.md."""
    srt = {
        # SRT's mandatory deny list covers .git/hooks and .mcp.json, but not
        # .claude/settings.json (Claude Code adds that itself) or build files.
        "baseline": dict(workspace_write=A, credential_file=A, credential_env=A, outside_write=B,
                         denied_http=B, direct_tcp=B, dns_udp=B, unix_socket=B, allowed_channel=A,
                         exfil_secret=A, git_hook=B, claude_settings=A, mcp_config=B, makefile=A,
                         npm_script=A, envrc=A, precommit_config=A),
    }
    if scope == "openshell":
        srt["baseline"].update(unix_socket=None, git_hook=A, mcp_config=A)
    base = srt["baseline"]
    hardened = dict(base, credential_file=B, credential_env=B, exfil_secret=B)
    result = {"control": {k: (None if base[k] is None else A) for k in IDS},
              "baseline": base, "hardened": hardened}
    if scope == "srt-cli":
        result["offline"] = dict(hardened, allowed_channel=B)
    return result


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text_sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


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


def redact(text):
    """Keep host paths out of published artifacts; nothing else is changed."""
    return text.replace(str(ROOT), "$REPO").replace(str(Path.home()), "$HOME")


def write_outputs(output, raw):
    """Write redacted raw JSON, then render the matrix from what was written."""
    (output / "raw.json").write_text(redact(json.dumps(raw, indent=2)) + "\n")
    saved = json.loads((output / "raw.json").read_text())
    (output / "matrix.md").write_text(render(saved))
    return saved


def parse(execution):
    meta, parsed, duplicates = {}, {}, set()
    for line in execution.get("stdout", "").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        if row.get("id") == "meta":
            meta = row
        elif row.get("id") in IDS:
            if row["id"] in parsed:
                duplicates.add(row["id"])
            parsed[row["id"]] = row
    return meta, parsed, duplicates


def expected_receipt(name, meta, canary):
    nonce = meta.get("nonce", "")
    return {"denied_http": ("denied", "/nonce/" + nonce), "direct_tcp": ("denied", "/direct/" + nonce),
            "dns_udp": ("udp", nonce + ".exfil.test"), "unix_socket": ("unix", "unix/" + nonce),
            "allowed_channel": ("allowed", "/nonce/" + nonce),
            "exfil_secret": ("allowed", "/secret/" + canary)}[name]


def expected_content(name, meta):
    return meta.get("nonce", "") if name in ("workspace_write", "outside_write") else DEFERRED[name][1]


def rows(raw):
    """Rebuild exclusively from captured child output, target state and receivers."""
    output = []
    control_delivered = set()
    for execution in raw["executions"]:
        meta, parsed, duplicates = parse(execution)
        not_run = execution.get("not_run", {})
        for name in IDS:
            if name in not_run:
                output.append({"id": name, "profile": execution["profile"], "outcome": "not_run",
                               "detail": not_run[name]})
                continue
            row = dict(parsed.get(name, {"id": name, "outcome": "error", "detail": "probe did not finish"}))
            if execution["returncode"] != 0:
                row.update(outcome="error", detail="runner failed; see stderr")
            elif not meta.get("nonce"):
                row.update(outcome="error", detail="probe did not report its nonce")
            if name in duplicates:
                row.update(outcome="error", detail="duplicate probe evidence")
            if row["outcome"] != "error" and name in ("credential_file", "credential_env"):
                if row["outcome"] == "allowed" and row.get("sha256") != text_sha(raw["canary"]):
                    row.update(outcome="error", detail="value read differs from the canary")
            if row["outcome"] != "error" and name in FILES:
                # The state of the target decides, not the probe's own report.
                target = execution.get("targets", {}).get(name)
                if target is None:
                    row.update(outcome="error", detail="no target-state observation")
                elif target["exists"] and target.get("sha256") == text_sha(expected_content(name, meta)):
                    if row["outcome"] != "allowed":
                        row.update(outcome="allowed", detail="target file written despite reported denial")
                elif target["exists"]:
                    row.update(outcome="error", detail="target exists with unexpected content")
                elif row["outcome"] == "allowed":
                    row.update(outcome="error", detail="probe reported a write the target does not show")
            if row["outcome"] != "error" and name in NETWORK:
                receiver, path = expected_receipt(name, meta, raw["canary"])
                received = any(e["receiver"] == receiver and e["profile"] == execution["profile"] and
                               e["path"] == path for e in raw["receipts"])
                if received:
                    row["outcome"] = "allowed"
                    if execution["profile"] == "control":
                        control_delivered.add(name)
                elif row["outcome"] == "allowed":
                    row.update(outcome="error", detail="collector did not receive marker")
            if (row["outcome"] == "error" and name in NETWORK and row.get("errno") in UNDELIVERED and
                    name in control_delivered and execution["profile"] != "control"):
                # The same receiver got the control's datagram/connection; this one did not arrive.
                row.update(outcome="blocked", detail="not delivered to receiver (" + row.get("detail", "") + ")")
            row["profile"] = execution["profile"]
            output.append(row)
    return output


def assess(raw):
    """Split deviations: stand errors (the measurement is invalid) vs findings."""
    expected = expectations(raw.get("scope"))
    errors, findings = [], []
    if raw.get("schema") != SCHEMA:
        errors.append({"id": "schema", "detail": f"expected schema {SCHEMA}"})
    if raw.get("error"):
        errors.append({"id": "setup", "detail": raw["error"]})
    if any(r.get("returncode") != 0 for r in raw.get("cleanup", [])):
        errors.append({"id": "cleanup", "detail": "resource cleanup failed or was not confirmed"})
    if sorted(e["profile"] for e in raw["executions"]) != sorted(expected):
        errors.append({"id": "profiles", "detail": "missing, duplicate or unexpected profile"})
    for row in rows(raw):
        want = expected.get(row["profile"], {}).get(row["id"], "missing")
        if row["outcome"] == "error" or want == "missing":
            errors.append(row)
        elif row["outcome"] == "not_run" or want is None:
            if row["outcome"] != "not_run":
                errors.append(dict(row, detail="ran although the stand marks it not_run"))
        elif row["outcome"] != want:
            if row["profile"] == "control":
                errors.append(dict(row, detail="control did not succeed; the test is invalid"))
            else:
                findings.append(dict(row, expected=want,
                                     kind="leak" if row["outcome"] == "allowed" else "overblock"))
    return errors, findings


def validate(raw):
    return assess(raw)[0]


SCOPE = {
    "srt-cli": [
        "Граница: процесс на хосте под SRT CLI (macOS — Seatbelt; Linux — bubblewrap,",
        "отдельное сетевое пространство имён, seccomp). Claude Code и managed settings не проверены.",
        "Канарейки: файл в домашнем каталоге хоста и переменная окружения процесса.",
        "control: тот же процесс на хосте без песочницы.",
    ],
    "openshell": [
        "Граница: workload-контейнер OpenShell (Docker driver) в Linux VM, Landlock hard_requirement,",
        "сетевой прокси OpenShell; без модели и IDE.",
        "Канарейки: файл, записанный в образ при сборке; переменная передаётся через `--env` только",
        "в control и baseline — это выбор раннера, а не механизм песочницы.",
        "control: `docker run` того же образа — это уже контейнерная изоляция, а не «без защиты».",
    ],
}


def render(raw):
    measurements = rows(raw)
    errors, findings = assess(raw)
    profiles = [e["profile"] for e in raw["executions"]]
    lookup = {(r["profile"], r["id"]): r["outcome"] for r in measurements}
    lines = ["# Измеренная матрица", "", f"UTC: {raw['started_at']}", "",
             f"Система: {raw.get('system', 'не записана')}", "",
             *SCOPE[raw["scope"]], "",
             "`allowed` = действие удалось; `blocked` = явный отказ или приёмник ничего не получил,",
             "хотя от control получил; `error` ≠ защита; `not_run` = в этом варианте не испытывалось.", "",
             "| Проверка | " + " | ".join(profiles) + " |",
             "|---|" + "---|" * len(profiles)]
    lines += ["| " + name + " | " + " | ".join(lookup.get((p, name), "error") for p in profiles) + " |"
              for name in IDS]
    lines += [""]
    hooks = [f"{e['profile']} — " + {True: "да", False: "нет", None: "хук не записан"}[e["hook_ran"]]
             for e in raw["executions"] if "hook_ran" in e]
    if hooks:
        lines += ["`git commit` вне песочницы исполнил хук из рабочего каталога: " + "; ".join(hooks) + ".", ""]
    not_run = sorted({f"{r['id']}: {r['detail']}" for r in measurements if r["outcome"] == "not_run"})
    if not_run:
        lines += ["Не испытывалось в этом варианте: " + "; ".join(not_run) + ".", ""]
    lines += ["Инъекция через правила репозитория: **not_run** (нужен агент с моделью).", ""]
    if raw.get("not_run", {}).get("offline"):
        lines += ["Профиль offline: **not_run** — " + raw["not_run"]["offline"] + ".", ""]
    lines += ["## Находки: исход не совпал с ожиданием политики", ""]
    lines += [f"- {f['profile']} / {f['id']}: ожидалось `{f['expected']}`, получено `{f['outcome']}` "
              f"({'утечка' if f['kind'] == 'leak' else 'лишний отказ'})" for f in findings] or ["Нет."]
    lines += ["", "## Ошибки стенда", ""]
    lines += [f"- {e.get('profile', '-')} / {e['id']}: {str(e.get('detail', e.get('outcome')))[:200]}"
              for e in errors] or ["Нет."]
    return "\n".join(line.replace("\n", " ") for line in lines) + "\n"


def summary(raw, output):
    errors, findings = assess(raw)
    print(f"{redact(str(output))}: {len(errors)} stand errors, {len(findings)} findings", flush=True)
    return 1 if errors else 2 if findings else 0


class Collectors:
    """Loopback HTTP, UDP and Unix-socket receivers; each logs what arrived."""

    def __init__(self, raw, active, unix_path=None):
        self.raw, self.active, self.servers = raw, active, []
        self.allowed = self.http("allowed")
        self.denied = self.http("denied")
        self.udp = self.serve(socketserver.ThreadingUDPServer(("127.0.0.1", 0), self.udp_handler()))
        if unix_path:
            self.serve(socketserver.ThreadingUnixStreamServer(str(unix_path), self.unix_handler()))

    def log(self, receiver, path):
        self.raw["receipts"].append({"receiver": receiver, "profile": self.active["profile"], "path": path})

    def serve(self, server):
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.servers.append(server)
        return server

    def http(self, label):
        collectors = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                collectors.log(label, self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_):
                pass
        return self.serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler))

    def udp_handler(self):
        collectors = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                collectors.log("udp", qname(data))
                sock.sendto(data[:2] + b"\x81\x83" + data[4:], self.client_address)
        return Handler

    def unix_handler(self):
        collectors = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                collectors.log("unix", self.rfile.readline(200).decode(errors="replace").strip())
                self.wfile.write(b"ok")
        return Handler

    def close(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()


def qname(packet):
    labels, i = [], 12
    while i < len(packet) and packet[i]:
        labels.append(packet[i + 1:i + 1 + packet[i]].decode(errors="replace"))
        i += 1 + packet[i]
    return ".".join(labels)


def observe(path):
    if not path.is_file():
        return {"exists": path.exists()}
    return {"exists": True, "sha256": sha(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--render", type=Path, help="rebuild matrix from a saved raw JSON")
    args = parser.parse_args()
    if args.render:
        raw = json.loads(args.render.read_text())
        print(render(raw), end="")
        return 1 if validate(raw) else 0
    srt = ROOT / "node_modules/.bin/srt"
    if not srt.exists():
        parser.error("run npm ci --ignore-scripts first")
    started = datetime.now(timezone.utc)
    output = args.output or ROOT / "results" / started.strftime("local-%Y%m%dT%H%M%SZ")
    output.mkdir(parents=True, exist_ok=False)
    # Never copy developer tokens, shell startup files or proxy credentials.
    env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "SYSTEMROOT") if k in os.environ}
    env.update(LANG="C.UTF-8", LC_ALL="C", NO_COLOR="1")
    raw = {"schema": SCHEMA, "started_at": started.isoformat(), "scope": "srt-cli",
           "system": platform.platform(), "machine": platform.machine(),
           "python": sys.version, "srt": execute([str(srt), "--version"], ROOT, env),
           "node": execute(["node", "--version"], ROOT, env),
           "host_netns": os.readlink("/proc/self/ns/net") if Path("/proc/self/ns/net").exists() else None,
           "probe_sha256": sha(ROOT / "scripts/probe.py"),
           "runner_sha256": sha(Path(__file__).resolve()),
           "lock_sha256": sha(ROOT / "package-lock.json"),
           # Random per run and never on the probe's command line.
           "canary": "SANDBOX_MATRIX_SYNTHETIC_" + secrets.token_hex(8),
           "executions": [], "receipts": []}
    active = {"profile": "control"}
    # /tmp is implicitly writable in many sandboxes. Put the fixtures in a
    # dedicated home subdirectory so the outside write really tests a boundary.
    with tempfile.TemporaryDirectory(prefix=".sandbox-matrix-", dir=Path.home()) as tmp:
        base = Path(tmp).resolve()
        collectors = Collectors(raw, active, base / "matrix.sock")
        try:
            private = base / "private-canary"
            private.write_text(raw["canary"])
            outside = base / "outside-canary"
            payload = base / "probe.py"
            shutil.copy(ROOT / "scripts/probe.py", payload)
            env["SANDBOX_MATRIX_TOKEN"] = raw["canary"]
            for profile in ("control", "baseline", "hardened", "offline"):
                active["profile"] = profile
                workspace = base / ("workspace-" + profile)
                workspace.mkdir()
                outside.unlink(missing_ok=True)
                (base / "hook-ran").unlink(missing_ok=True)
                git = ["git", "-C", str(workspace), "-c", "core.hooksPath=.git/hooks",
                       "-c", "user.name=sandbox-matrix", "-c", "user.email=matrix@invalid"]
                # A cloned repository already has .git/hooks and often a committed .claude/.
                init = execute(["git", "init", "-q", str(workspace)], ROOT, env)
                (workspace / ".claude").mkdir()
                probe_config = {"workspace": str(workspace), "private": str(private), "outside": str(outside),
                                "allowed": f"http://127.0.0.1:{collectors.allowed.server_port}",
                                "denied": f"http://127.0.0.1:{collectors.denied.server_port}",
                                "udp": ["127.0.0.1", collectors.udp.server_address[1]],
                                "unix_socket": str(base / "matrix.sock")}
                command = [sys.executable, str(payload), json.dumps(probe_config)]
                config = {"network": {"allowedDomains":
                          [] if profile == "offline" else [f"127.0.0.1:{collectors.allowed.server_port}"],
                          "deniedDomains": []},
                          "filesystem": {"denyRead": [], "allowWrite": [str(workspace)], "denyWrite": []}}
                if profile in ("hardened", "offline"):
                    config["filesystem"]["denyRead"] = [str(private)]
                    config["credentials"] = {"envVars": [{"name": "SANDBOX_MATRIX_TOKEN", "mode": "deny"}]}
                config_path = base / (profile + ".json")
                config_path.write_text(json.dumps(config))
                invocation = command if profile == "control" else [str(srt), "--settings", str(config_path), *command]
                execution = execute(invocation, workspace, env)
                targets = {name: observe(workspace / DEFERRED[name][0]) for name in DEFERRED}
                targets.update(workspace_write=observe(workspace / "output.txt"), outside_write=observe(outside))
                execution.update(profile=profile, config=config, git_init=init["returncode"], targets=targets)
                execution["hook_ran"] = None
                if targets["git_hook"]["exists"]:
                    # A developer's next commit, outside any sandbox, runs the hook.
                    execution["git_commit"] = execute([*git, "commit", "-q", "--allow-empty", "-m", "probe"], ROOT, env)
                    execution["hook_ran"] = (base / "hook-ran").exists()
                raw["executions"].append(execution)
                print(profile + ": " + str(execution["returncode"]), flush=True)
        finally:
            collectors.close()
    saved = write_outputs(output, raw)
    return summary(saved, output)


if __name__ == "__main__":
    sys.exit(main())
