#!/usr/bin/env python3
"""Run the same synthetic probes through an existing local OpenShell gateway."""
import argparse
import hashlib
import io
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from probe import DEFERRED
from run import ROOT, SCHEMA, execute, sha, summary, write_outputs

TARGETS = {"workspace_write": "/sandbox/output.txt", "outside_write": "/matrix-outside/canary",
           **{name: "/sandbox/" + relative for name, (relative, _) in DEFERRED.items()}}
LABEL = "label=openshell.ai/sandbox-name="
NOT_RUN = {"unix_socket": "в workload нет сокета хоста; монтирование Docker socket проверяется по docker inspect"}


def read_from_container(container, path):
    """Target state seen from outside the workload: docker cp works on stopped containers too."""
    result = subprocess.run(["docker", "cp", f"{container}:{path}", "-"], capture_output=True)
    if result.returncode != 0:
        return {"exists": False, "detail": result.stderr.decode(errors="replace").strip()[:200]}
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
        member = archive.getmembers()[0]
        if not member.isfile():
            return {"exists": True}
        return {"exists": True, "sha256": hashlib.sha256(archive.extractfile(member).read()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", default=shutil.which("openshell") or str(ROOT / ".tools/openshell"))
    parser.add_argument("--endpoint", default="http://127.0.0.1:18080")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ports", nargs=3, type=int, default=[19181, 19182, 19183])
    args = parser.parse_args()
    if args.endpoint != "http://127.0.0.1:18080":
        parser.error("this lab targets only its dedicated local gateway on port 18080")
    output = args.output or ROOT / "results" / datetime.now(timezone.utc).strftime("local-openshell-%Y%m%dT%H%M%SZ")
    output.mkdir(parents=True, exist_ok=False)
    env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR") if k in os.environ}
    env["NO_COLOR"] = "1"
    suffix = uuid.uuid4().hex[:6]
    image = "sandbox-matrix-fixture:" + suffix
    receiver = "sandbox-matrix-receiver-" + suffix
    control = "sandbox-matrix-control-" + suffix
    cli = [args.cli, "--gateway-endpoint", args.endpoint]
    raw = {"schema": SCHEMA, "scope": "openshell", "started_at": datetime.now(timezone.utc).isoformat(),
           "system": platform.platform(), "machine": platform.machine(),
           "probe_sha256": sha(ROOT / "scripts/probe.py"),
           "canary": "SANDBOX_MATRIX_SYNTHETIC_" + secrets.token_hex(8),
           "runner_sha256": sha(Path(__file__).resolve()),
           "receiver_sha256": sha(ROOT / "openshell/receiver.py"),
           "dockerfile_sha256": sha(ROOT / "openshell/fixture.Dockerfile"),
           "executions": [], "receipts": [], "setup": [], "cleanup": []}
    sandboxes = {}

    def setup(command, timeout=60, required=True):
        result = execute(command, ROOT, env, timeout)
        raw["setup"].append(result)
        if required and result["returncode"] != 0:
            raise RuntimeError(result["stderr"] or result["stdout"])
        return result

    def workload_container(name):
        """The Docker driver labels the workload (role sandbox) and its supervisor with the sandbox name."""
        listing = setup(["docker", "ps", "-a", "-q", "--no-trunc", "--filter", LABEL + name,
                         "--filter", "label=openshell.ai/isolation-role=sandbox"])
        matches = listing["stdout"].split()
        if len(matches) != 1:
            raise RuntimeError(f"expected one container for {name}, found {len(matches)}")
        return matches[0]

    try:
        setup([args.cli, "--version"])
        setup([*cli, "status"])
        setup(["docker", "version", "--format", "{{.Server.Version}}"])
        setup(["docker", "build", "--build-arg", "CANARY=" + raw["canary"], "-t", image,
               "-f", "openshell/fixture.Dockerfile", "."], timeout=180)
        setup(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
        for ref in ("gateway", "supervisor", "sandbox"):
            setup(["docker", "image", "inspect", "ghcr.io/nvidia/openshell/" + ref + ":0.1.6",
                   "--format", "{{json .RepoDigests}}"])
        setup(["docker", "run", "-d", "--name", receiver, "--network", "host", image,
               "python3", "/sandbox/receiver.py", *map(str, args.ports)])
        for _ in range(20):
            logs = setup(["docker", "logs", receiver])
            if "READY" in logs["stdout"]:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("receiver did not start; check ports and Docker host networking")
        host = "host.openshell.internal"
        probe_config = {"workspace": "/sandbox", "private": "/matrix-private/canary",
                        "outside": "/matrix-outside/canary", "allowed": f"http://{host}:{args.ports[0]}",
                        "denied": f"http://{host}:{args.ports[1]}", "udp": [host, args.ports[2]]}
        payload = ["python3", "/sandbox/probe.py", json.dumps(probe_config)]
        # The no-network-policy variant has no policy DNS responder in this
        # release. EAI_AGAIN would be inconclusive, so it is not a denial test.
        raw["not_run"] = {"offline": "без network rules в этом релизе нет DNS-ответчика политики; "
                                     "ошибку DNS нельзя засчитать как явный отказ"}
        for profile in ("control", "baseline", "hardened"):
            injected_env = ["--env", "SANDBOX_MATRIX_TOKEN=" + raw["canary"]] if profile in ("control", "baseline") else []
            if profile == "control":
                command = ["docker", "run", "--name", control, "--network", "host", "--add-host",
                           host + ":127.0.0.1", *injected_env, image, *payload]
                policy = None
            else:
                name = "mx-" + suffix + "-" + profile
                policy = {"version": 1, "filesystem_policy": {"include_workdir": True,
                          "read_only": ["/bin", "/usr", "/lib", "/etc", "/proc", "/dev/urandom", "/var/log"] +
                          (["/matrix-private"] if profile == "baseline" else []),
                          "read_write": ["/sandbox", "/tmp", "/dev/null"]},
                          "landlock": {"compatibility": "hard_requirement"}, "network_policies": {
                          "collector": {"name": "local-collector-only",
                                        "endpoints": [{"host": host, "port": args.ports[0], "protocol": "tcp"}],
                                        "binaries": [{"path": "/usr/local/bin/python3.12"}]}}}
                path = output.resolve() / (profile + ".yaml")
                # JSON is a YAML subset; no extra parser dependency required.
                path.write_text(json.dumps(policy, indent=2) + "\n")
                sandboxes[name] = None
                setup([*cli, "sandbox", "create", "--name", name, "--from", image,
                       "--policy", str(path), "--no-auto-providers", *injected_env,
                       "--detach", "--", "python3", "-c", "import time; time.sleep(600)"])
                # First exec waits for a ready sandbox; never use docker exec for measurements.
                ready = setup([*cli, "sandbox", "exec", name, "--no-login-shell", "--no-tty",
                               "--", "python3", "-c", "import platform; print('READY', platform.platform())"], timeout=90)
                if "READY" not in ready["stdout"]:
                    raise RuntimeError("workload is not ready")
                setup([*cli, "sandbox", "get", name, "--policy-only"])
                sandboxes[name] = workload_container(name)
                mounts = setup(["docker", "inspect", "--format", "{{json .Mounts}}", sandboxes[name]])
                if "docker.sock" in mounts["stdout"]:
                    raise RuntimeError("workload container has the Docker socket mounted")
                command = [*cli, "sandbox", "exec", name, "--no-login-shell", "--no-tty", "--", *payload]
            execution = execute(command, ROOT, env)
            container = control if profile == "control" else sandboxes[name]
            execution.update(profile=profile, config=policy, not_run=NOT_RUN,
                             targets={k: read_from_container(container, v) for k, v in TARGETS.items()},
                             environment_policy="inject synthetic variable" if injected_env else "do not forward host environment")
            raw["executions"].append(execution)
            logs = setup(["docker", "logs", receiver])["stdout"]
            observed = [json.loads(line) for line in logs.splitlines() if line.startswith("{")]
            seen = len(raw["receipts"])
            raw["receipts"] += [dict(e, profile=profile) for e in observed[seen:]]
            print(profile + ": " + str(execution["returncode"]), flush=True)
    except Exception as exc:
        raw["error"] = str(exc)
        print(str(exc), file=sys.stderr)
    finally:
        for name in sandboxes:
            raw["cleanup"].append(execute([*cli, "sandbox", "delete", name], ROOT, env, timeout=90))
            raw["cleanup"].append(confirm_deleted(cli, name, env))
        for container in (receiver, control):
            if execute(["docker", "container", "inspect", container], ROOT, env)["returncode"] == 0:
                raw["cleanup"].append(execute(["docker", "rm", "-f", container], ROOT, env))
        raw["cleanup"].append(execute(["docker", "image", "rm", image], ROOT, env))
        saved = write_outputs(output, raw)
    if len(saved["executions"]) != 3:
        print("incomplete run", file=sys.stderr)
        return 1
    return summary(saved, output)


def confirm_deleted(cli, name, env, timeout=60):
    """`sandbox delete` only accepts the request; wait until gateway and Docker both forget it."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        gateway = execute([*cli, "sandbox", "get", name], ROOT, env)
        docker = execute(["docker", "ps", "-a", "-q", "--filter", LABEL + name], ROOT, env)
        if "not found" in gateway["stderr"] and docker["returncode"] == 0 and not docker["stdout"].strip():
            return {"command": ["confirm-deleted", name], "returncode": 0,
                    "stdout": "gateway: sandbox not found; docker: no workload or supervisor container", "stderr": ""}
        time.sleep(1)
    return {"command": ["confirm-deleted", name], "returncode": 1, "stdout": "",
            "stderr": f"sandbox or container still present after {timeout}s"}


if __name__ == "__main__":
    sys.exit(main())
