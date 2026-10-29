#!/usr/bin/env python3
"""Run the same synthetic probes through an existing local OpenShell gateway."""
import argparse
import json
import os
import platform
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from run import ROOT, execute, render, sha, validate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", default=shutil.which("openshell") or str(ROOT / ".tools/openshell"))
    parser.add_argument("--endpoint", default="http://127.0.0.1:18080")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ports", nargs=2, type=int, default=[19181, 19182])
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
    cli = [args.cli, "--gateway-endpoint", args.endpoint]
    raw = {"schema": 1, "scope": "openshell", "started_at": datetime.now(timezone.utc).isoformat(),
           "system": platform.platform(), "machine": platform.machine(),
           "probe_sha256": sha(ROOT / "scripts/probe.py"), "canary": "SANDBOX_MATRIX_SYNTHETIC_ONLY",
           "runner_sha256": sha(Path(__file__).resolve()),
           "receiver_sha256": sha(ROOT / "openshell/receiver.py"),
           "dockerfile_sha256": sha(ROOT / "openshell/fixture.Dockerfile"),
           "executions": [], "receipts": [], "setup": [], "cleanup": []}
    sandboxes = []

    def setup(command, timeout=60, required=True):
        result = execute(command, ROOT, env, timeout)
        raw["setup"].append(result)
        if required and result["returncode"] != 0:
            raise RuntimeError(result["stderr"] or result["stdout"])
        return result

    try:
        setup([args.cli, "--version"])
        setup([*cli, "status"])
        setup(["docker", "version", "--format", "{{.Server.Version}}"])
        setup(["docker", "build", "-t", image, "-f", "openshell/fixture.Dockerfile", "."], timeout=180)
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
        payload = ["python3", "/sandbox/probe.py", "/sandbox", "/matrix-private/canary",
                   "/matrix-outside/canary", f"http://host.openshell.internal:{args.ports[0]}",
                   f"http://host.openshell.internal:{args.ports[1]}", raw["canary"]]
        # The no-network-policy variant has no policy DNS responder in this
        # release. EAI_AGAIN would be inconclusive, so it is not a denial test.
        raw["not_run"] = {"offline": "No policy DNS responder; DNS failure is not proof of enforcement"}
        for profile in ("control", "baseline", "hardened"):
            injected_env = ["--env", "SANDBOX_MATRIX_TOKEN=" + raw["canary"]] if profile in ("control", "baseline") else []
            if profile == "control":
                command = ["docker", "run", "--rm", "--network", "host", "--add-host",
                           "host.openshell.internal:127.0.0.1", *injected_env, image, *payload]
                policy = None
            else:
                name = "mx-" + suffix + "-" + profile
                sandboxes.append(name)
                policy = {"version": 1, "filesystem_policy": {"include_workdir": True,
                          "read_only": ["/bin", "/usr", "/lib", "/etc", "/proc", "/dev/urandom", "/var/log"] +
                          (["/matrix-private"] if profile == "baseline" else []),
                          "read_write": ["/sandbox", "/tmp", "/dev/null"]},
                          "landlock": {"compatibility": "hard_requirement"}, "network_policies": {}}
                if profile != "offline":
                    policy["network_policies"]["collector"] = {"name": "local-collector-only",
                        "endpoints": [{"host": "host.openshell.internal", "port": args.ports[0], "protocol": "tcp"}],
                        "binaries": [{"path": "/usr/local/bin/python3.12"}]}
                path = output.resolve() / (profile + ".yaml")
                # JSON is a YAML subset; no extra parser dependency required.
                path.write_text(json.dumps(policy, indent=2) + "\n")
                setup([*cli, "sandbox", "create", "--name", name, "--from", image,
                       "--policy", str(path), "--no-auto-providers", *injected_env,
                       "--detach", "--", "python3", "-c", "import time; time.sleep(600)"])
                # First exec waits for a ready sandbox; never use docker exec for measurements.
                ready = setup([*cli, "sandbox", "exec", name, "--no-login-shell", "--no-tty",
                               "--", "python3", "-c", "import platform; print('READY', platform.platform())"], timeout=90)
                if "READY" not in ready["stdout"]:
                    raise RuntimeError("workload is not ready")
                setup([*cli, "sandbox", "get", name, "--policy-only"])
                command = [*cli, "sandbox", "exec", name, "--no-login-shell", "--no-tty", "--", *payload]
            execution = execute(command, ROOT, env)
            execution.update(profile=profile, config=policy,
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
        raw["cleanup"].append(execute(["docker", "rm", "-f", receiver], ROOT, env))
        raw["cleanup"].append(execute(["docker", "image", "rm", image], ROOT, env))
        (output / "raw.json").write_text(json.dumps(raw, indent=2) + "\n")
        (output / "matrix.md").write_text(render(raw))
    failures = validate(raw)
    failed = bool(raw.get("error") or failures or len(raw["executions"]) != 3 or
                  any(r["returncode"] != 0 for r in raw["cleanup"]))
    print(f"{output}: {'FAILED' if failed else 'PASSED'}; {len(failures)} unexpected outcomes")
    return failed


if __name__ == "__main__":
    sys.exit(main())
