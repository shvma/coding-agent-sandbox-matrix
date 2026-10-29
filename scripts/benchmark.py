#!/usr/bin/env python3
"""One entry point: SRT, optionally a temporary local OpenShell 0.1.6 lab."""
import argparse
import hashlib
import io
import json
import platform
import subprocess
import sys
import tarfile
import time
import urllib.request
import uuid
from datetime import datetime, timezone

from run import ROOT, execute


def install_cli():
    machine = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}[platform.machine()]
    target = machine + ("-apple-darwin" if sys.platform == "darwin" else "-unknown-linux-musl")
    name = "openshell-" + target + ".tar.gz"
    base = "https://github.com/NVIDIA/OpenShell/releases/download/v0.1.6/"
    archive = urllib.request.urlopen(base + name, timeout=120).read()
    checksums = urllib.request.urlopen(base + "openshell-checksums-sha256.txt", timeout=30).read().decode()
    digest = hashlib.sha256(archive).hexdigest()
    if not any(line.split()[0] == digest and line.split()[-1].lstrip("*") == name
               for line in checksums.splitlines()):
        raise RuntimeError("OpenShell release checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        member = package.getmember("openshell")
        if not member.isfile():
            raise RuntimeError("invalid CLI archive")
        binary = ROOT / ".tools/openshell"
        binary.write_bytes(package.extractfile(member).read())
        binary.chmod(0o755)
    return binary, {"url": base + name, "sha256": digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-openshell", action="store_true")
    parser.add_argument("--output", default="results/local-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    args = parser.parse_args()
    output = (ROOT / args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    srt = subprocess.run([sys.executable, "scripts/run.py", "--output", str(output / "srt")], cwd=ROOT)
    if not args.with_openshell:
        return srt.returncode
    if subprocess.run(["docker", "container", "inspect", "sandbox-matrix-gateway"],
                      capture_output=True).returncode == 0:
        parser.error("sandbox-matrix-gateway already exists; this command will not replace it")
    state = (ROOT / ".tools/openshell-state").resolve()
    state.mkdir(parents=True, exist_ok=True)
    journal = {"steps": [], "cleanup": []}
    owner = uuid.uuid4().hex
    started = False
    failed = srt.returncode != 0

    def step(command, timeout=180):
        print("lab: " + command[0] + " " + command[1], flush=True)
        result = execute(command, ROOT, None, timeout)
        journal["steps"].append(result)
        if result["returncode"] != 0:
            raise RuntimeError(result["stderr"] or result["stdout"])
        return result

    try:
        cli, journal["cli_release"] = install_cli()
        step([str(cli), "--version"])
        for image in ("gateway", "supervisor", "sandbox"):
            step(["docker", "pull", f"ghcr.io/nvidia/openshell/{image}:0.1.6"])
        step(["docker", "run", "--rm", "--user", "0", "-v", f"{state}:{state}",
              "ghcr.io/nvidia/openshell/gateway:0.1.6", "generate-certs", "--output-dir", str(state / "tls")])
        config = '''[openshell]
version = 2
[openshell.gateway]
bind_address = "0.0.0.0:18080"
health_bind_address = "0.0.0.0:18081"
compute_driver = "docker"
disable_tls = true
[openshell.gateway.auth]
allow_unauthenticated_users = true
[openshell.gateway.gateway_jwt]
signing_key_path = SIGN
public_key_path = PUBLIC
kid_path = KID
gateway_id = "sandbox-matrix"
[openshell.drivers.docker]
sandbox_runtime_image = "ghcr.io/nvidia/openshell/sandbox:0.1.6"
supervisor_image = "ghcr.io/nvidia/openshell/supervisor:0.1.6"
image_pull_policy = "if_not_present"
sandbox_label = "sandbox-matrix"
app_armor_profile = "Unconfined"
'''
        for label, file in (("SIGN", "signing.pem"), ("PUBLIC", "public.pem"), ("KID", "kid")):
            config = config.replace(label, json.dumps(str(state / "tls/jwt" / file)))
        (state / "gateway.toml").write_text(config)
        journal["gateway_config"] = config
        # Mark ownership before launching so a timed-out Docker response is cleaned up too.
        started = True
        step(["docker", "run", "-d", "--name", "sandbox-matrix-gateway", "--user", "0",
              "--label", "sandbox-matrix.lab=true", "--label", "sandbox-matrix.owner=" + owner,
              "-p", "127.0.0.1:18080:18080",
              "-p", "127.0.0.1:18081:18081", "-v", "/var/run/docker.sock:/var/run/docker.sock",
              "-v", f"{state}:{state}", "-e", f"OPENSHELL_GATEWAY_CONFIG={state}/gateway.toml",
              "-e", f"OPENSHELL_DB_URL=sqlite:{state}/gateway.db?mode=rwc",
              "-e", f"XDG_DATA_HOME={state}", "ghcr.io/nvidia/openshell/gateway:0.1.6",
              "--bind-address", "0.0.0.0", "--port", "18080"])
        for _ in range(30):
            try:
                with urllib.request.urlopen("http://127.0.0.1:18081/readyz", timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError("gateway readiness timed out")
        step([sys.executable, "scripts/run_openshell.py", "--cli", str(cli), "--output", str(output / "openshell")], timeout=600)
    except Exception as exc:
        journal["error"] = str(exc)
        print(str(exc), file=sys.stderr)
        failed = True
    finally:
        if started:
            inspected = execute(["docker", "inspect", "--format",
                '{{.Id}} {{index .Config.Labels "sandbox-matrix.owner"}}', "sandbox-matrix-gateway"], ROOT, None)
            journal["steps"].append(inspected)
            parts = inspected["stdout"].strip().split()
            if inspected["returncode"] == 0 and len(parts) == 2 and parts[1] == owner:
                journal["steps"].append(execute(["docker", "logs", parts[0]], ROOT, None))
                result = execute(["docker", "rm", "-f", parts[0]], ROOT, None)
                journal["cleanup"].append(result)
                failed |= result["returncode"] != 0
        (output / "lab.json").write_text(json.dumps(journal, indent=2) + "\n")
    return failed


if __name__ == "__main__":
    sys.exit(main())
