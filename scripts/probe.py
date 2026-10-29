#!/usr/bin/env python3
"""Deterministic boundary probes. All paths and tokens are synthetic fixtures."""
import errno
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path


def run(workspace, private, outside, allowed, denied, token):
    def probe(name, operation):
        try:
            operation()
            result = {"id": name, "outcome": "allowed"}
        except urllib.error.HTTPError as exc:
            # Only an explicit proxy denial counts; DNS/TLS/timeouts are errors.
            result = {"id": name, "outcome": "blocked" if exc.code == 403 else "error",
                      "detail": str(exc)}
        except urllib.error.URLError as exc:
            reason = exc.reason
            result = {"id": name, "outcome": "blocked" if isinstance(reason, OSError) and
                      reason.errno in (errno.EACCES, errno.EPERM) else "error", "detail": str(exc)}
        except OSError as exc:
            result = {"id": name, "outcome": "blocked" if exc.errno in
                      (errno.EACCES, errno.EPERM, errno.EROFS) else "error",
                      "detail": str(exc), "errno": exc.errno}
        except Exception as exc:  # preserve diagnostics; never turn a crash into a pass
            result = {"id": name, "outcome": "error", "detail": str(exc)}
        print(json.dumps(result), flush=True)

    def read_canary():
        assert Path(private).read_text() == token

    def environment():
        if os.environ.get("SANDBOX_MATRIX_TOKEN") != token:
            raise PermissionError(errno.EACCES, "synthetic variable withheld")

    def request(url):
        # The collector acknowledges only an exact synthetic marker.
        # macOS urllib otherwise bypasses HTTP_PROXY for loopback addresses.
        urllib.request.proxy_bypass = lambda _host: False
        with urllib.request.urlopen(url + "/" + token, timeout=5) as response:
            assert response.status == 200 and response.read().decode() == token

    def direct():
        host, port = denied.removeprefix("http://").rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=5) as connection:
            connection.sendall(b"GET /direct HTTP/1.0\r\n\r\n")
            assert connection.recv(100)

    probe("workspace_write", lambda: (Path(workspace) / "output.txt").write_text(token))
    probe("credential_file", read_canary)
    probe("credential_env", environment)
    probe("outside_write", lambda: Path(outside).write_text(token))
    probe("denied_http", lambda: request(denied))
    probe("direct_tcp", direct)
    probe("allowed_channel", lambda: request(allowed))


if __name__ == "__main__":
    run(*sys.argv[1:])
