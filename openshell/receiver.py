"""Two local collectors in the Docker VM; never forward traffic to the Internet."""
import http.server
import json
import sys
import threading

TOKEN = b"SANDBOX_MATRIX_SYNTHETIC_ONLY"


def serve(port, label):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            print(json.dumps({"receiver": label, "path": self.path}), flush=True)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(TOKEN)

        def log_message(self, *_):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


if __name__ == "__main__":
    for number, label in zip(map(int, sys.argv[1:]), ("allowed", "denied")):
        serve(number, label)
    print("READY", flush=True)
    threading.Event().wait()
