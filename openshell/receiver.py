"""Local HTTP and UDP collectors in the Docker VM; never forward traffic to the Internet."""
import http.server
import json
import socketserver
import sys
import threading


def log(label, path):
    print(json.dumps({"receiver": label, "path": path}), flush=True)


def serve_http(port, label):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            log(label, self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def serve_udp(port):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            labels, i = [], 12
            while i < len(data) and data[i]:
                labels.append(data[i + 1:i + 1 + data[i]].decode(errors="replace"))
                i += 1 + data[i]
            log("udp", ".".join(labels))
            sock.sendto(data[:2] + b"\x81\x83" + data[4:], self.client_address)
    server = socketserver.ThreadingUDPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()


if __name__ == "__main__":
    allowed, denied, udp = map(int, sys.argv[1:4])
    serve_http(allowed, "allowed")
    serve_http(denied, "denied")
    serve_udp(udp)
    print("READY", flush=True)
    threading.Event().wait()
