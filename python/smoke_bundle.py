"""Check a frozen worker's authenticated loopback health endpoint."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time
import threading
import urllib.request


class Origin(BaseHTTPRequestHandler):
    calls = 0

    def do_POST(self):
        type(self).calls += 1
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(201)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

root = pathlib.Path(__file__).resolve().parents[1]
binary = root / "native" / ("bridge-worker.exe" if sys.platform == "win32" else "bridge-worker")
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
env = dict(os.environ, BRIDGE_TOKEN="bundle-smoke-token")
process = subprocess.Popen([str(binary), "--port", str(port)], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           start_new_session=(os.name != "nt"))
origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
thread = threading.Thread(target=origin.serve_forever, daemon=True)
thread.start()
try:
    for _ in range(100):
        if process.poll() is not None:
            raise SystemExit(f"worker exited with {process.returncode}")
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/health",
                headers={"Authorization": "Bearer bundle-smoke-token"})
            with urllib.request.urlopen(request, timeout=1) as response:
                payload = json.load(response)
            assert payload["status"] == "ok" and payload["ready"]
            print("frozen worker health: ok")
            break
        except (OSError, TimeoutError):
            time.sleep(0.2)
    else:
        raise SystemExit("worker did not become ready")
    payload = bytes(range(256))
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/proxy",
        data=json.dumps({"method": "POST",
                         "url": f"http://127.0.0.1:{origin.server_port}/binary",
                         "headers": [["Content-Type", "application/octet-stream"]],
                         "body": base64.b64encode(payload).decode(),
                         "profile": "chrome"}).encode(),
        headers={"Authorization": "Bearer bundle-smoke-token",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=35) as response:
        result = json.load(response)
    assert result["status_code"] == 201
    assert base64.b64decode(result["body"]) == payload
    assert Origin.calls == 1
    print("frozen worker binary POST: ok (one origin call)")
finally:
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    else:
        os.killpg(process.pid, signal.SIGTERM)
    process.wait(timeout=10)
    origin.shutdown()
    origin.server_close()
    thread.join(timeout=2)
