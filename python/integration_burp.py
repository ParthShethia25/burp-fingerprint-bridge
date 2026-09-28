"""Check a running Burp proxy and Fingerprint Bridge against a local origin.

In the extension tab, enable the host 127.0.0.1 before running this script.
No requests leave the local machine.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import httpx


class Origin(BaseHTTPRequestHandler):
    calls = 0
    lock = threading.Lock()

    def _record(self):
        with self.lock:
            type(self).calls += 1

    def do_GET(self):
        self._record()
        body = (self.path + "\n" + self.headers.get("User-Agent", "")).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self._record()
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(201)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", default="http://127.0.0.1:8080")
    parser.add_argument("--concurrency", type=int, default=24)
    args = parser.parse_args()
    if not 1 <= args.concurrency <= 32:
        parser.error("concurrency must be between 1 and 32")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        def get(index):
            with httpx.Client(proxy=args.proxy, trust_env=False, timeout=35) as client:
                return client.get(f"{base}/item/{index}")

        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            results = list(pool.map(get, range(args.concurrency)))
        for index, response in enumerate(results):
            assert response.status_code == 200, (index, response.status_code)
            path, user_agent = response.text.split("\n", 1)
            assert path == f"/item/{index}", (index, path)
            assert "Mozilla/5.0" in user_agent, (index, user_agent)

        payload = bytes(range(256))
        with httpx.Client(proxy=args.proxy, trust_env=False, timeout=35) as client:
            response = client.post(base + "/binary", content=payload)
        assert response.status_code == 201, response.status_code
        assert response.content == payload, "binary request/response changed"
        assert Origin.calls == args.concurrency + 1, Origin.calls
        print(f"PASS: {args.concurrency} concurrent GETs and one binary POST; "
              f"{Origin.calls} origin calls; browser User-Agent on selected host")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
