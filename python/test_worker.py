"""Transport contract and cookie isolation checks."""
import asyncio
import base64
import hashlib
import hmac
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import worker
from starlette.requests import Request


class Echo(BaseHTTPRequestHandler):
    calls = 0

    def do_GET(self):
        type(self).calls += 1
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/echo")
            self.end_headers()
            return
        data = self.headers.get("Cookie", "").encode()
        self.send_response(200)
        self.send_header("Set-Cookie", "one=a; Path=/")
        self.send_header("Set-Cookie", "two=b; Path=/")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        type(self).calls += 1
        data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(201)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


class WorkerTests(unittest.TestCase):
    def test_explicit_cookie_filter(self):
        pairs = [("Cookie", "sid=ok; cf_clearance=x; __cf_bm=y; locale=en"),
                 ("Accept", "text/html"), ("User-Agent", "curl/8")]
        self.assertEqual(worker.filtered_headers(pairs, ["cf_clearance", "__cf_bm"]),
                         [("Cookie", "sid=ok; locale=en"), ("Accept", "text/html")])
        self.assertEqual(worker.filtered_headers(pairs, []), pairs[:2])

    def test_one_send_redirect_and_cookie_isolation(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        os.environ["BRIDGE_TOKEN"] = "test-token"
        base = f"http://127.0.0.1:{server.server_port}"

        async def exercise():
            await worker.startup()
            try:
                first = await worker.proxy(worker.BridgeRequest(method="GET", url=base + "/echo",
                    headers=[("Cookie", "sid=fresh")]), "Bearer test-token")
                second = await worker.proxy(worker.BridgeRequest(method="GET", url=base + "/echo"), "Bearer test-token")
                redirect = await worker.proxy(worker.BridgeRequest(method="GET", url=base + "/redirect"), "Bearer test-token")
                return first, second, redirect
            finally:
                await worker.shutdown()

        try:
            Echo.calls = 0
            first, second, redirect = asyncio.run(exercise())
            self.assertEqual(base64.b64decode(first["body"]), b"sid=fresh")
            self.assertEqual(base64.b64decode(second["body"]), b"")
            self.assertEqual(first["status_code"], 200)
            self.assertEqual(redirect["status_code"], 302)
            self.assertEqual(sum(1 for name, _ in first["headers"] if name.lower() == "set-cookie"), 2)
            self.assertEqual(Echo.calls, 3)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_concurrent_requests_each_send_once(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        os.environ["BRIDGE_TOKEN"] = "test-token"
        url = f"http://127.0.0.1:{server.server_port}/echo"

        async def exercise():
            await worker.startup()
            try:
                return await asyncio.gather(*(worker.proxy(
                    worker.BridgeRequest(method="GET", url=url, headers=[("Cookie", f"id={i}")]),
                    "Bearer test-token") for i in range(64)))
            finally:
                await worker.shutdown()

        try:
            Echo.calls = 0
            results = asyncio.run(exercise())
            self.assertEqual(len(results), 64)
            self.assertEqual(Echo.calls, 64)
            self.assertEqual({base64.b64decode(r["body"]) for r in results},
                             {f"id={i}".encode() for i in range(64)})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_relay_returns_target_response_and_duplicate_cookies(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        os.environ["BRIDGE_TOKEN"] = "test-token"

        async def exercise():
            await worker.startup()
            try:
                target = f"http://127.0.0.1:{server.server_port}/echo"
                stamp = str(int(time.time()))
                prefix = f"GET\n{target}\nchrome\n\n{stamp}\n".encode()
                signature = base64.urlsafe_b64encode(
                    hmac.new(b"test-token", prefix, hashlib.sha256).digest()).rstrip(b"=")
                headers = [(b"host", b"127.0.0.1"), (b"cookie", b"sid=relay"),
                           (b"x-bridge-target", target.encode()),
                           (b"x-bridge-profile", b"chrome"),
                           (b"x-bridge-strip-cookies", b""),
                           (b"x-bridge-time", stamp.encode()),
                           (b"x-bridge-signature", signature)]
                scope = {"type": "http", "http_version": "1.1", "method": "GET",
                         "scheme": "http", "path": "/echo", "raw_path": b"/echo",
                         "query_string": b"", "headers": headers,
                         "server": ("127.0.0.1", 1), "client": ("127.0.0.1", 2)}
                async def receive():
                    return {"type": "http.request", "body": b"", "more_body": False}
                return await worker.transparent_relay(Request(scope, receive))
            finally:
                await worker.shutdown()

        try:
            Echo.calls = 0
            result = asyncio.run(exercise())
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.body, b"sid=relay")
            self.assertEqual(sum(1 for name, _ in result.raw_headers if name.lower() == b"set-cookie"), 2)
            self.assertEqual(Echo.calls, 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_binary_post_sent_once(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        os.environ["BRIDGE_TOKEN"] = "test-token"
        payload = bytes(range(256))

        async def exercise():
            await worker.startup()
            try:
                return await worker.proxy(worker.BridgeRequest(
                    method="POST", url=f"http://127.0.0.1:{server.server_port}/upload",
                    headers=[("Content-Type", "application/octet-stream")],
                    body=base64.b64encode(payload).decode()), "Bearer test-token")
            finally:
                await worker.shutdown()

        try:
            Echo.calls = 0
            result = asyncio.run(exercise())
            self.assertEqual(result["status_code"], 201)
            self.assertEqual(base64.b64decode(result["body"]), payload)
            self.assertEqual(Echo.calls, 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
