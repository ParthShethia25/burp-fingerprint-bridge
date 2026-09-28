#!/usr/bin/env python3
"""Loopback transport for Fingerprint Bridge. No request content is logged."""
import argparse
import asyncio
import base64
import hashlib
import hmac
import os
import sys
import time
from urllib.parse import urlsplit
from curl_cffi.requests import AsyncSession
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
import uvicorn

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

VERSION = "0.1.1"
MAX_BODY = 16 * 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
HOP_HEADERS = {"host", "connection", "proxy-connection", "transfer-encoding",
               "content-length", "accept-encoding", "keep-alive", "te", "trailer", "upgrade",
               "user-agent"}
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
session = None
slots = asyncio.Semaphore(32)


class BridgeRequest(BaseModel):
    method: str
    url: str
    headers: list[tuple[str, str]] = Field(default_factory=list)
    body: str = ""
    profile: str = "chrome"
    strip_cookies: list[str] = Field(default_factory=list)
    timeout: int = Field(default=30, ge=1, le=120)


def filtered_headers(pairs: list[tuple[str, str]], strip: list[str]) -> list[tuple[str, str]]:
    """Only strip explicitly configured cookies; leave application cookies intact."""
    names = {name.strip().lower() for name in strip if name.strip()}
    result = []
    for name, value in pairs:
        lower = name.lower()
        if lower in HOP_HEADERS or lower.startswith(":"):
            continue
        if lower == "cookie" and names:
            value = "; ".join(part.strip() for part in value.split(";")
                              if part.strip() and part.split("=", 1)[0].strip().lower() not in names)
            if not value:
                continue
        result.append((name, value))
    return result


def require_token(authorization: str | None) -> None:
    token = os.environ.get("BRIDGE_TOKEN", "")
    if not token or authorization != "Bearer " + token:
        raise HTTPException(401, "Unauthorized")


@app.middleware("http")
async def bridge_middleware(request: Request, call_next):
    if "x-bridge-target" not in request.headers:
        return await call_next(request)
    return await transparent_relay(request)


async def transparent_relay(request: Request) -> Response:
    """Compatibility path for Burp versions without spoof()."""
    target = request.headers.get("x-bridge-target", "")
    profile = request.headers.get("x-bridge-profile", "chrome")
    strip = request.headers.get("x-bridge-strip-cookies", "")
    timestamp = request.headers.get("x-bridge-time", "")
    signature = request.headers.get("x-bridge-signature", "")
    token = os.environ.get("BRIDGE_TOKEN", "")
    try:
        if abs(time.time() - int(timestamp)) > 60:
            raise ValueError()
    except ValueError:
        return Response("Unauthorized", status_code=401)
    body = await request.body()
    if len(body) > MAX_BODY:
        return Response("Request body too large", status_code=413)
    prefix = f"{request.method}\n{target}\n{profile}\n{strip}\n{timestamp}\n".encode()
    expected = base64.urlsafe_b64encode(
        hmac.new(token.encode(), prefix + body, hashlib.sha256).digest()).rstrip(b"=").decode()
    if not token or not hmac.compare_digest(signature, expected):
        return Response("Unauthorized", status_code=401)
    headers = [(name.decode("latin-1"), value.decode("latin-1"))
               for name, value in request.headers.raw
               if not name.lower().startswith(b"x-bridge-")]
    try:
        result = await proxy(BridgeRequest(
            method=request.method, url=target, headers=headers,
            body=base64.b64encode(body).decode("ascii"), profile=profile,
            strip_cookies=[name for name in strip.replace(";", ",").split(",") if name.strip()]),
            "Bearer " + token)
        response = Response(content=base64.b64decode(result["body"]),
                            status_code=result["status_code"])
        response.raw_headers = [(name.encode("latin-1"), value.encode("latin-1"))
                                for name, value in result["headers"]]
        return response
    except HTTPException as exc:
        return Response(str(exc.detail), status_code=exc.status_code)


@app.on_event("startup")
async def startup():
    global session
    session = AsyncSession(discard_cookies=True, max_clients=32)


@app.on_event("shutdown")
async def shutdown():
    global session
    if session is not None:
        await session.close()
        session = None


@app.get("/health")
async def health(authorization: str | None = Header(default=None)):
    require_token(authorization)
    return {"status": "ok", "version": VERSION, "ready": session is not None}


@app.post("/proxy")
async def proxy(request: BridgeRequest, authorization: str | None = Header(default=None)):
    require_token(authorization)
    if session is None:
        raise HTTPException(503, "Worker not ready")
    parsed = urlsplit(request.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(400, "Invalid URL")
    if not request.method.isascii() or not request.method.isalpha():
        raise HTTPException(400, "Invalid method")
    try:
        body = base64.b64decode(request.body, validate=True)
    except ValueError:
        raise HTTPException(400, "Invalid body encoding")
    if len(body) > MAX_BODY:
        raise HTTPException(413, "Request body too large")
    headers = filtered_headers(request.headers, request.strip_cookies)
    try:
        try:
            await asyncio.wait_for(slots.acquire(), timeout=2)
        except asyncio.TimeoutError:
            raise HTTPException(503, "Bridge busy") from None
        try:
            started = time.monotonic()
            response = await session.request(
                request.method.upper(), request.url, headers=headers, data=body,
                impersonate=request.profile, timeout=request.timeout,
                allow_redirects=False, verify=True)
            content = response.content
            if len(content) > MAX_RESPONSE:
                raise HTTPException(502, "Response exceeds 32 MiB limit")
            response_headers = [(name, value) for name, value in response.headers.multi_items()
                                if name.lower() not in HOP_HEADERS and name.lower() != "content-encoding"]
            response_headers.append(("Content-Length", str(len(content))))
            return {"status_code": response.status_code, "reason": response.reason or "OK",
                    "headers": response_headers, "body": base64.b64encode(content).decode("ascii"),
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 1)}
        finally:
            slots.release()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, "Transport failed: " + type(exc).__name__) from None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False, log_level="warning")
