# Burp Fingerprint Bridge

Some sites load in a browser but show a block page when you send the same
request through Burp Suite. A possible cause is Burp's TLS fingerprint: the
HTTPS handshake can reveal which network client sent the request. **Burp
Fingerprint Bridge** sends requests for the hosts you select through
[curl-cffi](https://github.com/lexiforest/curl_cffi) with a browser-like TLS
profile, then returns the response to Burp.

The extension works in Burp Community and Professional. Each release JAR
contains its local worker: **you do not need Python, a separate server, or a
Burp Professional license**. Burp Suite 2026.3.3 or newer is the tested and
supported range. Older releases have not been verified. The extension is off
until you add hosts and enable it.

## Quick start

1. In [Releases](https://github.com/ParthShethia25/burp-fingerprint-bridge/releases),
   download **one JAR** that matches your computer:
   `windows`, `linux`, `macos-arm64` (Apple Silicon), or
   `macos-intel` (Intel Mac). Save it anywhere you can find it.
2. Open your existing Burp Suite installation. Go to **Extensions → Installed
   → Add**, set **Extension type** to **Java**, choose the downloaded JAR,
   and click **Next**. A **Fingerprint Bridge** tab appears.
3. Open that tab. Wait for **Worker ready on loopback**. The bundled worker
   runs locally on your computer; no account or external service is needed.
4. In **Hosts**, enter a hostname such as `example.com`. This also includes
   subdomains such as `www.example.com`. Replace the placeholder with a
   host you are authorized to test. Check **Enable for host list** and
   click **Apply**.
5. Send a normal GET request to that host through Burp Proxy or Repeater.
   The **Bridged** counter should increase. Compare the response with the
   same request while the extension is disabled.

Use your usual Burp Proxy listener port (often `8080`). The extension does
not require a new proxy port or a browser proxy change.

The bridge changes transport behavior only for matching hosts. Empty host
lists and unchecked **Enable for host list** leave Burp traffic unchanged.

The worker uses the selected profile's User-Agent, so a command-line client
such as `curl` does not accidentally pair a curl User-Agent with Chrome TLS.
Leave the optional cookie list blank at first. If you have evidence that
specific browser challenge cookies are tied to a different fingerprint,
enter only those cookie names, for example `cf_clearance,__cf_bm`. Those
cookies are then removed only for selected hosts; application cookies remain
intact. The cookie field applies to every host in the list.

## Why this can help

The request still starts in Burp, so you can edit it and inspect the response
with familiar tools. The bridge changes the outgoing connection for selected
hosts. It also pairs the browser TLS profile with that profile's User-Agent;
this avoids an obvious mismatch when the request starts from a command-line
client. It does not solve every block. See [Limits and
troubleshooting](#limits-and-troubleshooting).

## How it works

```text
Burp tool → Montoya request hook → local authenticated worker → target
          ← spoofed HTTP response ← curl-cffi browser TLS profile
```

For Burp 2026.7+, `RequestToBeSentAction.spoof` replaces Burp's network
send with the worker's response. For Burp 2026.3.3, the compatibility mode
rewrites Burp's one outgoing connection to a local authenticated relay; the
relay sends once to the target and returns its response. The method, path,
body, and ordinary headers remain in the Burp request editor, while the
connection target and bridge metadata point to loopback. This is a
limitation of the older extension API.
Both modes avoid duplicate target sends. Redirects are returned to Burp
rather than followed by the worker. Response bytes are preserved, including
separate `Set-Cookie` headers. The worker never maintains a shared browser
cookie jar.

| Traffic source | Expected behavior |
| --- | --- |
| Proxy, Repeater, Intruder, Burp Scanner/crawler | Routed when Burp emits a Montoya HTTP request event |
| Extensions using Burp's HTTP API | Routed when they use Burp's request engine |
| Turbo Intruder with `Engine.BURP` or `Engine.BURP2` | Uses Burp's HTTP stack and should reach the hook; see [engine documentation](https://github.com/PortSwigger/turbo-intruder/blob/master/docs/engines.md) |
| Turbo Intruder with `Engine.THREADED` or extensions with their own sockets | Uses a separate HTTP stack and does not reach Burp's hook |
| WebSockets and HTTP CONNECT tunnels | Outside this extension's HTTP request hook |

The profile, host list, and cookie list are saved in Burp preferences. The
worker listens on a random loopback port. Current Burp sends an authenticated
worker request directly; compatibility mode signs its relay request with a
short-lived HMAC. It never logs URLs, headers, bodies, or tokens. If the
worker is unavailable, selected traffic fails locally rather than silently
falling back to Burp's usual connection. Capacity is capped at 32 in-flight
requests, requests at 16 MiB, and responses at 32 MiB. The extension does
not retry requests, so non-idempotent methods are not duplicated on a
transport failure.

## Verified behavior

The Windows release bundle was imported into **Community 2026.8** and
**Professional 2026.3.3**. Both were tested through their live Proxy
listeners. Each handled 24 concurrent local GETs and one binary POST with
exactly one target request per input. A GET to a live HTTPS target through
Community's `8080` listener returned HTTP 200. Worker unit tests cover 64 concurrent
requests, redirects, cookie isolation, and duplicate `Set-Cookie` headers.
The Linux and macOS bundles are built and checked on their respective GitHub
Actions runners; a live Burp session on those operating systems has not been
tested yet.

## Build and test

For development from source, use Java 21 and Python 3.10+. On macOS/Linux,
run `./gradlew build`; on Windows, run `./gradlew.bat build`. Then run:

```text
python -m pip install -r python/requirements.txt
python -m unittest discover -s python -p "test_*.py" -v
```

The source build creates `build/libs/burp-fingerprint-bridge-0.1.1.jar`.
It includes worker source and pinned requirements; this developer build
needs Python 3.10+ and the **Set up and start worker** button. Release JARs
contain a frozen worker executable instead. Optional
read-only live transport check:

```powershell
python python/smoke_live.py https://example.com/
```

To repeat the local Burp integration test, temporarily add `127.0.0.1` to
**Hosts**, enable the extension, and run
`python python/integration_burp.py --proxy http://127.0.0.1:8080`.
This test sends requests only to a local server. Remove `127.0.0.1` from
**Hosts** afterward if you do not need it.

## Limits and troubleshooting

| Symptom | What to check |
| --- | --- |
| No **Fingerprint Bridge** tab | Import the JAR as a **Java** extension in Burp 2026.3.3 or newer. Check **Extensions → Installed** for a load error. |
| **Worker** is not ready | Reopen Burp or click **Set up and start worker**. For a release JAR, Python is unnecessary. On macOS/Linux, confirm you downloaded the JAR for your CPU and allowed the bundled local executable to run. |
| **Bridged** stays at zero | Apply the settings, ensure the checkbox is on, and enter only the hostname (for example, `example.com`, without `https://` or a path). Confirm the request passes through Burp's HTTP stack. |
| The target still blocks | Try a different browser profile. Compare cookies and request headers with the browser. A TLS profile cannot execute JavaScript, change your IP or account reputation, or bypass every application rule. |
| A request fails under heavy load | The bridge accepts up to 32 in-flight requests, 16 MiB per request, and 32 MiB per response. Reduce concurrency or split large uploads. Failed requests are not silently retried. |

A browser challenge cookie may be tied to another client fingerprint. Strip
only the named cookies for hosts where you observed that mismatch. The
optional cookie list applies to all selected hosts. Burp 2026.3.3 uses a
compatibility relay, so history or Repeater may show its local connection
target and `X-Bridge-*` metadata; Burp 2026.7+ keeps the original request
visible. Test only targets you are authorized to assess.

## Credits

This project builds on the earlier MIT-licensed TLS Bypass prototype;
its copyright notice is retained in [LICENSE](LICENSE). Burp Suite and
the Montoya API are PortSwigger products.
