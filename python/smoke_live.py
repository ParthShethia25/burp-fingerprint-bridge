"""Optional read-only live transport smoke check: python smoke_live.py URL."""
import argparse
import asyncio
import os
import worker


async def main(url: str, strip: list[str]):
    os.environ["BRIDGE_TOKEN"] = "local-smoke-token"
    await worker.startup()
    try:
        result = await worker.proxy(worker.BridgeRequest(
            method="GET", url=url, strip_cookies=strip), "Bearer local-smoke-token")
        print(f"status={result['status_code']} bytes={len(result['body']) * 3 // 4} "
              f"elapsed_ms={result['elapsed_ms']}")
    finally:
        await worker.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--strip-cookie", action="append", default=[])
    args = parser.parse_args()
    asyncio.run(main(args.url, args.strip_cookie))
