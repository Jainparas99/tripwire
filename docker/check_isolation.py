"""Verify the untrusted agent can reach only the gateway network boundary."""

from __future__ import annotations

import os
import sys
from urllib.request import ProxyHandler, build_opener


def _reachable(url: str) -> bool:
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(url, timeout=3):
            return True
    except OSError:
        return False


def main() -> int:
    gateway_url = os.getenv("TRIPWIRE_GATEWAY_URL", "http://gateway:8080/tool-call")
    if not _reachable(gateway_url.replace("/tool-call", "/healthz")):
        print("FAIL: agent cannot reach the gateway", file=sys.stderr)
        return 1

    forbidden = {
        "mock-tools": "http://mock-tools:9090/healthz",
        "internet": "https://example.com/",
    }
    failures = [name for name, url in forbidden.items() if _reachable(url)]
    if failures:
        print(f"FAIL: agent reached forbidden endpoints: {', '.join(failures)}", file=sys.stderr)
        return 1

    print("PASS: gateway reachable; mock tools and internet unreachable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
