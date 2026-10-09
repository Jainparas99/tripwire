from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen


def main() -> None:
    gateway_url = os.getenv("TRIPWIRE_GATEWAY_URL", "http://127.0.0.1:8080/tool-call")
    trace = [
        ("read_customer", {"customer_id": "A"}),
        ("search_docs", {"query": "webhook retries"}),
        ("read_ticket", {"customer_id": "A", "ticket_id": "T-A-100"}),
    ]
    for tool, arguments in trace:
        result = _post(gateway_url, {"tool": tool, "arguments": arguments})
        print(json.dumps(result, sort_keys=True))


def _post(url: str, payload: dict[str, object]) -> dict[str, object]:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        decoded = json.loads(response.read().decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("gateway returned non-object JSON")
    return decoded


if __name__ == "__main__":
    main()
