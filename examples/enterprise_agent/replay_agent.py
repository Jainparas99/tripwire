"""Scripted agent: replays one synthetic scenario against the gateway over HTTP.

Standard library only, so the agent image needs nothing but this file and
scenarios.json. It holds no contract, tool data or honeytoken list.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

SCENARIO_FILE = Path(__file__).with_name("scenarios.json")


def main() -> None:
    gateway_url = os.getenv("TRIPWIRE_GATEWAY_URL", "http://127.0.0.1:8080/tool-call")
    name = sys.argv[1] if len(sys.argv) > 1 else os.getenv("TRIPWIRE_SCENARIO", "slow_drift")
    scenario = json.loads(SCENARIO_FILE.read_text(encoding="utf-8"))[name]
    print(f"scenario: {scenario['title']}")
    for step in scenario["calls"]:
        result = _post(gateway_url, {"tool": step["tool"], "arguments": step["arguments"]})
        decision = result.get("decision", {})
        print(
            f"  {result.get('event_id')}  {step['tool']:<14} {decision.get('action'):<5} "
            f"{decision.get('containment_state'):<7} {','.join(decision.get('reason_codes', []))}"
        )


def _post(url: str, payload: dict[str, object]) -> dict[str, object]:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            decoded = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        decoded = json.loads(exc.read().decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("gateway returned non-object JSON")
    return decoded


if __name__ == "__main__":
    main()
