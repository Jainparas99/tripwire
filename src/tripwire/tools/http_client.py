from __future__ import annotations

import json
from typing import Any
from urllib.request import Request, urlopen

from tripwire.contracts.models import ToolCall


class HttpToolRegistry:
    """Tool registry backed by the mock-tools HTTP service."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.call_counts: dict[str, int] = {}

    def has_tool(self, name: str) -> bool:
        response = self._post("/tools/has", {"tool": name})
        return bool(response["has_tool"])

    def validate(self, call: ToolCall) -> str | None:
        response = self._post("/tools/validate", call.model_dump(mode="json"))
        reason = response.get("reason")
        return str(reason) if reason is not None else None

    def resource_scope(self, call: ToolCall) -> dict[str, str]:
        response = self._post("/tools/resource-scope", call.model_dump(mode="json"))
        scope = response.get("scope", {})
        return {str(key): str(value) for key, value in scope.items()}

    def preview(self, call: ToolCall) -> str:
        response = self._post("/tools/preview", call.model_dump(mode="json"))
        return str(response.get("preview", ""))

    def run(self, call: ToolCall) -> dict[str, Any]:
        self.call_counts[call.tool] = self.call_counts.get(call.tool, 0) + 1
        response = self._post("/tools/call", call.model_dump(mode="json"))
        data = response.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("tool service returned non-object data")
        return data

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self.base_url}{path}",
            data=encoded,
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            raw = response.read()
        decoded = json.loads(raw.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("tool service returned non-object JSON")
        return decoded
