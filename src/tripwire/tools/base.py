from __future__ import annotations

from typing import Any, Protocol

from tripwire.contracts.models import ToolCall


class ToolRegistry(Protocol):
    """What the gateway needs from a tool backend (in-process or over HTTP)."""

    call_counts: dict[str, int]

    def has_tool(self, name: str) -> bool: ...

    def validate(self, call: ToolCall) -> str | None: ...

    def resource_scope(self, call: ToolCall) -> dict[str, str]: ...

    def preview(self, call: ToolCall) -> str:
        """Side-effect-free text of the resource a call targets, for gateway-side checks."""
        ...

    def run(self, call: ToolCall) -> dict[str, Any]: ...
