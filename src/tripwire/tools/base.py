from __future__ import annotations

from typing import Any, Protocol

from tripwire.contracts.models import ToolCall

TOOL_ARGUMENTS: dict[str, frozenset[str]] = {
    "read_customer": frozenset({"customer_id"}),
    "read_ticket": frozenset({"ticket_id", "customer_id"}),
    "search_docs": frozenset({"query"}),
    "send_email": frozenset({"to", "subject"}),
    "http_post": frozenset({"url"}),
}


class ToolRegistry(Protocol):
    """What the gateway needs from a tool backend (in-process or over HTTP)."""

    call_counts: dict[str, int]

    def has_tool(self, name: str) -> bool: ...

    def allowed_arguments(self, name: str) -> frozenset[str]: ...

    def validate(self, call: ToolCall) -> str | None: ...

    def resource_scope(self, call: ToolCall) -> dict[str, str]: ...

    def preview(self, call: ToolCall) -> str:
        """Side-effect-free text of the resource a call targets, for gateway-side checks."""
        ...

    def run(self, call: ToolCall) -> dict[str, Any]: ...
