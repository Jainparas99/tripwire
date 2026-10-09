from __future__ import annotations

from typing import Any

from tripwire.gateway import TripwireGateway


def handle_tool_call(gateway: TripwireGateway, payload: dict[str, Any]) -> dict[str, Any]:
    """Run one tool call. Malformed payloads are denied and audited, never dropped."""
    tool = payload.get("tool")
    arguments = payload.get("arguments", {})
    if not isinstance(tool, str) or not tool or not isinstance(arguments, dict):
        result = gateway.reject_malformed(payload)
    else:
        result = gateway.call_tool(tool, arguments)
    return {
        "event_id": result.event_id,
        "decision": result.decision.model_dump(mode="json"),
        "data": result.data,
    }


def handle_json_rpc(gateway: TripwireGateway, payload: dict[str, Any]) -> dict[str, Any]:
    request_id = payload.get("id")
    if payload.get("jsonrpc") != "2.0":
        return _error(request_id, -32600, "invalid JSON-RPC version")
    if payload.get("method") != "tools/call":
        return _error(request_id, -32601, "unsupported method")

    params = payload.get("params")
    if not isinstance(params, dict):
        gateway.reject_malformed(payload)
        return _error(request_id, -32602, "params must be an object")
    if "tool" not in params and "name" in params:
        # MCP names the tool `name`; the plain /tool-call body names it `tool`.
        params = {"tool": params["name"], "arguments": params.get("arguments", {})}
    return {"jsonrpc": "2.0", "id": request_id, "result": handle_tool_call(gateway, params)}


def _error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
