from __future__ import annotations

from typing import Any

from tripwire.gateway import TripwireGateway


def handle_tool_call(gateway: TripwireGateway, payload: dict[str, Any]) -> dict[str, Any]:
    tool = payload.get("tool")
    arguments = payload.get("arguments", {})
    if not isinstance(tool, str) or not tool:
        raise ValueError("payload.tool must be a non-empty string")
    if not isinstance(arguments, dict):
        raise ValueError("payload.arguments must be an object")

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
        return _error(request_id, -32602, "params must be an object")
    try:
        return {"jsonrpc": "2.0", "id": request_id, "result": handle_tool_call(gateway, params)}
    except ValueError as exc:
        return _error(request_id, -32602, str(exc))


def _error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
