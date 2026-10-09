"""MCP front end: MCP clients call tools, and every call goes through the gateway.

Stdio is for local development only: it runs the gateway in the client's process. Deploy
with --transport http so the gateway stays outside the agent's container.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import anyio
import mcp_types as types
from mcp.server.lowlevel import Server

from tripwire.gateway import DecisionAction, TripwireGateway
from tripwire.proxy.server import build_gateway

TOOL_SCHEMAS: dict[str, tuple[str, dict[str, Any]]] = {
    "read_customer": (
        "Read a customer record.",
        {
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
            "required": ["customer_id"],
        },
    ),
    "read_ticket": (
        "Read a support ticket.",
        {
            "type": "object",
            "properties": {"ticket_id": {"type": "string"}, "customer_id": {"type": "string"}},
            "required": ["ticket_id"],
        },
    ),
    "search_docs": (
        "Search product documentation.",
        {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
    ),
    "send_email": (
        "Send an email.",
        {
            "type": "object",
            "properties": {"to": {"type": "string"}, "subject": {"type": "string"}},
            "required": ["to", "subject"],
        },
    ),
    "http_post": (
        "POST to a URL.",
        {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    ),
}


def build_mcp_server(gateway: TripwireGateway) -> Server:
    async def list_tools(
        _ctx: Any, _params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        # Advertise only what the contract allows; other names are still authorized and audited.
        names = sorted(name for name in gateway.contract.allowed_tools if name in TOOL_SCHEMAS)
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=name, description=TOOL_SCHEMAS[name][0], input_schema=TOOL_SCHEMAS[name][1]
                )
                for name in names
            ]
        )

    async def call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        result = await anyio.to_thread.run_sync(
            gateway.call_tool, params.name, dict(params.arguments or {})
        )
        payload = {
            "event_id": result.event_id,
            "decision": result.decision.model_dump(mode="json"),
            "data": result.data,
        }
        return types.CallToolResult(
            content=[types.TextContent(text=json.dumps(payload))],
            structured_content=payload,
            is_error=result.decision.action is DecisionAction.DENY,
        )

    return Server("tripwire", on_list_tools=list_tools, on_call_tool=call_tool)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Tripwire as an MCP server.")
    parser.add_argument("--transport", choices=["stdio", "http"], default="http")
    parser.add_argument("--host", default=os.getenv("TRIPWIRE_HOST", "127.0.0.1"))
    parser.add_argument("--port", default=int(os.getenv("TRIPWIRE_MCP_PORT", "8081")), type=int)
    parser.add_argument(
        "--contract",
        default=os.getenv("TRIPWIRE_CONTRACT", "examples/contracts/support_summary.yaml"),
    )
    parser.add_argument(
        "--audit-log",
        default=os.getenv("TRIPWIRE_AUDIT_LOG", ".tripwire/mcp-audit.jsonl"),
    )
    args = parser.parse_args()

    gateway = build_gateway(contract_path=Path(args.contract), audit_log_path=Path(args.audit_log))
    server = build_mcp_server(gateway)
    if args.transport == "stdio":
        anyio.run(_run_stdio, server)
        return

    import uvicorn

    uvicorn.run(server.streamable_http_app(host=args.host), host=args.host, port=args.port)


async def _run_stdio(server: Server) -> None:
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    main()
