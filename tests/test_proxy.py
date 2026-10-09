from pathlib import Path

from tripwire.audit import AuditLog
from tripwire.contracts import TaskContract
from tripwire.gateway import TripwireGateway
from tripwire.proxy import handle_json_rpc, handle_tool_call
from tripwire.tools import MockToolRegistry


def _gateway(tmp_path: Path) -> tuple[TripwireGateway, MockToolRegistry]:
    contract = TaskContract(
        task_id="support-summary-001",
        description="Summarize Customer A support state",
        principal="user-123",
        scope={"customer_id": "A"},
        allowed_tools=frozenset({"read_customer"}),
        allowed_destinations=(),
        max_actions=25,
    )
    tools = MockToolRegistry()
    gateway = TripwireGateway(
        contract=contract,
        audit_log=AuditLog(tmp_path / "audit.jsonl", reset=True),
        tools=tools,
        session_id="sess_proxy",
    )
    return gateway, tools


def test_tool_call_proxy_denies_without_invoking_tool(tmp_path: Path) -> None:
    gateway, tools = _gateway(tmp_path)

    result = handle_tool_call(gateway, {"tool": "read_customer", "arguments": {"customer_id": "B"}})

    assert result["decision"]["action"] == "DENY"
    assert result["data"] is None
    assert tools.call_counts["read_customer"] == 0


def test_json_rpc_tools_call(tmp_path: Path) -> None:
    gateway, tools = _gateway(tmp_path)

    result = handle_json_rpc(
        gateway,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"tool": "read_customer", "arguments": {"customer_id": "A"}},
        },
    )

    assert result["result"]["decision"]["action"] == "ALLOW"
    assert tools.call_counts["read_customer"] == 1


def test_json_rpc_rejects_unknown_method(tmp_path: Path) -> None:
    gateway, _tools = _gateway(tmp_path)

    result = handle_json_rpc(gateway, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    assert result["error"]["code"] == -32601
