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


def test_concurrent_http_calls_keep_one_ordered_hash_chain(tmp_path: Path) -> None:
    import json
    from concurrent.futures import ThreadPoolExecutor
    from threading import Thread
    from urllib.request import Request, urlopen

    from tripwire.proxy.server import make_server

    contract = TaskContract(
        task_id="support-summary-001",
        description="Summarize Customer A support state",
        principal="user-123",
        scope={"customer_id": "A"},
        allowed_tools=frozenset({"search_docs"}),
        max_actions=25,
    )
    audit_log = AuditLog(tmp_path / "audit.jsonl", reset=True)
    gateway = TripwireGateway(contract=contract, audit_log=audit_log, session_id="sess_race")
    server = make_server(host="127.0.0.1", port=0, gateway=gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/tool-call"

    def post(index: int) -> str:
        body = json.dumps({"tool": "search_docs", "arguments": {"query": f"q{index}"}})
        request = Request(url, data=body.encode(), method="POST")
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read())["decision"]["action"]

    try:
        with ThreadPoolExecutor(max_workers=20) as pool:
            actions = list(pool.map(post, range(40)))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    events = audit_log.read_events()
    assert len(events) == 40
    assert [event.seq for event in events] == list(range(1, 41))
    assert audit_log.verify_chain()
    assert actions.count("ALLOW") == 25


def test_malformed_tool_call_is_denied_and_audited(tmp_path: Path) -> None:
    gateway, tools = _gateway(tmp_path)

    result = handle_tool_call(gateway, {"tool": "read_customer", "arguments": "customer B"})

    assert result["decision"]["action"] == "DENY"
    assert result["decision"]["reason_codes"] == ["MALFORMED_REQUEST"]
    assert tools.call_counts["read_customer"] == 0
    events = gateway._audit_log.read_events()
    assert len(events) == 1
    assert events[0].tool_executed is False
    assert "customer B" in events[0].attempted.arguments["raw"]


def test_non_json_http_body_is_audited(tmp_path: Path) -> None:
    from threading import Thread
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen

    import pytest

    from tripwire.proxy.server import make_server

    gateway, _tools = _gateway(tmp_path)
    server = make_server(host="127.0.0.1", port=0, gateway=gateway)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/tool-call"
        with pytest.raises(HTTPError) as excinfo:
            urlopen(Request(url, data=b"not json {", method="POST"), timeout=5)
        assert excinfo.value.code == 400
    finally:
        server.shutdown()
        thread.join(timeout=5)

    events = gateway._audit_log.read_events()
    assert [event.reason_codes for event in events] == [("MALFORMED_REQUEST",)]
    assert gateway._audit_log.verify_chain()
