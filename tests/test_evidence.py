from pathlib import Path

from tripwire.audit import AuditLog, build_evidence_report
from tripwire.contracts import TaskContract
from tripwire.gateway import TripwireGateway
from tripwire.tools import MockToolRegistry


def test_evidence_report_contains_hash_blocked_events_and_execution_invariant(
    tmp_path: Path,
) -> None:
    contract = TaskContract(
        task_id="evidence-test",
        description="Read Customer A",
        principal="tester",
        scope={"customer_id": "A"},
        allowed_tools=frozenset({"read_customer"}),
        max_actions=2,
    )
    audit = AuditLog(tmp_path / "audit.jsonl", reset=True)
    gateway = TripwireGateway(contract=contract, audit_log=audit, tools=MockToolRegistry())
    gateway.call_tool("read_customer", {"customer_id": "B"})

    report = build_evidence_report([audit.path], evaluation_metrics={"false_block_rate": 0.0})

    assert report["chain_valid"] is True
    assert report["logs"][0]["final_hash"] == audit.read_events()[-1].hash
    assert report["logs"][0]["blocked_events"][0]["reason_codes"] == ["CUSTOMER_SCOPE_VIOLATION"]
    assert report["metrics"]["denied_calls_executed"] == 0
    assert report["evaluation"] == {"false_block_rate": 0.0}
