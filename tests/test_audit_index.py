import sqlite3
from pathlib import Path

import pytest

from tripwire.audit import AuditLog
from tripwire.contracts import TaskContract
from tripwire.gateway import TripwireGateway
from tripwire.tools import MockToolRegistry


def _gateway(audit_log: AuditLog) -> TripwireGateway:
    contract = TaskContract(
        task_id="audit-index-test",
        description="Read Customer A",
        principal="tester",
        scope={"customer_id": "A"},
        allowed_tools=frozenset({"read_customer"}),
        max_actions=5,
    )
    return TripwireGateway(
        contract=contract,
        audit_log=audit_log,
        tools=MockToolRegistry(),
        session_id="reused-session",
    )


def test_index_rebuilds_from_verified_chain(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl", reset=True)
    _gateway(audit).call_tool("read_customer", {"customer_id": "A"})
    _gateway(audit).call_tool("read_customer", {"customer_id": "B"})

    index_path = audit.build_index()
    assert audit.verify_chain()
    with sqlite3.connect(index_path) as db:
        rows = db.execute(
            "SELECT position, seq, decision, tool, hash FROM audit_events ORDER BY position"
        ).fetchall()
        meta = dict(db.execute("SELECT key, value FROM audit_meta"))

    assert [row[:4] for row in rows] == [
        (1, 1, "ALLOW", "read_customer"),
        (2, 1, "DENY", "read_customer"),
    ]
    assert [row[4] for row in rows] == [event.hash for event in audit.read_events()]
    assert meta == {"event_count": "2", "final_hash": rows[-1][4]}

    audit.build_index()
    with sqlite3.connect(index_path) as db:
        assert db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 2


def test_tampered_chain_cannot_replace_existing_index(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl", reset=True)
    _gateway(audit).call_tool("read_customer", {"customer_id": "A"})
    index_path = audit.build_index()
    source = audit.path.read_text(encoding="utf-8")
    audit.path.write_text(source.replace("read_customer", "send_email"), encoding="utf-8")

    with pytest.raises(ValueError, match="invalid audit chain"):
        audit.build_index()

    with sqlite3.connect(index_path) as db:
        assert db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1


def test_empty_chain_and_same_path_guard(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl", reset=True)

    with pytest.raises(ValueError, match="must differ"):
        audit.build_index(audit.path)

    with sqlite3.connect(audit.build_index()) as db:
        assert db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0
        assert dict(db.execute("SELECT key, value FROM audit_meta")) == {
            "event_count": "0",
            "final_hash": "",
        }
