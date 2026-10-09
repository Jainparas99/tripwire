from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from tripwire.contracts.models import ToolCall
from tripwire.gateway.models import ContainmentState, Decision, DecisionAction


class AuditEvent(BaseModel):
    """Append-only record for one attempted protected tool call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    ts: datetime
    session_id: str
    task_id: str
    contract_hash: str
    seq: int
    attempted: ToolCall
    decision: DecisionAction
    containment_state: ContainmentState
    reason_codes: tuple[str, ...] = Field(default_factory=tuple)
    score: int = 0
    # ``tool_executed`` is retained as a compatibility field and means that the
    # invocation completed successfully. The explicit fields make failures clear.
    tool_executed: bool
    tool_invoked: bool = False
    tool_completed: bool = False
    prev_hash: str | None
    hash: str
    source_resource: str | None = None
    sensitivity: str | None = None
    untrusted_content_seen: bool = False


class AuditLog:
    """JSONL audit log with a SHA-256 hash chain."""

    def __init__(self, path: str | Path, *, reset: bool = False) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if reset:
            self.path.write_text("", encoding="utf-8")
        elif not self.path.exists():
            self.path.touch()

    def append(
        self,
        *,
        session_id: str,
        task_id: str,
        contract_hash: str,
        seq: int,
        attempted: ToolCall,
        decision: Decision,
        tool_executed: bool | None = None,
        tool_invoked: bool | None = None,
        tool_completed: bool | None = None,
        source_resource: str | None = None,
        sensitivity: str | None = None,
        untrusted_content_seen: bool = False,
    ) -> AuditEvent:
        if tool_completed is None:
            tool_completed = bool(tool_executed)
        if tool_invoked is None:
            tool_invoked = bool(tool_executed)
        if tool_executed is None:
            tool_executed = tool_completed
        if tool_completed and not tool_invoked:
            raise ValueError("a completed tool call must have been invoked")
        prev_hash = self._last_hash()
        event_without_hash = AuditEvent(
            event_id=f"evt_{seq:06d}",
            ts=datetime.now(UTC),
            session_id=session_id,
            task_id=task_id,
            contract_hash=contract_hash,
            seq=seq,
            attempted=attempted,
            decision=decision.action,
            containment_state=decision.containment_state,
            reason_codes=decision.reason_codes,
            score=decision.score,
            tool_executed=tool_executed,
            tool_invoked=tool_invoked,
            tool_completed=tool_completed,
            prev_hash=prev_hash,
            hash="",
            source_resource=source_resource,
            sensitivity=sensitivity,
            untrusted_content_seen=untrusted_content_seen,
        )
        event_hash = _event_hash(event_without_hash)
        event = event_without_hash.model_copy(update={"hash": event_hash})
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json() + "\n")
        return event

    def read_events(self) -> list[AuditEvent]:
        events: list[AuditEvent] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(AuditEvent.model_validate_json(line))
        return events

    def verify_chain(self) -> bool:
        return _chain_valid(self.read_events())

    def build_index(self, path: str | Path | None = None) -> Path:
        """Rebuild a queryable SQLite index from a verified JSONL chain."""
        target = Path(path) if path is not None else self.path.with_suffix(".sqlite3")
        if target.resolve() == self.path.resolve():
            raise ValueError("index path must differ from the JSONL source")
        events = self.read_events()
        if not _chain_valid(events):
            raise ValueError("cannot index an invalid audit chain")

        target.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(target)) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    position INTEGER PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    containment_state TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    event_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_session_seq ON audit_events(session_id, seq);
                CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision);
                CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_events(tool);
                CREATE TABLE IF NOT EXISTS audit_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            connection.execute("DELETE FROM audit_events")
            connection.execute("DELETE FROM audit_meta")
            connection.executemany(
                """
                INSERT INTO audit_events
                    (position, session_id, seq, event_id, tool, decision,
                     containment_state, hash, event_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        position,
                        event.session_id,
                        event.seq,
                        event.event_id,
                        event.attempted.tool,
                        event.decision.value,
                        event.containment_state.value,
                        event.hash,
                        event.model_dump_json(),
                    )
                    for position, event in enumerate(events, start=1)
                ],
            )
            connection.executemany(
                "INSERT INTO audit_meta (key, value) VALUES (?, ?)",
                [
                    ("event_count", str(len(events))),
                    ("final_hash", events[-1].hash if events else ""),
                ],
            )
        return target

    def _last_hash(self) -> str | None:
        previous: str | None = None
        for event in self.read_events():
            previous = event.hash
        return previous


def _event_hash(event: AuditEvent) -> str:
    # Exclude newly introduced default fields when validating an older entry
    # that never serialized them. New entries explicitly set the fields, so
    # they remain covered by the hash chain.
    payload = event.model_dump(mode="json", exclude={"hash"}, exclude_unset=True)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _chain_valid(events: list[AuditEvent]) -> bool:
    previous: str | None = None
    for event in events:
        if event.prev_hash != previous:
            return False
        if _event_hash(event.model_copy(update={"hash": ""})) != event.hash:
            return False
        previous = event.hash
    return True
