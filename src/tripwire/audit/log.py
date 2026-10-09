from __future__ import annotations

import hashlib
import json
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
    tool_executed: bool
    prev_hash: str | None
    hash: str


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
        tool_executed: bool,
    ) -> AuditEvent:
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
            prev_hash=prev_hash,
            hash="",
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
        previous: str | None = None
        for event in self.read_events():
            if event.prev_hash != previous:
                return False
            if _event_hash(event.model_copy(update={"hash": ""})) != event.hash:
                return False
            previous = event.hash
        return True

    def _last_hash(self) -> str | None:
        previous: str | None = None
        for event in self.read_events():
            previous = event.hash
        return previous


def _event_hash(event: AuditEvent) -> str:
    payload = event.model_dump(mode="json", exclude={"hash"})
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
