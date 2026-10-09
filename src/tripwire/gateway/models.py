from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DecisionAction(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class ContainmentState(StrEnum):
    OK = "OK"
    WARN = "WARN"
    PAUSED = "PAUSED"
    KILLED = "KILLED"


class Decision(BaseModel):
    """Authorization result. WARN is containment state, not a blocking decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: DecisionAction
    containment_state: ContainmentState = ContainmentState.OK
    reason_codes: tuple[str, ...] = Field(default_factory=tuple)
    score: int = 0
    evidence_event_ids: tuple[str, ...] = Field(default_factory=tuple)

    @classmethod
    def allow(cls) -> "Decision":
        return cls(action=DecisionAction.ALLOW)

    @classmethod
    def deny(cls, *reason_codes: str) -> "Decision":
        return cls(action=DecisionAction.DENY, reason_codes=tuple(reason_codes or ("DENY",)))


class GatewayResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Decision
    data: dict[str, Any] | None
    event_id: str
