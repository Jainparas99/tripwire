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
    def allow(
        cls,
        *,
        containment_state: ContainmentState = ContainmentState.OK,
        reason_codes: tuple[str, ...] = (),
        score: int = 0,
        evidence_event_ids: tuple[str, ...] = (),
    ) -> "Decision":
        return cls(
            action=DecisionAction.ALLOW,
            containment_state=containment_state,
            reason_codes=reason_codes,
            score=score,
            evidence_event_ids=evidence_event_ids,
        )

    @classmethod
    def deny(
        cls,
        *reason_codes: str,
        containment_state: ContainmentState = ContainmentState.OK,
        score: int = 0,
        evidence_event_ids: tuple[str, ...] = (),
    ) -> "Decision":
        return cls(
            action=DecisionAction.DENY,
            containment_state=containment_state,
            reason_codes=tuple(reason_codes or ("DENY",)),
            score=score,
            evidence_event_ids=evidence_event_ids,
        )


class GatewayResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Decision
    data: dict[str, Any] | None
    event_id: str
