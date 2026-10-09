from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tripwire.gateway.models import ContainmentState, DecisionAction


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str
    event_ids: tuple[str, ...] = Field(default_factory=tuple)
    tool: str | None = None
    arguments: dict[str, Any] | None = None
    decision: DecisionAction | None = None
    containment_state: ContainmentState | None = None
    tool_invoked: bool | None = None
    tool_completed: bool | None = None
    tool_executed: bool | None = None
    verified: bool | None = None


class IncidentReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: str
    generator: str = "template"
    severity: str
    summary: str
    stage_labels: tuple[str, ...] = Field(default_factory=tuple)
    timeline: tuple[str, ...] = Field(default_factory=tuple)
    claims: tuple[Claim, ...] = Field(default_factory=tuple)
