from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str
    event_ids: tuple[str, ...] = Field(default_factory=tuple)
    tool: str | None = None
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
