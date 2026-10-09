from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from tripwire.audit import AuditEvent
from tripwire.investigation.models import Claim, IncidentReport


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    verified: bool
    invalid_claims: tuple[str, ...] = Field(default_factory=tuple)
    report: IncidentReport


def verify_report(report: IncidentReport, events: list[AuditEvent]) -> VerificationResult:
    events_by_id = {event.event_id: event for event in events}
    invalid: list[str] = []
    verified_claims: list[Claim] = []

    for index, claim in enumerate(report.claims, start=1):
        claim_errors = _verify_claim(index=index, claim=claim, events_by_id=events_by_id)
        invalid.extend(claim_errors)
        verified_claims.append(claim.model_copy(update={"verified": not claim_errors}))

    verified_report = report.model_copy(update={"claims": tuple(verified_claims)})
    return VerificationResult(
        verified=not invalid,
        invalid_claims=tuple(invalid),
        report=verified_report,
    )


def _verify_claim(
    *,
    index: int,
    claim: Claim,
    events_by_id: dict[str, AuditEvent],
) -> list[str]:
    errors: list[str] = []
    if not claim.event_ids:
        errors.append(f"claim {index} cites no events")
        return errors

    for event_id in claim.event_ids:
        event = events_by_id.get(event_id)
        if event is None:
            errors.append(f"claim {index} cites unknown event {event_id}")
            continue
        if claim.tool is not None and event.attempted.tool != claim.tool:
            errors.append(
                f"claim {index} says tool {claim.tool} but {event_id} used {event.attempted.tool}"
            )
    return errors
