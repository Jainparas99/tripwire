from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from tripwire.audit import AuditEvent
from tripwire.investigation.models import Claim, IncidentReport
from tripwire.investigation.template import build_template_report


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    verified: bool
    invalid_claims: tuple[str, ...] = Field(default_factory=tuple)
    report: IncidentReport


def verify_report(report: IncidentReport, events: list[AuditEvent]) -> VerificationResult:
    events_by_id = {event.event_id: event for event in events}
    invalid: list[str] = []
    verified_claims: list[Claim] = []

    if not report.claims:
        invalid.append("report contains no claims")

    for index, claim in enumerate(report.claims, start=1):
        claim_errors = _verify_claim(index=index, claim=claim, events_by_id=events_by_id)
        invalid.extend(claim_errors)
        verified_claims.append(claim.model_copy(update={"verified": not claim_errors}))

    deterministic = build_template_report(events)
    narrative = report.model_narrative
    if narrative is None and report.generator != "template" and report.summary:
        narrative = report.summary
    verified_report = report.model_copy(
        update={
            "claims": tuple(verified_claims),
            "severity": deterministic.severity,
            "stage_labels": deterministic.stage_labels,
            # Only claims are checkable, so the headline summary always comes from the log.
            "summary": deterministic.summary,
            "model_narrative": narrative,
        }
    )
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
        if claim.arguments is not None:
            for key, value in claim.arguments.items():
                actual = event.attempted.arguments.get(key)
                if actual != value:
                    errors.append(
                        f"claim {index} says {key}={value!r} but {event_id} used {actual!r}"
                    )
        if claim.decision is not None and claim.decision != event.decision:
            errors.append(
                f"claim {index} says decision {claim.decision} but {event_id} was {event.decision}"
            )
        if (
            claim.containment_state is not None
            and claim.containment_state != event.containment_state
        ):
            errors.append(
                f"claim {index} says containment {claim.containment_state} but "
                f"{event_id} was {event.containment_state}"
            )
        if claim.tool_invoked is not None and claim.tool_invoked != event.tool_invoked:
            errors.append(
                f"claim {index} says tool_invoked={claim.tool_invoked} but "
                f"{event_id} was {event.tool_invoked}"
            )
        if claim.tool_completed is not None and claim.tool_completed != event.tool_completed:
            errors.append(
                f"claim {index} says tool_completed={claim.tool_completed} but "
                f"{event_id} was {event.tool_completed}"
            )
        if claim.tool_executed is not None and claim.tool_executed != event.tool_executed:
            errors.append(
                f"claim {index} says tool_executed={claim.tool_executed} but "
                f"{event_id} was {event.tool_executed}"
            )
    if claim.decision is None:
        errors.append(f"claim {index} does not state the event decision")
    if claim.tool_executed is None and claim.tool_completed is None:
        errors.append(f"claim {index} does not state whether the tool executed")
    return errors
