from __future__ import annotations

from tripwire.audit import AuditEvent
from tripwire.investigation.models import Claim, IncidentReport


def build_template_report(events: list[AuditEvent]) -> IncidentReport:
    flagged = [
        event
        for event in events
        if event.decision == "DENY" or event.containment_state in {"WARN", "PAUSED", "KILLED"}
    ]
    source_events = flagged or events
    severity = _severity(source_events)
    stages = tuple(dict.fromkeys(_stage(event) for event in source_events))
    timeline = tuple(_timeline_line(event) for event in source_events)
    claims = tuple(
        Claim(
            text=_claim_text(event),
            event_ids=(event.event_id,),
            tool=event.attempted.tool,
        )
        for event in source_events
    )
    return IncidentReport(
        report_id="template-report",
        severity=severity,
        summary=_summary(source_events, severity),
        stage_labels=stages,
        timeline=timeline,
        claims=claims,
    )


def _severity(events: list[AuditEvent]) -> str:
    states = {event.containment_state for event in events}
    if "KILLED" in states:
        return "critical"
    if "PAUSED" in states:
        return "high"
    if any(event.decision == "DENY" for event in events):
        return "medium"
    if "WARN" in states:
        return "low"
    return "informational"


def _summary(events: list[AuditEvent], severity: str) -> str:
    denied = sum(1 for event in events if event.decision == "DENY")
    contained = sum(1 for event in events if event.containment_state in {"PAUSED", "KILLED"})
    return (
        f"{severity.title()} Tripwire report: "
        f"{denied} denied event(s), {contained} contained event(s)."
    )


def _timeline_line(event: AuditEvent) -> str:
    return (
        f"{event.event_id}: {event.attempted.tool} -> {event.decision}"
        f" / {event.containment_state} ({', '.join(event.reason_codes) or 'no findings'})"
    )


def _claim_text(event: AuditEvent) -> str:
    reasons = ", ".join(event.reason_codes) or "no findings"
    return f"{event.event_id} attempted {event.attempted.tool}; reasons: {reasons}."


def _stage(event: AuditEvent) -> str:
    reasons = set(event.reason_codes)
    if "HONEYTOKEN_TOUCH" in reasons:
        return "credential_access"
    if "DESTINATION_NOT_ALLOWED" in reasons or "READ_THEN_SEND" in reasons:
        return "escape_attempt"
    if "UNKNOWN_TOOL" in reasons or "TOOL_NOT_ALLOWED" in reasons:
        return "execution_attempt"
    if "CUSTOMER_SCOPE_VIOLATION" in reasons or "ENUMERATION" in reasons:
        return "recon"
    if "MAX_ACTIONS_EXCEEDED" in reasons or "RETRY_AFTER_DENIAL" in reasons:
        return "persistence"
    return "benign_activity"
