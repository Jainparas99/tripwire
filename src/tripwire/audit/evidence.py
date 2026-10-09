from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tripwire.audit.log import AuditEvent, AuditLog


def build_evidence_report(
    audit_paths: list[str | Path], *, evaluation_metrics: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build a JSON-serializable evidence report from one or more audit logs."""
    logs: list[dict[str, Any]] = []
    all_events: list[AuditEvent] = []
    for raw_path in audit_paths:
        path = Path(raw_path)
        audit = AuditLog(path)
        events = audit.read_events()
        chain_valid = audit.verify_chain()
        blocked_events = [event for event in events if _is_blocked(event)]
        logs.append(
            {
                "path": str(path),
                "chain_valid": chain_valid,
                "event_count": len(events),
                "final_hash": events[-1].hash if events else None,
                "blocked_events": [_blocked_event(event) for event in blocked_events],
                "denied_calls_executed": sum(
                    event.decision == "DENY" and event.tool_invoked for event in events
                ),
            }
        )
        all_events.extend(events)

    report: dict[str, Any] = {
        "chain_valid": all(log["chain_valid"] for log in logs),
        "logs": logs,
        "metrics": _metrics(all_events),
    }
    if evaluation_metrics is not None:
        report["evaluation"] = evaluation_metrics
    return report


def _is_blocked(event: AuditEvent) -> bool:
    return event.decision == "DENY" or event.containment_state in {"PAUSED", "KILLED"}


def _blocked_event(event: AuditEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "seq": event.seq,
        "tool": event.attempted.tool,
        "decision": event.decision.value,
        "containment_state": event.containment_state.value,
        "reason_codes": list(event.reason_codes),
        "tool_invoked": event.tool_invoked,
        "tool_completed": event.tool_completed,
        "source_resource": event.source_resource,
        "sensitivity": event.sensitivity,
    }


def _metrics(events: list[AuditEvent]) -> dict[str, Any]:
    denied = [event for event in events if event.decision == "DENY"]
    return {
        "events": len(events),
        "allowed_events": len(events) - len(denied),
        "denied_events": len(denied),
        "blocked_events": sum(_is_blocked(event) for event in events),
        "tool_invocations": sum(event.tool_invoked for event in events),
        "tool_completions": sum(event.tool_completed for event in events),
        "denied_calls_executed": sum(
            event.decision == "DENY" and event.tool_invoked for event in events
        ),
        "containment_events": sum(
            event.containment_state in {"PAUSED", "KILLED"} for event in events
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a verified Tripwire evidence report.")
    parser.add_argument("audit_logs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, help="Write JSON to this path instead of stdout")
    parser.add_argument("--metrics-json", type=Path, help="Include metrics from an eval JSON file")
    args = parser.parse_args()

    evaluation_metrics = None
    if args.metrics_json is not None:
        evaluation_metrics = json.loads(args.metrics_json.read_text(encoding="utf-8"))
        if not isinstance(evaluation_metrics, dict):
            raise ValueError("evaluation metrics must be a JSON object")

    encoded = (
        json.dumps(
            build_evidence_report(args.audit_logs, evaluation_metrics=evaluation_metrics),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(args.output)


if __name__ == "__main__":
    main()
