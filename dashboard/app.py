from __future__ import annotations

from pathlib import Path

import streamlit as st

from tripwire.audit import AuditLog
from tripwire.evaluation.runner import run_eval
from tripwire.investigation.template import build_template_report
from tripwire.investigation.verifier import verify_report

ROOT = Path(__file__).resolve().parents[1]
AUDIT_LOG = ROOT / ".tripwire/demo-audit.jsonl"
TRACE_FILE = ROOT / "evaluation/traces/checkpoint_b.yaml"
CONTRACT_FILE = ROOT / "examples/contracts/support_summary.yaml"


def main() -> None:
    st.set_page_config(page_title="Tripwire", layout="wide")
    st.title("Tripwire")

    metrics = run_eval(contract_path=CONTRACT_FILE, trace_path=TRACE_FILE)
    metric_cols = st.columns(4)
    metric_cols[0].metric("Attack detection", f"{metrics['attack_detection_rate']:.0%}")
    metric_cols[1].metric("False blocks", f"{metrics['false_block_rate']:.0%}")
    metric_cols[2].metric("Containment", f"{metrics['attack_containment_rate']:.0%}")
    metric_cols[3].metric("Executed while blocked", metrics["executed_while_blocked"])

    events = _read_events()
    left, right = st.columns([3, 2])
    with left:
        st.subheader("Timeline")
        if not events:
            st.info("Run `make demo` to create `.tripwire/demo-audit.jsonl`.")
        for event in events:
            st.write(
                {
                    "event_id": event.event_id,
                    "tool": event.attempted.tool,
                    "decision": event.decision,
                    "containment": event.containment_state,
                    "executed": event.tool_executed,
                    "reasons": event.reason_codes,
                }
            )

    with right:
        st.subheader("Incident Report")
        if events:
            report = build_template_report(events)
            verified = verify_report(report, events)
            st.write({"verified": verified.verified, "severity": verified.report.severity})
            for line in verified.report.timeline:
                st.write(line)
        else:
            st.write("No audit events yet.")


def _read_events():
    if not AUDIT_LOG.exists():
        return []
    return AuditLog(AUDIT_LOG).read_events()


if __name__ == "__main__":
    main()
