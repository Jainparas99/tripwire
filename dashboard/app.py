from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

from tripwire.audit import AuditEvent, AuditLog
from tripwire.contracts import load_task_contract
from tripwire.evaluation.runner import run_eval
from tripwire.investigation.cache import load_cached_report
from tripwire.investigation.template import build_template_report
from tripwire.investigation.verifier import verify_report

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = Path(os.getenv("TRIPWIRE_LOG_DIR", ROOT / ".tripwire"))
REPORT_DIR = LOG_DIR / "reports"
TRACE_FILE = ROOT / "evaluation/traces/checkpoint_b.yaml"
CONTRACT_FILE = ROOT / "examples/contracts/support_summary.yaml"

# Containment colours: green -> amber -> red -> contained.
STATE_COLOR = {"OK": "green", "WARN": "orange", "PAUSED": "red", "KILLED": "red"}
STATE_LABEL = {"OK": "OK", "WARN": "WARN", "PAUSED": "PAUSED (contained)", "KILLED": "KILLED"}
DECISION_COLOR = {"ALLOW": "green", "DENY": "red"}
LOG_ORDER = ["demo-live", "demo-slow_drift", "demo-escape", "demo-benign", "gateway-audit"]


def main() -> None:
    st.set_page_config(page_title="Tripwire", layout="wide")
    st.title("Tripwire")
    st.caption(
        "Deterministic task-contract enforcement for agent tool calls. "
        "Replays are synthetic fixtures."
    )

    logs = _audit_logs()
    if not logs:
        st.info("No audit logs yet. Run `make demo` to replay the scripted scenarios.")
        _eval_panel()
        return

    selected = st.sidebar.radio("Audit log", logs, format_func=lambda path: path.stem)
    if st.sidebar.button("Reload"):
        st.rerun()
    events = AuditLog(selected).read_events()
    if not events:
        st.info(f"{selected.name} is empty.")
        return

    _status_row(events, selected)
    timeline, side = st.columns([3, 2], gap="large")
    with timeline:
        _timeline(events)
    with side:
        _blocked_panel(events)
        _report_panel(events)
    _eval_panel()


def _audit_logs() -> list[Path]:
    logs = [path for path in LOG_DIR.glob("*.jsonl") if path.stat().st_size > 0]
    rank = {stem: index for index, stem in enumerate(LOG_ORDER)}
    return sorted(logs, key=lambda path: (rank.get(path.stem, len(rank)), path.stem))


def _status_row(events: list[AuditEvent], log_path: Path) -> None:
    final = events[-1]
    blocked = [event for event in events if event.decision == "DENY"]
    executed_while_blocked = sum(
        1
        for event in events
        if event.tool_executed
        and (event.decision == "DENY" or event.containment_state in {"PAUSED", "KILLED"})
    )
    kill = load_task_contract(CONTRACT_FILE).thresholds.get("kill", 10)

    state = final.containment_state
    st.markdown(
        f"### Session `{final.session_id}` :{STATE_COLOR[state]}-background[{STATE_LABEL[state]}]"
    )
    cols = st.columns(5)
    cols[0].metric("Attempted", len(events))
    cols[1].metric("Blocked", len(blocked))
    cols[2].metric("Ran while blocked", executed_while_blocked)
    cols[3].metric("Score", f"{final.score} / {kill}")
    cols[4].metric("Audit chain", "valid" if AuditLog(log_path).verify_chain() else "BROKEN")


def _timeline(events: list[AuditEvent]) -> None:
    st.subheader("Timeline")
    for event in events:
        decision = event.decision.value
        state = event.containment_state.value
        executed = "executed" if event.tool_executed else "not executed"
        reasons = ", ".join(event.reason_codes) or "no findings"
        st.markdown(
            f"`{event.event_id}` **{event.attempted.tool}** "
            f":{DECISION_COLOR[decision]}-background[{decision}] "
            f":{STATE_COLOR[state]}[{state}] · score {event.score} · {executed}  \n"
            f"<small>{_arguments(event)} — {reasons}</small>",
            unsafe_allow_html=True,
        )


def _arguments(event: AuditEvent) -> str:
    args = ", ".join(f"{key}={value}" for key, value in event.attempted.arguments.items())
    return args.replace("<", "&lt;").replace(">", "&gt;") or "no arguments"


def _blocked_panel(events: list[AuditEvent]) -> None:
    st.subheader("Blocked actions")
    blocked = [event for event in events if event.decision == "DENY"]
    if not blocked:
        st.success("Nothing blocked.")
        return
    for event in blocked:
        st.markdown(
            f"- `{event.event_id}` **{event.attempted.tool}** — {', '.join(event.reason_codes)}"
        )


def _report_panel(events: list[AuditEvent]) -> None:
    st.subheader("Incident report")
    report = load_cached_report(events, REPORT_DIR) or build_template_report(events)
    result = verify_report(report, events)
    st.markdown(
        f"**Severity:** {report.severity} · **Generator:** {report.generator} · "
        f"**Citations:** {'all verified' if result.verified else 'INVALID'}"
    )
    st.write(report.summary)
    if report.stage_labels:
        st.markdown("**Stages:** " + " → ".join(report.stage_labels))
    with st.expander("Claims", expanded=False):
        for claim in result.report.claims:
            mark = "✓" if claim.verified else "✗"
            st.markdown(f"{mark} {claim.text} ({', '.join(claim.event_ids)})")


def _eval_panel() -> None:
    with st.expander("Evaluation over fixture trajectories (`make eval`)", expanded=False):
        metrics = run_eval(contract_path=CONTRACT_FILE, trace_path=TRACE_FILE)
        rows = {
            "Trajectories": metrics["traces"],
            "Attack detection rate": f"{metrics['attack_detection_rate']:.0%}",
            "Attack containment rate": f"{metrics['attack_containment_rate']:.0%}",
            "False-block rate (benign)": f"{metrics['false_block_rate']:.0%}",
            "Median actions to contain": metrics["median_actions_to_contain"],
            "p95 decision latency (ms)": f"{metrics['p95_latency_ms']:.2f}",
            "Executed while blocked": metrics["executed_while_blocked"],
        }
        st.table({"metric": list(rows), "value": [str(value) for value in rows.values()]})


if __name__ == "__main__":
    main()
