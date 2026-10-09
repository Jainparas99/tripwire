from __future__ import annotations

import html
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

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
REMEDIATION_DIR = LOG_DIR / "remediation"
TRACE_FILE = ROOT / "evaluation/traces/checkpoint_b.yaml"
GAUNTLET_SNAPSHOT = ROOT / "evaluation/gauntlet_results.json"
REDTEAM_SNAPSHOT = ROOT / "evaluation/redteam_results.json"
CONTRACT_FILE = ROOT / "examples/contracts/support_summary.yaml"

STATE_CLASS = {"OK": "ok", "WARN": "warn", "PAUSED": "paused", "KILLED": "killed"}
STATE_RANK = {"OK": 0, "WARN": 1, "PAUSED": 2, "KILLED": 3}
STATE_LABEL = {"OK": "OK", "WARN": "WARN", "PAUSED": "PAUSED", "KILLED": "KILLED"}
DECISION_CLASS = {"ALLOW": "allow", "DENY": "deny"}
LOG_ORDER = ["demo-live", "demo-slow_drift", "demo-escape", "demo-benign", "gateway-audit"]


def main() -> None:
    st.set_page_config(page_title="Tripwire control plane", page_icon="◈", layout="wide")
    _inject_styles()

    st.markdown('<div class="tw-eyebrow">TRIPWIRE / CONTROL PLANE</div>', unsafe_allow_html=True)
    st.title("Containment, in one clear flow")
    st.caption(
        "Deterministic task-contract enforcement for agent tool calls. "
        "Synthetic fixtures and local evaluation artifacts are shown read-only."
    )

    logs = _audit_logs()
    _header_strip(logs)
    st.markdown('<div class="tw-flow-rule"></div>', unsafe_allow_html=True)

    live, incident, gauntlet, remediation, redteam, fleet = st.tabs(
        [
            "Live containment",
            "Incident report",
            "Model gauntlet",
            "Remediation",
            "Red-team",
            "Fleet",
        ]
    )
    with live:
        _live_containment(logs)
    with incident:
        _incident_report(logs)
    with gauntlet:
        _gauntlet_tab()
    with remediation:
        _remediation_tab()
    with redteam:
        _redteam_tab()
    with fleet:
        _fleet_tab(logs)


def _inject_styles() -> None:
    st.markdown(
        """
        <style>
        :root {
          --tw-ink: #17212b;
          --tw-muted: #5e6b78;
          --tw-line: #dbe3ea;
          --tw-panel: #f7f9fb;
          --tw-ok: #18794e;
          --tw-warn: #a96800;
          --tw-paused: #c05621;
          --tw-killed: #bd2c2c;
        }
        @media (prefers-color-scheme: dark) {
          :root {
            --tw-ink: #eef4f8;
            --tw-muted: #aebdca;
            --tw-line: #334451;
            --tw-panel: #18232c;
          }
        }
        .tw-eyebrow { color: var(--tw-muted); font-size: .72rem; font-weight: 800;
          letter-spacing: .14em; margin: .25rem 0 .45rem; }
        .tw-flow-rule { border-top: 1px solid var(--tw-line); margin: 1.1rem 0 1.25rem; }
        .tw-strip-label { color: var(--tw-muted); font-size: .75rem; font-weight: 700;
          letter-spacing: .08em; text-transform: uppercase; margin: .3rem 0 .5rem; }
        .tw-state-legend { color: var(--tw-muted); font-size: .82rem; margin: .65rem 0 0; }
        .state-badge, .decision-badge { border: 1px solid currentColor; border-radius: 999px;
          display: inline-flex; align-items: center; gap: .32rem; font-size: .75rem;
          font-weight: 800; line-height: 1; padding: .28rem .52rem; white-space: nowrap; }
        .state-badge::before, .decision-badge::before { content: ""; background: currentColor;
          border-radius: 50%; height: .42rem; width: .42rem; }
        .state-ok { color: var(--tw-ok); }
        .state-warn { color: var(--tw-warn); }
        .state-paused { color: var(--tw-paused); }
        .state-killed { color: var(--tw-killed); }
        .state-unknown { color: var(--tw-muted); }
        .decision-allow { color: var(--tw-ok); }
        .decision-deny { color: var(--tw-killed); }
        .decision-unknown { color: var(--tw-muted); }
        .tw-card { background: var(--tw-panel); border: 1px solid var(--tw-line);
          border-radius: 12px; padding: .8rem 1rem; margin: .35rem 0 .75rem; }
        .tw-card-title { color: var(--tw-ink); font-weight: 750; margin-bottom: .3rem; }
        .tw-muted { color: var(--tw-muted); }
        .tw-small { color: var(--tw-muted); font-size: .82rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _header_strip(logs: list[Path]) -> None:
    overview = _overview_metrics(logs)
    st.markdown('<div class="tw-strip-label">System posture</div>', unsafe_allow_html=True)
    cols = st.columns(4)
    cols[0].metric("Executed while blocked", str(overview["executed_while_blocked"]))
    cols[1].metric("Chain valid", overview["chain_valid"])
    cols[2].metric("Traces", str(overview["traces"]))
    cols[3].metric("False-block rate", overview["false_block_rate"])
    st.markdown(
        '<div class="tw-state-legend">State key: '
        '<span class="state-badge state-ok">OK</span> '
        '<span class="state-badge state-warn">WARN</span> '
        '<span class="state-badge state-paused">PAUSED</span> '
        '<span class="state-badge state-killed">KILLED</span> '
        '<span class="tw-muted">— text labels are always shown with color.</span></div>',
        unsafe_allow_html=True,
    )


def _overview_metrics(logs: list[Path]) -> dict[str, Any]:
    events_by_log = _read_all_logs(logs)
    executed = sum(
        _executed_while_blocked(event) for events in events_by_log.values() for event in events
    )
    chain = "n/a" if not logs else "valid" if all(_chain_valid(path) for path in logs) else "BROKEN"
    try:
        metrics = run_eval(contract_path=CONTRACT_FILE, trace_path=TRACE_FILE)
    except (OSError, KeyError, TypeError, ValueError):
        metrics = {}
    return {
        "executed_while_blocked": executed,
        "chain_valid": chain,
        "traces": metrics.get("traces", "n/a"),
        "false_block_rate": _percent(metrics.get("false_block_rate")),
    }


def _live_containment(logs: list[Path]) -> None:
    st.subheader("Live containment")
    st.caption("Choose a session to inspect its append-only, hash-chained event stream.")
    if not logs:
        st.info("No audit sessions yet. Run `make demo` to replay the scripted scenarios.")
        return

    selected = st.sidebar.radio("Audit session", logs, format_func=lambda path: path.stem)
    events = _read_events(selected)
    if not events:
        st.info(f"{selected.name} is empty or unreadable.")
        return

    _session_summary(events, selected)
    timeline, side = st.columns([3, 2], gap="large")
    with timeline:
        _timeline(events)
    with side:
        _blocked_panel(events)
        st.markdown(
            '<div class="tw-card"><div class="tw-card-title">Read-only session</div>'
            '<div class="tw-small">Events are loaded from the JSONL source of truth. '
            "The dashboard does not execute, retry, or mutate tool calls.</div></div>",
            unsafe_allow_html=True,
        )


def _session_summary(events: list[AuditEvent], log_path: Path) -> None:
    final = events[-1]
    state = _value(final.containment_state)
    blocked = [event for event in events if _value(event.decision) == "DENY"]
    executed = sum(_executed_while_blocked(event) for event in events)
    try:
        kill = load_task_contract(CONTRACT_FILE).thresholds.get("kill", 10)
    except (OSError, KeyError, TypeError, ValueError):
        kill = 10
    st.markdown(
        f'<div class="tw-card"><div class="tw-card-title">Session '
        f"<code>{html.escape(final.session_id)}</code> {_state_badge(state)}</div>"
        f'<div class="tw-small">Final containment state with explicit text and color.</div></div>',
        unsafe_allow_html=True,
    )
    cols = st.columns(5)
    cols[0].metric("Attempted", len(events))
    cols[1].metric("Blocked", len(blocked))
    cols[2].metric("Ran while blocked", executed)
    cols[3].metric("Score", f"{final.score} / {kill}")
    cols[4].metric("Audit chain", "valid" if _chain_valid(log_path) else "BROKEN")


def _timeline(events: list[AuditEvent]) -> None:
    st.markdown("#### Timeline")
    for event in events:
        decision = _value(event.decision)
        state = _value(event.containment_state)
        if event.tool_completed:
            execution = "completed"
        elif event.tool_invoked:
            execution = "invoked, not completed"
        else:
            execution = "not invoked"
        reasons = ", ".join(event.reason_codes) or "no findings"
        st.markdown(
            f'<div class="tw-card"><div><code>{html.escape(event.event_id)}</code> '
            f"<strong>{html.escape(event.attempted.tool)}</strong> "
            f"{_decision_badge(decision)} {_state_badge(state)} "
            f'<span class="tw-small">score {event.score} · {html.escape(execution)}</span></div>'
            f'<div class="tw-small">{_arguments(event)} · {html.escape(reasons)}</div></div>',
            unsafe_allow_html=True,
        )


def _blocked_panel(events: list[AuditEvent]) -> None:
    st.markdown("#### Blocked actions")
    blocked = [event for event in events if _value(event.decision) == "DENY"]
    if not blocked:
        st.success("Nothing blocked.")
        return
    for event in blocked:
        st.markdown(
            f"- `{event.event_id}` **{html.escape(event.attempted.tool)}** — "
            f"{html.escape(', '.join(event.reason_codes) or 'denied')}"
        )


def _incident_report(logs: list[Path]) -> None:
    st.subheader("Incident report")
    st.caption("Verified citations keep the narrative tied to concrete audit events.")
    if not logs:
        st.info("No audit sessions yet, so there is no incident report to review.")
        return
    selected = st.selectbox(
        "Report session", logs, format_func=lambda path: path.stem, key="report_session"
    )
    events = _read_events(selected)
    if not events:
        st.info("This session has no readable events.")
        return
    report = load_cached_report(events, REPORT_DIR) or build_template_report(events)
    result = verify_report(report, events)
    citation_text = "all verified" if result.verified else "INVALID"
    st.markdown(
        f'<div class="tw-card"><div class="tw-card-title">{html.escape(report.severity)} '
        f'<span class="tw-muted">· generator {html.escape(report.generator)} · '
        f"citations {html.escape(citation_text)}</span></div>"
        f"<div>{html.escape(report.summary)}</div></div>",
        unsafe_allow_html=True,
    )
    if report.stage_labels:
        st.markdown("**Stages:** " + " → ".join(report.stage_labels))
    with st.expander("Claims", expanded=False):
        for claim in result.report.claims:
            mark = "✓" if claim.verified else "✗"
            st.markdown(f"{mark} {claim.text} ({', '.join(claim.event_ids)})")


def _gauntlet_tab() -> None:
    st.subheader("Model gauntlet")
    if not GAUNTLET_SNAPSHOT.exists():
        st.info("No gauntlet snapshot yet. Run `make model-gauntlet ARGS=--snapshot`.")
        return
    snapshot = _read_json(GAUNTLET_SNAPSHOT)
    if not isinstance(snapshot, dict):
        st.error("The gauntlet snapshot is not a JSON object.")
        return
    st.markdown(
        f"Snapshot from **{snapshot.get('date', 'unknown')}** · "
        f"temperature {snapshot.get('temperature', '—')} · "
        f"{snapshot.get('repeats', '—')} runs per model and prompt · "
        f"up to {snapshot.get('max_steps', '—')} calls"
    )
    st.caption(
        "Baited measures instruction-following: the prompt asks for the decoy ticket. "
        "Neutral measures susceptibility to injected ticket content, and only means something "
        "for runs that saw the injection. A model that never misbehaves is a valid result. "
        "Outcomes come from Tripwire audit logs, not from what the model says. "
        "This is a scripted scenario, not an autonomous red team."
    )
    rows = snapshot.get("results", [])
    if not isinstance(rows, list) or not rows:
        st.info("The gauntlet snapshot has no model results.")
        return
    st.table(
        {
            "Model": [row.get("model", "—") for row in rows],
            "Prompt": [row.get("prompt", "—") for row in rows],
            "Status": [row.get("status", "—") for row in rows],
            "Completed": [f"{row.get('completed_runs', 0)}/{row.get('runs', 0)}" for row in rows],
            "Saw injection": [str(row.get("runs_saw_injection", 0)) for row in rows],
            "Unsafe-attempt runs": [str(row.get("runs_with_unsafe_attempt", 0)) for row in rows],
            "Blocked runs": [str(row.get("runs_blocked", 0)) for row in rows],
            "Worst state": [row.get("worst_containment_state", "N/A") for row in rows],
            "Executed while blocked": [str(row.get("executed_while_blocked", 0)) for row in rows],
        }
    )
    with st.expander("Prompts", expanded=False):
        for name, text in snapshot.get("prompts", {}).items():
            st.markdown(f"**{name}:** {text}")


def _remediation_tab() -> None:
    st.subheader("Remediation")
    st.caption(f"Read-only proposals from `{REMEDIATION_DIR}`; policy is never changed here.")
    try:
        reports = sorted(
            REMEDIATION_DIR.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True
        )
    except OSError:
        reports = []
    if not reports:
        st.info("No remediation reports yet. Run `make remediate` to generate a proposal.")
        return
    selected = st.selectbox(
        "Remediation report", reports, format_func=lambda path: path.name, key="remediation_report"
    )
    report = _read_json(selected)
    if not isinstance(report, dict):
        st.error("This remediation report is not a JSON object.")
        return
    baseline = report.get("baseline", {})
    proposal = report.get("proposal", [])
    cols = st.columns(4)
    cols[0].metric("Proposal", ", ".join(proposal) or "no change")
    cols[1].metric("Attack detection", _percent(baseline.get("attack_detection_rate")))
    cols[2].metric("Attack containment", _percent(baseline.get("attack_containment_rate")))
    cols[3].metric("False blocks", _percent(baseline.get("false_block_rate")))
    candidates = report.get("candidates", [])
    if candidates:
        st.table(
            {
                "Candidate": [item.get("id", "—") for item in candidates],
                "Verdict": [
                    "accepted" if item.get("accepted") else "rejected" for item in candidates
                ],
                "Change": [item.get("change", "—") for item in candidates],
                "Reasons": ["; ".join(item.get("reasons", [])) or "—" for item in candidates],
            }
        )
    with st.expander("Report JSON", expanded=False):
        st.json(report)


def _redteam_tab() -> None:
    st.subheader("Red-team")
    st.caption("Model-generated trajectories are replayed through the real gateway, offline.")
    if not REDTEAM_SNAPSHOT.exists():
        st.info("No red-team results yet. Run `make redteam` to generate the first snapshot.")
        return
    results = _read_json(REDTEAM_SNAPSHOT)
    if not isinstance(results, dict):
        st.error("The red-team snapshot is not a JSON object.")
        return
    generator = results.get("generator", {})
    summary = results.get("summary", {})
    st.markdown(
        f"Generator **{generator.get('model', 'unknown')}** · "
        f"date **{generator.get('date', 'unknown')}** · "
        f"temperature **{generator.get('temperature', '—')}** · "
        f"seed **{generator.get('seed', '—')}**"
    )
    cols = st.columns(5)
    for col, label, key in (
        (cols[0], "Generated", "generated"),
        (cols[1], "Valid attacks", "valid_attacks"),
        (cols[2], "Detected", "detected"),
        (cols[3], "Contained", "contained"),
        (cols[4], "Ran while blocked", "executed_while_blocked"),
    ):
        col.metric(label, str(summary.get(key, 0)))
    traces = results.get("traces", [])
    if not traces:
        st.info("The red-team snapshot is present but contains no valid attack traces.")
        return
    st.table(
        {
            "Name": [trace.get("name", "—") for trace in traces],
            "Strategy": [trace.get("strategy", "—") for trace in traces],
            "Outcome": [trace.get("outcome", "—") for trace in traces],
            "Calls": [str(len(trace.get("calls", []))) for trace in traces],
            "Final state": [_trace_final_state(trace) for trace in traces],
        }
    )
    with st.expander("Trajectory calls", expanded=False):
        for trace in traces:
            st.markdown(f"**{trace.get('name', 'unnamed')}** · {trace.get('outcome', 'unknown')}")
            for call in trace.get("calls", []):
                st.markdown(
                    f"- `{call.get('tool', 'unknown')}` · "
                    f"{call.get('decision', '—')} · {call.get('containment_state', '—')}"
                )


def _fleet_tab(logs: list[Path]) -> None:
    st.subheader("Fleet")
    st.caption(
        "Preview of the control-plane idea · read-only aggregate of local sessions "
        "and gauntlet results."
    )
    if not logs:
        st.info("No `.tripwire/*.jsonl` sessions are available yet.")
    else:
        rows = []
        for path in logs:
            events = _read_events(path)
            if not events:
                continue
            final = events[-1]
            rows.append(
                {
                    "Session": final.session_id,
                    "Source": path.name,
                    "State": _value(final.containment_state),
                    "Events": len(events),
                    "Blocked": sum(_value(event.decision) == "DENY" for event in events),
                    "Ran while blocked": sum(_executed_while_blocked(event) for event in events),
                    "Chain": "valid" if _chain_valid(path) else "BROKEN",
                }
            )
        if rows:
            st.table({key: [row[key] for row in rows] for key in rows[0]})
        else:
            st.info("The available JSONL sessions contain no readable events.")
    _fleet_gauntlet()


def _fleet_gauntlet() -> None:
    st.markdown("#### Gauntlet fleet roll-up")
    snapshot = _read_json(GAUNTLET_SNAPSHOT) if GAUNTLET_SNAPSHOT.exists() else None
    if not isinstance(snapshot, dict) or not snapshot.get("results"):
        st.info("No gauntlet results are available for the fleet roll-up.")
        return
    grouped: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"runs": 0, "completed": 0, "unsafe": 0, "blocked": 0, "worst": "N/A"}
    )
    for row in snapshot["results"]:
        item = grouped[row.get("model", "unknown")]
        item["runs"] += row.get("runs", 0)
        item["completed"] += row.get("completed_runs", 0)
        item["unsafe"] += row.get("runs_with_unsafe_attempt", 0)
        item["blocked"] += row.get("runs_blocked", 0)
        state = row.get("worst_containment_state", "N/A")
        if STATE_RANK.get(state, -1) > STATE_RANK.get(item["worst"], -1):
            item["worst"] = state
    st.table(
        {
            "Model": list(grouped),
            "Runs": [item["runs"] for item in grouped.values()],
            "Completed": [item["completed"] for item in grouped.values()],
            "Unsafe attempts": [item["unsafe"] for item in grouped.values()],
            "Blocked": [item["blocked"] for item in grouped.values()],
            "Worst state": [item["worst"] for item in grouped.values()],
        }
    )


def _audit_logs() -> list[Path]:
    try:
        logs = [
            path for path in LOG_DIR.glob("*.jsonl") if path.is_file() and path.stat().st_size > 0
        ]
    except OSError:
        return []
    rank = {stem: index for index, stem in enumerate(LOG_ORDER)}
    return sorted(logs, key=lambda path: (rank.get(path.stem, len(rank)), path.stem))


def _read_all_logs(logs: list[Path]) -> dict[Path, list[AuditEvent]]:
    return {path: _read_events(path) for path in logs}


def _read_events(path: Path) -> list[AuditEvent]:
    try:
        return AuditLog(path).read_events()
    except (OSError, TypeError, ValueError):
        return []


def _chain_valid(path: Path) -> bool:
    try:
        return AuditLog(path).verify_chain()
    except (OSError, TypeError, ValueError):
        return False


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return None


def _executed_while_blocked(event: AuditEvent) -> bool:
    return bool(
        event.tool_invoked
        and (
            _value(event.decision) == "DENY"
            or _value(event.containment_state) in {"PAUSED", "KILLED"}
        )
    )


def _trace_final_state(trace: dict[str, Any]) -> str:
    calls = trace.get("calls", [])
    if not calls:
        return "N/A"
    return str(calls[-1].get("containment_state", "N/A"))


def _value(value: Any) -> str:
    return str(getattr(value, "value", value))


def _percent(value: Any) -> str:
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.0%}"
    except (TypeError, ValueError):
        return str(value)


def _state_badge(state: Any) -> str:
    value = _value(state)
    css_class = STATE_CLASS.get(value, "unknown")
    label = html.escape(STATE_LABEL.get(value, value))
    return f'<span class="state-badge state-{css_class}">{label}</span>'


def _decision_badge(decision: Any) -> str:
    value = _value(decision)
    css_class = DECISION_CLASS.get(value, "unknown")
    return f'<span class="decision-badge decision-{css_class}">{html.escape(value)}</span>'


def _arguments(event: AuditEvent) -> str:
    args = ", ".join(f"{key}={value}" for key, value in event.attempted.arguments.items())
    return html.escape(args or "no arguments")


if __name__ == "__main__":
    main()
