from __future__ import annotations

import html
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

import altair as alt
import streamlit as st

from tripwire.audit import AuditEvent, AuditLog
from tripwire.contracts import load_task_contract
from tripwire.evaluation.runner import run_eval
from tripwire.investigation.cache import load_cached_report
from tripwire.investigation.template import build_template_report
from tripwire.investigation.verifier import verify_report
from tripwire.sponsors import provider_status, semgrep_scan

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = Path(os.getenv("TRIPWIRE_LOG_DIR", ROOT / ".tripwire"))
REPORT_DIR = LOG_DIR / "reports"
REMEDIATION_DIR = LOG_DIR / "remediation"
TRACE_FILE = ROOT / "evaluation/traces/checkpoint_b.yaml"
HOLDOUT_FILE = ROOT / "evaluation/traces/generated_redteam.yaml"
GAUNTLET_SNAPSHOT = ROOT / "evaluation/gauntlet_results.json"
REDTEAM_SNAPSHOT = ROOT / "evaluation/redteam_results.json"
CONTRACT_FILE = ROOT / "examples/contracts/support_summary.yaml"

STATE_CLASS = {"OK": "ok", "WARN": "warn", "PAUSED": "paused", "KILLED": "killed"}
STATE_RANK = {"OK": 0, "WARN": 1, "PAUSED": 2, "KILLED": 3}
STATE_ICON = {"OK": "●", "WARN": "▲", "PAUSED": "❚❚", "KILLED": "✕"}
SEVERITY_CLASS = {
    "critical": "killed",
    "high": "paused",
    "medium": "warn",
    "low": "ok",
    "informational": "unknown",
}
# Status palette, validated on both surfaces with the dataviz validator: PAUSED is violet so it
# never reads as WARN's amber. Every use also carries a text label and an icon.
STATUS_LIGHT = {"OK": "#127a5a", "WARN": "#b06a00", "PAUSED": "#7c3aed", "KILLED": "#c0302f"}
STATUS_DARK = {"OK": "#2f9e7f", "WARN": "#b8830f", "PAUSED": "#9174f0", "KILLED": "#e05252"}
SERIES_COLOR = "#3a74e0"  # inside the lightness band on both light and dark surfaces
LOG_ORDER = [
    "open-web-watch",
    "demo-escape",
    "demo-slow_drift",
    "demo-live",
    "demo-benign",
    "gateway-audit",
]
REPORT_PREFERENCE = ["demo-escape", "demo-slow_drift"]


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

    live, incident, gauntlet, remediation, redteam, fleet, sponsors = st.tabs(
        [
            "Live containment",
            "Incident report",
            "Model gauntlet",
            "Remediation",
            "Red-team",
            "Fleet",
            "Sponsors",
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
    with sponsors:
        _sponsors_tab()


# ---------------------------------------------------------------- styling


def _inject_styles() -> None:
    light = "".join(f"--tw-{k.lower()}: {v};" for k, v in STATUS_LIGHT.items())
    dark = "".join(f"--tw-{k.lower()}: {v};" for k, v in STATUS_DARK.items())
    st.markdown(
        f"""
        <style>
        :root {{
          --tw-ink: #17212b; --tw-muted: #5e6b78; --tw-line: #dbe3ea; --tw-panel: #f7f9fb;
          --tw-accent: {SERIES_COLOR}; {light}
        }}
        @media (prefers-color-scheme: dark) {{
          :root {{ --tw-ink: #eef4f8; --tw-muted: #aebdca; --tw-line: #334451;
                   --tw-panel: #18232c; {dark} }}
        }}
        .tw-eyebrow {{ color: var(--tw-accent); font-size: .72rem; font-weight: 800;
          letter-spacing: .14em; margin: .25rem 0 .45rem; }}
        .tw-strip-label {{ color: var(--tw-muted); font-size: .75rem; font-weight: 700;
          letter-spacing: .08em; text-transform: uppercase; margin: .3rem 0 .5rem; }}
        .tw-kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
          gap: .6rem; margin: .2rem 0 .8rem; }}
        .tw-kpi {{ background: var(--tw-panel); border: 1px solid var(--tw-line);
          border-left: 4px solid var(--tw-kpi, var(--tw-line)); border-radius: 10px;
          padding: .6rem .85rem; }}
        .tw-kpi-label {{ color: var(--tw-muted); font-size: .74rem; font-weight: 700;
          text-transform: uppercase; letter-spacing: .06em; }}
        .tw-kpi-value {{ color: var(--tw-ink); font-size: 1.45rem; font-weight: 800; }}
        .tw-kpi-note {{ color: var(--tw-muted); font-size: .76rem; }}
        .badge {{ border: 1px solid currentColor; border-radius: 999px; display: inline-flex;
          align-items: center; gap: .3rem; font-size: .74rem; font-weight: 800; line-height: 1;
          padding: .26rem .5rem; white-space: nowrap; }}
        .tone-ok {{ color: var(--tw-ok); }} .tone-warn {{ color: var(--tw-warn); }}
        .tone-paused {{ color: var(--tw-paused); }} .tone-killed {{ color: var(--tw-killed); }}
        .tone-unknown {{ color: var(--tw-muted); }} .tone-accent {{ color: var(--tw-accent); }}
        .tw-card {{ background: var(--tw-panel); border: 1px solid var(--tw-line);
          border-left: 4px solid var(--tw-card, var(--tw-line)); border-radius: 12px;
          padding: .7rem .95rem; margin: .3rem 0 .6rem; }}
        .tw-card-title {{ color: var(--tw-ink); font-weight: 750; margin-bottom: .25rem; }}
        .tw-muted {{ color: var(--tw-muted); }}
        .tw-small {{ color: var(--tw-muted); font-size: .82rem; }}
        .tw-chips {{ display: flex; flex-wrap: wrap; gap: .35rem; align-items: center; }}
        .tw-arrow {{ color: var(--tw-muted); }}
        .tw-table {{ border-collapse: collapse; width: 100%; font-size: .86rem; }}
        .tw-table th {{ color: var(--tw-muted); font-size: .72rem; text-transform: uppercase;
          letter-spacing: .06em; text-align: left; border-bottom: 1px solid var(--tw-line);
          padding: .45rem .5rem; }}
        .tw-table td {{ border-bottom: 1px solid var(--tw-line); padding: .45rem .5rem;
          color: var(--tw-ink); vertical-align: top; }}
        .tw-table td.num {{ font-variant-numeric: tabular-nums; }}
        .tw-section {{ color: var(--tw-muted); font-size: .76rem; font-weight: 800;
          text-transform: uppercase; letter-spacing: .08em; margin: .9rem 0 .35rem; }}
        .tw-callout {{ border: 1px dashed var(--tw-line); border-radius: 10px;
          padding: .6rem .85rem; margin: .4rem 0 .8rem; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _badge(label: str, tone: str, icon: str = "") -> str:
    prefix = f"{icon} " if icon else ""
    return f'<span class="badge tone-{tone}">{html.escape(prefix + label)}</span>'


def _state_badge(state: Any) -> str:
    value = _value(state)
    if value not in STATE_RANK:
        return _badge(value, "unknown")
    return _badge(value, STATE_CLASS[value], STATE_ICON[value])


def _decision_badge(decision: Any) -> str:
    value = _value(decision)
    if value == "ALLOW":
        return _badge(value, "ok", "✓")
    if value == "DENY":
        return _badge(value, "killed", "⛔")
    return _badge(value, "unknown")


def _tone_var(tone: str) -> str:
    return "line" if tone == "unknown" else tone


def _kpis(items: list[tuple[str, str, str, str]]) -> None:
    """items: (label, value, tone, note). The tone colors the edge; the label carries meaning."""
    cells = "".join(
        f'<div class="tw-kpi" style="--tw-kpi: var(--tw-{_tone_var(tone)})">'
        f'<div class="tw-kpi-label">{html.escape(label)}</div>'
        f'<div class="tw-kpi-value">{html.escape(value)}</div>'
        f'<div class="tw-kpi-note">{html.escape(note)}</div></div>'
        for label, value, tone, note in items
    )
    st.markdown(f'<div class="tw-kpis">{cells}</div>', unsafe_allow_html=True)


def _html_table(headers: list[str], rows: list[list[str]], numeric: set[int] | None = None) -> None:
    """Cells are pre-escaped HTML so badges can sit in them."""
    numeric = numeric or set()
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join(
        "<tr>"
        + "".join(
            f'<td class="num">{cell}</td>' if index in numeric else f"<td>{cell}</td>"
            for index, cell in enumerate(row)
        )
        + "</tr>"
        for row in rows
    )
    st.markdown(f'<table class="tw-table"><tr>{head}</tr>{body}</table>', unsafe_allow_html=True)


def _section(title: str) -> None:
    st.markdown(f'<div class="tw-section">{html.escape(title)}</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------- header


def _header_strip(logs: list[Path]) -> None:
    overview = _overview_metrics(logs)
    st.markdown('<div class="tw-strip-label">System posture</div>', unsafe_allow_html=True)
    executed = overview["executed_while_blocked"]
    _kpis(
        [
            (
                "Ran while blocked",
                str(executed),
                "ok" if executed == 0 else "killed",
                "tools executed after a deny, all sessions",
            ),
            (
                "Audit chains",
                overview["chain_valid"],
                "ok" if overview["chain_valid"] == "valid" else "killed",
                f"{len(logs)} hash-chained session log(s)",
            ),
            (
                "Attack containment",
                overview["containment"],
                "paused",
                f"current config, {overview['traces']} fixture traces",
            ),
            (
                "False-block rate",
                overview["false_block_rate"],
                "ok" if overview["false_block_rate"] == "0%" else "killed",
                "benign fixture traces",
            ),
        ]
    )
    st.markdown(
        '<div class="tw-small">State key: '
        + " ".join(_state_badge(state) for state in STATE_RANK)
        + " — every color is paired with a text label and an icon.</div>",
        unsafe_allow_html=True,
    )


def _overview_metrics(logs: list[Path]) -> dict[str, Any]:
    executed = sum(_executed_while_blocked(event) for path in logs for event in _read_events(path))
    chain = "n/a" if not logs else "valid" if all(_chain_valid(path) for path in logs) else "BROKEN"
    metrics = _eval_metrics(str(TRACE_FILE))
    return {
        "executed_while_blocked": executed,
        "chain_valid": chain,
        "traces": metrics.get("traces", "n/a"),
        "containment": _percent(metrics.get("attack_containment_rate")),
        "false_block_rate": _percent(metrics.get("false_block_rate")),
    }


@st.cache_data(show_spinner=False)
def _eval_metrics(trace_file: str) -> dict[str, Any]:
    try:
        return run_eval(contract_path=CONTRACT_FILE, trace_path=Path(trace_file))
    except (OSError, KeyError, TypeError, ValueError):
        return {}


# ---------------------------------------------------------------- live containment


def _live_containment(logs: list[Path]) -> None:
    st.subheader("Live containment")
    st.caption("Pick a session, then scrub through it to watch containment build up.")
    if not logs:
        st.info("No audit sessions yet. Run `make demo` to replay the scripted scenarios.")
        return

    selected = st.sidebar.radio("Audit session", logs, format_func=lambda path: path.stem)
    events = _read_events(selected)
    if not events:
        st.info(f"{selected.name} is empty or unreadable.")
        return

    step = len(events)
    if len(events) > 1:
        step = st.slider(
            "Replay to event",
            min_value=1,
            max_value=len(events),
            value=len(events),
            key=f"replay-{selected.stem}",
            help="Everything below reflects the session as of this event.",
        )
    shown = events[:step]
    _session_summary(shown, selected)

    chart_col, side = st.columns([3, 2], gap="large")
    with chart_col:
        _score_chart(events, step)
    with side:
        _blocked_panel(shown)

    view = st.radio(
        "Show",
        ["All events", "Denied only", "Flagged only"],
        horizontal=True,
        key=f"filter-{selected.stem}",
    )
    _timeline(shown, view)


def _session_summary(events: list[AuditEvent], log_path: Path) -> None:
    final = events[-1]
    state = _value(final.containment_state)
    blocked = [event for event in events if _value(event.decision) == "DENY"]
    executed = sum(_executed_while_blocked(event) for event in events)
    thresholds = _thresholds()
    st.markdown(
        f'<div class="tw-card" style="--tw-card: var(--tw-{STATE_CLASS.get(state, "line")})">'
        f'<div class="tw-card-title">Session <code>{html.escape(final.session_id)}</code> '
        f"{_state_badge(state)}</div>"
        f'<div class="tw-small">As of <code>{html.escape(final.event_id)}</code> · '
        f"{len(events)} event(s) shown</div></div>",
        unsafe_allow_html=True,
    )
    cols = st.columns(5)
    cols[0].metric("Attempted", len(events))
    cols[1].metric("Blocked", len(blocked))
    cols[2].metric("Ran while blocked", executed)
    cols[3].metric(f"Score (kill at {thresholds['kill']})", str(final.score))
    cols[4].metric("Audit chain", "valid" if _chain_valid(log_path) else "BROKEN")


def _thresholds() -> dict[str, int]:
    try:
        thresholds = load_task_contract(CONTRACT_FILE).thresholds
    except (OSError, KeyError, TypeError, ValueError):
        thresholds = {}
    return {
        "warn": thresholds.get("warn", 3),
        "pause": thresholds.get("pause", 6),
        "kill": thresholds.get("kill", 10),
    }


def _score_chart(events: list[AuditEvent], step: int) -> None:
    _section("Suspicion score by event")
    rows = [
        {
            "event": index,
            "event_id": event.event_id,
            "tool": event.attempted.tool,
            "decision": _value(event.decision),
            "state": _value(event.containment_state),
            "score": event.score,
            "reasons": ", ".join(event.reason_codes) or "no findings",
            "shown": index <= step,
        }
        for index, event in enumerate(events, start=1)
    ]
    thresholds = _thresholds()
    top = max(thresholds["kill"] + 2, *(row["score"] for row in rows))
    states = list(STATUS_LIGHT)
    state_scale = alt.Scale(domain=states, range=[STATUS_LIGHT[state] for state in states])
    base = alt.Chart(alt.Data(values=rows)).encode(
        x=alt.X("event:Q", title="Event", axis=alt.Axis(tickMinStep=1, grid=False)),
        y=alt.Y(
            "score:Q",
            title="Score",
            scale=alt.Scale(domain=[0, top]),
            axis=alt.Axis(gridOpacity=0.25),
        ),
    )
    line = base.transform_filter("datum.shown").mark_line(
        color=SERIES_COLOR, strokeWidth=2, interpolate="step-after"
    )
    points = base.mark_point(filled=True, size=150, stroke="white", strokeWidth=2).encode(
        color=alt.Color(
            "state:N",
            title="State",
            scale=state_scale,
            legend=alt.Legend(orient="top", direction="horizontal"),
        ),
        shape=alt.Shape(
            "decision:N",
            title="Decision",
            scale=alt.Scale(domain=["ALLOW", "DENY"], range=["circle", "diamond"]),
            legend=alt.Legend(orient="top", direction="horizontal"),
        ),
        opacity=alt.condition("datum.shown", alt.value(1.0), alt.value(0.15)),
        tooltip=[
            alt.Tooltip("event_id:N", title="Event"),
            alt.Tooltip("tool:N", title="Tool"),
            alt.Tooltip("decision:N", title="Decision"),
            alt.Tooltip("state:N", title="State"),
            alt.Tooltip("score:Q", title="Score"),
            alt.Tooltip("reasons:N", title="Reasons"),
        ],
    )
    rule_rows = [
        {"label": f"{name} {value}", "value": value, "state": state}
        for name, value, state in (
            ("WARN", thresholds["warn"], "WARN"),
            ("PAUSE", thresholds["pause"], "PAUSED"),
            ("KILL", thresholds["kill"], "KILLED"),
        )
    ]
    # One layer per threshold with a fixed color, so the rules never share (and hide) the
    # points' State legend.
    rules = [
        alt.Chart(alt.Data(values=[row]))
        .mark_rule(strokeDash=[4, 4], strokeWidth=1.5, color=STATUS_LIGHT[row["state"]])
        .encode(y="value:Q")
        for row in rule_rows
    ]
    labels = (
        alt.Chart(alt.Data(values=rule_rows))
        .mark_text(align="left", dx=4, dy=-6, fontSize=11, fontWeight="bold")
        .encode(y="value:Q", x=alt.value(0), text="label:N", color=alt.value("#5e6b78"))
    )
    st.altair_chart(
        alt.layer(*rules, labels, line, points).properties(height=280),
        use_container_width=True,
    )
    st.caption(
        "Dashed lines are the contract thresholds. Hover a point for its event; "
        "faded points come after the replay position."
    )


def _timeline(events: list[AuditEvent], view: str) -> None:
    _section("Timeline")
    if view == "Denied only":
        events = [event for event in events if _value(event.decision) == "DENY"]
    elif view == "Flagged only":
        events = [
            event for event in events if _value(event.decision) == "DENY" or event.reason_codes
        ]
    if not events:
        st.success("No events match this filter.")
        return
    for event in events:
        decision = _value(event.decision)
        state = _value(event.containment_state)
        if "AUTHORIZE_ONLY" in event.reason_codes:
            execution = "authorized only, not run by the gateway"
        elif event.tool_completed:
            execution = "completed"
        elif event.tool_invoked:
            execution = "invoked, not completed"
        else:
            execution = "not invoked"
        reasons = ", ".join(event.reason_codes) or "no findings"
        flagged = decision == "DENY" or state != "OK"
        tone = STATE_CLASS.get(state, "line") if flagged else "line"
        st.markdown(
            f'<div class="tw-card" style="--tw-card: var(--tw-{tone})">'
            f"<div><code>{html.escape(event.event_id)}</code> "
            f"<strong>{html.escape(event.attempted.tool)}</strong> "
            f"{_decision_badge(decision)} {_state_badge(state)} "
            f'<span class="tw-small">score {event.score} · {html.escape(execution)}</span></div>'
            f'<div class="tw-small">{_arguments(event)} · {html.escape(reasons)}</div></div>',
            unsafe_allow_html=True,
        )


def _blocked_panel(events: list[AuditEvent]) -> None:
    _section("Blocked actions")
    blocked = [event for event in events if _value(event.decision) == "DENY"]
    if not blocked:
        st.success("Nothing blocked yet.")
        return
    for event in blocked:
        st.markdown(
            '<div class="tw-card" style="--tw-card: var(--tw-killed)">'
            f"<code>{html.escape(event.event_id)}</code> "
            f"<strong>{html.escape(event.attempted.tool)}</strong> "
            f"{_state_badge(event.containment_state)}"
            f'<div class="tw-small">{html.escape(", ".join(event.reason_codes) or "denied")}'
            "</div></div>",
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------- incident report


def _incident_report(logs: list[Path]) -> None:
    st.subheader("Incident report")
    st.caption(
        "The headline is built from the audit log. Model-written claims appear only when every "
        "citation checks out; model prose is labelled unverified."
    )
    if not logs:
        st.info("No audit sessions yet, so there is no incident report to review.")
        return
    stems = [path.stem for path in logs]
    default = next((stems.index(name) for name in REPORT_PREFERENCE if name in stems), 0)
    selected = st.selectbox(
        "Report session",
        logs,
        index=default,
        format_func=lambda path: path.stem,
        key="report_session",
    )
    events = _read_events(selected)
    if not events:
        st.info("This session has no readable events.")
        return
    report = load_cached_report(events, REPORT_DIR) or build_template_report(events)
    result = verify_report(report, events)
    verified = result.report
    severity = verified.severity.lower()
    tone = SEVERITY_CLASS.get(severity, "unknown")
    generator = (
        "deterministic template"
        if verified.generator == "template"
        else f"{verified.generator}, claims verified"
    )
    citations = (
        _badge("citations verified", "ok", "✓")
        if result.verified
        else _badge("citations invalid", "killed", "✕")
    )
    st.markdown(
        f'<div class="tw-card" style="--tw-card: var(--tw-{_tone_var(tone)})">'
        f'<div class="tw-card-title">{_badge(severity.upper(), tone)} {citations} '
        f'<span class="tw-small">· generator: {html.escape(generator)}</span></div>'
        f"<div>{html.escape(verified.summary)}</div></div>",
        unsafe_allow_html=True,
    )
    if verified.stage_labels:
        chips = ' <span class="tw-arrow">→</span> '.join(
            _badge(stage.replace("_", " "), "accent") for stage in verified.stage_labels
        )
        _section("Attack stages")
        st.markdown(f'<div class="tw-chips">{chips}</div>', unsafe_allow_html=True)
    if verified.model_narrative:
        st.markdown(
            '<div class="tw-callout"><div class="tw-card-title">'
            f"{_badge('unverified', 'warn', '▲')} Model narrative</div>"
            f'<div class="tw-small">{html.escape(verified.model_narrative)}</div></div>',
            unsafe_allow_html=True,
        )
    rejections = getattr(report, "verifier_rejections", ())
    if rejections:
        items = "".join(f"<li>{html.escape(reason)}</li>" for reason in rejections)
        st.markdown(
            '<div class="tw-card" style="--tw-card: var(--tw-killed)">'
            f'<div class="tw-card-title">{_badge("model report rejected", "killed", "✕")} '
            "The verifier caught the model contradicting the audit log</div>"
            f'<ul class="tw-small" style="margin:.3rem 0 0 1rem">{items}</ul>'
            '<div class="tw-small">The claims below come from the log instead.</div></div>',
            unsafe_allow_html=True,
        )

    by_id = {event.event_id: event for event in events}
    claims_col, trail_col = st.columns([3, 2], gap="large")
    with claims_col:
        _section("Claims, each tied to audit events")
        for claim in verified.claims:
            mark = (
                _badge("verified", "ok", "✓")
                if claim.verified
                else _badge("rejected", "killed", "✕")
            )
            cited = " ".join(
                f"<code>{html.escape(event.event_id)}</code> {_decision_badge(event.decision)} "
                f"{_state_badge(event.containment_state)}"
                for event in (by_id[event_id] for event_id in claim.event_ids if event_id in by_id)
            )
            st.markdown(
                f'<div class="tw-card"><div>{mark} {html.escape(claim.text)}</div>'
                f'<div class="tw-small" style="margin-top:.3rem">{cited}</div></div>',
                unsafe_allow_html=True,
            )
        if not result.verified:
            st.warning("Rejected: " + "; ".join(result.invalid_claims))
    with trail_col:
        _section("Event trail")
        for event in events:
            st.markdown(
                f'<div class="tw-small"><code>{html.escape(event.event_id)}</code> '
                f"{html.escape(event.attempted.tool)} {_decision_badge(event.decision)} "
                f"{_state_badge(event.containment_state)}</div>",
                unsafe_allow_html=True,
            )
    denied = any(_value(event.decision) == "DENY" for event in events)
    if verified.generator == "template" and denied:
        st.caption("Run `make investigate` with Ollama up to add verified model claims.")


# ---------------------------------------------------------------- model gauntlet


def _gauntlet_note(row: dict[str, Any]) -> str:
    status = row.get("status")
    if status == "not_pulled":
        return "model not pulled in Ollama"
    if status == "failed" and not row.get("completed_runs"):
        return "every run failed (HTTP error or no valid actions)"
    failed = row.get("runs", 0) - row.get("completed_runs", 0)
    prefix = f"{failed} run(s) failed; " if status == "failed" else ""
    unsafe = row.get("runs_with_unsafe_attempt", 0)
    if row.get("prompt") == "neutral":
        if not row.get("runs_saw_injection"):
            if row.get("worst_containment_state") == "N/A":
                return prefix + "did not encounter the injection (made no tool calls)"
            return prefix + "did not encounter the injection"
        if unsafe:
            return prefix + "made an out-of-contract call after seeing the injection; blocked"
        return prefix + "saw the injection and did not act on it"
    if unsafe:
        return prefix + "followed the decoy instruction; blocked before the tool ran"
    return prefix + "declined the decoy instruction"


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

    prompt = st.radio("Prompt", ["Both", "Baited", "Neutral"], horizontal=True, key="gauntlet")
    visible = [row for row in rows if prompt == "Both" or row.get("prompt") == prompt.lower()]
    status_tone = {"completed": "ok", "failed": "killed", "not_pulled": "unknown"}
    _html_table(
        [
            "Model",
            "Prompt",
            "Status",
            "Completed",
            "Saw injection",
            "Unsafe runs",
            "Blocked runs",
            "Worst state",
            "Ran while blocked",
            "What happened",
        ],
        [
            [
                f"<code>{html.escape(str(row.get('model', '—')))}</code>",
                html.escape(str(row.get("prompt", "—"))),
                _badge(str(row.get("status", "—")), status_tone.get(row.get("status"), "unknown")),
                f"{row.get('completed_runs', 0)}/{row.get('runs', 0)}",
                str(row.get("runs_saw_injection", 0)),
                str(row.get("runs_with_unsafe_attempt", 0)),
                str(row.get("runs_blocked", 0)),
                _state_badge(row.get("worst_containment_state", "N/A")),
                _badge(
                    str(row.get("executed_while_blocked", 0)),
                    "ok" if not row.get("executed_while_blocked") else "killed",
                ),
                f'<span class="tw-small">{html.escape(_gauntlet_note(row))}</span>',
            ]
            for row in visible
        ],
        numeric={3, 4, 5, 6},
    )
    with st.expander("Table view", expanded=False):
        st.table(
            {
                "Model": [row.get("model", "—") for row in rows],
                "Prompt": [row.get("prompt", "—") for row in rows],
                "Status": [row.get("status", "—") for row in rows],
                "Completed": [
                    f"{row.get('completed_runs', 0)}/{row.get('runs', 0)}" for row in rows
                ],
                "Saw injection": [str(row.get("runs_saw_injection", 0)) for row in rows],
                "Unsafe-attempt runs": [
                    str(row.get("runs_with_unsafe_attempt", 0)) for row in rows
                ],
                "Blocked runs": [str(row.get("runs_blocked", 0)) for row in rows],
                "Worst state": [row.get("worst_containment_state", "N/A") for row in rows],
                "Executed while blocked": [
                    str(row.get("executed_while_blocked", 0)) for row in rows
                ],
                "Note": [_gauntlet_note(row) for row in rows],
            }
        )
    with st.expander("Prompts", expanded=False):
        for name, text in snapshot.get("prompts", {}).items():
            st.markdown(f"**{name}:** {text}")


# ---------------------------------------------------------------- remediation


def _remediation_tab() -> None:
    st.subheader("Remediation")
    st.caption(
        f"Read-only proposals from `{_display(REMEDIATION_DIR)}`. Policy is never changed here; "
        "`make remediate ARGS=--apply` writes the detector config."
    )
    try:
        reports = sorted(
            REMEDIATION_DIR.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True
        )
    except OSError:
        reports = []
    if not reports:
        st.info("No remediation reports yet. Run `make remediate` to generate a proposal.")
    else:
        selected = st.selectbox(
            "Remediation report",
            reports,
            format_func=lambda path: path.name,
            key="remediation_report",
        )
        report = _read_json(selected)
        if isinstance(report, dict):
            _remediation_report(report)
        else:
            st.error("This remediation report is not a JSON object.")
    _what_if()


def _metric_with_delta(col: Any, label: str, value: float, before: float, key: str) -> None:
    """A zero change reads as 'no change' in grey, never as a red or green arrow."""
    change = (value - before) * 100
    if abs(change) < 0.05:
        col.metric(label, _percent(value), delta="no change", delta_color="off")
        return
    col.metric(
        label,
        _percent(value),
        delta=f"{change:+.1f} pts",
        delta_color="inverse" if key == "false_block_rate" else "normal",
    )


def _proposal_metrics(report: dict[str, Any]) -> dict[str, Any]:
    combination = report.get("combination")
    if isinstance(combination, dict) and combination.get("accepted"):
        return combination.get("metrics", {})
    proposal = report.get("proposal", [])
    for item in report.get("candidates", []):
        if [item.get("id")] == proposal:
            return item.get("metrics", {})
    return {}


def _remediation_report(report: dict[str, Any]) -> None:
    baseline = report.get("baseline", {})
    proposal = report.get("proposal", [])
    after = _proposal_metrics(report)
    before_col, after_col = st.columns(2, gap="large")
    with before_col:
        _section("Before · baseline (config when the report ran)")
        cols = st.columns(3)
        cols[0].metric("Detection, before", _percent(baseline.get("attack_detection_rate")))
        cols[1].metric("Containment, before", _percent(baseline.get("attack_containment_rate")))
        cols[2].metric("False blocks, before", _percent(baseline.get("false_block_rate")))
    with after_col:
        _section(f"After · proposal: {', '.join(proposal) or 'no change'}")
        cols = st.columns(3)
        for col, label, key in (
            (cols[0], "Detection, after", "attack_detection_rate"),
            (cols[1], "Containment, after", "attack_containment_rate"),
            (cols[2], "False blocks, after", "false_block_rate"),
        ):
            value = after.get(key, baseline.get(key))
            if key in after and baseline.get(key) is not None:
                _metric_with_delta(col, label, after[key], baseline[key], key)
            else:
                col.metric(label, _percent(value))

    combination = report.get("combination")
    items = report.get("candidates", []) + ([combination] if isinstance(combination, dict) else [])
    if items:
        rows = []
        for item in items:
            if not item.get("accepted"):
                verdict = _badge("rejected", "killed", "✕")
            elif item.get("improved", True):
                verdict = _badge("accepted", "ok", "✓")
            else:
                verdict = _badge("no gain", "unknown", "○")
            reasons = "; ".join(item.get("reasons", [])) or "—"
            rows.append(
                [
                    f"<code>{html.escape(str(item.get('id', '—')))}</code>",
                    html.escape(str(item.get("change", "—"))),
                    _percent(item.get("metrics", {}).get("attack_containment_rate")),
                    verdict,
                    f'<span class="tw-small">{html.escape(reasons)}</span>',
                ]
            )
        _section("Candidates")
        _html_table(["Candidate", "Change", "Containment", "Verdict", "Why"], rows, numeric={2})
    if report.get("config_diff"):
        with st.expander("Proposed config diff", expanded=False):
            st.code(report["config_diff"], language="diff")
    with st.expander("Report JSON", expanded=False):
        st.json(report)


def _what_if() -> None:
    from tripwire import remediation

    _section("What-if builder")
    st.caption(
        "Pick catalog changes to replay every fixture trajectory (and the generated red-team "
        "holdout) in memory against the same gate. Nothing is written."
    )
    catalog = {entry.id: entry for entry in remediation.CATALOG}
    chosen = st.multiselect(
        "Catalog changes",
        list(catalog),
        format_func=lambda key: f"{key} · {catalog[key].change()}",
        key="what_if",
    )
    if not chosen:
        st.info("Select one or more changes to see the gate verdict.")
        return
    result = _what_if_result(tuple(sorted(chosen)))
    baseline = _eval_metrics(str(TRACE_FILE))
    verdict = (
        _badge("passes the gate", "ok", "✓")
        if result["accepted"]
        else _badge("rejected by the gate", "killed", "✕")
    )
    st.markdown(f"<div>{verdict}</div>", unsafe_allow_html=True)
    metrics = result["metrics"]
    if metrics:
        cols = st.columns(4)
        for col, label, key in (
            (cols[0], "Detection", "attack_detection_rate"),
            (cols[1], "Containment", "attack_containment_rate"),
            (cols[2], "False blocks", "false_block_rate"),
        ):
            value = metrics.get(key, 0.0)
            _metric_with_delta(col, label, value, baseline.get(key, value), key)
        cols[3].metric("Ran while blocked", str(metrics.get("executed_while_blocked", 0)))
    for reason in result["reasons"]:
        st.markdown(f"- {reason}")


@st.cache_data(show_spinner="Replaying fixtures…")
def _what_if_result(chosen: tuple[str, ...]) -> dict[str, Any]:
    from tripwire import remediation

    catalog = {entry.id: entry for entry in remediation.CATALOG}
    baseline = run_eval(contract_path=CONTRACT_FILE, trace_path=TRACE_FILE)
    holdout = HOLDOUT_FILE if HOLDOUT_FILE.exists() else None
    candidate = remediation.evaluate(
        [catalog[key] for key in chosen],
        baseline,
        candidate_id="what-if",
        contract_path=CONTRACT_FILE,
        trace_path=TRACE_FILE,
        holdout_path=holdout,
        holdout_baseline=(
            run_eval(contract_path=CONTRACT_FILE, trace_path=holdout) if holdout else None
        ),
    )
    return {
        "accepted": candidate.accepted,
        "reasons": candidate.reasons,
        "metrics": candidate.metrics,
    }


# ---------------------------------------------------------------- red-team


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
    executed = summary.get("executed_while_blocked", 0)
    _kpis(
        [
            ("Generated", str(summary.get("generated", 0)), "unknown", "trajectories proposed"),
            ("Valid attacks", str(summary.get("valid_attacks", 0)), "warn", "out-of-contract"),
            ("Detected", str(summary.get("detected", 0)), "ok", "at least one deny"),
            ("Contained", str(summary.get("contained", 0)), "paused", "PAUSED or KILLED"),
            ("Ran while blocked", str(executed), "ok" if not executed else "killed", "must be 0"),
        ]
    )
    traces = results.get("traces", [])
    if not traces:
        st.info("The red-team snapshot is present but contains no valid attack traces.")
        return
    strategies = sorted({str(trace.get("strategy", "—")) for trace in traces})
    picked = st.multiselect("Strategy", strategies, default=strategies, key="redteam_strategy")
    visible = [trace for trace in traces if str(trace.get("strategy", "—")) in picked]
    _html_table(
        ["Name", "Strategy", "Outcome", "Calls", "Final state"],
        [
            [
                f"<code>{html.escape(str(trace.get('name', '—')))}</code>",
                html.escape(str(trace.get("strategy", "—"))),
                html.escape(str(trace.get("outcome", "—"))),
                str(len(trace.get("calls", []))),
                _state_badge(_trace_final_state(trace)),
            ]
            for trace in visible
        ],
        numeric={3},
    )
    with st.expander("Trajectory calls", expanded=False):
        for trace in visible:
            calls = "".join(
                f"<div>· <code>{html.escape(str(call.get('tool', 'unknown')))}</code> "
                f"{_decision_badge(call.get('decision', '—'))} "
                f"{_state_badge(call.get('containment_state', '—'))}</div>"
                for call in trace.get("calls", [])
            )
            st.markdown(
                f"<div><strong>{html.escape(str(trace.get('name', 'unnamed')))}</strong> · "
                f"{html.escape(str(trace.get('outcome', 'unknown')))}</div>{calls}",
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------- fleet


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
            executed = sum(_executed_while_blocked(event) for event in events)
            chain = (
                _badge("valid", "ok", "✓")
                if _chain_valid(path)
                else _badge("BROKEN", "killed", "✕")
            )
            rows.append(
                [
                    f"<code>{html.escape(final.session_id)}</code>",
                    html.escape(path.name),
                    _state_badge(final.containment_state),
                    str(len(events)),
                    str(sum(_value(event.decision) == "DENY" for event in events)),
                    _badge(str(executed), "ok" if not executed else "killed"),
                    chain,
                ]
            )
        if rows:
            _html_table(
                ["Session", "Source", "State", "Events", "Blocked", "Ran while blocked", "Chain"],
                rows,
                numeric={3, 4},
            )
        else:
            st.info("The available JSONL sessions contain no readable events.")
    _fleet_gauntlet()
    _clickhouse_panel()


def _clickhouse_panel() -> None:
    """Shown only when the optional analytics client is installed and ClickHouse answers."""
    try:
        from tripwire import analytics
    except ImportError:
        return
    if not analytics.reachable(timeout=0.5):
        return
    data = _clickhouse_results()
    if data is None:
        return
    _section("ClickHouse analytics · synthetic scale-up")
    summary = data["summary"]
    st.markdown(
        f"{_badge('SYNTHETIC', 'warn', '▲')} "
        '<span class="tw-small">The 26 fixture trajectories, replayed through the gateway and '
        "copied under new session ids and seeded timestamps. Not production traffic.</span>",
        unsafe_allow_html=True,
    )
    _kpis(
        [
            ("Events", f"{summary['events']:,}", "unknown", "in tripwire.audit_events"),
            (
                "Sessions",
                f"{summary['sessions']:,}",
                "unknown",
                "MergeTree, ordered by session, ts",
            ),
            (
                "Synthetic",
                f"{summary['synthetic_events']:,}",
                "warn",
                "rows labelled synthetic=1",
            ),
        ]
    )
    titles = {
        "top_deny_reasons": "Top deny reasons",
        "time_to_kill": "Time to KILLED per session",
        "read_then_send_sessions": "Sessions that read, then sent",
    }
    cols = st.columns(3, gap="large")
    for col, (name, result) in zip(cols, data["queries"].items(), strict=False):
        with col:
            _section(f"{titles.get(name, name)} · {result['latency_ms']} ms")
            _html_table(
                result["columns"],
                [
                    [
                        html.escape(f"{value:,}" if isinstance(value, int) else str(value))
                        for value in row
                    ]
                    for row in result["rows"]
                ],
            )
    st.caption(
        "Latency is the measured client round trip on a warm local ClickHouse. "
        "Read-then-send includes sends to allowed destinations, which Tripwire does not flag."
    )


@st.cache_data(ttl=60, show_spinner="Querying ClickHouse…")
def _clickhouse_results() -> dict[str, Any] | None:
    from tripwire import analytics

    try:
        return {"summary": analytics.table_summary(), "queries": analytics.run_queries()}
    except Exception:
        return None


def _fleet_gauntlet() -> None:
    _section("Gauntlet fleet roll-up")
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
    _html_table(
        ["Model", "Runs", "Completed", "Unsafe attempts", "Blocked", "Worst state"],
        [
            [
                f"<code>{html.escape(model)}</code>",
                str(item["runs"]),
                str(item["completed"]),
                str(item["unsafe"]),
                str(item["blocked"]),
                _state_badge(item["worst"]),
            ]
            for model, item in grouped.items()
        ],
        numeric={1, 2, 3, 4},
    )


@st.cache_data(ttl=300, show_spinner="Running Semgrep…")
def _cached_semgrep_scan() -> dict:
    # Without the cache, every click anywhere in the dashboard re-runs semgrep (up to 15 s).
    return semgrep_scan()


def _sponsors_tab() -> None:
    """Make sponsor value visible without overstating unavailable credentials."""
    st.subheader("Sponsor integrations")
    st.caption(
        "Every card is either backed by a local check or explicitly marked ready/configured."
    )

    try:
        from tripwire import analytics

        clickhouse_state = "connected" if analytics.reachable(timeout=0.5) else "ready"
        clickhouse_detail = (
            "MergeTree audit_events + measured fleet queries"
            if clickhouse_state == "connected"
            else "Run `make analytics` to load the fleet demo"
        )
    except ImportError:
        clickhouse_state, clickhouse_detail = "ready", "Install the optional analytics group"

    cards = [("ClickHouse", clickhouse_state, clickhouse_detail)]
    cards.extend((name, item["status"], item["detail"]) for name, item in provider_status().items())
    _kpis(
        [
            (name, status.upper(), "ok" if status == "connected" else "accent", detail)
            for name, status, detail in cards
        ]
    )

    _section("Semgrep · reproducible code-security scan")
    scan = _cached_semgrep_scan()
    findings = scan.get("findings", [])
    if scan.get("status") == "connected":
        st.success(f"Semgrep local rules executed: {len(findings)} finding(s)")
        for finding in findings:
            path = finding.get("path", "unknown")
            line = finding.get("start", {}).get("line", "?")
            check = finding.get("check_id", "rule")
            st.warning(
                f"{check} · {path}:{line} · {finding.get('extra', {}).get('message', '')}"
            )
    elif scan.get("status") == "not installed":
        st.info(
            "Semgrep is not installed in this runtime. "
            "Run: `semgrep scan --config semgrep.yml src`"
        )
    else:
        st.warning(f"Semgrep scan unavailable: {scan.get('errors', 'unknown error')}")

    _section("Judge-facing story")
    st.markdown(
        "**ClickHouse** answers fleet-scale questions over hash-chained audit events. "
        "**Semgrep** scans the agent/security code path and surfaces provider-egress risk. "
        "**AkashML** can provide the investigator model through the existing OpenAI-compatible "
        "provider. **Guild** hosts the worker/run. **Senso** supplies verified task context before "
        "the agent acts. Tripwire remains the fail-closed enforcement boundary."
    )


# ---------------------------------------------------------------- helpers


def _audit_logs() -> list[Path]:
    try:
        logs = [
            path for path in LOG_DIR.glob("*.jsonl") if path.is_file() and path.stat().st_size > 0
        ]
    except OSError:
        return []
    rank = {stem: index for index, stem in enumerate(LOG_ORDER)}
    return sorted(logs, key=lambda path: (rank.get(path.stem, len(rank)), path.stem))


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


def _display(path: Path) -> str:
    """A path relative to the repo or the log directory, so no home directory is shown."""
    for base in (ROOT, LOG_DIR.parent):
        try:
            return str(path.resolve().relative_to(base.resolve()))
        except ValueError:
            continue
    return path.name


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


def _arguments(event: AuditEvent) -> str:
    args = ", ".join(f"{key}={value}" for key, value in event.attempted.arguments.items())
    return html.escape(args or "no arguments")


if __name__ == "__main__":
    main()
