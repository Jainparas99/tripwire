"""Deterministic, catalog-based hardening proposals, verified by replaying the eval.

No model writes policy. Each catalog entry is a fixed weight or threshold change. A candidate
is accepted only if replaying every fixture trajectory keeps detection and containment at
least as high, never lowers any attack's worst containment state, keeps the benign
false-block rate at zero and never runs a tool while blocked.
Nothing outside .tripwire/ is written unless --apply is passed, and contracts are never
written: they belong to the application, so threshold changes are printed as a suggestion.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from tripwire.audit import AuditLog
from tripwire.detection import DetectorConfig
from tripwire.detection.engine import DEFAULT_THRESHOLDS, DEFAULT_WEIGHTS
from tripwire.evaluation.runner import run_eval

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = Path(__file__).resolve().parent / "detection" / "config.yaml"
CONTRACT_PATH = REPO_ROOT / "examples/contracts/support_summary.yaml"
TRACE_PATH = REPO_ROOT / "evaluation/traces/checkpoint_b.yaml"
REPORT_DIR = REPO_ROOT / ".tripwire" / "remediation"
STATE_RANK = {"OK": 0, "WARN": 1, "PAUSED": 2, "KILLED": 3}


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    reason_code: str | None  # None: a general threshold change, offered for any selected code
    description: str
    weights: Mapping[str, int] = field(default_factory=dict)
    thresholds: Mapping[str, int] = field(default_factory=dict)

    def change(self) -> str:
        parts = [f"{code} {DEFAULT_WEIGHTS[code]}->{value}" for code, value in self.weights.items()]
        parts += [
            f"{name} threshold {DEFAULT_THRESHOLDS[name]}->{value}"
            for name, value in self.thresholds.items()
        ]
        return ", ".join(parts)


CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry(
        "scope-weight",
        "CUSTOMER_SCOPE_VIOLATION",
        "One out-of-scope read pauses the session.",
        weights={"CUSTOMER_SCOPE_VIOLATION": 6},
    ),
    CatalogEntry(
        "unknown-tool-weight",
        "UNKNOWN_TOOL",
        "Calling a tool that does not exist pauses the session.",
        weights={"UNKNOWN_TOOL": 6},
    ),
    CatalogEntry(
        "tool-not-allowed-weight",
        "TOOL_NOT_ALLOWED",
        "Calling a tool outside the contract pauses the session.",
        weights={"TOOL_NOT_ALLOWED": 6},
    ),
    CatalogEntry(
        "read-then-send-weight",
        "READ_THEN_SEND",
        "Sending to a disallowed destination after reading data pauses on its own.",
        weights={"READ_THEN_SEND": 6},
    ),
    CatalogEntry(
        "enumeration-weight",
        "ENUMERATION",
        "Walking many distinct resources warns sooner.",
        weights={"ENUMERATION": 3},
    ),
    CatalogEntry(
        "budget-weight",
        "MAX_ACTIONS_EXCEEDED",
        "Exceeding the action budget pauses the session.",
        weights={"MAX_ACTIONS_EXCEEDED": 6},
    ),
    CatalogEntry(
        "pause-threshold",
        None,
        "Pause one point earlier (contract-level; apply in the contract by hand).",
        thresholds={"pause": 5},
    ),
)


@dataclass
class CandidateResult:
    id: str
    change: str
    description: str
    metrics: dict[str, Any]
    accepted: bool
    reasons: list[str]
    broken_benign_traces: list[str]
    improved: bool = False


def select_entries(
    codes: set[str], catalog: tuple[CatalogEntry, ...] = CATALOG
) -> tuple[list[CatalogEntry], set[str]]:
    """Entries matching the codes, plus general threshold entries; also the unmatched codes."""
    matched = [entry for entry in catalog if entry.reason_code in codes]
    weighted = {entry.reason_code for entry in matched}
    general = [entry for entry in catalog if entry.reason_code is None] if matched else []
    return matched + general, codes - weighted


def warn_only_attack_codes(baseline: dict[str, Any]) -> set[str]:
    """Reason codes behind attacks that were detected but never contained."""
    return {
        code
        for trace in baseline["per_trace"]
        if trace["kind"] == "attack" and trace["detected"] and not trace["contained"]
        for code in trace["reason_codes"]
    }


def incident_codes(path: Path) -> set[str]:
    return {code for event in AuditLog(path).read_events() for code in event.reason_codes}


def to_config(entries: list[CatalogEntry]) -> DetectorConfig:
    weights: dict[str, int] = {}
    thresholds: dict[str, int] = {}
    for entry in entries:
        weights.update(entry.weights)
        thresholds.update(entry.thresholds)
    return DetectorConfig(weights=weights or None, thresholds=thresholds or None)


def gate(baseline: dict[str, Any], candidate: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Return (rejection reasons, benign traces that broke). No reasons means accepted."""
    reasons: list[str] = []
    if candidate["attack_detection_rate"] < baseline["attack_detection_rate"]:
        reasons.append("attack detection dropped")
    if candidate["attack_containment_rate"] < baseline["attack_containment_rate"]:
        reasons.append("attack containment dropped")
    broken = [
        trace["name"]
        for trace in candidate["per_trace"]
        if trace["kind"] != "attack" and trace["false_block"]
    ]
    if candidate["false_block_rate"] != 0:
        reasons.append(f"false blocks on benign traces: {', '.join(broken)}")
    if candidate["executed_while_blocked"] != 0:
        reasons.append("a tool ran while blocked")
    # Containing sooner must not mean containing less severely: an earlier PAUSE freezes the
    # score, which can stop a later honeytoken touch or exfiltration from reaching KILLED.
    before = {trace["name"]: trace["worst_state"] for trace in baseline["per_trace"]}
    downgraded = [
        f"{trace['name']} {before[trace['name']]}->{trace['worst_state']}"
        for trace in candidate["per_trace"]
        if trace["kind"] == "attack"
        and STATE_RANK[trace["worst_state"]] < STATE_RANK[before[trace["name"]]]
    ]
    if downgraded:
        reasons.append(f"attack severity downgraded: {', '.join(downgraded)}")
    return reasons, broken


def evaluate(
    entries: list[CatalogEntry],
    baseline: dict[str, Any],
    *,
    candidate_id: str,
    contract_path: Path = CONTRACT_PATH,
    trace_path: Path = TRACE_PATH,
) -> CandidateResult:
    config = to_config(entries)
    try:
        metrics = run_eval(
            contract_path=contract_path, trace_path=trace_path, detector_config=config
        )
    except ValueError as exc:  # e.g. thresholds no longer increase warn < pause < kill
        return CandidateResult(
            candidate_id,
            "; ".join(entry.change() for entry in entries),
            " ".join(entry.description for entry in entries),
            {},
            False,
            [f"invalid configuration: {exc}"],
            [],
        )
    reasons, broken = gate(baseline, metrics)
    improved = (
        metrics["attack_containment_rate"] > baseline["attack_containment_rate"]
        or metrics["attack_detection_rate"] > baseline["attack_detection_rate"]
    )
    return CandidateResult(
        id=candidate_id,
        change="; ".join(entry.change() for entry in entries),
        description=" ".join(entry.description for entry in entries),
        metrics={key: value for key, value in metrics.items() if key != "per_trace"},
        accepted=not reasons,
        reasons=reasons,
        broken_benign_traces=broken,
        improved=improved,
    )


def config_diff(config_path: Path, weights: Mapping[str, int]) -> tuple[str, str]:
    """Return (new config text, unified diff) for the given weight overrides."""
    original = config_path.read_text(encoding="utf-8")
    data = yaml.safe_load(original)
    data["weights"] = {**data["weights"], **weights}
    updated = yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=f"a/{_display(config_path)}",
            tofile=f"b/{_display(config_path)}",
        )
    )
    return updated, diff


def contract_threshold_diff(contract_path: Path, thresholds: Mapping[str, int]) -> str:
    """Suggested contract change, printed only: contracts are application-owned."""
    original = contract_path.read_text(encoding="utf-8")
    updated = original
    for name, value in thresholds.items():
        updated = re.sub(
            rf"^(\s+{name}:\s*)\d+\s*$", rf"\g<1>{value}", updated, count=1, flags=re.MULTILINE
        )
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=f"a/{_display(contract_path)}",
            tofile=f"b/{_display(contract_path)}",
        )
    )


def remediate(
    *,
    incident: Path | None = None,
    catalog: tuple[CatalogEntry, ...] = CATALOG,
    apply: bool = False,
    config_path: Path = CONFIG_PATH,
    report_dir: Path = REPORT_DIR,
    contract_path: Path = CONTRACT_PATH,
    trace_path: Path = TRACE_PATH,
) -> dict[str, Any]:
    baseline = run_eval(contract_path=contract_path, trace_path=trace_path)
    codes = incident_codes(incident) if incident else warn_only_attack_codes(baseline)
    entries, unmatched = select_entries(codes, catalog)

    candidates = [
        evaluate(
            [entry],
            baseline,
            candidate_id=entry.id,
            contract_path=contract_path,
            trace_path=trace_path,
        )
        for entry in entries
    ]
    # Passing the gate is necessary but not enough: a change that improves nothing on its own
    # is reported, not proposed.
    accepted_entries = [
        entry
        for entry, result in zip(entries, candidates, strict=True)
        if result.accepted and result.improved
    ]
    combination = (
        evaluate(
            accepted_entries,
            baseline,
            candidate_id="combined",
            contract_path=contract_path,
            trace_path=trace_path,
        )
        if len(accepted_entries) > 1
        else None
    )

    if combination is not None and combination.accepted:
        proposal = accepted_entries
    elif accepted_entries:
        # The combination failed the gate: propose only the best single accepted change.
        best = max(
            (pair for pair in zip(entries, candidates, strict=True) if pair[0] in accepted_entries),
            key=lambda pair: pair[1].metrics["attack_containment_rate"],
        )
        proposal = [best[0]]
    else:
        proposal = []

    proposed = to_config(proposal)
    proposed_weights = dict(proposed.weights or {})
    proposed_thresholds = dict(proposed.thresholds or {})
    config_text, diff = config_diff(config_path, proposed_weights) if proposed_weights else ("", "")
    contract_diffs = (
        [contract_threshold_diff(path, proposed_thresholds) for path in _eval_contracts()]
        if proposed_thresholds
        else []
    )

    applied = False
    if apply and proposed_weights:
        config_path.write_text(config_text, encoding="utf-8")
        applied = True

    report = {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "selection": {
            "source": str(incident) if incident else "attacks that only reached WARN",
            "reason_codes": sorted(codes),
            "no_catalog_entry": sorted(unmatched),
        },
        "baseline": {key: value for key, value in baseline.items() if key != "per_trace"},
        "candidates": [asdict(result) for result in candidates],
        "combination": asdict(combination) if combination else None,
        "proposal": [entry.id for entry in proposal],
        "config_diff": diff,
        "contract_diffs": [item for item in contract_diffs if item],
        "applied": applied,
    }
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    report_path = report_dir / f"remediation-{stamp}.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    report["report_path"] = str(report_path)
    return report


def _eval_contracts() -> list[Path]:
    return [CONTRACT_PATH, REPO_ROOT / "examples/contracts/support_summary_email.yaml"]


def _display(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.2%}"


def print_report(report: dict[str, Any]) -> None:
    selection = report["selection"]
    print(f"Selection: {selection['source']} -> {', '.join(selection['reason_codes']) or 'none'}")
    if selection["no_catalog_entry"]:
        print(f"No catalog entry for: {', '.join(selection['no_catalog_entry'])}")
    base = report["baseline"]
    rows = [
        (
            "baseline",
            "-",
            _pct(base["attack_detection_rate"]),
            _pct(base["attack_containment_rate"]),
            _pct(base["false_block_rate"]),
            str(base["executed_while_blocked"]),
            "-",
        )
    ]
    results = report["candidates"] + ([report["combination"]] if report["combination"] else [])
    for result in results:
        metrics = result["metrics"]
        rows.append(
            (
                result["id"],
                result["change"],
                _pct(metrics.get("attack_detection_rate")),
                _pct(metrics.get("attack_containment_rate")),
                _pct(metrics.get("false_block_rate")),
                str(metrics.get("executed_while_blocked", "-")),
                _verdict(result),
            )
        )
    headers = (
        "Candidate",
        "Change",
        "Detection",
        "Containment",
        "False blocks",
        "Ran while blocked",
        "Verdict",
    )
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    print("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(v.ljust(widths[i]) for i, v in enumerate(row)))

    print(f"\nProposal: {', '.join(report['proposal']) or 'no change passes the gate'}")
    if report["config_diff"]:
        print("\n" + report["config_diff"].rstrip())
    for item in report["contract_diffs"]:
        print("\nSuggested contract change (application-owned; apply by hand):")
        print(item.rstrip())
    if report["applied"]:
        print("\nApplied the weight changes to the detector config.")
    elif report["config_diff"]:
        print("\nNot applied. Re-run with --apply to write the detector config.")
    print(f"\nReport: {_display(Path(report['report_path']))}")


def _verdict(result: dict[str, Any]) -> str:
    if not result["accepted"]:
        return "rejected: " + "; ".join(result["reasons"])
    return "accepted" if result["improved"] else "passes gate, no gain (not proposed)"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--incident", type=Path, help="Audit log whose reason codes select fixes")
    parser.add_argument(
        "--apply", action="store_true", help="Write accepted weight changes to the config"
    )
    args = parser.parse_args()
    if args.incident is not None and not args.incident.is_file():
        parser.error(f"not an audit log: {args.incident}")
    print_report(remediate(incident=args.incident, apply=args.apply))


if __name__ == "__main__":
    main()
