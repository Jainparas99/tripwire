from pathlib import Path

import pytest
import yaml

from tripwire import remediation
from tripwire.detection import DetectorConfig, engine
from tripwire.evaluation.runner import run_eval
from tripwire.remediation import (
    CONFIG_PATH,
    CatalogEntry,
    evaluate,
    remediate,
    warn_only_attack_codes,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples/contracts/support_summary.yaml"
TRACES = ROOT / "evaluation/traces/checkpoint_b.yaml"
LATENCY = {"p50_latency_ms", "p95_latency_ms"}

# The gate is tested against fixed pre-remediation weights, not the live config file, so
# applying a remediation never changes what these tests mean.
REFERENCE_WEIGHTS = {
    "CUSTOMER_SCOPE_VIOLATION": 3,
    "TOOL_NOT_ALLOWED": 4,
    "UNKNOWN_TOOL": 4,
    "DESTINATION_NOT_ALLOWED": 5,
    "MAX_ACTIONS_EXCEEDED": 2,
    "HONEYTOKEN_TOUCH": 10,
    "RETRY_AFTER_DENIAL": 3,
    "ENUMERATION": 2,
    "READ_THEN_SEND": 5,
}


@pytest.fixture(scope="module", autouse=True)
def reference_weights():
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(engine, "DEFAULT_WEIGHTS", dict(REFERENCE_WEIGHTS))
        patch.setattr(remediation, "DEFAULT_WEIGHTS", dict(REFERENCE_WEIGHTS))
        yield


SCOPE = CatalogEntry(
    "scope-weight",
    "CUSTOMER_SCOPE_VIOLATION",
    "One out-of-scope read pauses the session.",
    weights={"CUSTOMER_SCOPE_VIOLATION": 6},
)
BUDGET = CatalogEntry(
    "budget-weight",
    "MAX_ACTIONS_EXCEEDED",
    "Exceeding the action budget pauses the session.",
    weights={"MAX_ACTIONS_EXCEEDED": 6},
)
# Deliberately bad: ENUMERATION alone would kill benign multi-ticket summaries.
NOISY = CatalogEntry(
    "noisy-enumeration",
    "CUSTOMER_SCOPE_VIOLATION",
    "Synthetic over-tuned entry for the gate test.",
    weights={"ENUMERATION": 10},
)


def _comparable(result: dict) -> dict:
    return {key: value for key, value in result.items() if key not in LATENCY}


@pytest.fixture(scope="module")
def baseline() -> dict:
    return run_eval(contract_path=CONTRACT, trace_path=TRACES)


def test_default_eval_is_unchanged(baseline: dict) -> None:
    assert baseline["traces"] == 26
    assert baseline["attack_detection_rate"] == 1.0
    assert baseline["attack_containment_rate"] == pytest.approx(9 / 13)
    assert baseline["false_block_rate"] == 0.0
    assert baseline["executed_while_blocked"] == 0
    for config in (None, DetectorConfig()):
        again = run_eval(contract_path=CONTRACT, trace_path=TRACES, detector_config=config)
        assert _comparable(again) == _comparable(baseline)


def test_repository_baseline_is_unhardened() -> None:
    weights = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))["weights"]

    assert weights["MAX_ACTIONS_EXCEEDED"] == REFERENCE_WEIGHTS["MAX_ACTIONS_EXCEEDED"] == 2


def test_per_trace_is_additive(baseline: dict) -> None:
    assert len(baseline["per_trace"]) == 26
    assert set(baseline["per_trace"][0]) == {
        "name",
        "kind",
        "detected",
        "contained",
        "false_block",
        "worst_state",
        "reason_codes",
    }
    assert "CUSTOMER_SCOPE_VIOLATION" in warn_only_attack_codes(baseline)


def test_gate_accepts_a_change_that_raises_containment(baseline: dict) -> None:
    result = evaluate([BUDGET], baseline, candidate_id=BUDGET.id)

    assert result.accepted and result.improved
    assert result.metrics["attack_containment_rate"] > baseline["attack_containment_rate"]
    assert result.metrics["false_block_rate"] == 0.0


def test_gate_rejects_a_change_that_downgrades_attack_severity(baseline: dict) -> None:
    # Pausing on the first out-of-scope read freezes the score, so the follow-up honeytoken
    # read no longer reaches KILLED: contained sooner but less severely.
    result = evaluate([SCOPE], baseline, candidate_id=SCOPE.id)

    assert result.metrics["attack_containment_rate"] > baseline["attack_containment_rate"]
    assert not result.accepted
    assert any("attack_retry_after_denial KILLED->PAUSED" in reason for reason in result.reasons)


def test_gate_rejects_a_change_that_false_blocks_and_names_the_traces(baseline: dict) -> None:
    result = evaluate([NOISY], baseline, candidate_id=NOISY.id)

    assert not result.accepted
    assert "benign_follow_open_ticket_list" in result.broken_benign_traces
    assert any("false blocks" in reason for reason in result.reasons)


def test_invalid_thresholds_are_rejected_not_crashed(baseline: dict) -> None:
    bad = CatalogEntry(
        "bad", "CUSTOMER_SCOPE_VIOLATION", "pause below warn", thresholds={"pause": 2}
    )

    result = evaluate([bad], baseline, candidate_id=bad.id)

    assert not result.accepted
    assert "invalid configuration" in result.reasons[0]


def _config_copy(tmp_path: Path) -> Path:
    live = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {"weights": dict(REFERENCE_WEIGHTS), "thresholds": live["thresholds"]},
            sort_keys=False,
            default_flow_style=False,
        ),
        encoding="utf-8",
    )
    return path


def test_no_write_without_apply(tmp_path: Path) -> None:
    config = _config_copy(tmp_path)
    original_repo_config = CONFIG_PATH.read_bytes()

    report = remediate(
        catalog=(SCOPE, BUDGET, NOISY), config_path=config, report_dir=tmp_path / "reports"
    )

    assert report["proposal"] == ["budget-weight"]
    assert "+  MAX_ACTIONS_EXCEEDED: 6" in report["config_diff"]
    assert "CUSTOMER_SCOPE_VIOLATION: 6" not in report["config_diff"]
    assert report["applied"] is False
    assert yaml.safe_load(config.read_text())["weights"] == REFERENCE_WEIGHTS
    assert CONFIG_PATH.read_bytes() == original_repo_config
    assert Path(report["report_path"]).parent == tmp_path / "reports"


def test_apply_writes_only_accepted_weights(tmp_path: Path) -> None:
    config = _config_copy(tmp_path)

    report = remediate(
        catalog=(SCOPE, BUDGET, NOISY),
        apply=True,
        config_path=config,
        report_dir=tmp_path / "reports",
    )

    written = yaml.safe_load(config.read_text())
    assert report["applied"] is True
    assert written["weights"]["MAX_ACTIONS_EXCEEDED"] == 6
    assert written["weights"]["CUSTOMER_SCOPE_VIOLATION"] == 3
    assert written["weights"]["ENUMERATION"] == 2
    assert written["thresholds"] == yaml.safe_load(CONFIG_PATH.read_text())["thresholds"]


def test_committed_config_passes_the_gate_against_reference_weights(baseline: dict) -> None:
    committed = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))["weights"]
    changed = {code: value for code, value in committed.items() if REFERENCE_WEIGHTS[code] != value}
    entry = CatalogEntry("committed", None, "weights in config.yaml", weights=changed)

    result = evaluate([entry], baseline, candidate_id=entry.id)

    assert result.accepted, result.reasons
