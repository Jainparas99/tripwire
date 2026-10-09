from pathlib import Path

import pytest

from tripwire.demo import load_scenarios, replay_scenario

DASHBOARD = Path(__file__).resolve().parents[1] / "dashboard/app.py"


def test_demo_scenarios_end_in_expected_states(tmp_path: Path) -> None:
    final_states = {
        name: replay_scenario(name, output_dir=tmp_path)[-1]["containment_state"]
        for name in load_scenarios()
    }

    assert final_states == {"benign": "OK", "slow_drift": "PAUSED", "escape": "KILLED"}


def test_agent_scenarios_carry_no_honeytokens() -> None:
    text = Path("examples/enterprise_agent/scenarios.json").read_text(encoding="utf-8")

    for token in ("aws_key_decoy", "answer_key_pointer", "internal_url_decoy"):
        assert token not in text


def test_dashboard_renders_each_demo_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    streamlit_testing = pytest.importorskip("streamlit.testing.v1")
    for name in load_scenarios():
        replay_scenario(name, output_dir=tmp_path)
    monkeypatch.setenv("TRIPWIRE_LOG_DIR", str(tmp_path))

    app = streamlit_testing.AppTest.from_file(str(DASHBOARD), default_timeout=30).run()
    assert not app.exception
    radio = app.sidebar.radio[0]
    for option in radio.options:
        app = radio.set_value(option).run()
        assert not app.exception
        metrics = {metric.label: metric.value for metric in app.metric}
        assert metrics["Ran while blocked"] == "0"
        assert metrics["Audit chain"] == "valid"
        radio = app.sidebar.radio[0]


def test_dashboard_gauntlet_tab_reads_committed_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    streamlit_testing = pytest.importorskip("streamlit.testing.v1")
    snapshot = json.loads(
        (DASHBOARD.parents[1] / "evaluation/gauntlet_results.json").read_text(encoding="utf-8")
    )
    monkeypatch.setenv("TRIPWIRE_LOG_DIR", str(tmp_path))

    app = streamlit_testing.AppTest.from_file(str(DASHBOARD), default_timeout=30).run()

    assert not app.exception
    assert [tab.label for tab in app.tabs] == [
        "Live containment",
        "Incident report",
        "Model gauntlet",
        "Remediation",
        "Red-team",
        "Fleet",
    ]
    gauntlet = app.tabs[2]
    assert gauntlet.table, "gauntlet tab should render the snapshot table"
    rendered = gauntlet.table[0].value
    assert list(rendered["Model"]) == [row["model"] for row in snapshot["results"]]
    assert "not an autonomous red team" in " ".join(caption.value for caption in gauntlet.caption)
