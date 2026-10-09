import subprocess
import sys
from pathlib import Path

import pytest

from tripwire import analytics

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "dashboard/app.py"


def test_enforcement_never_imports_analytics() -> None:
    code = (
        "import sys, tripwire.gateway, tripwire.proxy.server, tripwire.proxy.mcp_server;"
        "bad = [m for m in ('tripwire.analytics', 'clickhouse_connect') if m in sys.modules];"
        "assert not bad, bad"
    )
    subprocess.run([sys.executable, "-c", code], check=True, cwd=ROOT)


def test_synthetic_scaleup_is_labelled_deterministic_and_sized() -> None:
    replayed = analytics.replay_fixtures()
    assert len(replayed) == 26

    rows = list(analytics.synthetic_rows(replayed, target_events=1_000))
    again = list(analytics.synthetic_rows(replayed, target_events=1_000))

    longest = max(len(events) for _name, events in replayed)
    assert 1_000 <= len(rows) < 1_000 + longest
    assert rows == again
    columns = dict(zip(analytics.COLUMNS, zip(*rows, strict=True), strict=True))
    assert set(columns["synthetic"]) == {1}
    assert set(columns["source"]) == {analytics.SYNTHETIC_SOURCE}
    assert all(session.startswith("syn-") for session in columns["session_id"])


def test_synthetic_copies_keep_the_gateway_decisions() -> None:
    replayed = dict(analytics.replay_fixtures())
    escape = replayed["attack_escape_style"]
    rows = list(analytics.synthetic_rows([("attack_escape_style", escape)], target_events=1))

    assert [row[6] for row in rows] == [event.decision.value for event in escape]
    assert [row[7] for row in rows] == [event.containment_state.value for event in escape]


def test_unreachable_clickhouse_is_reported_without_raising(monkeypatch) -> None:
    monkeypatch.setenv("TRIPWIRE_CLICKHOUSE_PORT", "1")
    assert analytics.reachable(timeout=0.2) is False


def test_fleet_hides_clickhouse_panel_when_unreachable(tmp_path, monkeypatch) -> None:
    streamlit_testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("TRIPWIRE_LOG_DIR", str(tmp_path))
    monkeypatch.setattr(analytics, "reachable", lambda timeout=0.5: False)

    app = streamlit_testing.AppTest.from_file(str(DASHBOARD), default_timeout=30).run()

    assert not app.exception
    text = " ".join(item.value for item in app.markdown)
    assert "ClickHouse analytics" not in text


def test_fleet_shows_clickhouse_panel_when_reachable(tmp_path, monkeypatch) -> None:
    streamlit_testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("TRIPWIRE_LOG_DIR", str(tmp_path))
    monkeypatch.setattr(analytics, "reachable", lambda timeout=0.5: True)
    monkeypatch.setattr(
        analytics,
        "table_summary",
        lambda: {"events": 1_000_021, "sessions": 288_895, "synthetic_events": 1_000_001},
    )
    monkeypatch.setattr(
        analytics,
        "run_queries",
        lambda: {
            "top_deny_reasons": {
                "columns": ["reason", "denials"],
                "rows": [["CUSTOMER_SCOPE_VIOLATION", 66668]],
                "latency_ms": 18.1,
            }
        },
    )

    app = streamlit_testing.AppTest.from_file(str(DASHBOARD), default_timeout=30).run()

    assert not app.exception
    text = " ".join(item.value for item in app.markdown)
    assert "ClickHouse analytics · synthetic scale-up" in text
    assert "SYNTHETIC" in text
    assert "18.1 ms" in text


def test_sub_second_timeout_does_not_break_the_client(monkeypatch) -> None:
    pytest.importorskip("clickhouse_connect")
    monkeypatch.setenv("TRIPWIRE_CLICKHOUSE_PORT", "1")
    try:
        analytics.client(timeout=0.5)
    except ValueError as exc:  # the client rejected the timeout itself
        pytest.fail(f"sub-second timeout rejected: {exc}")
    except Exception:
        pass  # nothing listens on port 1; a connection error is expected
