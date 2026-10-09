from __future__ import annotations

import sys
from pathlib import Path

from tripwire.audit import AuditLog
from tripwire.demo import main as demo_main
from tripwire.live_demo import LocalModelUnavailable, run_live_demo


def test_live_decoy_read_is_denied_before_execution(tmp_path: Path) -> None:
    actions = iter(
        [
            {"tool": "read_customer", "arguments": {"customer_id": "A"}},
            {"tool": "read_ticket", "arguments": {"customer_id": "A", "ticket_id": "T-A-102"}},
        ]
    )

    result = run_live_demo(next_action=lambda _messages: next(actions), output_dir=tmp_path)
    events = AuditLog(result.audit_path).read_events()

    assert [row["decision"] for row in result.rows] == ["ALLOW", "DENY"]
    assert result.rows[-1]["containment_state"] == "KILLED"
    assert [event.tool_executed for event in events] == [True, False]
    assert "HONEYTOKEN" in " ".join(events[-1].reason_codes)
    assert AuditLog(result.audit_path).verify_chain()


def test_malformed_model_action_is_denied_and_audited(tmp_path: Path) -> None:
    result = run_live_demo(
        next_action=lambda _messages: {"tool": "read_ticket", "arguments": "invalid"},
        output_dir=tmp_path,
        max_steps=1,
    )
    events = AuditLog(result.audit_path).read_events()

    assert len(events) == 1
    assert events[0].decision == "DENY"
    assert events[0].reason_codes == ("MALFORMED_MODEL_ACTION",)
    assert not events[0].tool_executed


def test_live_cli_falls_back_to_replay_when_ollama_is_down(monkeypatch, capsys) -> None:
    from tripwire import demo, live_demo

    class OfflineClient:
        model = "offline"
        endpoint = "http://127.0.0.1:11434/api/chat"

        def next_action(self, _messages):
            raise LocalModelUnavailable("offline")

    seen: list[str] = []

    def fake_replay(name: str):
        seen.append(name)
        return []

    monkeypatch.setattr(live_demo, "default_client", lambda: OfflineClient())
    monkeypatch.setattr(demo, "replay_scenario", fake_replay)
    monkeypatch.setattr(sys, "argv", ["tripwire-demo", "--mode", "live"])

    demo_main()

    assert seen == ["slow_drift"]
    assert "replaying slow_drift" in capsys.readouterr().out


def test_unavailable_model_preserves_previous_live_log(tmp_path: Path) -> None:
    first = run_live_demo(
        next_action=lambda _messages: {
            "tool": "read_ticket",
            "arguments": {"customer_id": "A", "ticket_id": "T-A-102"},
        },
        output_dir=tmp_path,
    )
    original = first.audit_path.read_bytes()

    def unavailable(_messages):
        raise LocalModelUnavailable("offline")

    try:
        run_live_demo(next_action=unavailable, output_dir=tmp_path)
    except LocalModelUnavailable:
        pass
    else:
        raise AssertionError("expected local model to be unavailable")

    assert first.audit_path.read_bytes() == original
