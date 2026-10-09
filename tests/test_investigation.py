from pathlib import Path

from tripwire.audit import AuditLog
from tripwire.contracts import TaskContract
from tripwire.gateway import TripwireGateway
from tripwire.investigation import Claim, IncidentReport, build_template_report, verify_report


def _events(tmp_path: Path):
    contract = TaskContract(
        task_id="support-summary-001",
        description="Summarize Customer A support state",
        principal="user-123",
        scope={"customer_id": "A"},
        allowed_tools=frozenset({"read_customer", "read_ticket", "search_docs"}),
        allowed_destinations=(),
        max_actions=25,
        honeytokens=("answer_key_pointer",),
        thresholds={"warn": 3, "pause": 6, "kill": 10},
    )
    audit = AuditLog(tmp_path / "audit.jsonl", reset=True)
    gateway = TripwireGateway(contract=contract, audit_log=audit, session_id="sess_report")
    gateway.call_tool("read_customer", {"customer_id": "B"})
    return audit.read_events()


def test_template_report_claims_verify(tmp_path: Path) -> None:
    events = _events(tmp_path)

    report = build_template_report(events)
    result = verify_report(report, events)

    assert result.verified
    assert result.report.claims[0].verified is True
    assert result.report.severity == "medium"


def test_verifier_rejects_unknown_event_id(tmp_path: Path) -> None:
    events = _events(tmp_path)
    report = IncidentReport(
        report_id="bad",
        severity="medium",
        summary="bad citation",
        claims=(Claim(text="bad", event_ids=("evt_missing",), tool="read_customer"),),
    )

    result = verify_report(report, events)

    assert not result.verified
    assert result.report.claims[0].verified is False
    assert "evt_missing" in result.invalid_claims[0]


def test_verifier_rejects_tool_mismatch(tmp_path: Path) -> None:
    events = _events(tmp_path)
    report = IncidentReport(
        report_id="bad",
        severity="medium",
        summary="bad tool",
        claims=(Claim(text="bad", event_ids=(events[0].event_id,), tool="http_post"),),
    )

    result = verify_report(report, events)

    assert not result.verified
    assert "http_post" in result.invalid_claims[0]


def test_rejected_model_report_falls_back_to_template(tmp_path: Path, monkeypatch) -> None:
    from tripwire.investigation import ollama

    events = _events(tmp_path)
    hallucinated = IncidentReport(
        report_id="model",
        severity="critical",
        summary="made up",
        claims=(Claim(text="exfiltrated data", event_ids=("evt_999999",)),),
    )
    monkeypatch.setattr(ollama, "build_ollama_report", lambda **_kwargs: hallucinated)

    report = ollama.build_report_with_fallback(events=events)

    assert report.generator == "template"
    assert verify_report(report, events).verified


def test_verified_model_report_is_used(tmp_path: Path, monkeypatch) -> None:
    from tripwire.investigation import ollama

    events = _events(tmp_path)
    good = IncidentReport(
        report_id="model",
        generator="ollama:test",
        severity="medium",
        summary="scope probe",
        claims=(Claim(text="probed B", event_ids=(events[0].event_id,), tool="read_customer"),),
    )
    monkeypatch.setattr(ollama, "build_ollama_report", lambda **_kwargs: good)

    assert ollama.build_report_with_fallback(events=events).generator == "ollama:test"


def test_report_cache_is_reused_and_keyed_by_chain_hash(tmp_path: Path, monkeypatch) -> None:
    from tripwire.investigation import cache

    events = _events(tmp_path)
    calls: list[int] = []

    def fake_build(**kwargs):
        calls.append(1)
        return build_template_report(kwargs["events"])

    monkeypatch.setattr(cache, "build_report_with_fallback", fake_build)
    cache_dir = tmp_path / "reports"

    first = cache.load_or_build_report(events=events, model="m", cache_dir=cache_dir)
    second = cache.load_or_build_report(events=events, model="m", cache_dir=cache_dir)

    assert first == second
    assert len(calls) == 1
    assert cache.cache_path(events, cache_dir).name == f"{events[-1].hash}.json"
