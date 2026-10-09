from pathlib import Path

from tripwire.audit import AuditLog
from tripwire.contracts import TaskContract
from tripwire.gateway import TripwireGateway
from tripwire.investigation import Claim, IncidentReport, build_template_report, verify_report
from tripwire.investigation.providers import ProviderSpec, build_report_with_providers


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


def test_cache_key_is_stable_across_replays_with_new_timestamps(tmp_path: Path) -> None:
    from tripwire.investigation.cache import cache_path

    first = _events(tmp_path / "first")
    second = _events(tmp_path / "second")

    assert cache_path(first) == cache_path(second)


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


def test_verifier_rejects_argument_mismatch(tmp_path: Path) -> None:
    events = _events(tmp_path)
    report = IncidentReport(
        report_id="bad",
        severity="medium",
        summary="bad arguments",
        claims=(
            Claim(
                text="bad",
                event_ids=(events[0].event_id,),
                tool="read_customer",
                arguments={"customer_id": "A"},
            ),
        ),
    )

    result = verify_report(report, events)

    assert not result.verified
    assert "customer_id" in result.invalid_claims[0]


def test_verifier_rejects_contradictory_decision_and_execution_claim(tmp_path: Path) -> None:
    events = _events(tmp_path)
    report = IncidentReport(
        report_id="bad",
        severity="medium",
        summary="bad facts",
        claims=(
            Claim(
                text="tool ran and was allowed",
                event_ids=(events[0].event_id,),
                decision="ALLOW",
                tool_executed=True,
            ),
        ),
    )

    result = verify_report(report, events)

    assert not result.verified
    assert any("decision" in error for error in result.invalid_claims)
    assert any("tool_executed" in error for error in result.invalid_claims)


def test_verifier_rejects_report_without_claims(tmp_path: Path) -> None:
    events = _events(tmp_path)
    report = IncidentReport(
        report_id="empty",
        severity="medium",
        summary="no evidence",
    )

    result = verify_report(report, events)

    assert not result.verified
    assert result.invalid_claims == ("report contains no claims",)


def test_verifier_derives_severity_and_stages_from_events(tmp_path: Path) -> None:
    events = _events(tmp_path)
    template = build_template_report(events)
    report = template.model_copy(
        update={"severity": "critical", "stage_labels": ("Data Exfiltration",)}
    )

    verified = verify_report(report, events)

    assert verified.verified
    assert verified.report.severity == template.severity
    assert verified.report.stage_labels == template.stage_labels


def test_benign_sessions_skip_model_investigation(tmp_path: Path, monkeypatch) -> None:
    contract = TaskContract(
        task_id="benign-investigation",
        description="Read Customer A",
        principal="tester",
        scope={"customer_id": "A"},
        allowed_tools=frozenset({"read_customer"}),
        max_actions=2,
    )
    audit = AuditLog(tmp_path / "audit.jsonl", reset=True)
    gateway = TripwireGateway(contract=contract, audit_log=audit)
    gateway.call_tool("read_customer", {"customer_id": "A"})

    def fail_if_called(**_kwargs):
        raise AssertionError("model provider should not run for a benign session")

    monkeypatch.setattr("tripwire.investigation.providers._build_provider_report", fail_if_called)
    report = build_report_with_providers(
        events=audit.read_events(),
        providers=(ProviderSpec(kind="ollama", model="qwen"),),
    )

    assert report.generator == "template"
    assert report.severity == "informational"


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
        claims=(
            Claim(
                text="probed B",
                event_ids=(events[0].event_id,),
                tool="read_customer",
                decision="DENY",
                tool_executed=False,
            ),
        ),
    )
    monkeypatch.setattr(ollama, "build_ollama_report", lambda **_kwargs: good)

    assert ollama.build_report_with_fallback(events=events).generator == "ollama:test"


def test_template_report_is_rebuilt_when_model_becomes_available(
    tmp_path: Path, monkeypatch
) -> None:
    from tripwire.investigation import cache

    events = _events(tmp_path)
    calls: list[int] = []

    def fake_build(**kwargs):
        calls.append(1)
        report = build_template_report(kwargs["events"])
        if len(calls) == 1:
            return report
        return report.model_copy(update={"generator": "ollama:glm4:9b"})

    monkeypatch.setattr(cache, "build_report_with_providers", fake_build)
    cache_dir = tmp_path / "reports"
    path = cache.cache_path(events, cache_dir)

    first = cache.load_or_build_report(events=events, model="glm4:9b", cache_dir=cache_dir)
    assert first.generator == "template"
    assert path.exists()

    second = cache.load_or_build_report(
        events=events, model="glm4:9b", cache_dir=cache_dir, refresh=True
    )
    third = cache.load_or_build_report(events=events, model="glm4:9b", cache_dir=cache_dir)

    assert second.generator == third.generator == "ollama:glm4:9b"
    assert len(calls) == 2
    assert path == cache.cache_path(events, cache_dir)


def test_legacy_template_cache_is_ignored_and_model_change_rebuilds(
    tmp_path: Path, monkeypatch
) -> None:
    from tripwire.investigation import cache

    events = _events(tmp_path)
    cache_dir = tmp_path / "reports"
    cache_dir.mkdir()
    cache.cache_path(events, cache_dir).write_text(
        build_template_report(events).model_dump_json(), encoding="utf-8"
    )
    calls: list[str] = []

    def fake_build(**kwargs):
        label = kwargs["providers"][0].label
        calls.append(label)
        return build_template_report(kwargs["events"]).model_copy(update={"generator": label})

    monkeypatch.setattr(cache, "build_report_with_providers", fake_build)

    first = cache.load_or_build_report(
        events=events, model="qwen", cache_dir=cache_dir, refresh=True
    )
    second = cache.load_or_build_report(
        events=events, model="glm4:9b", cache_dir=cache_dir, refresh=True
    )
    third = cache.load_or_build_report(events=events, model="glm4:9b", cache_dir=cache_dir)

    assert first.generator == "ollama:qwen"
    assert second.generator == third.generator == "ollama:glm4:9b"
    assert calls == ["ollama:qwen", "ollama:glm4:9b"]


def test_cli_model_selects_requested_ollama_model(tmp_path: Path, monkeypatch, capsys) -> None:
    import sys

    from tripwire.investigation import cli

    events = _events(tmp_path)
    log_path = tmp_path / "audit.jsonl"
    seen: list[str] = []

    def fake_load_or_build_report(**kwargs):
        seen.append(kwargs["providers"][0].label)
        return build_template_report(kwargs["events"])

    monkeypatch.setenv("TRIPWIRE_INVESTIGATOR_PROVIDERS", "ollama:qwen2.5:3b-instruct")
    monkeypatch.setattr(cli, "load_or_build_report", fake_load_or_build_report)
    monkeypatch.setattr(sys, "argv", ["investigate", str(log_path), "--model", "glm4:9b"])
    cli.main()

    assert seen == ["ollama:glm4:9b"]
    assert events
    assert '"generator": "template"' in capsys.readouterr().out
