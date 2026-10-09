from pathlib import Path

from tripwire.audit import AuditLog
from tripwire.contracts import TaskContract
from tripwire.gateway import TripwireGateway
from tripwire.investigation.providers import (
    InvestigatorProviderUnavailable,
    ProviderSpec,
    build_anthropic_report,
    build_report_with_providers,
)


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
    gateway = TripwireGateway(contract=contract, audit_log=audit, session_id="sess_provider")
    gateway.call_tool("read_customer", {"customer_id": "B"})
    return audit.read_events()


def test_provider_spec_preserves_model_names_with_colons() -> None:
    provider = ProviderSpec.parse("ollama:glm4:9b-chat")

    assert provider.kind == "ollama"
    assert provider.model == "glm4:9b-chat"


def test_provider_chain_falls_back_to_template_when_model_unavailable(tmp_path: Path) -> None:
    report = build_report_with_providers(
        events=_events(tmp_path),
        providers=(ProviderSpec(kind="ollama", model="not-running"), ProviderSpec(kind="template")),
        timeout=0.01,
    )

    assert report.generator == "template"
    assert report.claims[0].verified is True


def test_anthropic_provider_requires_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("CLAUDE_API_KEY", raising=False)

    try:
        build_anthropic_report(events=_events(tmp_path), model="claude-sonnet-4-5")
    except InvestigatorProviderUnavailable as exc:
        assert "ANTHROPIC_API_KEY" in str(exc)
    else:  # pragma: no cover - the provider must not silently continue without a key
        raise AssertionError("anthropic provider should require an API key")


def test_openai_compatible_provider_accepts_glm_style_response(tmp_path: Path, monkeypatch) -> None:
    from tripwire.investigation import providers as provider_module

    events = _events(tmp_path)
    event_id = events[0].event_id
    payload = {
        "report_id": "glm-report",
        "severity": "medium",
        "summary": "GLM-compatible report",
        "stage_labels": ["recon"],
        "timeline": [f"{event_id}: denied"],
        "claims": [
            {
                "text": "scope violation",
                "event_ids": [event_id],
                "tool": "read_customer",
                "arguments": {"customer_id": "B"},
            }
        ],
    }

    def fake_post_json(endpoint, body, *, timeout, headers=None):
        return {"choices": [{"message": {"content": provider_module.json.dumps(payload)}}]}

    monkeypatch.setenv("TRIPWIRE_OPENAI_COMPAT_ENDPOINT", "http://localhost/v1/chat/completions")
    monkeypatch.setattr(provider_module, "_post_json", fake_post_json)

    report = build_report_with_providers(
        events=events,
        providers=(ProviderSpec(kind="openai-compatible", model="glm-4.5"),),
    )

    assert report.generator == "openai-compatible:glm-4.5"
    assert report.claims[0].verified is True


def test_ollama_report_requests_incident_schema(tmp_path: Path, monkeypatch) -> None:
    from tripwire.investigation import providers as provider_module
    from tripwire.investigation.template import build_template_report

    events = _events(tmp_path)
    seen: list[dict] = []

    def fake_post_json(_endpoint, payload, *, timeout, headers=None):
        seen.append(payload)
        return {"response": build_template_report(events).model_dump_json()}

    monkeypatch.setattr(provider_module, "_post_json", fake_post_json)

    report = provider_module.build_ollama_report(events=events, model="qwen2.5:3b-instruct")

    assert report.generator == "ollama:qwen2.5:3b-instruct"
    assert seen[0]["format"]["properties"]["timeline"]["items"]["type"] == "string"
