from __future__ import annotations

import json
import os
from dataclasses import dataclass
from json import JSONDecodeError
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import ValidationError

from tripwire.audit import AuditEvent
from tripwire.investigation.models import IncidentReport
from tripwire.investigation.template import build_template_report
from tripwire.investigation.verifier import verify_report

DEFAULT_PROVIDER_CHAIN = ("ollama:qwen2.5:3b-instruct", "template")


class InvestigatorProviderUnavailable(RuntimeError):
    """Raised when a model provider cannot produce a valid, verified report."""


@dataclass(frozen=True)
class ProviderSpec:
    kind: str
    model: str | None = None

    @classmethod
    def parse(cls, raw: str) -> ProviderSpec:
        value = raw.strip()
        if not value:
            raise ValueError("empty provider")
        if value == "template":
            return cls(kind="template")
        if ":" not in value:
            return cls(kind="ollama", model=value)
        kind, rest = value.split(":", 1)
        if kind in {"ollama", "anthropic", "openai-compatible"}:
            if not rest:
                raise ValueError(f"{kind} provider requires a model")
            return cls(kind=kind, model=rest)
        raise ValueError(f"unknown investigator provider: {kind}")

    @property
    def label(self) -> str:
        return self.kind if self.model is None else f"{self.kind}:{self.model}"


def provider_chain_from_env() -> tuple[ProviderSpec, ...]:
    raw = os.getenv("TRIPWIRE_INVESTIGATOR_PROVIDERS")
    if raw:
        return tuple(ProviderSpec.parse(item) for item in raw.split(",") if item.strip())
    model = os.getenv("TRIPWIRE_MODEL")
    if model:
        return (ProviderSpec(kind="ollama", model=model), ProviderSpec(kind="template"))
    return tuple(ProviderSpec.parse(item) for item in DEFAULT_PROVIDER_CHAIN)


def build_report_with_providers(
    *,
    events: list[AuditEvent],
    providers: tuple[ProviderSpec, ...] | None = None,
    timeout: float = 20,
) -> IncidentReport:
    if not any(event.decision == "DENY" for event in events):
        return build_template_report(events)
    chain = providers or provider_chain_from_env()
    errors: list[str] = []
    for provider in chain:
        try:
            report = _build_provider_report(provider=provider, events=events, timeout=timeout)
        except InvestigatorProviderUnavailable as exc:
            errors.append(f"{provider.label}: {exc}")
            continue
        verified = verify_report(report, events)
        if verified.verified:
            return verified.report
        errors.append(f"{provider.label}: invalid citations: {verified.invalid_claims}")
    return build_template_report(events).model_copy(
        update={"summary": _fallback_summary(errors, events)}
    )


def build_ollama_report(
    *,
    events: list[AuditEvent],
    model: str,
    endpoint: str | None = None,
    timeout: float = 20,
) -> IncidentReport:
    endpoint = endpoint or os.getenv(
        "TRIPWIRE_OLLAMA_ENDPOINT", "http://127.0.0.1:11434/api/generate"
    )
    payload = {
        "model": model,
        "prompt": build_investigator_prompt(events),
        "stream": False,
        "format": IncidentReport.model_json_schema(),
        "options": {"temperature": 0},
    }
    response = _post_json(endpoint, payload, timeout=timeout)
    report_json = json.loads(str(response["response"]))
    report = IncidentReport.model_validate(report_json)
    return report.model_copy(update={"generator": f"ollama:{model}"})


def build_anthropic_report(
    *,
    events: list[AuditEvent],
    model: str,
    timeout: float = 20,
) -> IncidentReport:
    api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY")
    if not api_key:
        raise InvestigatorProviderUnavailable("ANTHROPIC_API_KEY or CLAUDE_API_KEY is not set")
    endpoint = os.getenv("TRIPWIRE_ANTHROPIC_ENDPOINT", "https://api.anthropic.com/v1/messages")
    payload = {
        "model": model,
        "max_tokens": 1600,
        "temperature": 0,
        "messages": [{"role": "user", "content": build_investigator_prompt(events)}],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": os.getenv("TRIPWIRE_ANTHROPIC_VERSION", "2023-06-01"),
    }
    response = _post_json(endpoint, payload, timeout=timeout, headers=headers)
    report_json = _json_from_text(_anthropic_text(response))
    report = IncidentReport.model_validate(report_json)
    return report.model_copy(update={"generator": f"anthropic:{model}"})


def build_openai_compatible_report(
    *,
    events: list[AuditEvent],
    model: str,
    timeout: float = 20,
) -> IncidentReport:
    endpoint = os.getenv("TRIPWIRE_OPENAI_COMPAT_ENDPOINT")
    if not endpoint:
        raise InvestigatorProviderUnavailable("TRIPWIRE_OPENAI_COMPAT_ENDPOINT is not set")
    payload = {
        "model": model,
        "temperature": 0,
        "messages": [{"role": "user", "content": build_investigator_prompt(events)}],
    }
    headers: dict[str, str] = {}
    api_key = os.getenv("TRIPWIRE_OPENAI_COMPAT_API_KEY")
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    response = _post_json(endpoint, payload, timeout=timeout, headers=headers)
    content = response["choices"][0]["message"]["content"]
    report = IncidentReport.model_validate(_json_from_text(str(content)))
    return report.model_copy(update={"generator": f"openai-compatible:{model}"})


def build_investigator_prompt(events: list[AuditEvent]) -> str:
    event_json = [event.model_dump(mode="json") for event in events]
    return (
        "You are Tripwire's incident investigator. Return only JSON matching this schema: "
        "{report_id:string,severity:string,summary:string,stage_labels:string[],"
        "timeline:string[],claims:{text:string,event_ids:string[],tool:string|null,"
        "arguments:object|null,decision:string|null,containment_state:string|null,"
        "tool_invoked:boolean|null,tool_completed:boolean|null,tool_executed:boolean|null}[]}. "
        "Use short timeline strings and at most three claims, focusing on denied or flagged "
        "events. Every claim must cite real event_ids from the provided events and must not "
        "invent tools, arguments, destinations, decisions, execution states, or containment "
        "states. Copy decision and execution fields exactly from the cited event. Events: "
        f"{json.dumps(event_json, sort_keys=True)}"
    )


def _build_provider_report(
    *,
    provider: ProviderSpec,
    events: list[AuditEvent],
    timeout: float,
) -> IncidentReport:
    try:
        if provider.kind == "template":
            return build_template_report(events)
        if provider.kind == "ollama":
            return build_ollama_report(events=events, model=str(provider.model), timeout=timeout)
        if provider.kind == "anthropic":
            return build_anthropic_report(events=events, model=str(provider.model), timeout=timeout)
        if provider.kind == "openai-compatible":
            return build_openai_compatible_report(
                events=events, model=str(provider.model), timeout=timeout
            )
    except (
        KeyError,
        IndexError,
        JSONDecodeError,
        OSError,
        URLError,
        ValueError,
        ValidationError,
        TimeoutError,
    ) as exc:
        raise InvestigatorProviderUnavailable(str(exc)) from exc
    raise InvestigatorProviderUnavailable(f"unsupported provider {provider.kind}")


def _post_json(
    endpoint: str,
    payload: dict[str, Any],
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    request = Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            decoded = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise InvestigatorProviderUnavailable(f"HTTP {exc.code}: {body}") from exc
    if not isinstance(decoded, dict):
        raise ValueError("provider returned non-object JSON")
    return decoded


def _anthropic_text(response: dict[str, Any]) -> str:
    chunks = response.get("content", [])
    if not isinstance(chunks, list):
        raise ValueError("Anthropic response content must be a list")
    parts = [item.get("text", "") for item in chunks if isinstance(item, dict)]
    return "\n".join(str(part) for part in parts if part)


def _json_from_text(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.startswith("json"):
            stripped = stripped[4:].strip()
    parsed = json.loads(stripped)
    if not isinstance(parsed, dict):
        raise ValueError("model returned non-object JSON")
    return parsed


def _fallback_summary(errors: list[str], events: list[AuditEvent]) -> str:
    base = build_template_report(events).summary
    if not errors:
        return base
    return f"{base} Model providers unavailable or unverifiable: {'; '.join(errors)}"
