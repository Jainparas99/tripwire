from __future__ import annotations

import json
from json import JSONDecodeError
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from pydantic import ValidationError

from tripwire.audit import AuditEvent
from tripwire.investigation.models import IncidentReport
from tripwire.investigation.template import build_template_report
from tripwire.investigation.verifier import verify_report


class OllamaUnavailable(RuntimeError):
    """Raised when the local Ollama endpoint cannot produce a verified JSON report."""


def build_ollama_report(
    *,
    events: list[AuditEvent],
    model: str = "qwen2.5:3b-instruct",
    endpoint: str = "http://127.0.0.1:11434/api/generate",
    timeout: float = 20,
) -> IncidentReport:
    prompt = _prompt(events)
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
    }
    try:
        response = _post_json(endpoint, payload, timeout=timeout)
        report_json = json.loads(str(response["response"]))
        report = IncidentReport.model_validate(report_json)
        return report.model_copy(update={"generator": f"ollama:{model}"})
    except (
        KeyError,
        JSONDecodeError,
        OSError,
        URLError,
        ValueError,
        ValidationError,
        TimeoutError,
    ) as exc:
        raise OllamaUnavailable(str(exc)) from exc


def build_report_with_fallback(
    *,
    events: list[AuditEvent],
    model: str = "qwen2.5:3b-instruct",
    endpoint: str = "http://127.0.0.1:11434/api/generate",
    timeout: float = 20,
) -> IncidentReport:
    """Use the model report only if every claim verifies; otherwise use the template."""
    try:
        report = build_ollama_report(events=events, model=model, endpoint=endpoint, timeout=timeout)
    except OllamaUnavailable:
        return build_template_report(events)
    if not verify_report(report, events).verified:
        return build_template_report(events)
    return report


def _post_json(endpoint: str, payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    encoded = json.dumps(payload).encode("utf-8")
    request = Request(
        endpoint,
        data=encoded,
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        decoded = json.loads(response.read().decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("Ollama returned non-object JSON")
    return decoded


def _prompt(events: list[AuditEvent]) -> str:
    event_json = [event.model_dump(mode="json") for event in events]
    return (
        "You are Tripwire's local incident investigator. Return only JSON matching this schema: "
        "{report_id:string,severity:string,summary:string,stage_labels:string[],"
        "timeline:string[],claims:{text:string,event_ids:string[],tool:string|null}[]}. "
        "Every claim must cite real event_ids from the provided events. Events: "
        f"{json.dumps(event_json, sort_keys=True)}"
    )
