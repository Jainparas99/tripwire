from __future__ import annotations

import json
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from pydantic import ValidationError

from tripwire.audit import AuditEvent
from tripwire.investigation.models import IncidentReport
from tripwire.investigation.template import build_template_report


class OllamaUnavailable(RuntimeError):
    """Raised when the local Ollama endpoint cannot produce a verified JSON report."""


def build_ollama_report(
    *,
    events: list[AuditEvent],
    model: str = "qwen2.5:3b-instruct",
    endpoint: str = "http://127.0.0.1:11434/api/generate",
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
        response = _post_json(endpoint, payload)
        report_json = json.loads(str(response["response"]))
        return IncidentReport.model_validate(report_json)
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
) -> IncidentReport:
    try:
        return build_ollama_report(events=events, model=model, endpoint=endpoint)
    except OllamaUnavailable:
        return build_template_report(events)


def _post_json(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(payload).encode("utf-8")
    request = Request(
        endpoint,
        data=encoded,
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=20) as response:
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


JSONDecodeError = json.JSONDecodeError
