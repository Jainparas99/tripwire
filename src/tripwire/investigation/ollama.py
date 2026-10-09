from __future__ import annotations

from tripwire.audit import AuditEvent
from tripwire.investigation.models import IncidentReport
from tripwire.investigation.providers import (
    InvestigatorProviderUnavailable,
)
from tripwire.investigation.providers import (
    build_ollama_report as _build_ollama_report,
)
from tripwire.investigation.template import build_template_report
from tripwire.investigation.verifier import verify_report


class OllamaUnavailable(InvestigatorProviderUnavailable):
    """Raised when the local Ollama endpoint cannot produce a verified JSON report."""


def build_ollama_report(
    *,
    events: list[AuditEvent],
    model: str = "qwen2.5:3b-instruct",
    endpoint: str = "http://127.0.0.1:11434/api/generate",
    timeout: float = 20,
) -> IncidentReport:
    try:
        return _build_ollama_report(events=events, model=model, endpoint=endpoint, timeout=timeout)
    except InvestigatorProviderUnavailable as exc:
        raise OllamaUnavailable(str(exc)) from exc


def build_report_with_fallback(
    *,
    events: list[AuditEvent],
    model: str = "qwen2.5:3b-instruct",
    endpoint: str = "http://127.0.0.1:11434/api/generate",
    timeout: float = 20,
) -> IncidentReport:
    """Backward-compatible Ollama-first entry point with template fallback."""
    try:
        report = build_ollama_report(events=events, model=model, endpoint=endpoint, timeout=timeout)
    except OllamaUnavailable:
        return build_template_report(events)
    verified = verify_report(report, events)
    return verified.report if verified.verified else build_template_report(events)
