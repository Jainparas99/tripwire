from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tripwire.audit import AuditEvent
from tripwire.investigation.models import IncidentReport
from tripwire.investigation.providers import (
    ProviderSpec,
    build_report_with_providers,
    provider_chain_from_env,
)
from tripwire.investigation.verifier import verify_report

DEFAULT_CACHE_DIR = Path(".tripwire/reports")


def cache_path(events: list[AuditEvent], cache_dir: Path = DEFAULT_CACHE_DIR) -> Path:
    """Return a stable report path for the same audited behavior across replays.

    Timestamps and chain-link hashes are intentionally excluded because deterministic
    replays produce the same behavior with different timestamps.
    """
    payload = [
        event.model_dump(mode="json", exclude={"ts", "prev_hash", "hash"}) for event in events
    ]
    key = (
        hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if payload
        else "empty"
    )
    return cache_dir / f"{key}.json"


def load_cached_report(
    events: list[AuditEvent],
    cache_dir: Path = DEFAULT_CACHE_DIR,
    preferred_generator: str | None = None,
) -> IncidentReport | None:
    path = cache_path(events, cache_dir)
    if not path.exists():
        return None
    try:
        report = IncidentReport.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    if preferred_generator is not None and report.generator not in {
        preferred_generator,
        "template",
    }:
        return None
    return report if verify_report(report, events).verified else None


def load_or_build_report(
    *,
    events: list[AuditEvent],
    model: str | None = None,
    providers: tuple[ProviderSpec, ...] | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    timeout: float = 60,
    refresh: bool = False,
) -> IncidentReport:
    chain = providers or (
        (ProviderSpec(kind="ollama", model=model), ProviderSpec(kind="template"))
        if model
        else provider_chain_from_env()
    )
    if not refresh:
        cached = load_cached_report(
            events, cache_dir, preferred_generator=chain[0].label if chain else None
        )
        if cached is not None:
            return cached
    report = build_report_with_providers(events=events, providers=chain, timeout=timeout)
    path = cache_path(events, cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return report
