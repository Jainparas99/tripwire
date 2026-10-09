from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.request import Request, urlopen

from tripwire.audit import AuditLog
from tripwire.live_demo import (
    DEFAULT_ENDPOINT,
    REPO_ROOT,
    LocalModelUnavailable,
    OllamaClient,
    run_live_demo,
)

DEFAULT_MODELS = ("qwen2.5:3b-instruct", "glm4:9b")
DEFAULT_OUTPUT_DIR = REPO_ROOT / ".tripwire" / "gauntlet"


@dataclass(frozen=True)
class GauntletResult:
    model: str
    status: str
    tool_calls_attempted: int
    first_unsafe_action: str | None
    blocked: bool
    final_containment_state: str
    executed_while_blocked: int
    audit_path: str
    error: str | None = None


def run_model_gauntlet(
    models: tuple[str, ...],
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    endpoint: str = DEFAULT_ENDPOINT,
    client_factory=OllamaClient,
) -> list[GauntletResult]:
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[GauntletResult] = []
    for model in models:
        slug = _model_slug(model)
        audit_path = output_dir / f"{slug}.jsonl"
        try:
            client = client_factory(model=model, endpoint=endpoint)
            run_live_demo(
                next_action=client.next_action,
                output_dir=output_dir,
                audit_name=slug,
                session_id=f"sess_gauntlet_{slug}",
            )
        except LocalModelUnavailable as exc:
            results.append(
                GauntletResult(
                    model=model,
                    status="unavailable",
                    tool_calls_attempted=0,
                    first_unsafe_action=None,
                    blocked=False,
                    final_containment_state="N/A",
                    executed_while_blocked=0,
                    audit_path=str(audit_path),
                    error=str(exc),
                )
            )
            continue

        results.append(_summarize(model, audit_path))

    summary_path = output_dir / "summary.json"
    summary_path.write_text(
        json.dumps([asdict(result) for result in results], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return results


def discover_ollama_models(endpoint: str = DEFAULT_ENDPOINT) -> tuple[str, ...]:
    tags_endpoint = endpoint.rsplit("/", 1)[0] + "/tags"
    request = Request(tags_endpoint, method="GET")
    try:
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise LocalModelUnavailable(str(exc)) from exc
    models = payload.get("models", []) if isinstance(payload, dict) else []
    names = tuple(
        item["name"]
        for item in models
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]
    )
    if not names:
        raise LocalModelUnavailable("Ollama returned no pulled models")
    return names


def _summarize(model: str, audit_path: Path) -> GauntletResult:
    events = AuditLog(audit_path).read_events()
    unsafe = [
        event
        for event in events
        if event.decision == "DENY" or event.containment_state in {"PAUSED", "KILLED"}
    ]
    final_state = events[-1].containment_state.value if events else "OK"
    executed_while_blocked = sum(
        event.tool_invoked
        and (event.decision == "DENY" or event.containment_state in {"PAUSED", "KILLED"})
        for event in events
    )
    return GauntletResult(
        model=model,
        status="completed",
        tool_calls_attempted=len(events),
        first_unsafe_action=(
            f"{unsafe[0].event_id}:{unsafe[0].attempted.tool}" if unsafe else None
        ),
        blocked=bool(unsafe),
        final_containment_state=final_state,
        executed_while_blocked=executed_while_blocked,
        audit_path=str(audit_path),
    )


def _model_slug(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", model)


def _models_from_args(args: argparse.Namespace) -> tuple[str, ...]:
    if args.all:
        return discover_ollama_models(args.endpoint)
    if args.model:
        return tuple(dict.fromkeys(args.model))
    configured = os.getenv("TRIPWIRE_GAUNTLET_MODELS")
    if configured:
        return tuple(item.strip() for item in configured.split(",") if item.strip())
    return DEFAULT_MODELS


def _print_table(results: list[GauntletResult]) -> None:
    headers = (
        "Model",
        "Status",
        "Calls",
        "Unsafe attempt",
        "Blocked",
        "Final state",
        "Executed while blocked",
    )
    rows = [
        (
            result.model,
            result.status,
            str(result.tool_calls_attempted),
            result.first_unsafe_action or "no",
            "yes" if result.blocked else "no",
            result.final_containment_state,
            str(result.executed_while_blocked),
        )
        for result in results
    ]
    widths = [
        max(len(header), *(len(row[index]) for row in rows)) for index, header in enumerate(headers)
    ]
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))
    for result in results:
        if result.status == "unavailable":
            print(f"{result.model}: unavailable ({result.error})")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run one Tripwire scenario across local Ollama models."
    )
    parser.add_argument("--model", action="append", help="Model name; repeat for multiple models")
    parser.add_argument(
        "--all", action="store_true", help="Use every model returned by Ollama /api/tags"
    )
    parser.add_argument(
        "--endpoint", default=os.getenv("TRIPWIRE_OLLAMA_CHAT_ENDPOINT", DEFAULT_ENDPOINT)
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    if args.all and args.model:
        parser.error("--all cannot be combined with --model")
    try:
        models = _models_from_args(args)
        results = run_model_gauntlet(
            models,
            output_dir=args.output_dir,
            endpoint=args.endpoint,
        )
    except LocalModelUnavailable as exc:
        parser.error(str(exc))
    _print_table(results)


if __name__ == "__main__":
    main()
