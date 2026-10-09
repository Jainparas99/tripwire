from __future__ import annotations

import argparse
import json
from pathlib import Path

from tripwire.audit import AuditLog
from tripwire.investigation.cache import DEFAULT_CACHE_DIR, load_or_build_report
from tripwire.investigation.providers import ProviderSpec, provider_chain_from_env
from tripwire.investigation.verifier import verify_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a Tripwire incident report.")
    parser.add_argument("audit_logs", nargs="*", default=[".tripwire/demo-audit.jsonl"])
    parser.add_argument("--model", help="Ollama model (shorthand for --provider ollama:MODEL)")
    parser.add_argument(
        "--provider",
        action="append",
        help=(
            "Investigator provider, repeatable. Examples: ollama:qwen2.5:3b-instruct, "
            "ollama:glm4:9b-chat, anthropic:MODEL, "
            "openai-compatible:MODEL, template"
        ),
    )
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR))
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--refresh", action="store_true", help="ignore cached reports")
    args = parser.parse_args()
    if args.provider and args.model:
        parser.error("--model and --provider cannot be combined")
    if args.provider:
        providers = tuple(ProviderSpec.parse(item) for item in args.provider)
    elif args.model:
        providers = (ProviderSpec(kind="ollama", model=args.model), ProviderSpec(kind="template"))
    else:
        providers = provider_chain_from_env()

    for audit_log in args.audit_logs:
        events = AuditLog(Path(audit_log)).read_events()
        report = load_or_build_report(
            events=events,
            providers=providers,
            cache_dir=Path(args.cache_dir),
            timeout=args.timeout,
            refresh=args.refresh,
        )
        verified = verify_report(report, events)
        print(json.dumps(verified.report.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    main()
