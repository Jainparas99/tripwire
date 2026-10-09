from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from tripwire.audit import AuditLog
from tripwire.investigation.ollama import build_report_with_fallback
from tripwire.investigation.verifier import verify_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a Tripwire incident report.")
    parser.add_argument("audit_log", nargs="?", default=".tripwire/demo-audit.jsonl")
    parser.add_argument("--model", default=os.getenv("TRIPWIRE_MODEL", "qwen2.5:3b-instruct"))
    args = parser.parse_args()

    events = AuditLog(Path(args.audit_log)).read_events()
    report = build_report_with_fallback(events=events, model=args.model)
    verified = verify_report(report, events)
    print(json.dumps(verified.report.model_dump(mode="json"), indent=2))
    if not verified.verified:
        print(json.dumps({"invalid_claims": verified.invalid_claims}, indent=2))


if __name__ == "__main__":
    main()
