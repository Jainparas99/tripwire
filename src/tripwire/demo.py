from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tripwire.audit import AuditLog
from tripwire.contracts import load_task_contract
from tripwire.gateway import TripwireGateway

REPO_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_FILE = REPO_ROOT / "examples/enterprise_agent/scenarios.json"
CONTRACT_FILE = REPO_ROOT / "examples/contracts/support_summary.yaml"
OUTPUT_DIR = REPO_ROOT / ".tripwire"


def load_scenarios(path: Path = SCENARIO_FILE) -> dict[str, dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {name: value for name, value in raw.items() if not name.startswith("_")}


def demo_log_path(name: str, output_dir: Path = OUTPUT_DIR) -> Path:
    return output_dir / f"demo-{name}.jsonl"


def replay_scenario(name: str, *, output_dir: Path = OUTPUT_DIR) -> list[dict[str, Any]]:
    """Replay one scripted scenario offline through an in-process gateway."""
    scenario = load_scenarios()[name]
    audit_log = AuditLog(demo_log_path(name, output_dir), reset=True)
    gateway = TripwireGateway(
        contract=load_task_contract(CONTRACT_FILE),
        audit_log=audit_log,
        session_id=f"sess_demo_{name}",
    )
    rows = []
    for step in scenario["calls"]:
        result = gateway.call_tool(step["tool"], step.get("arguments", {}))
        rows.append(
            {
                "event_id": result.event_id,
                "tool": step["tool"],
                "decision": result.decision.action.value,
                "containment_state": result.decision.containment_state.value,
                "score": result.decision.score,
                "tool_executed": result.data is not None,
            }
        )
    if not audit_log.verify_chain():
        raise RuntimeError(f"audit chain invalid for scenario {name}")
    return rows


def main() -> None:
    scenarios = load_scenarios()
    parser = argparse.ArgumentParser(description="Replay scripted agent scenarios offline.")
    parser.add_argument("scenarios", nargs="*", help=f"default: all of {', '.join(scenarios)}")
    parser.add_argument("--mode", choices=("replay", "live"), default="replay")
    parser.add_argument("--model", help="local Ollama model for live mode")
    parser.add_argument("--ollama-endpoint", help="Ollama /api/chat URL for live mode")
    args = parser.parse_args()
    unknown = sorted(set(args.scenarios) - set(scenarios))
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")
    if args.mode == "live":
        if args.scenarios:
            parser.error("scenario names are only valid in replay mode")
        from tripwire.live_demo import (
            LocalModelUnavailable,
            OllamaClient,
            default_client,
            run_live_demo,
        )

        client = default_client()
        if args.model or args.ollama_endpoint:
            client = OllamaClient(
                model=args.model or client.model,
                endpoint=args.ollama_endpoint or client.endpoint,
            )
        try:
            live = run_live_demo(next_action=client.next_action)
        except LocalModelUnavailable as exc:
            print(f"Local model unavailable ({exc}); replaying slow_drift instead.")
            args.scenarios = ["slow_drift"]
        else:
            print(f"\nLive local-model run  ->  {live.audit_path.relative_to(REPO_ROOT)}")
            _print_rows(live.rows)
            if live.final_answer:
                print(f"\nModel summary: {live.final_answer}")
            return

    for name in args.scenarios or list(scenarios):
        rows = replay_scenario(name)
        print(f"\n{scenarios[name]['title']}  ->  {demo_log_path(name).relative_to(REPO_ROOT)}")
        _print_rows(rows)


def _print_rows(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        executed = "executed" if row["tool_executed"] else "not executed"
        print(
            f"  {row['event_id']}  {row['tool']:<14} {row['decision']:<5} "
            f"{row['containment_state']:<7} score={row['score']:<3} {executed}"
        )


if __name__ == "__main__":
    main()
