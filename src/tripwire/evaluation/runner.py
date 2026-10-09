from __future__ import annotations

import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import yaml

from tripwire.audit import AuditLog
from tripwire.contracts import load_task_contract
from tripwire.gateway import TripwireGateway


def main() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    contract_path = repo_root / "examples/contracts/support_summary.yaml"
    trace_path = repo_root / "evaluation/traces/checkpoint_b.yaml"
    result = run_eval(contract_path=contract_path, trace_path=trace_path)
    print(_format_table(result))


def run_eval(*, contract_path: Path, trace_path: Path) -> dict[str, Any]:
    traces = _load_traces(trace_path)
    attack_total = 0
    attack_detected = 0
    benign_total = 0
    false_blocks = 0
    actions_to_detect: list[int] = []
    latencies_ms: list[float] = []
    executed_after_block = 0

    with TemporaryDirectory() as tmpdir:
        for index, trace in enumerate(traces, start=1):
            contract = load_task_contract(contract_path)
            audit_log = AuditLog(Path(tmpdir) / f"trace-{index}.jsonl", reset=True)
            gateway = TripwireGateway(
                contract=contract,
                audit_log=audit_log,
                session_id=f"sess_eval_{index:03d}",
            )

            detected_at: int | None = None
            blocked_seen = False
            for step_index, step in enumerate(trace["calls"], start=1):
                started = time.perf_counter()
                result = gateway.call_tool(step["tool"], step.get("arguments", {}))
                latencies_ms.append((time.perf_counter() - started) * 1000)

                if blocked_seen and audit_log.read_events()[-1].tool_executed:
                    executed_after_block += 1
                if result.decision.action == "DENY":
                    blocked_seen = True

                if detected_at is None and (
                    result.decision.action == "DENY"
                    or result.decision.containment_state in {"PAUSED", "KILLED"}
                ):
                    detected_at = step_index

            if trace["kind"] == "attack":
                attack_total += 1
                if detected_at is not None:
                    attack_detected += 1
                    actions_to_detect.append(detected_at)
            else:
                benign_total += 1
                if detected_at is not None:
                    false_blocks += 1

    return {
        "traces": len(traces),
        "attack_detection_rate": attack_detected / attack_total if attack_total else 0.0,
        "false_block_rate": false_blocks / benign_total if benign_total else 0.0,
        "median_actions_to_detect": _median(actions_to_detect),
        "p50_latency_ms": _median(latencies_ms),
        "p95_latency_ms": _percentile(latencies_ms, 0.95),
        "executed_after_block": executed_after_block,
    }


def _load_traces(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("traces"), list):
        raise ValueError("trace file must contain a traces list")
    return raw["traces"]


def _format_table(result: dict[str, Any]) -> str:
    rows = [
        ("traces", str(result["traces"])),
        ("attack_detection_rate", f"{result['attack_detection_rate']:.2%}"),
        ("false_block_rate", f"{result['false_block_rate']:.2%}"),
        ("median_actions_to_detect", str(result["median_actions_to_detect"])),
        ("p50_latency_ms", f"{result['p50_latency_ms']:.2f}"),
        ("p95_latency_ms", f"{result['p95_latency_ms']:.2f}"),
        ("executed_after_block", str(result["executed_after_block"])),
    ]
    width = max(len(name) for name, _value in rows)
    return "\n".join(f"{name:<{width}}  {value}" for name, value in rows)


def _median(values: list[float] | list[int]) -> float | int:
    if not values:
        return 0
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile)))
    return ordered[index]


if __name__ == "__main__":
    main()
