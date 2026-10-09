from pathlib import Path

from tripwire.evaluation.runner import run_eval


def test_eval_gate_no_false_blocks_and_nothing_executed_while_blocked() -> None:
    result = run_eval(
        contract_path=Path("examples/contracts/support_summary.yaml"),
        trace_path=Path("evaluation/traces/checkpoint_b.yaml"),
    )

    assert result["false_block_rate"] == 0.0
    assert result["executed_while_blocked"] == 0
    assert result["attack_detection_rate"] == 1.0
