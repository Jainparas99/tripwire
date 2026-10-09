from pathlib import Path

import pytest

from tripwire.contracts import ContractLoadError, load_task_contract


def test_load_task_contract_from_yaml() -> None:
    contract = load_task_contract(Path("examples/contracts/support_summary.yaml"))

    assert contract.task_id == "support-summary-001"
    assert "read_customer" in contract.allowed_tools
    assert contract.scope == {"customer_id": "A"}
    assert len(contract.contract_hash) == 64


def test_invalid_contract_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("task_id: missing-required-fields\n", encoding="utf-8")

    with pytest.raises(ContractLoadError):
        load_task_contract(path)
