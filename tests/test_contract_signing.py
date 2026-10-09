from pathlib import Path

import pytest

from tripwire.audit import AuditLog
from tripwire.contracts import ContractLoadError, TaskContract, load_task_contract
from tripwire.gateway import TripwireGateway
from tripwire.tools import MockToolRegistry


def _contract() -> TaskContract:
    return TaskContract(
        task_id="signed-task",
        description="Read one customer",
        principal="tester",
        scope={"customer_id": "A"},
        allowed_tools=frozenset({"read_customer"}),
        max_actions=2,
    )


def test_hmac_seals_contract_contents() -> None:
    sealed = _contract().with_signature("test-secret")

    assert sealed.verify_signature("test-secret")
    assert not sealed.verify_signature("wrong-secret")
    assert not sealed.model_copy(update={"description": "altered"}).verify_signature("test-secret")


def test_gateway_can_require_a_valid_contract_signature(tmp_path: Path) -> None:
    contract = _contract().with_signature("test-secret")
    TripwireGateway(
        contract=contract,
        audit_log=AuditLog(tmp_path / "audit.jsonl", reset=True),
        tools=MockToolRegistry(),
        contract_signing_key="test-secret",
    )

    with pytest.raises(ValueError, match="signature"):
        TripwireGateway(
            contract=contract,
            audit_log=AuditLog(tmp_path / "bad.jsonl", reset=True),
            tools=MockToolRegistry(),
            contract_signing_key="wrong-secret",
        )


def test_loader_can_require_a_valid_contract_signature(tmp_path: Path) -> None:
    contract = _contract().with_signature("test-secret")
    path = tmp_path / "contract.json"
    path.write_text(contract.model_dump_json(), encoding="utf-8")

    assert load_task_contract(path, signing_key="test-secret").verify_signature("test-secret")
    with pytest.raises(ContractLoadError, match="signature"):
        load_task_contract(path, signing_key="wrong-secret")
