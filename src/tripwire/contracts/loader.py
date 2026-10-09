from pathlib import Path

import yaml
from pydantic import ValidationError

from tripwire.contracts.models import TaskContract


class ContractLoadError(ValueError):
    """Raised when a task contract cannot be loaded or validated."""


def load_task_contract(path: str | Path, *, signing_key: str | bytes | None = None) -> TaskContract:
    """Load a trusted YAML task contract supplied by the application."""
    contract_path = Path(path)
    try:
        raw = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ContractLoadError(f"could not read task contract: {contract_path}") from exc
    except yaml.YAMLError as exc:
        raise ContractLoadError(f"invalid YAML task contract: {contract_path}") from exc

    if not isinstance(raw, dict):
        raise ContractLoadError("task contract must be a YAML mapping")

    try:
        contract = TaskContract.model_validate(raw)
    except ValidationError as exc:
        raise ContractLoadError(str(exc)) from exc

    if signing_key is not None and not contract.verify_signature(signing_key):
        raise ContractLoadError("task contract signature is missing or invalid")
    return contract
