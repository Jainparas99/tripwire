from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from tripwire.audit.log import AuditEvent
from tripwire.contracts.destinations import (
    destination_allowed,
    destination_host,
    extract_destinations,
)
from tripwire.contracts.models import TaskContract, ToolCall
from tripwire.gateway.models import ContainmentState
from tripwire.tools.base import ToolRegistry


def _load_detector_config() -> tuple[dict[str, int], dict[str, int]]:
    path = Path(__file__).with_name("config.yaml")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("detector config must be a mapping")
    weights = raw.get("weights")
    thresholds = raw.get("thresholds")
    if not isinstance(weights, dict) or not isinstance(thresholds, dict):
        raise ValueError("detector config needs weights and thresholds")
    required = {
        "CUSTOMER_SCOPE_VIOLATION",
        "TOOL_NOT_ALLOWED",
        "UNKNOWN_TOOL",
        "DESTINATION_NOT_ALLOWED",
        "MAX_ACTIONS_EXCEEDED",
        "HONEYTOKEN_TOUCH",
        "RETRY_AFTER_DENIAL",
        "ENUMERATION",
        "READ_THEN_SEND",
    }
    if set(weights) != required or any(
        type(value) is not int or value <= 0 for value in weights.values()
    ):
        raise ValueError("detector weights must cover every reason with positive integers")
    if set(thresholds) != {"warn", "pause", "kill"} or any(
        type(value) is not int or value <= 0 for value in thresholds.values()
    ):
        raise ValueError("detector thresholds must be positive integers")
    if not thresholds["warn"] < thresholds["pause"] < thresholds["kill"]:
        raise ValueError("detector thresholds must increase from warn to kill")
    return weights, thresholds


DEFAULT_WEIGHTS, DEFAULT_THRESHOLDS = _load_detector_config()

ENUMERATION_WINDOW = 6
ENUMERATION_DISTINCT_RESOURCES = 3
RETRY_WINDOW = 3


@dataclass(frozen=True)
class DetectorFinding:
    reason_code: str
    score: int
    evidence_event_ids: tuple[str, ...] = ()


def analyze_call(
    *,
    call: ToolCall,
    contract: TaskContract,
    tools: ToolRegistry,
    history: list[AuditEvent],
    policy_reason_codes: tuple[str, ...],
) -> list[DetectorFinding]:
    findings = [_finding(reason) for reason in policy_reason_codes if reason in DEFAULT_WEIGHTS]

    if _honeytoken_touched(call, contract, tools):
        findings.append(_finding("HONEYTOKEN_TOUCH"))

    retry_evidence = _retry_after_denial(call, contract, tools, history)
    if retry_evidence:
        findings.append(_finding("RETRY_AFTER_DENIAL", retry_evidence))

    enumeration_evidence = _enumeration(call, history)
    if enumeration_evidence:
        findings.append(_finding("ENUMERATION", enumeration_evidence))

    read_send_evidence = _read_then_send(call, contract, history)
    if read_send_evidence:
        findings.append(_finding("READ_THEN_SEND", read_send_evidence))

    return findings


def containment_for_score(score: int, thresholds: dict[str, int]) -> ContainmentState:
    kill = thresholds.get("kill", DEFAULT_THRESHOLDS["kill"])
    pause = thresholds.get("pause", DEFAULT_THRESHOLDS["pause"])
    warn = thresholds.get("warn", DEFAULT_THRESHOLDS["warn"])
    if score >= kill:
        return ContainmentState.KILLED
    if score >= pause:
        return ContainmentState.PAUSED
    if score >= warn:
        return ContainmentState.WARN
    return ContainmentState.OK


def _finding(reason_code: str, evidence_event_ids: tuple[str, ...] = ()) -> DetectorFinding:
    return DetectorFinding(
        reason_code=reason_code,
        score=DEFAULT_WEIGHTS[reason_code],
        evidence_event_ids=evidence_event_ids,
    )


def _honeytoken_touched(call: ToolCall, contract: TaskContract, tools: ToolRegistry) -> bool:
    """Match honeytokens in the gateway; the token list never leaves the gateway."""
    if not contract.honeytokens:
        return False
    haystacks = [str(call.arguments)]
    if tools.has_tool(call.tool):
        haystacks.append(tools.preview(call))
    return any(token in haystack for token in contract.honeytokens for haystack in haystacks)


def _retry_after_denial(
    call: ToolCall,
    contract: TaskContract,
    tools: ToolRegistry,
    history: list[AuditEvent],
) -> tuple[str, ...]:
    targets = _out_of_contract_targets(call, contract, tools)
    if not targets:
        return ()

    for event in reversed(history[-RETRY_WINDOW:]):
        if event.decision != "DENY":
            continue
        if targets & _out_of_contract_targets(event.attempted, contract, tools):
            return (event.event_id,)
    return ()


def _enumeration(call: ToolCall, history: list[AuditEvent]) -> tuple[str, ...]:
    if call.tool not in {"read_customer", "read_ticket"}:
        return ()

    candidates = [
        event
        for event in history[-ENUMERATION_WINDOW:]
        if event.tool_completed and event.attempted.tool == call.tool
    ]
    resources = {_resource_id(event.attempted) for event in candidates}
    resources.add(_resource_id(call))
    resources.discard(None)
    if len(resources) >= ENUMERATION_DISTINCT_RESOURCES:
        return tuple(
            event.event_id for event in candidates if _resource_id(event.attempted) in resources
        )
    return ()


def _read_then_send(
    call: ToolCall,
    contract: TaskContract,
    history: list[AuditEvent],
) -> tuple[str, ...]:
    if call.tool not in {"http_post", "send_email"}:
        return ()
    destinations = extract_destinations(call.arguments)
    if not destinations or all(
        destination_allowed(destination, contract.allowed_destinations)
        for destination in destinations
    ):
        return ()

    sensitive_reads = [
        event
        for event in history[-ENUMERATION_WINDOW:]
        if event.tool_completed and event.attempted.tool in {"read_customer", "read_ticket"}
    ]
    return tuple(event.event_id for event in sensitive_reads[-2:])


def _out_of_contract_targets(
    call: ToolCall,
    contract: TaskContract,
    tools: ToolRegistry,
) -> set[str]:
    """Targets the contract forbids: other customers, disallowed hosts, disallowed tools."""
    targets: set[str] = set()
    if call.tool not in contract.allowed_tools:
        targets.add(f"tool:{call.tool}")

    expected_customer = contract.scope.get("customer_id")
    if expected_customer is not None:
        customers = {
            call.arguments.get("customer_id"),
            tools.resource_scope(call).get("customer_id"),
        }
        for customer in customers:
            if isinstance(customer, str) and customer and customer != expected_customer:
                targets.add(f"customer_id:{customer}")

    for destination in extract_destinations(call.arguments):
        if not destination_allowed(destination, contract.allowed_destinations):
            targets.add(f"destination:{destination_host(destination)}")
    return targets


def _resource_id(call: ToolCall) -> str | None:
    for key in ("ticket_id", "customer_id"):
        value = call.arguments.get(key)
        if isinstance(value, str) and value:
            return f"{key}:{value}"
    return None
