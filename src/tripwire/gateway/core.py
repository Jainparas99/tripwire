from __future__ import annotations

from threading import RLock
from typing import Any

from tripwire.audit.log import AuditLog
from tripwire.contracts.destinations import destination_allowed, extract_destinations
from tripwire.contracts.models import TaskContract, ToolCall
from tripwire.detection import analyze_call, containment_for_score
from tripwire.gateway.models import ContainmentState, Decision, DecisionAction, GatewayResult
from tripwire.tools.base import ToolRegistry
from tripwire.tools.mock import MockToolRegistry

MALFORMED_TOOL = "<malformed>"


class TripwireGateway:
    """Deterministic enforcement point for all protected tool calls."""

    def __init__(
        self,
        *,
        contract: TaskContract,
        audit_log: AuditLog,
        tools: ToolRegistry | None = None,
        session_id: str = "sess_01",
        contract_signing_key: str | bytes | None = None,
    ) -> None:
        if contract_signing_key is not None and not contract.verify_signature(contract_signing_key):
            raise ValueError("task contract signature is missing or invalid")
        self._contract = contract
        self._audit_log = audit_log
        self._tools: ToolRegistry = tools or MockToolRegistry()
        self._session_id = session_id
        self._seq = 0
        self._score = 0
        self._containment_state = ContainmentState.OK
        # One session's score, containment state and hash chain must advance one call at a time.
        self._lock = RLock()

    @property
    def contract(self) -> TaskContract:
        return self._contract

    @property
    def seq(self) -> int:
        return self._seq

    def authorize(self, call: ToolCall) -> Decision:
        """Authorize and audit an attempted call without executing its tool."""
        with self._lock:
            decision = self._authorize(call)
            self._append_audit_event(call=call, decision=decision)
            return decision

    def _authorize(self, call: ToolCall) -> Decision:
        if self._containment_state in {ContainmentState.PAUSED, ContainmentState.KILLED}:
            return Decision.deny(
                f"SESSION_{self._containment_state.value}",
                containment_state=self._containment_state,
                score=self._score,
            )

        policy_reason_codes: list[str] = []
        try:
            if self._seq >= self._contract.max_actions:
                policy_reason_codes.append("MAX_ACTIONS_EXCEEDED")
            elif not self._tools.has_tool(call.tool):
                policy_reason_codes.append("UNKNOWN_TOOL")
            else:
                if call.tool not in self._contract.allowed_tools:
                    policy_reason_codes.append("TOOL_NOT_ALLOWED")

                unknown_arguments = set(call.arguments) - set(
                    self._tools.allowed_arguments(call.tool)
                )
                if unknown_arguments:
                    policy_reason_codes.append("UNKNOWN_ARGUMENTS")

                validation_reason = self._tools.validate(call)
                if validation_reason is not None:
                    policy_reason_codes.append(validation_reason)

                if validation_reason is None:
                    scope_reason = self._scope_violation(call)
                    if scope_reason is not None:
                        policy_reason_codes.append(scope_reason)

                    destination_reason = self._destination_violation(call)
                    if destination_reason is not None:
                        policy_reason_codes.append(destination_reason)
        except Exception:
            policy_reason_codes.append("AUTHORIZATION_ERROR")

        try:
            findings = analyze_call(
                call=call,
                contract=self._contract,
                tools=self._tools,
                history=self._audit_log.read_events(),
                policy_reason_codes=tuple(policy_reason_codes),
            )
        except Exception:
            return Decision.deny(
                *dict.fromkeys([*policy_reason_codes, "DETECTOR_ERROR"]),
                containment_state=self._containment_state,
                score=self._score,
            )
        finding_reason_codes = [item.reason_code for item in findings]
        reason_codes = tuple(dict.fromkeys(policy_reason_codes + finding_reason_codes))
        evidence_event_ids = tuple(
            dict.fromkeys(
                event_id for finding in findings for event_id in finding.evidence_event_ids
            )
        )

        next_score = self._score + sum(item.score for item in findings)
        next_containment_state = (
            ContainmentState.KILLED
            if any(item.reason_code == "HONEYTOKEN_TOUCH" for item in findings)
            else containment_for_score(next_score, self._contract.thresholds)
        )

        self._score = next_score
        self._containment_state = next_containment_state

        hard_deny = bool(policy_reason_codes)
        contained = next_containment_state in {ContainmentState.PAUSED, ContainmentState.KILLED}
        if hard_deny or contained:
            return Decision.deny(
                *reason_codes,
                containment_state=next_containment_state,
                score=next_score,
                evidence_event_ids=evidence_event_ids,
            )

        return Decision.allow(
            containment_state=next_containment_state,
            reason_codes=reason_codes,
            score=next_score,
            evidence_event_ids=evidence_event_ids,
        )

    def call_tool(self, tool: str, arguments: dict[str, Any] | None = None) -> GatewayResult:
        """Authorize, execute only on ALLOW, and append exactly one audit event."""
        with self._lock:
            return self._call_tool(tool, arguments)

    def _call_tool(self, tool: str, arguments: dict[str, Any] | None) -> GatewayResult:
        call = ToolCall(tool=tool, arguments=arguments or {})
        decision = self._authorize(call)

        data: dict[str, Any] | None = None
        tool_invoked = False
        tool_completed = False
        if decision.action is DecisionAction.ALLOW:
            tool_invoked = True
            try:
                data = self._tools.run(call)
                tool_completed = True
            except Exception:
                decision = Decision.deny(
                    "TOOL_EXECUTION_ERROR",
                    containment_state=self._containment_state,
                    score=self._score,
                )

        event = self._append_audit_event(
            call=call,
            decision=decision,
            tool_invoked=tool_invoked,
            tool_completed=tool_completed,
            data=data,
        )
        return GatewayResult(decision=decision, data=data, event_id=event.event_id)

    def _append_audit_event(
        self,
        *,
        call: ToolCall,
        decision: Decision,
        tool_invoked: bool = False,
        tool_completed: bool = False,
        data: dict[str, Any] | None = None,
    ):
        self._seq += 1
        return self._audit_log.append(
            session_id=self._session_id,
            task_id=self._contract.task_id,
            contract_hash=self._contract.contract_hash,
            seq=self._seq,
            attempted=call,
            decision=decision,
            tool_invoked=tool_invoked,
            tool_completed=tool_completed,
            tool_executed=tool_completed,
            source_resource=_source_resource(call),
            sensitivity=_sensitivity(call),
            untrusted_content_seen=tool_completed and data is not None,
        )

    def reject_malformed(self, raw: object, reason: str = "MALFORMED_REQUEST") -> GatewayResult:
        """Audit a request that could not be parsed into a tool call. It is always denied."""
        with self._lock:
            call = ToolCall(tool=MALFORMED_TOOL, arguments={"raw": repr(raw)[:500]})
            decision = Decision.deny(
                reason,
                containment_state=self._containment_state,
                score=self._score,
            )
            event = self._append_audit_event(call=call, decision=decision)
            return GatewayResult(decision=decision, data=None, event_id=event.event_id)

    def _scope_violation(self, call: ToolCall) -> str | None:
        expected_customer = self._contract.scope.get("customer_id")
        if expected_customer is None:
            return None

        requested_customer = call.arguments.get("customer_id")
        if requested_customer is not None and requested_customer != expected_customer:
            return "CUSTOMER_SCOPE_VIOLATION"

        resource_scope = self._tools.resource_scope(call)
        resource_customer = resource_scope.get("customer_id")
        if resource_customer is not None and resource_customer != expected_customer:
            return "CUSTOMER_SCOPE_VIOLATION"
        return None

    def _destination_violation(self, call: ToolCall) -> str | None:
        for destination in extract_destinations(call.arguments):
            if not destination_allowed(destination, self._contract.allowed_destinations):
                return "DESTINATION_NOT_ALLOWED"
        return None


def _source_resource(call: ToolCall) -> str | None:
    for key in ("ticket_id", "customer_id", "query", "url", "to"):
        value = call.arguments.get(key)
        if isinstance(value, str) and value:
            return f"{key}:{value}"
    return None


def _sensitivity(call: ToolCall) -> str | None:
    if call.tool in {"read_customer", "read_ticket"}:
        return "customer_data"
    if call.tool == "search_docs":
        return "documentation"
    if call.tool in {"send_email", "http_post"}:
        return "external_destination"
    return None
