from __future__ import annotations

from typing import Any

from tripwire.audit.log import AuditLog
from tripwire.contracts.destinations import destination_allowed, extract_destination
from tripwire.contracts.models import TaskContract, ToolCall
from tripwire.detection import analyze_call, containment_for_score
from tripwire.gateway.models import ContainmentState, Decision, DecisionAction, GatewayResult
from tripwire.tools.mock import MockToolRegistry


class TripwireGateway:
    """Deterministic enforcement point for all protected tool calls."""

    def __init__(
        self,
        *,
        contract: TaskContract,
        audit_log: AuditLog,
        tools: MockToolRegistry | None = None,
        session_id: str = "sess_01",
    ) -> None:
        self._contract = contract
        self._audit_log = audit_log
        self._tools = tools or MockToolRegistry()
        self._session_id = session_id
        self._seq = 0
        self._score = 0
        self._containment_state = ContainmentState.OK

    @property
    def seq(self) -> int:
        return self._seq

    def authorize(self, call: ToolCall) -> Decision:
        """Return ALLOW or DENY using only trusted contract state and call arguments."""
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

        self._score += sum(item.score for item in findings)
        self._containment_state = containment_for_score(self._score, self._contract.thresholds)

        hard_deny = bool(policy_reason_codes)
        contained = self._containment_state in {ContainmentState.PAUSED, ContainmentState.KILLED}
        if hard_deny or contained:
            return Decision.deny(
                *reason_codes,
                containment_state=self._containment_state,
                score=self._score,
                evidence_event_ids=evidence_event_ids,
            )

        return Decision.allow(
            containment_state=self._containment_state,
            reason_codes=reason_codes,
            score=self._score,
            evidence_event_ids=evidence_event_ids,
        )

    def call_tool(self, tool: str, arguments: dict[str, Any] | None = None) -> GatewayResult:
        """Authorize, execute only on ALLOW, and append exactly one audit event."""
        call = ToolCall(tool=tool, arguments=arguments or {})
        decision = self.authorize(call)

        data: dict[str, Any] | None = None
        tool_executed = False
        if decision.action is DecisionAction.ALLOW:
            try:
                data = self._tools.run(call)
                tool_executed = True
            except Exception:
                decision = Decision.deny(
                    "TOOL_EXECUTION_ERROR",
                    containment_state=self._containment_state,
                    score=self._score,
                )

        self._seq += 1
        event = self._audit_log.append(
            session_id=self._session_id,
            task_id=self._contract.task_id,
            contract_hash=self._contract.contract_hash,
            seq=self._seq,
            attempted=call,
            decision=decision,
            tool_executed=tool_executed,
        )
        return GatewayResult(decision=decision, data=data, event_id=event.event_id)

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
        destination = extract_destination(call.arguments)
        if destination is None:
            return None
        if destination_allowed(destination, self._contract.allowed_destinations):
            return None
        return "DESTINATION_NOT_ALLOWED"
