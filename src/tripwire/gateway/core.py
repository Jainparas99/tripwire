from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from tripwire.audit.log import AuditLog
from tripwire.contracts.models import TaskContract, ToolCall
from tripwire.gateway.models import Decision, DecisionAction, GatewayResult
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

    @property
    def seq(self) -> int:
        return self._seq

    def authorize(self, call: ToolCall) -> Decision:
        """Return ALLOW or DENY using only trusted contract state and call arguments."""
        try:
            if self._seq >= self._contract.max_actions:
                return Decision.deny("MAX_ACTIONS_EXCEEDED")
            if not self._tools.has_tool(call.tool):
                return Decision.deny("UNKNOWN_TOOL")
            if call.tool not in self._contract.allowed_tools:
                return Decision.deny("TOOL_NOT_ALLOWED")

            validation_reason = self._tools.validate(call)
            if validation_reason is not None:
                return Decision.deny(validation_reason)

            scope_reason = self._scope_violation(call)
            if scope_reason is not None:
                return Decision.deny(scope_reason)

            destination_reason = self._destination_violation(call)
            if destination_reason is not None:
                return Decision.deny(destination_reason)
        except Exception:
            return Decision.deny("AUTHORIZATION_ERROR")

        return Decision.allow()

    def call_tool(self, tool: str, arguments: dict[str, Any] | None = None) -> GatewayResult:
        """Authorize, execute only on ALLOW, and append exactly one audit event."""
        call = ToolCall(tool=tool, arguments=arguments or {})
        decision = self.authorize(call)

        data: dict[str, Any] | None = None
        tool_executed = False
        if decision.action is DecisionAction.ALLOW:
            data = self._tools.run(call)
            tool_executed = True

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
        destination = _extract_destination(call.arguments)
        if destination is None:
            return None

        allowed = set(self._contract.allowed_destinations)
        if not allowed:
            return "DESTINATION_NOT_ALLOWED"

        host = _destination_host(destination)
        if destination in allowed or host in allowed:
            return None
        return "DESTINATION_NOT_ALLOWED"


def _extract_destination(arguments: dict[str, Any]) -> str | None:
    for key in ("url", "destination", "to"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _destination_host(destination: str) -> str:
    parsed = urlparse(destination)
    return parsed.netloc or destination.split("@")[-1]
