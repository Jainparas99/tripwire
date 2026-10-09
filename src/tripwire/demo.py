from __future__ import annotations

import json
from pathlib import Path

from tripwire.audit import AuditLog
from tripwire.contracts import load_task_contract
from tripwire.gateway import TripwireGateway


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    contract = load_task_contract(repo_root / "examples/contracts/support_summary.yaml")
    audit_log = AuditLog(repo_root / ".tripwire/demo-audit.jsonl", reset=True)
    gateway = TripwireGateway(contract=contract, audit_log=audit_log, session_id="sess_demo")

    trace = [
        ("read_customer", {"customer_id": "A"}),
        ("search_docs", {"query": "webhook retries"}),
        ("read_ticket", {"customer_id": "A", "ticket_id": "T-A-100"}),
        ("read_ticket", {"customer_id": "A", "ticket_id": "T-A-101"}),
    ]

    decisions = []
    for tool, arguments in trace:
        result = gateway.call_tool(tool, arguments)
        decisions.append(
            {
                "event_id": result.event_id,
                "tool": tool,
                "decision": result.decision.action,
                "containment_state": result.decision.containment_state,
                "tool_executed": result.data is not None,
            }
        )

    output = {"decisions": decisions, "audit_chain_valid": audit_log.verify_chain()}
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
