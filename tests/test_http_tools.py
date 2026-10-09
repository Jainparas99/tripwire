from __future__ import annotations

from threading import Thread

from tripwire.contracts.models import ToolCall
from tripwire.tools import HttpToolRegistry, MockToolRegistry
from tripwire.tools.server import make_server


def test_http_tool_registry_calls_mock_tool_service() -> None:
    server = make_server(host="127.0.0.1", port=0, registry=MockToolRegistry())
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        registry = HttpToolRegistry(f"http://{host}:{port}")
        call = ToolCall(tool="read_customer", arguments={"customer_id": "A"})

        assert registry.has_tool("read_customer")
        assert registry.validate(call) is None
        assert registry.run(call)["customer_id"] == "A"
        decoy = ToolCall(tool="read_ticket", arguments={"ticket_id": "T-A-102"})
        assert "answer_key_pointer" in registry.preview(decoy)
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_honeytoken_list_is_never_sent_to_tool_service(tmp_path) -> None:
    from tripwire.audit import AuditLog
    from tripwire.contracts import load_task_contract
    from tripwire.gateway import ContainmentState, TripwireGateway

    sent: list[str] = []

    class RecordingRegistry(HttpToolRegistry):
        def _post(self, path, payload):
            sent.append(str(payload))
            return super()._post(path, payload)

    server = make_server(host="127.0.0.1", port=0, registry=MockToolRegistry())
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        contract = load_task_contract("examples/contracts/support_summary.yaml")
        gateway = TripwireGateway(
            contract=contract,
            audit_log=AuditLog(tmp_path / "audit.jsonl", reset=True),
            tools=RecordingRegistry(f"http://{host}:{port}"),
        )
        result = gateway.call_tool("read_ticket", {"customer_id": "A", "ticket_id": "T-A-102"})
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert result.decision.containment_state is ContainmentState.KILLED
    assert "HONEYTOKEN_TOUCH" in result.decision.reason_codes
    for token in contract.honeytokens:
        assert not any(token in payload for payload in sent)
