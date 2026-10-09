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
    finally:
        server.shutdown()
        thread.join(timeout=5)
