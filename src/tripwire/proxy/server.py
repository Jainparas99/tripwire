from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from tripwire.audit import AuditLog
from tripwire.contracts import load_task_contract
from tripwire.gateway import GatewayResult, TripwireGateway
from tripwire.proxy import handle_json_rpc, handle_tool_call
from tripwire.tools import HttpToolRegistry, MockToolRegistry


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Tripwire JSON gateway.")
    parser.add_argument("--host", default=os.getenv("TRIPWIRE_HOST", "127.0.0.1"))
    parser.add_argument("--port", default=int(os.getenv("TRIPWIRE_PORT", "8080")), type=int)
    parser.add_argument(
        "--contract",
        default=os.getenv("TRIPWIRE_CONTRACT", "examples/contracts/support_summary.yaml"),
    )
    parser.add_argument(
        "--audit-log",
        default=os.getenv("TRIPWIRE_AUDIT_LOG", ".tripwire/gateway.jsonl"),
    )
    args = parser.parse_args()

    gateway = build_gateway(contract_path=Path(args.contract), audit_log_path=Path(args.audit_log))
    server = make_server(host=args.host, port=args.port, gateway=gateway)
    print(f"Tripwire gateway listening on http://{args.host}:{args.port}")
    server.serve_forever()


def build_gateway(*, contract_path: Path, audit_log_path: Path) -> TripwireGateway:
    tool_base_url = os.getenv("TRIPWIRE_TOOL_BASE_URL")
    tools = HttpToolRegistry(tool_base_url) if tool_base_url else MockToolRegistry()
    return TripwireGateway(
        contract=load_task_contract(contract_path, signing_key=os.getenv("TRIPWIRE_CONTRACT_KEY")),
        audit_log=AuditLog(audit_log_path, reset=True),
        tools=tools,
        session_id=os.getenv("TRIPWIRE_SESSION_ID", "sess_http"),
    )


def make_server(
    *,
    host: str,
    port: int,
    gateway: TripwireGateway,
) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/healthz":
                _write_json(self, 200, {"ok": True})
                return
            _write_json(self, 404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path not in {"/tool-call", "/jsonrpc"}:
                _write_json(self, 404, {"error": "not found"})
                return
            raw = _read_body(self)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                payload = None
            if not isinstance(payload, dict):
                result = gateway.reject_malformed(raw)
                _write_json(
                    self, 400, {"error": "request body must be a JSON object", **_dump(result)}
                )
                return
            if self.path == "/tool-call":
                _write_json(self, 200, handle_tool_call(gateway, payload))
            else:
                _write_json(self, 200, handle_json_rpc(gateway, payload))

        def log_message(self, format: str, *args: object) -> None:
            return

    return _Server((host, port), Handler)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


MAX_BODY_BYTES = 1_000_000


def _read_body(handler: BaseHTTPRequestHandler) -> bytes:
    try:
        length = int(handler.headers.get("content-length", "0"))
    except ValueError:
        length = 0
    return handler.rfile.read(max(0, min(length, MAX_BODY_BYTES)))


def _dump(result: GatewayResult) -> dict[str, Any]:
    return {"event_id": result.event_id, "decision": result.decision.model_dump(mode="json")}


def _write_json(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "application/json")
    handler.send_header("content-length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)


if __name__ == "__main__":
    main()
