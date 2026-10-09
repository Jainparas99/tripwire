from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from tripwire.contracts.models import ToolCall
from tripwire.tools.mock import MockToolRegistry


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the synthetic Tripwire tool service.")
    parser.add_argument("--host", default=os.getenv("TRIPWIRE_TOOLS_HOST", "127.0.0.1"))
    parser.add_argument("--port", default=int(os.getenv("TRIPWIRE_TOOLS_PORT", "9090")), type=int)
    args = parser.parse_args()
    server = make_server(host=args.host, port=args.port, registry=MockToolRegistry())
    print(f"Tripwire mock tools listening on http://{args.host}:{args.port}")
    server.serve_forever()


def make_server(
    *,
    host: str,
    port: int,
    registry: MockToolRegistry,
) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/healthz":
                _write_json(self, 200, {"ok": True})
                return
            _write_json(self, 404, {"error": "not found"})

        def do_POST(self) -> None:
            try:
                payload = _read_json(self)
                if self.path == "/tools/has":
                    has_tool = registry.has_tool(str(payload.get("tool")))
                    _write_json(self, 200, {"has_tool": has_tool})
                    return
                if self.path == "/tools/validate":
                    call = ToolCall.model_validate(payload)
                    _write_json(self, 200, {"reason": registry.validate(call)})
                    return
                if self.path == "/tools/resource-scope":
                    call = ToolCall.model_validate(payload)
                    _write_json(self, 200, {"scope": registry.resource_scope(call)})
                    return
                if self.path == "/tools/preview":
                    call = ToolCall.model_validate(payload)
                    _write_json(self, 200, {"preview": registry.preview(call)})
                    return
                if self.path == "/tools/call":
                    call = ToolCall.model_validate(payload)
                    _write_json(self, 200, {"data": registry.run(call)})
                    return
                _write_json(self, 404, {"error": "not found"})
            except (KeyError, TypeError, ValueError) as exc:
                _write_json(self, 400, {"error": str(exc)})

        def log_message(self, format: str, *args: object) -> None:
            return

    return _Server((host, port), Handler)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("content-length", "0"))
    payload = json.loads(handler.rfile.read(length).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")
    return payload


def _write_json(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("content-type", "application/json")
    handler.send_header("content-length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)


if __name__ == "__main__":
    main()
