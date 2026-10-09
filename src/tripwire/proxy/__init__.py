"""HTTP/JSON proxy surface for protected tool calls."""

from tripwire.proxy.json_proxy import handle_json_rpc, handle_tool_call

__all__ = ["handle_json_rpc", "handle_tool_call"]
