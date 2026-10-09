# Tripwire

Tripwire is a deterministic enforcement layer for autonomous agent tool calls. Checkpoint A
builds the local core only: trusted task contracts, in-process synthetic tools, gateway
authorization, and a hash-chained audit log.

No LLM is used in enforcement. Full MCP proxying, Docker isolation, Ollama investigation,
dashboard UI, autonomous red team, policy fixing, and SENTINEL are intentionally out of scope
for this checkpoint.

## Quickstart

```bash
make setup
make test
make lint
make demo
```

`make demo` replays a benign support-summary trace through the gateway and writes a JSONL audit
log to `.tripwire/demo-audit.jsonl`.

## Checkpoint A Surface

- Pydantic models for `TaskContract`, `ToolCall`, `Decision`, and `AuditEvent`.
- YAML task contract loader for trusted application-supplied contracts.
- Five synthetic in-process tools: `read_customer`, `read_ticket`, `search_docs`, `send_email`,
  and `http_post`.
- `TripwireGateway.authorize()` with fail-closed `ALLOW` / `DENY` decisions for tool allowlist,
  customer scope, destination allowlist, and `max_actions`.
- Protected tool execution path that runs tools only on `ALLOW`.
- JSONL audit events with `attempted`, `decision`, `containment_state`, `tool_executed`,
  `prev_hash`, and `hash`.
