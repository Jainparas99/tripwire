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
make eval
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

## Checkpoint B Core

- Deterministic detector findings for scope creep, disallowed tools, retry-after-denial,
  enumeration, read-then-send, honeytoken touch, destination violations, and budget.
- Cumulative score mapped through contract thresholds into `OK`, `WARN`, `PAUSED`, and
  `KILLED`.
- `WARN` remains non-blocking; `PAUSED` and `KILLED` deny the triggering call and every later
  call.
- Offline trace eval with 20 YAML trajectories: 5 benign, 5 benign-but-tricky, 10 attack/drift
  variants.

Current local eval:

```text
traces                    20
attack_detection_rate     100.00%
false_block_rate          0.00%
executed_after_block      0
```

Still out of scope here: full MCP proxy mode, Docker compose isolation, Ollama investigator,
dashboard, autonomous red team, policy fixer, and SENTINEL.
