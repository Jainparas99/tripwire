# Tripwire

Tripwire is a deterministic enforcement layer for autonomous agent tool calls. It loads a trusted
task contract, authorizes every protected tool call in code, records a hash-chained audit log, and
replays incidents through local reporting surfaces.

No LLM is used in enforcement. The optional investigator can use Ollama, but falls back to a
deterministic template report when no local model is available.

## Quickstart

```bash
make setup
make test
make lint
make eval
make demo
make investigate
make dashboard
```

`make demo` replays a benign support-summary trace through the gateway and writes a JSONL audit
log to `.tripwire/demo-audit.jsonl`.

## Built Surface

- Pydantic models for `TaskContract`, `ToolCall`, `Decision`, and `AuditEvent`.
- YAML task contract loader for trusted application-supplied contracts.
- Five synthetic in-process tools: `read_customer`, `read_ticket`, `search_docs`, `send_email`,
  and `http_post`.
- `TripwireGateway.authorize()` with fail-closed `ALLOW` / `DENY` decisions for tool allowlist,
  customer scope, destination allowlist, and `max_actions`.
- Protected tool execution path that runs tools only on `ALLOW`.
- JSONL audit events with `attempted`, `decision`, `containment_state`, `tool_executed`,
  `prev_hash`, and `hash`.
- Deterministic detector findings for scope creep, disallowed tools, retry-after-denial,
  enumeration, read-then-send, honeytoken touch, destination violations, and budget.
- Cumulative score mapped through contract thresholds into `OK`, `WARN`, `PAUSED`, and
  `KILLED`.
- `WARN` remains non-blocking; `PAUSED` and `KILLED` deny the triggering call and every later
  call.
- HTTP/JSON proxy surface with JSON-RPC-style `tools/call`, plus a gateway-only mock tool service.
- Optional Ollama investigator client, deterministic template report fallback, and citation
  verifier.
- Streamlit dashboard reading replay audit logs and eval metrics.
- Docker compose topology with an agent/gateway internal network and a separate gateway/tools
  network.
- Offline trace eval with 26 YAML fixture trajectories: 13 benign (including a typo-then-correct
  run and read-then-email to an allowed address) and 13 attack/drift variants (including slow
  drift and an escape-style attempt). These are synthetic fixtures, not recorded incidents.

Current local eval (`make eval`):

```text
traces                     26
attack_detection_rate      100.00%
attack_containment_rate    69.23%
false_block_rate           0.00%
median_actions_to_detect   1
median_actions_to_contain  1
executed_while_blocked     0
```

Detection means at least one call was denied. Containment means the session reached `PAUSED`
or `KILLED`; single probes such as one out-of-scope read only reach `WARN` by design.

## HTTP Gateway

Run the mock tools and gateway in separate shells:

```bash
make tools
make gateway
```

Then call the gateway:

```bash
curl -s http://127.0.0.1:8080/tool-call \
  -H 'content-type: application/json' \
  -d '{"tool":"read_customer","arguments":{"customer_id":"A"}}'
```

## Docker

The compose topology is in `docker/compose.yaml`.

```bash
make docker-build
make docker-up
```

Docker Desktop/daemon must be running. Both compose networks are marked `internal: true`; the
agent only joins `agent_internal`, while the mock tools only join `tools_only`.

## Still Out Of Scope

Autonomous red team, LLM-written policy fixer, hosted deployment, real vendor connectors,
multi-tenant auth, and SENTINEL.
