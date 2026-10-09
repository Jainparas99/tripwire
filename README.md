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

`make demo` replays three scripted scenarios offline through the gateway and writes one
hash-chained audit log each to `.tripwire/demo-<scenario>.jsonl`:

| Scenario | What the scripted agent does | Ends |
|---|---|---|
| `benign` | Summarizes Customer A's open tickets | `OK` |
| `slow_drift` | Legitimate reads, then repeated probes of Customer B, then exfiltration | `PAUSED` |
| `escape` | Shell attempt, then exfiltration over HTTP and email | `KILLED` |

`make investigate` writes an incident report per log (cached in `.tripwire/reports/`), and
`make dashboard` shows the timeline, blocked actions, report and eval metrics. Scenarios are
synthetic fixtures in `examples/enterprise_agent/scenarios.json`.

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
- MCP server front end (`tripwire-mcp`, official `mcp` SDK, Streamable HTTP or stdio) plus a
  plain HTTP/JSON endpoint; both route every call through the same gateway. Malformed requests
  are denied and audited.
- Gateway-only mock tool service. Honeytoken matching happens in the gateway; the token list is
  never sent to the tool service.
- Optional Ollama investigator, deterministic template fallback, and a citation verifier. A
  model report with any invalid citation is replaced by the template. Reports are cached by the
  audit log's final hash so the demo never waits on the model.
- Streamlit dashboard: containment banner, coloured timeline, blocked actions, ran-while-blocked
  counter, incident report and eval metrics.
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

## MCP

```bash
make tools   # mock tool service on :9090
make mcp     # Tripwire MCP server on http://127.0.0.1:8081/mcp
```

`tools/list` advertises only the tools the contract allows. A denied call comes back as a tool
error carrying the decision and event ID. `--transport stdio` exists for local development, but
it runs the gateway inside the client's process; use HTTP whenever the agent is sandboxed.

## Investigator

The investigator is optional and never in the allow/deny path. With no model it uses the
template report. To use a local model:

```bash
brew install ollama
ollama pull qwen2.5:3b-instruct
make investigate
```

## Docker

The compose topology is in `docker/compose.yaml`.

```bash
make docker-build
make docker-up
```

Docker Desktop/daemon must be running. Both compose networks are marked `internal: true`; the
agent only joins `agent_internal`, while the mock tools only join `tools_only`. The agent has its
own image (`docker/agent.Dockerfile`) holding just the replay script and scenarios: no Tripwire
code, contracts, tool data or honeytokens. Pick a scenario with
`TRIPWIRE_SCENARIO=escape make docker-up`. Gateway audit logs are written to `.tripwire/` on the
host, so the dashboard can show a Docker run.

Checked locally: from the agent container the gateway is reachable, while the mock tools and the
internet are not.

## Limits

Tripwire detects a defined set of scope violations and suspicious sequences at the tool-call
layer. It is one layer and does not replace OS, container or network isolation. Each gateway
process enforces one contract for one session.

## Still Out Of Scope

Autonomous red team, LLM-written policy fixer, hosted deployment, real vendor connectors,
multi-tenant auth, and SENTINEL.
