# AGENTS.md — Tripwire (shared rules for Claude Code and Codex)

Tripwire is an open-source runtime security engine for autonomous AI agents. It enforces a trusted task contract on every tool call, detects suspicious *sequences*, contains offending sessions, and reconstructs incidents with a local open-weight model by default. A future control plane ("SENTINEL") will manage many Tripwire engines; **do not build SENTINEL now**.

Read first: `docs/DESIGN.md` (architecture), `docs/PLAN.md` (checkpoints), `docs/REQUIREMENTS.md` (acceptance criteria). Private context lives in `docs/internal/HANDOFF.md` (gitignored).

## Architecture invariants (do not violate; ask before changing)

1. Task contracts come from the application, never from the model or from retrieved content.
2. Every protected tool call passes through `gateway.authorize()`. A tool runs only on ALLOW.
3. Authorization is deterministic code. No LLM in the allow/deny path.
4. The gateway runs **outside** the agent's sandbox/container. The agent can reach only the gateway.
5. Fail closed: unknown tool, malformed input, missing contract or detector error → DENY.
6. Paused/killed sessions deny every later call.
7. Every call yields exactly one audit event with `attempted`, `decision`, `tool_executed`; log is hash-chained.
8. The investigator may explain but never decide. Its claims must cite event IDs; the verifier rejects invalid citations.
9. Enforcement keeps working if Ollama or any future control plane is unavailable.
10. Replay mode must run offline and deterministically (same trace → same decisions).

## Repo layout

```
src/tripwire/
  contracts/      task-contract models + loader
  gateway/        authorize(), decisions, MCP proxy adapter
  detection/      detectors, scoring, containment state machine
  honeytokens/
  audit/          event schema, hash-chained log
  investigation/  ollama client, report schema, verifier, template fallback
  sdk/            Python wrapper (stretch)
examples/enterprise_agent/   mock MCP server, synthetic data, scripted + Ollama agents
evaluation/{attacks,benign,traces}/  fixtures and runner
dashboard/       Streamlit app
docker/          Dockerfiles, compose (internal network)
tests/
docs/            DESIGN, PLAN, REQUIREMENTS; docs/internal/ is private
```

## Commands (create these in the Makefile as part of Checkpoint A)

- `make setup` → `uv sync`
- `make test` → `uv run pytest -q`
- `make lint` → `uv run ruff check . && uv run ruff format --check .`
- `make eval` → run all trajectories, print the metrics table
- `make demo` → replay demo (offline)
- `make dashboard` → `uv run streamlit run dashboard/app.py`

## Conventions

- Python 3.12+, type hints everywhere, pydantic v2 models for all data crossing a boundary.
- Small modules, pure functions for detectors (input: event window + contract; output: findings).
- Config (weights, thresholds) in YAML, not hard-coded.
- Tests next to behavior: every detector has a positive and a negative case; every invariant above has a test.
- Commit small and often, imperative messages. Update `docs/internal/HANDOFF.md` before switching agents.
- One agent per directory at a time. Suggested split: Claude Code owns `contracts/ gateway/ detection/ audit/ investigation/ tests/ evaluation/`; Codex owns `dashboard/ docker/ examples/ README.md`.

## Safety rules

- Synthetic data only. No real credentials, customer data, or employer code/material.
- No real exploits and no real network targets. Honeytokens are fake strings.
- Do not weaken a test to make it pass; fix the code or raise the issue.
- Never claim more than is true: Tripwire detects a *defined set* of violations; it is one layer and does not replace OS/network isolation; do not claim it would have stopped the July 2026 Hugging Face incident. Label recorded traces as fixtures.
- Do not add dependencies with non-OSS licenses. No paid service is required for the demo. Optional remote investigator APIs may be used only with an explicitly selected provider and synthetic audit data; they may incur charges and receive the full audit events.

## Definition of done (per task)

Tests pass, lint clean, invariants intact, docs updated if behavior changed, handoff log appended.

## Out of scope until the demo works

LLM-written policy fixes, CI integration, multi-framework adapters, per-value taint tracking, hosted deployment, auth/multi-tenant, vendor connectors, autonomous red-team agent, SENTINEL.
