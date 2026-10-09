# Tripwire — Requirements

Priorities: **M** must (demo fails without it), **S** should, **C** could (only if ahead).

## 1. Functional requirements

| ID | Pri | Requirement | Acceptance test |
|---|---|---|---|
| FR-1 | M | **Task contracts** are loaded from YAML supplied by the application, validated, and immutable for the session. The agent cannot read-write or influence them. | Invalid contract fails to load; contract hash is logged on every event |
| FR-2 | M | **Gateway**: every protected tool call passes through `authorize()`; the tool runs only on ALLOW. | Test: for every DENY/PAUSE/KILL, the tool implementation was never invoked |
| FR-3 | M | **Resource authorization**: tool allowlist, customer/resource scope, destination allowlist, `max_actions`. | Customer B read under a Customer A contract → DENY `SCOPE_VIOLATION` |
| FR-4 | M | **Honeytokens**: any access to a decoy credential / answer-key pointer / decoy URL → immediate KILL. | Touching any decoy kills the session in ≤ 1 action |
| FR-5 | M | **Sequence detectors**: scope creep, retry-after-denial, enumeration, read-then-send, budget; weights and thresholds in config. | Each detector has a positive and a negative test |
| FR-6 | M | **Containment** state machine: warn → pause → kill. Paused/killed sessions deny everything, even if the agent keeps trying. | Property test over random post-kill calls |
| FR-7 | M | **Audit log**: one event per call; includes `attempted`, `decision`, `containment_state`, `tool_executed`, `prev_hash`, `hash`; hash-chained; JSONL + SQLite index. | Chain verifies; tampering is detected |
| FR-8 | M | **Eval harness**: ≥ 20 trajectories (benign, benign-but-tricky, attack); reports detection rate, false-block rate, actions-to-detect, gateway latency, executed-after-block count. | One command reproduces the table; executed-after-block == 0 |
| FR-9 | M | **Replay** of recorded traces through the gateway, offline, deterministic. | Same trace → identical decisions across runs |
| FR-10 | S | **Investigator** (Ollama, local open-weight model): JSON incident report, stage labels, claims with event-ID citations. | Verifier rejects a report citing a non-existent event |
| FR-11 | S | **Template fallback** report when Ollama is unavailable. | Demo runs with Ollama stopped |
| FR-12 | S | **Dashboard** (Streamlit): live timeline, containment state, blocked-action panel, metrics, incident report. | Replay demo drives the UI end to end |
| FR-13 | S | **MCP proxy mode**: Tripwire fronts the mock MCP server. | Agent reaches tools only through the proxy |
| FR-14 | S | **Docker isolation**: agent and gateway share an internal network; mock tools are on a gateway-only network; agent has no egress. | From inside the agent container, direct tool access and internet both fail |
| FR-15 | C | **Python SDK**: `protect(tool, ctx)` wrapper; a second demo agent integrates without engine changes. | Second agent runs under the same gateway |
| FR-16 | C | Live mode: local-model agent attempts the task against decoys. | Falls back to replay with one toggle |

## 2. Non-functional requirements

- **Fail closed.** Unknown tool, malformed call, missing contract, or detector error → DENY. `WARN` is a containment state, not a blocking decision. Enforcement continues if Ollama (or any future control plane) is down.
- **Deterministic enforcement.** No LLM in the allow/deny path.
- **Offline demo.** Replay mode needs no network and no model.
- **Safety.** Synthetic data only. No real exploits, no real network targets, no employer code, credentials or internal material.
- **Reproducible.** `uv sync`, `make test`, `make eval`, `make demo` work from a clean clone.
- **Performance (measure, don't claim):** report gateway p50/p95 latency per call in the eval output.
- **Licensing:** MIT for this repo; dependencies must be OSS-compatible.

## 3. Milestone acceptance (maps to PLAN.md checkpoints)

- **A (tonight):** benign trace runs through gateway; denied call never reaches tool (test); audit chain verifies.
- **B (morning):** attack traces caught, benign set has 0 false blocks, eval table generated.
- **C (event):** investigator report passes verifier; fallback works with Ollama off.
- **D (event):** full 90-second demo runs three times, once with wifi off.
- **E (submission):** README with honest limits and reproduce commands; tagged release.

## 4. Tooling — all free / open source

| Need | Tool | Notes |
|---|---|---|
| Language / env | Python 3.12+, `uv` | Pin via `uv.lock` on first install |
| Models / validation | `pydantic` v2, `pyyaml` | |
| MCP | official `mcp` Python SDK | Verify the current API on first use |
| Web/API (if needed) | FastAPI + uvicorn | Only for gateway HTTP mode |
| UI | Streamlit | Apache-2.0 |
| Graph (optional) | networkx | |
| Storage | SQLite + JSONL | stdlib |
| Local LLM runtime | Ollama | Free, local, offline after model pull |
| Investigator model | small open-weight Qwen instruct (e.g. a 3B–8B tag) | Pick by free RAM; verify tag with `ollama list`. GLM-5.2 is too large for a laptop |
| Isolation | Docker Engine / Docker Desktop (free for personal use) or Podman | Use an `internal: true` network |
| Tests / lint | pytest, hypothesis (property tests), ruff, pre-commit | |
| Optional scanners | Semgrep, OSV-Scanner | Not required for the MVP |
| Repo / CI | GitHub (free), GitHub Actions free tier | Private until employer question is settled |
| Coding agents | Claude Code, Codex | Already available; no extra cost |

No paid accounts are required. Optional cloud model keys may be used for the agent under test or an explicitly selected remote investigator. The remote investigator receives full audit events, including tool arguments; use synthetic data only. Enforcement never calls a model.

## 5. Machine prerequisites to confirm tonight

- Docker works (`docker run hello-world`).
- Ollama installed and a small model answers a test prompt.
- Free RAM for the chosen model (pick the smaller one if unsure).
- `uv`, `git`, and `gh` (or a GitHub login) available.

## 6. Open questions (owner: Paras)

1. Does the hackathon allow pre-built code, or must the repo start fresh at 11:00? (Check the rules page/organizers.)
2. Employment agreement: outside-project and IP-assignment terms, before any public release or investor pitch.
3. Trademark/name check for "SENTINEL" before using it commercially (widely used name in security). "Tripwire" is also an existing security product name; verify before public branding.
4. Which small model fits the laptop?
