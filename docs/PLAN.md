# Tripwire — Build Plan

Event: Oct 9, 2026. Doors 9:30, hack 11:00, lunch 1:30, **submission 4:30**, finalist demos 5:00, awards 7:00.
Strategy: pre-build the core tonight and tomorrow morning; use event hours for investigator, dashboard, polish and demo. Confirm the event's rules on pre-built work before relying on this.

Rule: **depth over breadth.** One thing built properly. No scope added after Checkpoint B.

## Checkpoints (each ends with a working, committed state)

### Checkpoint A — Tonight: skeleton that runs end to end
Target: an agent does a benign task through the gateway, fully logged.
- [x] Repo scaffold per `AGENTS.md` layout (`uv`, `pyproject.toml`, `Makefile`, `ruff`, `pytest`, `pre-commit`, MIT license, `.gitignore` incl. `docs/internal/`)
- [x] Pydantic models: `TaskContract`, `ToolCall`, `Decision`, `AuditEvent`
- [x] Task contract loader + YAML schema validation
- [x] Python tool wrappers with 5 in-process mock tools and synthetic data (customers A/B, tickets, injection payload, honeytokens)
- [x] Gateway `authorize()` with ALLOW/DENY only (contract tool + scope + destination checks)
- [x] Audit log: JSONL, hash-chained, with `attempted`, `decision`, `containment_state`, `tool_executed`, `prev_hash`, `hash`
- [x] Unit test: denied call never reaches the tool
- [x] Scripted agent that replays a benign trace through the gateway
- [x] Document Docker topology: agent and gateway share an internal network; mock tools are reachable only by gateway; agent has no internet

### Checkpoint B — Tomorrow morning (before doors): the detection core
Target: attack traces get caught; benign traces don't.
- [x] Honeytoken detector (instant KILL)
- [x] Sequence detectors: scope creep, retry-after-denial, enumeration, read-then-send, budget
- [x] Suspicion score + warn/pause/kill state machine; paused/killed sessions deny everything
- [x] Record 3 attack traces (slow drift, honeytoken grab, escape-style) + 10 benign traces
- [x] Eval harness over ≥ 20 trajectories → detection rate, false-block rate, actions-to-detect, latency
- [x] Tests for every detector (positive and negative cases)
- [x] MCP proxy mode: Tripwire sits in front of the mock MCP server
- [x] Dockerfile + compose: agent alone on an `internal: true` network; gateway can reach tools; agent cannot reach tools or internet

### Checkpoint C — At the event (11:00–1:30): investigation
- [x] Investigator prompt + JSON schema output via Ollama
- [ ] Ollama installed, small model pulled, one test prompt works
- [x] Citation verifier (reject non-existent event IDs)
- [x] Deterministic template fallback report
- [x] Stage labels (recon → credential access → escape attempt → persistence)
- [x] Cache reports from tonight so the demo never waits on the model

### Checkpoint D — At the event (2:00–3:45): demo surface
- [x] Streamlit: live timeline (green → amber → red → contained), blocked-action panel, "sensitive ops executed: 0", incident report, metrics table
- [ ] Live mode: local model agent attempts the task against a decoy; replay mode as fallback toggle
- [ ] Dry-run the 90-second demo three times, including with wifi off

### Checkpoint E — 3:45–4:30: submission
- [ ] README (what, why, honest limits, how to run, eval command, results)
- [ ] 60-second backup demo video
- [ ] Architecture diagram image
- [ ] Submission form; tag release `v0.1.0`

## What to skip (do not build before the demo works)
LLM-generated policy fixes, CI integration, multi-framework adapters, per-value taint tracking, hosted deployment, auth/multi-tenant, vendor connectors (Workato etc.), autonomous red-team agent.

## Test strategy
- Unit: contract validation, each detector, state machine, audit hash chain, verifier.
- Property-style: any call after PAUSE/KILL is denied.
- Safety invariant test: for every attack trace, `tool_executed == false` for all DENY/PAUSE/KILL events.
- Eval gate: benign false-block rate must be 0 on the committed benign set before demo; otherwise tune thresholds, not the test set.
- Offline test: run the replay demo with network disabled.

## Risks and mitigations
| Risk | Mitigation |
|---|---|
| Model refuses/drifts in live mode | Replay is the primary demo; live is a bonus |
| Ollama slow or model too big | Small model, cached reports, template fallback |
| Detector false positives on legit multi-step work | Benign-but-tricky trajectories in eval; tune thresholds; report the number honestly |
| Docker/Ollama setup eats the evening | Time-box 45 min; if stuck, keep Python-level sandbox and note it |
| Scope creep at 2am | Checkpoints are the only scope; new ideas go in `IDEAS.md` |
| Employer IP/conflict | Only synthetic data and public docs; no employer code, creds or internal material; verify employment agreement before pitching a commercial product |

## Division of work between agents
- **Claude Code**: architecture, gateway/detectors/audit core, tests, eval harness, investigator/verifier.
- **Codex**: scaffolding, mock MCP data and traces, Streamlit UI, README, Dockerfile polish.
- Rule: one agent per directory at a time; commit before switching; `HANDOFF.md` is updated at every switch.
