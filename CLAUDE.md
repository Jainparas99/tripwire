@AGENTS.md

# Claude Code specifics

- Use plan mode before touching `docs/DESIGN.md` invariants, the audit schema, or the `authorize()` contract; propose the change and wait for the user.
- Run `make test` and `make lint` before every commit.
- Prefer small, reviewable commits per checkpoint item in `docs/PLAN.md`; tick the checklist as you go.
- At the end of every session, append a dated entry to the handoff log in `docs/internal/HANDOFF.md` (what changed, what's next, blockers).
- When unsure about the current MCP SDK or Ollama API, check the installed package/docs rather than relying on memory.
- Keep answers to the user short; put detail in commits and docs.
