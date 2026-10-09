# Senso: trusted context for the threat-watch agent (verification record)

Recorded 2026-10-09. Every result below is the verbatim output of the command shown; nothing was
edited except trimming an unrelated note about the claude.ai Google Drive connector.

## 1. Senso MCP connected to Claude Code

```bash
claude mcp add --transport http --scope user senso https://apiv2.senso.ai/mcp \
  --header "X-API-Key: $SENSO_API_KEY"
claude mcp list
```

`claude mcp list` reported: `senso: https://apiv2.senso.ai/mcp (HTTP) - ✔ Connected`
(the server was already registered on this machine; the API key is not reproduced here).

## 2. Threat-watch contract added as trusted context

The document is built from `examples/contracts/threat_watch.yaml` with the **honeytoken list
removed**: decoys must stay unknown to the agent, or the tripwire stops working. It carries the
full contract's hash (`853d1b13…c2103`) and states that the gateway's copy wins on any difference.

```bash
claude -p "<create the doc, then poll senso_get_doc until complete>" \
  --allowedTools "mcp__senso__senso_create_doc mcp__senso__senso_get_doc"
```

Result: node_id `4f435737-60cc-495f-8033-5d4ac195a51b`, processing_status `complete` (version 1),
1,428 characters, tags `tripwire`, `trusted-context`.

## 3. Claude retrieves and cites it

A fresh session with only `senso_search` allowed:

```bash
claude -p "<answer three questions about the contract, citing content_ids>" \
  --allowedTools "mcp__senso__senso_search"
```

```text
All four results came from one document in the Senso knowledge base, so every answer cites the same content_id.

**1. Allowed tools and destinations**
- Tools: only `fetch_cisa_kev` and `publish_alert`. Any other tool is denied. *(content_id `45d2b792-ef3a-4df1-9bbc-2af5e73870be`)*
- Destinations: only `www.cisa.gov`. Any other destination is denied. *(content_id `45d2b792-ef3a-4df1-9bbc-2af5e73870be`)*

**2. max_actions and kill threshold**
- `max_actions`: 3 tool calls per session. *(content_id `45d2b792-ef3a-4df1-9bbc-2af5e73870be`)*
- Kill threshold: a suspicion score of 10. The other thresholds are warn at 3 and pause at 6. Once a session is paused or killed, every later call is denied. *(content_id `45d2b792-ef3a-4df1-9bbc-2af5e73870be`)*

**3. Is posting to hooks.example.com allowed?**
No. `hooks.example.com` isn't in `allowed_destinations`, and the contract says "Any other destination is denied." *(content_id `45d2b792-ef3a-4df1-9bbc-2af5e73870be`)*

The document describes itself as "context for the agent, not the policy itself; the gateway's copy wins on any difference." So these answers match the knowledge-base copy, which may differ from what the gateway actually enforces. It also says the contract's honeytoken list was left out on purpose.

**Raw content_id values and titles returned by senso_search (verbatim):**
```
1. content_id: 45d2b792-ef3a-4df1-9bbc-2af5e73870be  title: Tripwire threat-watch task contract (trusted context)
2. content_id: 45d2b792-ef3a-4df1-9bbc-2af5e73870be  title: Tripwire threat-watch task contract (trusted context)
3. content_id: 45d2b792-ef3a-4df1-9bbc-2af5e73870be  title: Tripwire threat-watch task contract (trusted context)
4. content_id: 45d2b792-ef3a-4df1-9bbc-2af5e73870be  title: Tripwire threat-watch task contract (trusted context)
```
```

The cited `content_id` `45d2b792-ef3a-4df1-9bbc-2af5e73870be` is the uploaded document: a
`senso_search` result returned it together with node_id `4f435737-…`. A search for the honeytoken
string found no document containing it.

## Limits

- This is context for the agent, not enforcement. Tripwire's gateway still enforces the contract
  on every call; a model that ignores the context is denied the same way.
- Guild: not verified. The CLI (`@guildai/cli` 0.27.1 on npm) is not installed here and no Guild
  credentials are present, so no deployment note was written.
