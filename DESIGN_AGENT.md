# c2-engine — Analyst Agent Plan (conversational access to the C2 data)

> How we give analysts a chat interface over the C2 data **today on ES/Kibana
> 8.19**, built so it migrates cleanly to **Elastic Agent Builder** if/when we
> upgrade to 9.4+. Companion to DESIGN.md / DESIGN_PARITY.md.

## 1. Constraint (from the Agent Builder research)

- **Elastic Agent Builder is 9.4+ and Enterprise-tier.** Not available on our
  `4warned/*:v2.3` (ES/Kibana **8.19.8**) images — getting it is a 9.x upgrade,
  not a flag. So it is NOT our near-term path.
- On 8.19 the Elastic-native options are Kibana **Playground** (RAG, tech
  preview, paid LLM connector) and the **AI Assistant** (Enterprise) — neither
  gives a governed, custom tool layer.
- **`semantic_text` + ELSER** over `content` IS usable on 8.19, but needs a paid
  tier + ML node, and exact IOC lookups beat embeddings — so it's optional, not
  the backbone.

**Decision: build our own agent now** — a small **MCP server exposing
ES|QL-backed tools** over our indices, driven by an LLM (Claude). This is the
same architecture Agent Builder uses (tool-using agent over ES|QL), so it is
**forward-compatible**: the tool definitions port to Agent Builder's
`type: esql` tools, or Agent Builder can consume our MCP server directly.

## 2. Why MCP-tools-over-ES|QL (not free-form NL→query, not a bespoke chatbot)

- **Governed & safe:** only our vetted, read-only, parameterized ES|QL touches
  ES. The LLM picks a tool + fills params; it never writes raw queries against
  the cluster. Scope an API key to the three indices so it can't wander.
- **Accurate:** hand-written tools that map 1:1 to real analyst questions
  out-accuracy free-form `generate_esql` for a known question set.
- **Portable:** MCP is the lingua franca. Today: Claude Desktop / Claude Code /
  our own thin chat UI connect to the server. Tomorrow: Elastic Agent Builder
  (9.4+) consumes the same MCP tools, or we re-register the identical ES|QL
  bodies as native Agent Builder tools. Either way the *queries* are the asset
  and they don't change.

## 3. Architecture

```
 Analyst ──chat──▶ LLM (Claude)  ──MCP──▶  c2-agent (MCP server)  ──ES|QL──▶  Elasticsearch
                  (tool-calling)            read-only, API-key-scoped         stingar-* / stingarc2-* / c2-entities
                                            tools = parameterized ES|QL
```

- **`c2-agent`** — a small service in this repo (reuses the `c2engine` package +
  its ES client). Exposes an MCP server; each tool runs one parameterized ES|QL
  query and returns rows. Stateless, read-only.
- **LLM** — Claude (any MCP-capable client). The agent service holds NO model;
  the model is the caller. (A thin built-in chat UI is optional later.)
- **Surfaces:** `c2-entities` answers *which / how many / what stage*;
  `stingarc2-*` is *drill-down* (files, scripts, chain); `stingar-*` is session
  context.

## 4. Tool library (maps 1:1 to analyst questions)

Each tool = `{id, description, params, esql}` — the exact shape Agent Builder's
`POST /api/agent_builder/tools` expects, so they transfer verbatim later.

| Tool | Index | Answers | ES|QL sketch |
|---|---|---|---|
| `c2.top_by_stage` | c2-entities | "which C2s are stage2 this week?" | `FROM c2-entities \| WHERE stage == ?stage AND last_seen >= ?since \| SORT last_seen DESC \| KEEP c2_host, stage, families, sighting_count, sensor_count, c2_asn_org \| LIMIT ?limit` |
| `c2.detail` | c2-entities | "tell me about 45.137.21.9" | `FROM c2-entities \| WHERE c2_host == ?c2_host` |
| `c2.families_by_host` | stingarc2-* | "what families is this C2 serving, to which sensors?" | `FROM stingarc2-* \| WHERE c2_host == ?c2_host \| STATS sightings=COUNT(*), sensors=COUNT_DISTINCT(sensor_hostname) BY family \| SORT sightings DESC` |
| `c2.srcs_for_host` | stingarc2-* | "which src_ips contacted this C2?" | `FROM stingarc2-* \| WHERE c2_host == ?c2_host \| STATS hits=COUNT(*) BY src_ip \| SORT hits DESC \| LIMIT ?limit` |
| `c2.sensors_for_host` | stingarc2-* | "which honeypots saw this C2?" | `FROM stingarc2-* \| WHERE c2_host == ?c2_host \| STATS hits=COUNT(*) BY sensor_hostname \| SORT hits DESC` |
| `c2.scripts` | stingarc2-* | "show served scripts (optionally matching X)" | `FROM stingarc2-* \| WHERE file_kind == "script" AND c2_host == ?c2_host \| KEEP sha256, family, interpreter, callbacks, content \| LIMIT ?limit` |
| `c2.scripts_calling_second_host` | stingarc2-* | "scripts that fetch from another host (chain)" | `FROM stingarc2-* \| WHERE file_kind == "script" AND content RLIKE ?pattern \| KEEP c2_host, sha256, callbacks, content \| LIMIT ?limit` |
| `c2.chain` | stingarc2-* | "where do this C2's files call back to?" | `FROM stingarc2-* \| WHERE evidence == "file_callback" AND c2_via_sha256 IN (?shas) \| KEEP c2_host, c2_via_sha256` |
| `payloads.by_family` | stingarc2-* | "show me Mozi samples + hashes" | `FROM stingarc2-* \| WHERE family == ?family AND file_kind IS NOT NULL \| STATS hosts=COUNT_DISTINCT(c2_host) BY sha256, size, magic \| LIMIT ?limit` |
| `payloads.by_sha` | stingarc2-* | "who served this exact file?" | `FROM stingarc2-* \| WHERE sha256 == ?sha256 \| STATS sensors=COUNT_DISTINCT(sensor_hostname), c2s=COUNT_DISTINCT(c2_host)` |
| `sessions.for_c2` | stingar-* | "raw attacker sessions for this C2" | `FROM stingar-* \| WHERE c2_host == ?c2_host \| KEEP @timestamp, src_ip, sensor_hostname, hp_data.playbook_hash \| LIMIT ?limit` |

(Optional, if `semantic_text` on `content` is adopted: a `c2.scripts_semantic`
tool using `MATCH`/semantic query for fuzzy "looks like a loader" intent.)

## 5. Governance / safety
- Read-only ES API key **scoped to `stingar-*`, `stingarc2-*`, `c2-entities`**.
- Only allowlisted, parameterized ES|QL runs — no raw query passthrough.
- Every tool has a `LIMIT`; the server caps result size + ES|QL timeout.
- The server never mutates; it shares the ledger's immutability guarantee.

## 6. Data-model prerequisites (version-independent — do these regardless)
These help our own agent AND a future Agent Builder equally. **Status: done
2026-06-06** (except the optional semantic_text item).
1. **Field `_meta` descriptions** ✅ — rich `_meta` blocks on both the ledger
   (`stingarc2-*`) and entity (`c2-entities`) templates: a per-index description +
   a `fields` legend explaining every field and enum (`evidence`, `stage`,
   `evidence_rank` 0/1/2, `file_kind`). `_meta` is free-form (no 50-char limit
   that field-level `meta` imposes) and is returned by `get_index_mapping`, which
   is what an LLM reads to choose fields. In `es_assets.py` + the `es/` copy.
2. **Flatten `nested` arrays** ✅ (audited, non-issue) — live audit of all three
   index patterns found **zero** `nested`-typed fields. Our templates use flat
   `keyword[]` (`callbacks`); the session index's arrays dynamic-map to `object`,
   not `nested`. Nothing to flatten.
3. **Naming consistency** ✅ (resolved by documenting, not rewriting) — our own
   indices (ledger + entities) are internally consistent: `sensor_hostname` + `ts`.
   The stock session index `stingar-*` uses `sensor.hostname` + `@timestamp`. We
   deliberately do **not** rewrite those — the pass-through invariant (we never
   mutate stock STINGAR fields) takes precedence. The difference is recorded in
   the `c2-entities` `_meta._naming_note` so the agent/tools know to normalize at
   query time, not in storage.
4. **`c2-entities` is the primary surface** ✅ (already built).
5. Optional (deferred): `semantic_text` + ELSER over `content` (paid tier) for
   fuzzy payload-behavior search.

## 7. Migration to Elastic Agent Builder (if we go 9.4+/Enterprise)
- Re-register each tool's ES|QL body as a native Agent Builder `type: esql` tool
  (`POST /api/agent_builder/tools`), OR point Agent Builder at our MCP server as
  `type: mcp` tools — zero query rewrite either way.
- Agent Builder then also gives: built-in `generate_esql`/`index_explorer`,
  a Kibana chat UI, and its own MCP/A2A endpoints (so Claude can still drive it).
- Our governance model (API-key-scoped, allowlisted ES|QL) maps onto Agent
  Builder's security profiles.

## 8. Milestones
- **A1** — `c2-agent` MCP server skeleton + ES client + 3 core tools
  (`c2.top_by_stage`, `c2.detail`, `c2.families_by_host`); connect from Claude,
  verify against live ES.
- **A2** — full tool library (§4); result caps + timeouts; read-only API key.
- **A3** — data-model prerequisites (§6: `_meta`, naming, nested audit).
- **A4** *(optional)* — `semantic_text`+ELSER on `content` + a semantic tool.
- **A5** *(optional)* — a thin built-in chat UI, or document the Claude-Desktop /
  Claude-Code MCP connection for analysts.

## 9. Decision record / open questions
- **Build our own (MCP+ES|QL) now; Agent Builder later if we upgrade.** The tool
  queries are the durable asset; the runtime (our MCP server vs Agent Builder) is
  swappable.
- **Open (needs supervisor):** is a 9.4+/Enterprise upgrade of the STINGAR stack
  on the table? If yes, Agent Builder is the endgame; if no, our MCP server is
  the product. Either way §6 work is not wasted.
- **Open:** which LLM/host for analysts day-to-day (Claude Desktop, Claude Code,
  or a hosted chat) — affects only the client, not the tools.
