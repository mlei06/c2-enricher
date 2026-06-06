# c2-engine — Parity Plan (closing the GreyNoise C2-Detection gaps)

> Extends DESIGN.md. Implements the items deferred in DESIGN §9, in the order
> that delivers the most GreyNoise-parity per unit of work. Nothing here changes
> the ingest hot path or the immutable ledger.

## 0. Where we stand (from the alignment review)

Aligned already: payload-derived detection, 3-tier evidence ladder
(`evidence_rank` 0/1/2), `category.family/variant` labels, triple hashes, size,
src-IPs-per-callback, the `callback_ips`-style pivot, first/last seen, top
threats, in-session victim-identity capture, static chain edges.

Gaps to close, by leverage:
1. **No persistent, escalating per-C2 stage** — we compute stage at query time
   from `max(evidence_rank)`; GreyNoise has one escalating record per callback IP.
2. **No intel escalation** (known-malware SHA, HASSH-toolkit, VirusTotal).
3. **No VirusTotal detection ratios.**
4. **No blocklist / alert automation.**
5. **Classifier is a regex starter set; no Maps geo layer / entity detail UI.**

Out of scope (cannot match cheaply, and accepted): sandbox-behavioral Stage 2,
global-sensor scale, a bespoke console.

## 1. Principles (unchanged, reaffirmed)

- **Ledger is immutable & authoritative.** Nothing in this plan mutates
  `stingarc2-*` rows. Everything derived is recomputable from the ledger.
- **Entities are a *decaying materialized view*, not an archive.** One doc per
  `c2_host`, expired ~30 d after `last_seen` (C2 IPs live ~3 days; stale stage
  poisons blocklists). The ledger keeps history; the entity index is "active C2
  infrastructure right now."
- **Enrichment grounds; reason interprets.** The transform derives facts
  (counts, evidence_stage). The reason layer overlays *judgments* (intel stage,
  VT, attribution) onto the entity — never the ledger.
- **Never block ingest.** Reason/VT run as an out-of-band periodic job, not in
  the Fluent-forward path. ES/VT being slow or down can't stall sessions.

## 2. Target architecture (additive)

```
 stingarc2-*  (ledger, immutable)                         [exists]
      │
      │ ES continuous transform (group_by c2_host, retention 30d)
      ▼
 stingarc2-entities  (one upserted doc per C2, decaying)  [M1]
      ▲
      │ reason job (periodic, out-of-band)                [M2/M3]
      │   - known-malware SHA / HASSH-toolkit  → stage_signals, escalate stage
      │   - VirusTotal by sha256 (cached, rate-limited)  → vt_ratio, vt_families
      │   writes ONLY to entity docs (+ a vt cache index)
      │
 stingarc2-vt  (sha256 → VT verdict cache, fleet-wide)    [M3]
      │
      ▼ blocklist/alert feed                              [M4]
   GET /feed (engine)  or  Kibana alert  or  CIF push
```

New pieces: one ES transform, one `reason/` job (new `c2-engine reason`
subcommand), one VT cache index, one feed surface. No change to `ingest/`.

## 3. Milestones

### M1 — Entity rollup + evidence stage (the headline; ES-native, no new service)

Continuous **ES transform** over `stingarc2-*`, `group_by: c2_host`, with
`retention_policy { field: last_seen, max_age: 30d }`. Pure aggregations
(transforms can't call out — intel comes in M2):

`stingarc2-entities` doc (id = `c2_host`):
```jsonc
{
  "c2_host": "45.137.21.9", "c2_host_kind": "ip",
  "first_seen": <min ts>, "last_seen": <max ts>,         // min/max(ts)
  "sighting_count": <value_count>,
  "sensor_count": <cardinality sensor_hostname>,
  "src_ip_count": <cardinality src_ip>,
  "distinct_files": <cardinality sha256>,
  "max_evidence_rank": <max evidence_rank>,              // 0|1|2
  "evidence_stage": "unconfirmed|stage1_serving|stage2_c2",  // derived from max rank
  "self_hosted": <max self_hosted>,                       // ever loader-is-scanner
  "c2_geo": <top_metrics c2_geo by ts desc>,             // latest geo
  "c2_country": <top_metrics>, "c2_asn": <top_metrics>, "c2_asn_org": <top_metrics>
}
```
- `evidence_stage` from `max_evidence_rank`: 0→unconfirmed, 1→stage1_serving,
  2→stage2_c2. Computed in the transform via a `bucket_script`/runtime field, or
  written by M2 (simpler: M2 owns the final `stage`; transform writes the raw
  `max_evidence_rank` + `evidence_stage`).
- Index template + ILM for `stingarc2-entities` (geo_point on `c2_geo`),
  installed by `ensure_bootstrap` like the ledger.
- **Exit:** transform runs continuously; one decaying doc per active C2; the
  Command Center "Top C2s" + the (deferred) Maps layer read this index.

### M2 — Reason layer: static intel escalation (no external dependency)

New `c2engine/reason/` (re-derive the useful bits of the abandoned
`reasoning/data/`): a periodic job (`c2-engine reason --interval 300`) that,
per entity updated since last run, reads its ledger rows and overlays judgment:

| Signal | Source | Effect |
|---|---|---|
| served sha256 ∈ known-malware list | `reason/data/known_sha.json` | `stage_signals += known_malware`, escalate → `stage2_c2` |
| any `file_callback` (chain) | ledger | escalate → `stage2_c2` (a host malware points at) |
| session HASSH ∈ toolkit map | `reason/data/hassh_toolkits.json` | `attributed_toolkit`, `stage_signals += hassh_toolkit` |
| `families[]` for the entity | ledger `terms(family)` | entity-level family rollup (GreyNoise "families linked to this IP") |

Writes onto the entity doc only: `stage` (final, ≥ `evidence_stage`, may
escalate), `stage_signals[]`, `families[]`, `attributed_toolkit`,
`reason_version`. Idempotent; re-running re-stages all entities without touching
the ledger. **Exit:** entities carry an escalating `stage` + `families[]` +
`stage_signals`; matches GreyNoise's per-callback stage UX.

### M3 — VirusTotal enrichment (cached, rate-limited, optional)

In the reason job, for each distinct served-file `sha256` lacking a fresh
verdict: look up VT, cache fleet-wide.

- **Cache index** `stingarc2-vt` (id = sha256): `{sha256, vt_malicious,
  vt_total, vt_ratio, vt_families[], checked_at}`. One lookup per distinct file,
  ever (until staleness window) — dedupes across the whole fleet.
- **Rate limit**: token bucket (VT public = 4/min, 500/day); `VT_API_KEY` env,
  **disabled by default**. Budget exhausted → skip, try next pass (never block).
- Overlay onto entity: `max_vt_ratio`, `vt_families[]`; `vt_ratio ≥ threshold`
  → escalate stage + `stage_signals += virustotal`.
- **Exit:** the dashboard file/entity view shows a VT detection ratio (GreyNoise's
  "50 / 77 engines") for files VT knows; unknown files simply omit it.

### M4 — Blocklist / alert feed (the actionable output)

Read `stingarc2-entities` where `stage ≥ stage1_serving AND last_seen ≥
now-<window>` (default 7d) → fresh, high-confidence C2 IPs.

- **Primary**: a tiny HTTP endpoint in the engine (`GET /feed/blocklist.txt`,
  plain IP list) firewalls/SIEMs can pull; `?stage=2`, `?window=3d` params.
- **Optional**: push the same set to the existing **CIF** out (reuse STINGAR's
  threat-sharing channel) and/or a Kibana alerting rule on the entity index.
- Correctness is trivial because the entity index is already decaying — no stale
  IPs in the feed by construction. **Exit:** a curl-able, always-fresh C2
  blocklist; optional CIF contribution.

### M5 — Classifier + UI polish (incremental, data-driven)

- **Family classifier**: harvest markers from the `trojan.elf/<arch>`
  unclassified bucket as real captures accumulate; optionally add `yara-python`
  rules in the reason layer (heavier, gated on need).
- **Maps geo layer** on `stingarc2-entities` (styled by `stage`) — author in the
  Kibana UI once real attacker IPs with geo flow, then export to
  `es/dashboards/`.
- **Entity detail dashboard** (GreyNoise's callback detail page): filtered by
  `c2_host` — stage, files (hashes/size/family/vt), `stage_signals`, the scanner
  (src_ip) panel, evidence-source markdown.

## 4. Data contracts (new)

- `stingarc2-entities` — §3 M1/M2/M3 fields. Index template + ILM via
  `ensure_bootstrap`. `c2_geo: geo_point`, `*_seen: date`, ints as `long/byte`.
- `stingarc2-vt` — `{sha256 keyword, vt_malicious int, vt_total int, vt_ratio
  float, vt_families keyword[], checked_at date}`. ILM: re-lookup window (e.g.
  30 d) via `checked_at`.
- Stage enum everywhere: `unconfirmed | stage1_serving | stage2_c2` (rank 0/1/2).
  `stage` (final, reason) ≥ `evidence_stage` (transform). Reason never *demotes*.

## 5. Decisions & trade-offs

| Decision | Choice | Why |
|---|---|---|
| Entity maintenance | **ES continuous transform** for facts; reason job for intel | Transform is ES-native/no-service for the rollup; only intel needs a job |
| Entity lifetime | decaying (retention 30d on last_seen) | C2s live ~3d; stale stage poisons blocklists (revisited & reaffirmed) |
| Stage escalation | reason can only **raise** stage above evidence_stage | evidence is the floor; intel adds confidence, never hides it |
| VT placement | reason job, cached, off the hot path, default-off | VT rate limits + latency must never touch ingestion |
| Reason cadence | periodic batch (`--interval`), not per-event | idempotent, cheap, re-stageable; honeypot volume doesn't need streaming |
| Blocklist freshness | derive from the already-decaying entity index | correct-by-construction; no separate expiry logic |

## 6. Non-goals (explicit)
- **Sandbox detonation / behavioral Stage 2** — out of scope; our Stage 2 stays
  static (chain edges + intel). Documented divergence from GreyNoise.
- **Global-scale sensor network** — N/A; we enrich what our fleet sees.
- **Mutating the ledger** — never; all derived state is recomputable.

## 7. Sequencing & triggers
M1 → M2 are the core parity win (escalating staged entities) and unblock M4
(blocklist) and the Maps/entity-detail UI. M3 (VT) and M5 (YARA/classifier) are
independent add-ons. Recommended: **M1 → M2 → M4 → M3 → M5**, building each
against the real served-file/chain data now flowing in `stingarc2-*`.
