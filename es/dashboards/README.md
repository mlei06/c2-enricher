# Kibana saved objects — C2 dashboards

Two exported, self-contained dashboards (Kibana 8.19), built and verified live
on the STINGAR Kibana (DESIGN.md §7):

| File | Dashboard | Focus |
|---|---|---|
| `c2-command-center.ndjson` | **C2 Command Center** | C2-host-first: map of the threat, click a C2 → its honeypots/src_ips/payloads/sessions |
| `c2-payload-explorer.ndjson` | **Payload Explorer** | file-first: families over time, one row per sha256, cross-sensor dedupe, script source |

(DESIGN §7's "C2 Detail" is **not** a separate dashboard — it's the Command
Center's post-click state once a `c2_host: X` filter is pinned.)

Import on any matching stack via **Stack Management → Saved Objects → Import**, or:

```bash
curl -s -X POST "<kibana>/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf:true" --form file=@c2-command-center.ndjson
curl -s -X POST "<kibana>/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf:true" --form file=@c2-payload-explorer.ndjson
```
(On the STINGAR server Kibana is under the `/kibana` basePath, e.g.
`http://localhost:5601/kibana/...`.)

## C2 Command Center

## What's in it (11 objects)
- **Data views**: `c2-ledger` (`stingarc2-*`, timeField `ts`) and `c2-sessions`
  (`stingar-*`, timeField `@timestamp`).
- **Dashboard** "C2 Command Center" (default window: last 7 days) with 8 panels:
  | Panel | Source | Shows |
  |---|---|---|
  | note | — | how to pivot + the evidence ladder legend |
  | Top C2 Hosts | ledger | `terms(c2_host)` — **click a host → Filter for value** |
  | Evidence Ladder | ledger | `terms(evidence)` (0 referenced · 1 served · 2 callback) |
  | Top Threats | ledger | `terms(family)`, `evidence:served_file` |
  | Honeypots Hit | ledger | `terms(sensor_hostname)` |
  | Source IPs | ledger | `terms(src_ip)` |
  | Payloads Served | ledger | served_file rows (sha256/family/kind) |
  | Raw Sessions | sessions | the enriched `stingar-*` session docs |

## The pivot
Clicking a `c2_host` value (Top C2 Hosts) → *Filter for value* adds a dashboard
filter `c2_host: X` that applies to **every** panel — ledger panels *and* the
session panel — because both indices share the `c2_host` field. That answers:
which honeypots it hit, which src_ips called it, what it served, and the raw
sessions, in one click.

## Payload Explorer (`c2-payload-explorer.ndjson`)
File-first, over the ledger `served_file` rows (default window: last 30 days):
- **Families Over Time** — stacked `date_histogram(ts)` split by `family`
- **Distinct Files by Family** — `cardinality(sha256)` by family
- **File Catalog** — one row per `sha256` with count, distinct C2s, distinct
  sensors, latest seen, family. **Click a sha256 → Filter for value** to see
  every C2/sensor that served that exact artifact (cross-sensor dedupe).
- **Script Source** — `file_kind:script` rows; the `content` column is the
  script itself.

Generator: `build_payload_explorer.py`.

## Regenerate / edit
`build_dash.py` (Command Center) and `build_payload_explorer.py` produce the
importable NDJSON (agg-based visualizations — stable across Kibana 8.x, unlike
hand-authored Lens). Edit, then:
```bash
python build_dash.py            # writes /tmp/c2-dash.ndjson
curl ... _import?overwrite=true --form file=@/tmp/c2-dash.ndjson
# then re-export with includeReferencesDeep to refresh c2-command-center.ndjson
```

## Not yet included
- **Maps (geo_point) layer** — deferred: Kibana Maps saved objects are very
  version-fragile to hand-author, and geo only populates on real attacker IPs
  (test IPs / TEST-NET have no geo). Add via the UI once real C2 geo data flows.
- `family`/`Payloads` panels populate only on real malware downloads
  (`served_file`); test sessions that reference but don't download stay rank-0.
