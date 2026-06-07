# Kibana saved objects — C2 dashboards

Two exported, self-contained dashboards (Kibana 8.19), built and verified live
on the STINGAR Kibana (DESIGN.md §7):

| File | Dashboard | Focus |
|---|---|---|
| `c2-command-center.ndjson` | **C2 Command Center** | C2-host-first: map of the threat, click a C2 → its honeypots/src_ips/payloads/sessions |
| `c2-payload-explorer.ndjson` | **Payload Explorer** | file-first: families over time, one row per sha256, cross-sensor dedupe, script source |
| `c2-entity-view.ndjson` | **C2 Entity View** (M5) | reason-layer-first: staged/decaying entities (`c2-entities`) — stage, signals, family rollup, VT ratio, ASN — click a C2 → its served files / scanners / sensors |
| `c2-geo-map.ndjson` | **C2 — Geo** (M5, Maps app) | world map: one point per active C2 (`c2_geo`), fill-colored by final `stage` (red stage2 / amber stage1 / grey unconfirmed). Import the Entity View first (it bundles the `c2-entities` data view this references) |

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

## C2 Entity View (`c2-entity-view.ndjson`, M5)
The first surface for the **reason layer's output** — the `c2-entities` decaying
view (default window: last 30 days, on `last_seen`). Self-contained: bundles the
`c2-entities` (timeField `last_seen`) and `c2-ledger` (`stingarc2-*`) data views.

- **Confirmed C2s (stage2)** — metric, `stage:stage2_c2`.
- **By Stage / Stage Signals / Families (entity rollup) / Top ASN Orgs** —
  terms over `c2-entities` (`stage`, `stage_signals`, `families`,
  `latest.c2_asn_org`).
- **Active C2 Entities** — one row per C2 with stage, signals, families,
  `max_evidence_rank`, `max_vt_ratio`, counts, ASN, `last_seen`. **Click a
  `c2_host` → Filter for value** to pin the **detail page**.
- The pinned `c2_host:X` filter also drives the ledger drill-down panels —
  **Served Files** (sha/family/size/magic), **Scanners (src_ip)**, **Honeypots
  Hit** — because `c2_host` is shared across `c2-entities` and `stingarc2-*`.
  That single click is GreyNoise's "callback detail" page: the entity's verdict
  plus everything it did.

Generator: `build_entity_view.py`.

## Regenerate / edit
`build_dash.py` (Command Center) and `build_payload_explorer.py` produce the
importable NDJSON (agg-based visualizations — stable across Kibana 8.x, unlike
hand-authored Lens). Edit, then:
```bash
python build_dash.py            # writes /tmp/c2-dash.ndjson
curl ... _import?overwrite=true --form file=@/tmp/c2-dash.ndjson
# then re-export with includeReferencesDeep to refresh c2-command-center.ndjson
```

## C2 — Geo (`c2-geo-map.ndjson`, M5)
The GreyNoise-style world map of active C2 infrastructure: a Maps-app object
with an EMS basemap + a documents layer over `c2-entities` (`c2_geo`), point
fill **categorical on the final `stage`** (red `stage2_c2` / amber
`stage1_serving` / grey `unconfirmed`); tooltip carries host / stage / signals /
families / ASN / last_seen. Because the entity index decays, the map is
self-cleaning — dots vanish ~30 d after a C2 goes quiet.

- **Hand-authored against Kibana 8.19** (generator `build_geo_map.py`). Maps
  `layerListJSON` is version-fluid — if a Kibana upgrade breaks it, re-author in
  the Maps UI and re-export (the data needs nothing new).
- **Geo data**: ledger rows geo-locate at enrich time; entities take the
  attack-time `geo_centroid`, with a **reason-job fallback** that locates the
  host *now* when older rows predate the City-db fix. The engine image ships
  **DB-IP City Lite** (CC BY 4.0 — *IP geolocation by [DB-IP](https://db-ip.com)*)
  because the only City db in the STINGAR fluentd image is the geoip gem's
  2017 copy, which misses post-2017 IP allocations entirely.
- Import order: `c2-entity-view.ndjson` first (bundles the `c2-entities` data
  view), then this.

## Not yet included (M5 remainder — deferred with rationale)
- **Family classifier upgrade** — data-gated: the current rules cover what our
  captures show. Harvesting new markers / adding YARA needs a real malware
  corpus; our served test files are synthetic (VT has no record of them), so
  there's nothing to harvest yet. Revisit as real `served_file` volume grows.
- `family`/`Payloads` panels populate only on real malware downloads
  (`served_file`); test sessions that reference but don't download stay rank-0.
