# STINGAR central server deployment

The central stack: the full STINGAR v2.3 services (Elasticsearch, Kibana,
Fluentd, the STINGAR UI/API, redis, nginx) **plus** the c2-engine services
(`c2engine` ingest, `c2reason` rollup, `c2feed` blocklist). Sensors forward
here; this is where enrichment, the entity rollup, and the dashboards live.

This is a **drop-in**: stock sensors are untouched. Legacy sensors keep emitting
`stingar.events.cowrie` and Fluentd writes them to `stingar-*` as today. Only
**new sensors** (updated `output_stingar` plugin) emit
`stingar.enrichable.cowrie`; Fluentd forwards those to c2-engine, which writes
directly to Elasticsearch. Both generations run side-by-side.

For the honeypot side see [sensor/README.md](sensor/README.md); for the
top-level orientation see [README.md](README.md).

## Quick start

```bash
cd deploy

# 1. Configure environment (fill every CHANGEME — secrets + hostnames)
cp stingar.env.example stingar.env
$EDITOR stingar.env

# 2. TLS certs + nginx config (from your STINGAR install)
#    certs/     — TLS material for the web front-end
#    nginx.conf — reverse-proxy config

# 3. Build and start
docker compose up -d --build
```

The `stingarc2` ILM policy + index template (and the `c2-entities` / `c2-vt` /
`c2-intel` templates) are installed **automatically** by c2-engine on startup
(`EsWriter.ensure_bootstrap`, idempotent), so the `geo_point`/`ip` mappings
exist before the first write — no manual step. To seed the ledger template by
hand (e.g. before the engine first runs):

```bash
curl -X PUT "http://localhost:9200/_ilm/policy/stingarc2" \
  -H 'Content-Type: application/json' -d @../es/ilm/stingarc2-policy.json
curl -X PUT "http://localhost:9200/_index_template/stingarc2" \
  -H 'Content-Type: application/json' -d @../es/templates/stingarc2.json
```

## Let sensors reach you

Sensors forward to **Fluentd on `:24224`** authenticated by the shared
`FLUENTD_KEY` in `stingar.env`. For remote sensors to connect, that port must be
reachable from them — publish it on the host (the stack already maps `24224`)
**and** open it in any cloud security group / network firewall in front of the
server. Each sensor's `FLUENTD_KEY` must equal this stack's `FLUENTD_KEY`, and
its `FLUENTD_HOST` must match this server's `FLUENTD_REMOTE_HOST` / `UI_HOSTNAME`.

## Tag routing (drop-in)

| Sensor generation | Cowrie emits | Fluentd path | Lands in |
|-------------------|--------------|--------------|----------|
| **Stock** | `stingar.events.cowrie` | geo → ES (unchanged) | `stingar-*` |
| **New (c2)** | `stingar.enrichable.cowrie` | geo → c2-engine → ES | `stingar-*` + `stingarc2-*` |

## Data flow (new sensors only)

```
Cowrie output_stingar  →  tag stingar.enrichable.cowrie
Sensor Fluent Bit      →  fluentd :24224
fluentd geo filters    →  match stingar.enrichable.*
c2-engine :24230       →  enrich → ES stingar-* / stingarc2-*
```

If c2-engine is down, fluentd buffers enrichable events and retries — they
delay, never drop (DESIGN.md §8).

## Dashboards + data views

The Kibana saved objects live in [`../es/dashboards/`](../es/dashboards/). Import
them once the stack is up (Kibana under its `basePath`, often `/kibana`):

```bash
for f in c2-command-center c2-payload-explorer c2-entity-view c2-intel; do
  curl -s -X POST "<kibana>/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" --form file=@../es/dashboards/$f.ndjson
done
```

This installs the three dashboards (Command Center, Payload Explorer, Entity
View — the geo map is bundled inside Entity View) and their data views, plus the
`c2-intel` data view for browsing the abuse.ch IOC cache. See
[../es/dashboards/README.md](../es/dashboards/README.md) for the panel layout and
the pivot model.

## VirusTotal enrichment (M3, optional)

The reason job can enrich served-file hashes with VirusTotal verdicts. It's
**off by default** — set `VT_API_KEY` (in `stingar.env` or the host env) to
enable it:

```bash
echo 'VT_API_KEY=<your-vt-key>' >> stingar.env
docker compose up -d c2reason
```

Verdicts cache fleet-wide in the `c2-vt` index (one lookup per distinct file
until it goes stale at 30 d), so a single key easily covers the fleet. With a
**public** key keep `C2E_VT_MAX_PER_RUN<=4` (matches VT's 4 req/min; the job
sleeps 5 min between runs). A file with `vt_malicious >= C2E_VT_MIN_MALICIOUS`
(default 1) adds a `virustotal` signal to its C2 and the entity gains
`max_vt_ratio` + `vt_families`. VT is **enrichment, not a classifier** — it never
changes `stage` (the evidence ladder alone sets it; GreyNoise model). VT being
slow/over-budget never blocks — the verdict just fills in on a later pass.

## abuse.ch intel feeds (M6, optional)

The reason job can corroborate entities against the **ThreatFox / URLhaus /
Feodo Tracker** `recent` exports. **Off by default** — abuse.ch needs a free
Auth-Key (get one at https://auth.abuse.ch/):

```bash
echo 'ABUSECH_AUTH_KEY=<your-abusech-key>' >> stingar.env
docker compose up -d c2reason
```

The feeds bulk-download on a TTL (`C2E_INTEL_TTL_HOURS`, default 12) into the
`c2-intel` cache and are matched locally against each entity's `c2_host` /
`c2_resolved_ip` / `c2_url` / `sha256` — so there's no per-host rate limit, just
the periodic download. A match adds the feed's name to `stage_signals`
(`threatfox` / `urlhaus` / `feodo`) and records `intel_sources` + `intel_malware`.
Like VT, it's **enrichment only** — it never changes `stage`. Choose feeds with
`C2E_INTEL_FEEDS` (default all three).

## Blocklist / alert feed (M4)

The `c2feed` service serves a read-only feed over the decaying `c2-entities`
view on `:8088` (bound to localhost on the host by default). It's always-fresh
by construction — the entity index already decays ~30 d after `last_seen`, and
the feed window narrows further.

```bash
# active C2 IPs, one per line (firewalls/SIEMs pull this)
curl localhost:8088/feed/blocklist.txt

# only stage-2 (referenced inside captured malware) C2s seen in the last 3 days
curl 'localhost:8088/feed/blocklist.txt?stage=2&window=3d'

# full entity summaries (stage, families, signals, asn_org, ...) incl. domains
curl localhost:8088/feed/c2.json
```

Params: `?stage=1|2` (min `stage` — set by the evidence ladder; intel annotates
but never raises it), `?window=<int>[smhd]` (default `7d`), `?limit=N` (≤10000).
For off-box pulls, widen the port mapping or add an nginx route.

## Layout

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Full STINGAR v2.3 stack + `c2engine` / `c2reason` / `c2feed` |
| `docker-compose.overlay.yml` | Overlay for **existing** installs — adds only the c2-engine services |
| `fluent.conf` | Stock `stingar.events.*` path + the enrichable hop |
| `stingar.env.example` | Server env template — copy to `stingar.env`, fill CHANGEME |

Geo databases in the c2-engine image: the **ASN** db is copied from
`4warned/fluentd:v2.3` at build time, but the **City** db is fetched fresh from
**DB-IP City Lite** (CC BY 4.0 — *IP geolocation by [DB-IP](https://db-ip.com)*),
because the only City db the fluentd image ships is the geoip gem's 2017 copy,
which misses post-2017 IP allocations (verified live). Bump the `DBIP_MONTH`
build arg when rebuilding much later.

## Adding c2-engine to an existing STINGAR install

`docker-compose.overlay.yml` adds only the `c2engine` / `c2reason` / `c2feed`
services to a stack you already run. Mount `deploy/fluent.conf` over the stock
fluentd config (it carries both the stock `stingar.events.*` path and the
enrichable hop), then `docker compose -f docker-compose.yml -f
docker-compose.overlay.yml up -d`. On the sensor side, deploy the updated
`sensor/stingar.py` to new honeypots so they emit `enrichable.cowrie`; stock
forks without the change stay on the legacy path automatically.
