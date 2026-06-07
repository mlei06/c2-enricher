# STINGAR + c2-engine deployment

Drop-in central server stack. **Stock sensors are untouched**: legacy sensors
keep emitting `stingar.events.cowrie` and Fluentd writes them to `stingar-*`
as today. Only **new sensors** (updated `output_stingar` plugin) emit
`stingar.enrichable.cowrie`; Fluentd forwards those to c2-engine, which writes
directly to Elasticsearch.

## Quick start

```bash
cd deploy

# 1. Configure environment (edit secrets and hostnames)
cp env.txt stingar.env
$EDITOR stingar.env

# 2. TLS certs + nginx config (from your STINGAR install)
#    certs/     — TLS material for the web front-end
#    nginx.conf — reverse-proxy config

# 3. Build and start
docker compose up -d --build
```

The `stingarc2` ILM policy + index template are installed **automatically** by
c2-engine on startup (`EsWriter.ensure_bootstrap`, idempotent), so the
`geo_point`/`ip` mappings exist before the first ledger write — no manual step.
To seed them by hand (e.g. before the engine first runs):

```bash
curl -X PUT "http://localhost:9200/_ilm/policy/stingarc2" \
  -H 'Content-Type: application/json' -d @../es/ilm/stingarc2-policy.json
curl -X PUT "http://localhost:9200/_index_template/stingarc2" \
  -H 'Content-Type: application/json' -d @../es/templates/stingarc2.json
```

## Tag routing (drop-in)

| Sensor generation | Cowrie emits | Fluentd path | Lands in |
|-------------------|--------------|--------------|----------|
| **Stock** | `stingar.events.cowrie` | geo → ES (unchanged) | `stingar-*` |
| **New (c2)** | `stingar.enrichable.cowrie` | geo → c2-engine → ES | `stingar-*` + `stingarc2-*` |

Both generations can run side-by-side on the same central server.

## Data flow (new sensors only)

```
Cowrie output_stingar  →  tag stingar.enrichable.cowrie
Sensor Fluent Bit      →  fluentd :24224
fluentd geo filters    →  match stingar.enrichable.*
c2-engine :24230       →  enrich → ES stingar-* / stingarc2-*
```

If c2-engine is down, fluentd buffers enrichable events and retries — they
delay, never drop (DESIGN.md §8).

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
(default 1) escalates its C2 to `stage2_c2` with a `virustotal` signal; entities
gain `max_vt_ratio` + `vt_families`. VT being slow/over-budget never blocks —
the verdict just fills in on a later pass.

## Blocklist / alert feed (M4)

The `c2feed` service serves a read-only feed over the decaying `c2-entities`
view on `:8088` (bound to localhost on the host by default). It's always-fresh
by construction — the entity index already decays ~30 d after `last_seen`, and
the feed window narrows further.

```bash
# active C2 IPs, one per line (firewalls/SIEMs pull this)
curl localhost:8088/feed/blocklist.txt

# only stage-2 (intel-confirmed) C2s seen in the last 3 days
curl 'localhost:8088/feed/blocklist.txt?stage=2&window=3d'

# full entity summaries (stage, families, signals, asn_org, ...) incl. domains
curl localhost:8088/feed/c2.json
```

Params: `?stage=1|2` (min **final** stage — the intel-escalated `stage`, not raw
evidence rank), `?window=<int>[smhd]` (default `7d`), `?limit=N` (≤10000). For
off-box pulls, widen the port mapping or add an nginx route.

## Layout

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Full STINGAR v2.3 stack + `c2engine` / `c2reason` / `c2feed` |
| `fluent.conf` | Stock `stingar.events.*` path + enrichable hop |
| `env.txt` | Environment template — copy to `stingar.env` |
| `fluentd/c2-engine.conf` | Enrichable-hop snippet for manual merges |

Geo databases in the c2-engine image: the **ASN** db is copied from
`4warned/fluentd:v2.3` at build time, but the **City** db is fetched fresh from
**DB-IP City Lite** (CC BY 4.0 — *IP geolocation by [DB-IP](https://db-ip.com)*),
because the only City db the fluentd image ships is the geoip gem's 2017 copy,
which misses post-2017 IP allocations (verified live). Bump the `DBIP_MONTH`
build arg when rebuilding much later.

## Sensor-side change

Deploy the updated `sensor/stingar.py` on new honeypots. It emits
`enrichable.cowrie` instead of `events.cowrie`. Stock cowrie forks without
this change continue on the legacy path automatically.

## Overlay (existing installs)

`docker-compose.overlay.yml` adds only the `c2engine` service. Mount
`deploy/fluent.conf` over the stock fluentd config (or merge
`fluentd/c2-engine.conf` into your existing file).
