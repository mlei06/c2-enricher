# c2-engine

Central **command-and-control (C2) detection** engine for a STINGAR/Cowrie
honeypot fleet, modeled on [GreyNoise's C2 Detection](https://www.greynoise.io/blog/introducing-c2-detection).

Drop-in on the STINGAR server: new sensors emit `stingar.enrichable.cowrie`,
Fluentd forwards only those to c2-engine, which writes enriched sessions plus an
append-only **C2 evidence ledger** (`stingarc2-*`) directly to Elasticsearch.
Stock sensors keep the unchanged `stingar.events.*` path, so the two run
side-by-side. An out-of-band reason job rolls the ledger up into a decaying
per-C2 entity view (`c2-entities`) with intel/VirusTotal staging, and a feed
service serves a fresh blocklist.

**Start with [docs/DESIGN.md](docs/DESIGN.md)** — the founding design document
(architecture, data contracts, evidence/stage model, dashboards, decision
record). [docs/DESIGN_PARITY.md](docs/DESIGN_PARITY.md) tracks the
GreyNoise-parity milestones; [docs/DESIGN_AGENT.md](docs/DESIGN_AGENT.md) covers
the planned analyst chat agent.

## Pipeline

```
new sensor → stingar.enrichable.cowrie → central Fluentd → c2-engine (ingest)
                                                               │ enrich + extract evidence
                                                               ▼
                          stingar-* (enriched sessions)  +  stingarc2-* (C2 evidence ledger)
                                                               │ reason job (out-of-band)
                                                               ▼
                                            c2-entities (decaying per-C2 view, staged)
                                                               │ feed
                                                               ▼
                                              GET /feed/blocklist.txt   (fresh C2 IPs)
```

## Layout

```
src/c2engine/
├── model/        pydantic wire contracts — SessionIn (input), C2Observation (ledger row)
├── analyze/      session-content parsers: iocs, banner, credentials, shape (hassh),
│                 shell, canonical (playbook hash) — shared by the whole pipeline
├── pipeline/     one session → enriched doc + ledger rows
│   ├── extract/  evidence rows: hosts.py (shell_reference), files.py (served_file),
│   │             chains.py (file_callback)
│   └── enrich/   geo.py (MaxMind), family.py (rules), session.py (additive fields)
├── elastic/      shared ES infra — client.py (EsWriter), schema.py (templates/ILM/names)
├── services/     the three runnable deployables
│   ├── ingest/   Fluent forward server in → direct ES out
│   ├── reason/   entity rollup + intel staging + VirusTotal (out-of-band)
│   └── feed/     blocklist/alert HTTP feed over c2-entities
└── cli.py        subcommands: replay · serve · reason · feed
es/               index template, ILM policy, Kibana dashboard exports
deploy/           STINGAR + c2-engine compose, fluent.conf, env template
sensor/           cowrie fork + STINGAR overlay (the honeypot build)
tests/            golden session fixtures → expected evidence rows
```

## Commands

```bash
c2-engine serve     # Fluent-forward ingest server (:24230) → ES
c2-engine reason    # rebuild c2-entities rollup + intel/VT overlay (--interval N to loop)
c2-engine feed      # blocklist/alert HTTP feed (:8088) over c2-entities
c2-engine replay session.ndjson[.gz]   # offline pipeline / backfill → evidence NDJSON
```

## Development

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,geo]'
pytest          # unit tests
ruff check src tests
mypy src/c2engine
```

## Deployment & sensor

See [deploy/README.md](deploy/README.md) for the compose stack (ingest + reason
+ feed services, Fluentd routing, the M3 VirusTotal and M4 blocklist setup) and
`sensor/` for the cowrie fork + STINGAR overlay that produces the enrichable
session docs.

## License

c2-engine is released under the MIT License ([LICENSE](LICENSE)). The vendored
`sensor/cowrie/` subtree retains its own upstream licenses (BSD-3-Clause, plus
FoxIO-1.1 for the bundled ja4 code) — see [NOTICE](NOTICE).
