# c2-engine

Central C2-detection engine for a STINGAR/Cowrie honeypot fleet. Drop-in on
the STINGAR server: new sensors emit `stingar.enrichable.cowrie`, Fluentd
forwards only those to c2-engine, which writes enriched sessions and the
append-only C2 evidence ledger (`stingar-c2-*`) directly to Elasticsearch.
Stock sensors keep the unchanged `stingar.events.*` path.

**Read [DESIGN.md](DESIGN.md) first** — it is the founding design document:
architecture, data contracts, evidence/stage model, dashboard specs, and the
decision record (including what is deliberately deferred and why).

## Layout

```
src/c2engine/
├── model/      wire contracts (milestone 1 — implemented)
├── extract/    evidence-row producers          (milestone 2 — skeleton)
├── enrich/     geo / family / session fields   (milestone 2 — skeleton)
├── ingest/     Fluent forward in, direct ES out
└── cli.py      offline replay & backfill       (milestone 2 — skeleton)
es/             index template, ILM policy, dashboard exports
deploy/         full STINGAR + c2-engine compose, fluent.conf, env template
tests/          golden session fixtures → expected evidence rows
```

`reason/` (intel escalation) and the `stingar-c2-entities` rollup are
**phase 2, trigger-gated** — see DESIGN.md §9 before adding either.

## Development

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,geo]'
pytest
```

## Sensor-side counterpart

The cowrie fork (separate repo/workstream) must: inline download bytes into
the session doc (`output_stingar`), record attack-time `c2_resolved_ip`
(`url_fetcher`), and collapse sensor deploys back to STINGAR's stock
2-container compose. See DESIGN.md §5.2.
