# Deployment

c2-engine deploys in two halves:

- **[server.md](server.md)** — the **central STINGAR server**: the full STINGAR
  v2.3 stack plus the c2-engine services (ingest, reason rollup, blocklist
  feed), Elasticsearch, Kibana, and the dashboards. Deploy this **first**.
- **[sensor/README.md](sensor/README.md)** — a **honeypot sensor**: an
  internet-facing host running enrichment-enabled Cowrie that forwards attacker
  sessions to the central server. Deploy one or many, **after** the server is up.

```
   honeypot sensors (many)                      central server (one)
 ┌─────────────────────────┐                ┌──────────────────────────────┐
 │ cowrie-stingar (22/23)   │  Fluent Bit    │ fluentd :24224               │
 │  → in-session capture    │ ─────────────► │  → geo → c2-engine :24230    │
 │ Fluent Bit forwarder     │   :24224       │  → Elasticsearch (stingar-*  │
 └─────────────────────────┘   FLUENTD_KEY   │      / stingarc2-*)          │
        sensor/README.md                     │  → reason rollup → c2-entities│
                                             │  → Kibana dashboards, c2feed  │
                                             └──────────────────────────────┘
                                                      server.md
```

The two are joined by one shared secret (`FLUENTD_KEY`) and the server's FQDN.
Stock STINGAR sensors are untouched and keep working alongside c2 sensors — see
the tag-routing table in [server.md](server.md).

## Order of operations

1. **Server** — bring up the central stack and import the dashboards
   ([server.md](server.md)). Note its FQDN and `FLUENTD_KEY`, and make sure
   Fluentd `:24224` is reachable from where your sensors will live.
2. **Sensors** — point each honeypot host at that FQDN/key
   ([sensor/README.md](sensor/README.md)). Verify each one registers in the
   STINGAR sensor list.

## What's in this directory

| Path | For | Purpose |
|------|-----|---------|
| `server.md` | server | central STINGAR + c2-engine deployment guide |
| `sensor/README.md` | sensor | honeypot host deployment guide (host-agnostic) |
| `docker-compose.yml` | server | full STINGAR v2.3 stack + c2-engine services |
| `docker-compose.overlay.yml` | server | add c2-engine to an existing STINGAR install |
| `fluent.conf` | server | Fluentd config (stock path + enrichable hop) |
| `stingar.env.example` | server | central env template |
| `sensor/docker-compose.yml` | sensor | honeypot stack (cowrie-stingar + fluentbit) |
| `sensor/stingar-hp.env.example` | sensor | sensor env template |

For the design rationale see [../docs/DESIGN.md](../docs/DESIGN.md); for the
honeypot image internals see [../sensor/README.md](../sensor/README.md).
