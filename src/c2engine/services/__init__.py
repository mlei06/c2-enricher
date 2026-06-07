"""The runnable services — three deployables driven by ``c2-engine <cmd>``.

- :mod:`c2engine.services.ingest` — Fluent-forward server, direct ES writer.
- :mod:`c2engine.services.reason` — out-of-band entity rollup + intel + VT.
- :mod:`c2engine.services.feed`   — read-only blocklist/alert HTTP feed.

Each is independent and shares only the pipeline, the model, and the ES client.
"""
