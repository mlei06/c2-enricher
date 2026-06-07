"""Shared Elasticsearch infrastructure — the client and the index schema.

Used by every service: the ingest server writes session/ledger docs, the reason
job upserts entities + the VT cache, and the feed reads the entity index. Lives
outside ``services/`` precisely because it is shared (it is not "ingest").

- :mod:`c2engine.elastic.client` — :class:`EsWriter` (thin urllib client).
- :mod:`c2engine.elastic.schema` — index templates, ILM, index names, retention.
"""
