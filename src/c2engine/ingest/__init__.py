"""Fluent forward in, direct Elasticsearch out.

In:  Forward server receiving ``stingar.enrichable.*`` from central Fluentd.
Out: Session docs -> ``stingar-YYYY-MM-DD``; ledger rows -> ``stingarc2-YYYY-MM-DD``.

Only new sensors emit the enrichable tag family; stock ``stingar.events.*``
sensors keep the unchanged Fluentd -> ES path.
"""

from c2engine.ingest.server import serve

__all__ = ["serve"]
