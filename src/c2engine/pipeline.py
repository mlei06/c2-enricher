"""The pipeline: one inbound session doc -> enriched session + ledger rows.

Shared by the offline CLI (milestone 2) and the Fluent forward server
(milestone 3). Pure except for the optional GeoEnricher it is handed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from c2engine.enrich.geo import GeoEnricher
from c2engine.enrich.session import enrich_session
from c2engine.extract import all_observations
from c2engine.model import C2Observation, SessionIn

#: Inbound tag from new sensors (output_stingar on the cowrie fork).
TAG_INBOUND = "stingar.enrichable.cowrie"

#: ES index prefixes (logstash_format, daily rotation) — written by ingest/es.py.
INDEX_SESSION = "stingar"
INDEX_C2 = "stingar-c2"


@dataclass
class Enriched:
    """One processed session: the doc to re-emit plus its ledger rows."""

    session_doc: dict[str, Any]
    observations: list[C2Observation]

    def envelopes(self) -> list[tuple[str, dict[str, Any]]]:
        """(index_prefix, record) pairs — for offline replay / backfill tooling."""
        out: list[tuple[str, dict[str, Any]]] = [(INDEX_SESSION, self.session_doc)]
        out.extend(
            (INDEX_C2, o.model_dump(mode="json", exclude_none=True)) for o in self.observations
        )
        return out


def process(raw: dict[str, Any], geo: GeoEnricher | None = None) -> Enriched:
    """Run extract + enrich over one raw session doc.

    On any failure the session is still emitted (bytes stripped, no additive
    fields) and no rows are produced — the engine never blocks the session
    stream (DESIGN.md §8). Callers log the exception.
    """
    session = SessionIn.model_validate(raw)
    observations = all_observations(session)
    if geo is not None and geo.enabled:
        observations = [geo.enrich(o) for o in observations]
    doc = enrich_session(raw, session, observations)
    return Enriched(session_doc=doc, observations=observations)
