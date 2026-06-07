"""Wire Fluent forward ingress to the pipeline and direct ES egress."""

from __future__ import annotations

import copy
import logging
import os
from typing import Any

from c2engine.pipeline.enrich.geo import GeoEnricher
from c2engine.elastic.client import EsWriter
from c2engine.services.ingest.forward import ForwardServer
from c2engine.pipeline import TAG_INBOUND, process

log = logging.getLogger(__name__)


def _strip_bytes(raw: dict[str, Any]) -> dict[str, Any]:
    """Drop transport-only inlined bytes. Defensive: the fallback path runs on
    records that already failed validation, so hp_data/files may be malformed."""
    doc = copy.deepcopy(raw)
    hp = doc.get("hp_data")
    if isinstance(hp, dict):
        for f in hp.get("files") or ():
            if isinstance(f, dict):
                f.pop("content_b64", None)
    return doc


def _handle_record(
    tag: str,
    record: dict[str, Any],
    *,
    geo: GeoEnricher,
    es: EsWriter,
) -> None:
    """Process one record.

    ES failures PROPAGATE (the forward handler then skips the ack, so Fluentd
    retries the chunk — at-least-once). Enrichment failures degrade to a
    stripped session that is still written, so a poison record doesn't wedge
    the chunk in an infinite retry loop.
    """
    if not tag.startswith("stingar.enrichable."):
        log.debug("ignoring non-enrichable tag %s", tag)
        return

    # Enrichment is best-effort: a bad record falls back to a stripped session.
    try:
        enriched = process(record, geo)
        session_doc = enriched.session_doc
        rows = [o.model_dump(mode="json", exclude_none=True) for o in enriched.observations]
    except Exception:
        log.exception("enrichment failed for %s — writing stripped session", tag)
        session_doc, rows = _strip_bytes(record), []

    # ES writes are deliberately NOT guarded: if ES is down, EsWriter raises
    # after its retries, the exception reaches the forward handler, the frame
    # is not acked, and Fluentd resends the chunk.
    es.write_session(session_doc, source_tag=tag)
    if rows:
        es.write_observations(rows, source_tag=tag)
    hp = session_doc.get("hp_data")
    sensor = session_doc.get("sensor")
    log.info(
        "enriched session %s from %s: +%d ledger rows",
        hp.get("session", "?") if isinstance(hp, dict) else "?",
        sensor.get("hostname", "?") if isinstance(sensor, dict) else "?",
        len(rows),
    )


def serve() -> None:
    host = os.environ.get("C2E_LISTEN_HOST", "0.0.0.0")
    port = int(os.environ.get("C2E_LISTEN_PORT", "24230"))
    geo = GeoEnricher()
    es = EsWriter()

    # Install ILM policy + index template before accepting traffic, so the very
    # first ledger write lands in a correctly-mapped (geo_point) index.
    es.ensure_bootstrap()

    if not geo.enabled:
        log.warning("MaxMind unavailable — C2 ledger rows will lack geo fields")

    def on_record(tag: str, record: dict[str, Any]) -> None:
        _handle_record(tag, record, geo=geo, es=es)

    server = ForwardServer(host, port, on_record)
    log.info("c2-engine ready on :%s (out=ES direct, expect tag %s)", port, TAG_INBOUND)
    server.serve_forever()
