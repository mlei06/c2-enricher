"""Compute the C2 entity index: rollup (from the ledger) + intel overlay.

One composite aggregation over ``stingarc2-*`` grouped by ``c2_host`` (restricted
to the retention window) yields the rollup; the overlay adds stage escalation,
families, and signals. Each entity is upserted with ``_id = c2_host``; entities
whose last sighting fell out of the window are deleted (decay).
"""

from __future__ import annotations

import datetime
import importlib.resources
import json
import logging
import time
from typing import Any

from c2engine.ingest.es import EsWriter
from c2engine.ingest.es_assets import ENTITIES_INDEX, ENTITY_RETENTION_DAYS

log = logging.getLogger(__name__)

REASON_VERSION = "r1"
LEDGER = "stingarc2-*"
_KW = ("c2_host_kind", "c2_country", "c2_asn_org")  # latest-by-ts keyword fields


def _rank_to_stage(rank: int) -> str:
    return "stage2_c2" if rank >= 2 else "stage1_serving" if rank == 1 else "unconfirmed"


def _load_json(name: str) -> Any:
    return json.loads((importlib.resources.files("c2engine.reason.data") / name).read_text())


def load_known_shas() -> set[str]:
    return {s.lower() for s in _load_json("known_sha.json")}


def compute_overlay(
    max_rank: int, families: list[str], shas: list[str], known_shas: set[str]
) -> dict[str, Any]:
    """Stage + signals + families. `stage` is the evidence floor, escalated by
    intel; reason never demotes below the evidence rank."""
    signals: list[str] = []
    stage = _rank_to_stage(max_rank)
    if max_rank >= 2:
        signals.append("callback_in_malware")
    if {s.lower() for s in shas} & known_shas:
        signals.append("known_malware")
        stage = "stage2_c2"  # escalate
    return {
        "stage": stage,
        "stage_signals": sorted(signals),
        "families": sorted({f for f in families if f}),
    }


def run_once(es: EsWriter, now: datetime.datetime | None = None) -> int:
    now = now or datetime.datetime.now(datetime.UTC)
    nowiso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    since = (now - datetime.timedelta(days=ENTITY_RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    known = load_known_shas()

    updated = 0
    after: dict[str, Any] | None = None
    while True:
        comp: dict[str, Any] = {"size": 500, "sources": [{"c2_host": {"terms": {"field": "c2_host"}}}]}
        if after:
            comp["after"] = after
        body = {
            "size": 0,
            "query": {"range": {"ts": {"gte": since}}},
            "aggs": {"hosts": {"composite": comp, "aggregations": {
                "first_seen": {"min": {"field": "ts"}},
                "last_seen": {"max": {"field": "ts"}},
                "sensor_count": {"cardinality": {"field": "sensor_hostname"}},
                "src_ip_count": {"cardinality": {"field": "src_ip"}},
                "distinct_files": {"cardinality": {"field": "sha256"}},
                "max_rank": {"max": {"field": "evidence_rank"}},
                "asn": {"max": {"field": "c2_asn"}},
                "geo": {"geo_centroid": {"field": "c2_geo"}},
                "families": {"terms": {"field": "family", "size": 25}},
                "shas": {"terms": {"field": "sha256", "size": 200}},
                "latest": {"top_metrics": {
                    "metrics": [{"field": f} for f in _KW], "sort": [{"ts": "desc"}]}},
            }}},
        }
        agg = es.search(LEDGER, body)["aggregations"]["hosts"]
        buckets = agg.get("buckets", [])
        if not buckets:
            break
        for b in buckets:
            host = b["key"]["c2_host"]
            max_rank = int(b["max_rank"]["value"] or 0)
            fams = [x["key"] for x in b["families"]["buckets"]]
            shas = [x["key"] for x in b["shas"]["buckets"]]
            metrics = (b["latest"]["top"][0]["metrics"] if b["latest"]["top"] else {})
            doc: dict[str, Any] = {
                "c2_host": host,
                "first_seen": b["first_seen"]["value_as_string"],
                "last_seen": b["last_seen"]["value_as_string"],
                "sighting_count": b["doc_count"],
                "sensor_count": int(b["sensor_count"]["value"]),
                "src_ip_count": int(b["src_ip_count"]["value"]),
                "distinct_files": int(b["distinct_files"]["value"]),
                "max_evidence_rank": max_rank,
                "latest": {k: metrics.get(k) for k in _KW if metrics.get(k) is not None},
                "reason_version": REASON_VERSION,
                "updated_at": nowiso,
                **compute_overlay(max_rank, fams, shas, known),
            }
            if b["asn"]["value"] is not None:
                doc["c2_asn"] = int(b["asn"]["value"])
            if b["geo"].get("location"):
                doc["c2_geo"] = b["geo"]["location"]  # {"lat":.., "lon":..}
            es.index_doc(ENTITIES_INDEX, host, doc)
            updated += 1
        after = agg.get("after_key")
        if not after:
            break

    expired = es.delete_by_query(ENTITIES_INDEX, {"query": {"range": {"last_seen": {"lt": since}}}})
    log.info("reason: %d entities upserted, %d expired (known-malware shas: %d)",
             updated, expired, len(known))
    return updated


def run(interval: int | None = None) -> None:
    es = EsWriter()
    es.ensure_bootstrap()  # entity index template must exist before first write
    while True:
        try:
            run_once(es)
        except Exception:  # noqa: BLE001 - a pass failing must not kill the loop
            log.exception("reason pass failed")
        if not interval:
            break
        time.sleep(interval)
