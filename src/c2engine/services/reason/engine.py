"""Compute the C2 entity index: rollup (from the ledger) + intel overlay.

One composite aggregation over ``stingarc2-*`` grouped by ``c2_host`` (restricted
to the retention window) yields the rollup; the overlay adds signals, families,
and toolkit attribution (stage stays evidence-derived — intel never raises it).
Each entity is upserted with ``_id = c2_host``; entities
whose last sighting fell out of the window are deleted (decay).
"""

from __future__ import annotations

import datetime
import importlib.resources
import json
import logging
import os
import time
from typing import Any

from c2engine.elastic.client import EsWriter
from c2engine.elastic.schema import ENTITIES_INDEX, ENTITY_RETENTION_DAYS
from c2engine.pipeline.enrich.geo import GeoEnricher
from c2engine.services.reason.intel import IntelMatcher, apply_intel
from c2engine.services.reason.vt import (
    DEFAULT_MIN_MALICIOUS,
    VtResolver,
    apply_vt,
    summarize_vt,
)

log = logging.getLogger(__name__)

REASON_VERSION = "r1"
LEDGER = "stingarc2-*"
_KW = ("c2_host_kind", "c2_country", "c2_asn_org")  # latest-by-ts keyword fields


def _rank_to_stage(rank: int) -> str:
    return "stage2_c2" if rank >= 2 else "stage1_serving" if rank == 1 else "unconfirmed"


def _load_json(name: str) -> Any:
    return json.loads((importlib.resources.files("c2engine.services.reason.data") / name).read_text())


def load_known_shas() -> set[str]:
    return {s.lower() for s in _load_json("known_sha.json")}


def load_hassh_toolkits() -> dict[str, str]:
    """HASSH (lowercased) -> attacker toolkit name."""
    return {k.lower(): v for k, v in _load_json("hassh_toolkits.json").items()}


def compute_overlay(
    max_rank: int,
    families: list[str],
    shas: list[str],
    known_shas: set[str],
    hasshes: list[str] | None = None,
    hassh_toolkits: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Stage + signals + families (+ toolkit attribution). `stage` is derived
    SOLELY from the evidence ladder (max evidence_rank). Intel adds
    `stage_signals` and descriptive fields but never moves the stage — the
    GreyNoise model: the evidence we observed sets the stage; known-malware /
    VirusTotal / HASSH are third-party corroboration (signals), not classifiers."""
    signals: list[str] = []
    stage = _rank_to_stage(max_rank)
    if max_rank >= 2:
        signals.append("callback_in_malware")
    if {s.lower() for s in shas} & known_shas:
        signals.append("known_malware")  # annotate only; does not raise stage
    overlay: dict[str, Any] = {
        "stage": stage,
        "stage_signals": sorted(signals),
        "families": sorted({f for f in families if f}),
    }
    toolkits = sorted(
        {tk for h in (hasshes or []) if (tk := (hassh_toolkits or {}).get(h.lower()))}
    )
    if toolkits:
        overlay["attributed_toolkit"] = toolkits
        overlay["stage_signals"] = sorted(set(overlay["stage_signals"]) | {"hassh_toolkit"})
    return overlay


def run_once(
    es: EsWriter,
    now: datetime.datetime | None = None,
    *,
    geo: GeoEnricher | None = None,
    intel: IntelMatcher | None = None,
) -> int:
    now = now or datetime.datetime.now(datetime.UTC)
    nowiso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    since = (now - datetime.timedelta(days=ENTITY_RETENTION_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    known = load_known_shas()
    hassh_toolkits = load_hassh_toolkits()
    # VT (M3): cache-first, budget-bounded, no-op without VT_API_KEY. One resolver
    # per pass so the per-run lookup budget is shared across all entities.
    vt = VtResolver(es, now=now)
    # Entity-geo fallback (M5 map): graceful no-op without mmdbs.
    geo = geo if geo is not None else GeoEnricher()
    # abuse.ch intel feeds (M6): cache-first, TTL-refreshed, no-op without
    # ABUSECH_AUTH_KEY. Refresh once per pass; matches are local set lookups.
    intel = intel if intel is not None else IntelMatcher(es, now=now)
    intel.refresh(now=now)
    try:
        min_mal = int(os.environ.get("C2E_VT_MIN_MALICIOUS", str(DEFAULT_MIN_MALICIOUS)))
    except ValueError:
        min_mal = DEFAULT_MIN_MALICIOUS

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
                "hasshes": {"terms": {"field": "hassh", "size": 50}},
                "urls": {"terms": {"field": "c2_url", "size": 50}},
                "resolved_ips": {"terms": {"field": "c2_resolved_ip", "size": 50}},
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
            hasshes = [x["key"] for x in b["hasshes"]["buckets"]]
            urls = [x["key"] for x in b["urls"]["buckets"]]
            resolved_ips = [x["key"] for x in b["resolved_ips"]["buckets"]]
            metrics = (b["latest"]["top"][0]["metrics"] if b["latest"]["top"] else {})
            overlay = compute_overlay(max_rank, fams, shas, known, hasshes, hassh_toolkits)
            overlay = apply_vt(overlay, summarize_vt(vt.verdicts_for(shas)), min_mal)
            overlay = apply_intel(overlay, intel.match(
                host=host, resolved_ips=resolved_ips, urls=urls, shas=shas))
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
                **overlay,
            }
            if b["asn"]["value"] is not None:
                doc["c2_asn"] = int(b["asn"]["value"])
            if b["geo"].get("location"):
                doc["c2_geo"] = b["geo"]["location"]  # {"lat":.., "lon":..}
            elif geo.enabled:
                # Current-location fallback: rows written while the City db was
                # stale (or before geo shipped) carry no c2_geo, so the
                # attack-time centroid is empty. Locate the host NOW instead —
                # for "active C2 infrastructure" current geo is the right
                # semantic anyway. Centroid still wins when present.
                found = geo.locate(host)
                if "c2_geo" in found:
                    doc["c2_geo"] = found["c2_geo"]
                    if found.get("c2_country") and "c2_country" not in doc["latest"]:
                        doc["latest"]["c2_country"] = found["c2_country"]
            es.index_doc(ENTITIES_INDEX, host, doc)
            updated += 1
        after = agg.get("after_key")
        if not after:
            break

    expired = es.delete_by_query(ENTITIES_INDEX, {"query": {"range": {"last_seen": {"lt": since}}}})
    log.info("reason: %d entities upserted, %d expired (known-malware shas: %d, "
             "hassh toolkits: %d, vt lookups: %d, vt enabled: %s, intel enabled: %s, "
             "intel refreshed: %s)",
             updated, expired, len(known), len(hassh_toolkits), vt.looked_up,
             vt.client.enabled, intel.enabled, intel.refreshed or "-")
    return updated


def run(interval: int | None = None) -> None:
    es = EsWriter()
    es.ensure_bootstrap()  # entity index template must exist before first write
    # Built once and reused across passes: the GeoEnricher holds open mmdb
    # readers (reopening every pass churns file handles) and the IntelMatcher
    # keeps its IOC indexes in memory between TTL refreshes.
    geo = GeoEnricher()
    intel = IntelMatcher(es)
    while True:
        try:
            run_once(es, geo=geo, intel=intel)
        except Exception:  # noqa: BLE001 - a pass failing must not kill the loop
            log.exception("reason pass failed")
        if not interval:
            break
        time.sleep(interval)
