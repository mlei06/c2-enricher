"""ES index template + ILM policy for ``stingarc2-*``, as in-package data.

Single source of truth for both the engine's startup bootstrap (ingest/es.py)
and the repo-root ``es/`` copies used by the manual README path. ``geo_point``
and ``ip`` types never dynamic-map, so the template MUST exist before the first
ledger write or the C2 map silently breaks.
"""

from __future__ import annotations

from typing import Any

ILM_POLICY_NAME = "stingarc2"
INDEX_TEMPLATE_NAME = "stingarc2"

# Daily indices (stingarc2-YYYY-MM-DD) are time-named, not rollover-aliased —
# so the policy is delete-only, keyed on index age. A rollover action here would
# need index.lifecycle.rollover_alias (absent on daily indices) and would stall
# ILM with "rollover_alias [null]". (DESIGN.md §2: the ledger is the permanent
# record; "active C2" views are time-filtered at query time.)
ILM_POLICY: dict[str, Any] = {
    "policy": {
        "phases": {
            "hot": {"min_age": "0ms", "actions": {}},
            "delete": {"min_age": "365d", "actions": {"delete": {}}},
        }
    }
}

INDEX_TEMPLATE: dict[str, Any] = {
    "index_patterns": ["stingarc2-*"],
    "priority": 200,
    "template": {
        "settings": {
            "number_of_shards": 1,
            "index.lifecycle.name": ILM_POLICY_NAME,
        },
        "mappings": {
            "dynamic": False,
            "properties": {
                "schema_version": {"type": "keyword"},
                "ts": {"type": "date"},
                "sensor_uuid": {"type": "keyword"},
                "sensor_hostname": {"type": "keyword"},
                "src_ip": {"type": "ip"},
                "session_id": {"type": "keyword"},
                "c2_host": {"type": "keyword"},
                "c2_host_kind": {"type": "keyword"},
                "c2_resolved_ip": {"type": "ip"},
                "c2_url": {"type": "keyword"},
                "c2_port": {"type": "integer"},
                "c2_path": {"type": "keyword"},
                "c2_geo": {"type": "geo_point"},
                "c2_country": {"type": "keyword"},
                "c2_asn": {"type": "long"},
                "c2_asn_org": {"type": "keyword"},
                "evidence": {"type": "keyword"},
                "evidence_rank": {"type": "byte"},
                "self_hosted": {"type": "boolean"},
                "file_kind": {"type": "keyword"},
                "sha256": {"type": "keyword"},
                "sha1": {"type": "keyword"},
                "md5": {"type": "keyword"},
                "size": {"type": "long"},
                "magic": {"type": "keyword"},
                "family": {"type": "keyword"},
                "interpreter": {"type": "keyword"},
                "content": {"type": "text"},
                "content_truncated": {"type": "boolean"},
                "callbacks": {"type": "keyword"},
                "c2_via_sha256": {"type": "keyword"},
                # Parity with stock stingar-* (fluentd include_tag_key).
                "fluentd_tag": {"type": "keyword"},
            },
        },
    },
}


# --- M1: entity rollup (one decaying doc per C2, via ES continuous transform) -

ENTITIES_INDEX = "c2-entities"
ENTITIES_TEMPLATE_NAME = "c2-entities"
TRANSFORM_ID = "c2-entities"

# Dest index for the transform. dynamic:true — the transform controls all writes
# (no untrusted input) and deduces correct types (incl. geo_point); we add the
# `evidence_stage` runtime field (max_evidence_rank -> stage string) and pre-map
# the fields the M2/M3 reason job will overlay so later writes stay typed.
ENTITIES_TEMPLATE: dict[str, Any] = {
    "index_patterns": [ENTITIES_INDEX],
    # `c2-entities` is deliberately OUTSIDE the `stingarc2-*` ledger glob, so no
    # template-priority collision and no transform self-reference to work around.
    "priority": 200,
    "template": {
        "settings": {"number_of_shards": 1},
        "mappings": {
            "dynamic": True,
            "runtime": {
                "evidence_stage": {
                    "type": "keyword",
                    "script": {
                        "source": (
                            "long r = doc['max_evidence_rank'].size()==0 ? -1 "
                            ": doc['max_evidence_rank'].value; "
                            "if (r>=2) emit('stage2_c2'); "
                            "else if (r==1) emit('stage1_serving'); "
                            "else if (r==0) emit('unconfirmed');"
                        )
                    },
                }
            },
            "properties": {
                "c2_host": {"type": "keyword"},
                "first_seen": {"type": "date"},
                "last_seen": {"type": "date"},
                "sighting_count": {"type": "long"},
                "sensor_count": {"type": "long"},
                "src_ip_count": {"type": "long"},
                "distinct_files": {"type": "long"},
                "max_evidence_rank": {"type": "byte"},
                "c2_geo": {"type": "geo_point"},
                "c2_asn": {"type": "long"},
                "latest": {
                    "properties": {
                        "c2_host_kind": {"type": "keyword"},
                        "c2_country": {"type": "keyword"},
                        "c2_asn_org": {"type": "keyword"},
                    }
                },
                # reason-layer overlay (M2/M3) — pre-mapped, written later.
                "stage": {"type": "keyword"},
                "stage_signals": {"type": "keyword"},
                "families": {"type": "keyword"},
                "attributed_toolkit": {"type": "keyword"},
                "reason_version": {"type": "keyword"},
                "max_vt_ratio": {"type": "float"},
                "vt_families": {"type": "keyword"},
            },
        },
    },
}

# Continuous transform: stingarc2-* (events) -> c2-entities (decaying view).
# top_metrics can't take geo_point, so c2_geo uses geo_centroid (all sightings of
# one IP share a point, so the centroid IS that point); the rest ride top_metrics
# (latest-by-ts). retention_policy expires entities 30d after last_seen.
TRANSFORM: dict[str, Any] = {
    # `c2-entities` (dest) is not matched by `stingarc2-*`, so no self-reference.
    "source": {"index": ["stingarc2-*"]},
    "dest": {"index": ENTITIES_INDEX},
    "pivot": {
        "group_by": {"c2_host": {"terms": {"field": "c2_host"}}},
        "aggregations": {
            "first_seen": {"min": {"field": "ts"}},
            "last_seen": {"max": {"field": "ts"}},
            "sighting_count": {"value_count": {"field": "c2_host"}},
            "sensor_count": {"cardinality": {"field": "sensor_hostname"}},
            "src_ip_count": {"cardinality": {"field": "src_ip"}},
            "distinct_files": {"cardinality": {"field": "sha256"}},
            "max_evidence_rank": {"max": {"field": "evidence_rank"}},
            "c2_geo": {"geo_centroid": {"field": "c2_geo"}},
            # numeric ASN via max (null-safe: missing -> absent). top_metrics
            # would write a non-numeric placeholder for hosts with no ASN and
            # break the `long` mapping. All sightings of one IP share the ASN.
            "c2_asn": {"max": {"field": "c2_asn"}},
            # keyword "latest" fields tolerate missing; numeric stays out.
            "latest": {
                "top_metrics": {
                    "metrics": [
                        {"field": "c2_host_kind"},
                        {"field": "c2_country"},
                        {"field": "c2_asn_org"},
                    ],
                    "sort": [{"ts": "desc"}],
                }
            },
        },
    },
    "sync": {"time": {"field": "ts", "delay": "60s"}},
    "retention_policy": {"time": {"field": "last_seen", "max_age": "30d"}},
    "frequency": "1m",
    "settings": {"max_page_search_size": 500},
}
