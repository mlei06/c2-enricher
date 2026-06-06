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
