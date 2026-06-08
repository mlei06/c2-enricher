"""ES index template + ILM policy for ``stingarc2-*``, as in-package data.

Single source of truth for both the engine's startup bootstrap (elastic/client.py)
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
            # _meta documents the index for humans AND for LLM agents — Agent
            # Builder / our MCP agent read it via get_index_mapping to choose
            # fields. Free-form (no size limit, unlike field-level `meta`).
            "_meta": {
                "owner": "c2-engine",
                "description": (
                    "C2 evidence ledger: one immutable row per (session, c2_host, "
                    "evidence). Drill-down surface; aggregate to c2-entities for "
                    "per-C2 summaries."
                ),
                "fields": {
                    "c2_host": "C2 host/IP the attacker referenced or fetched from (THE pivot; same field name on every index)",
                    "c2_host_kind": "ip | domain",
                    "c2_resolved_ip": "attack-time DNS resolution of c2_host (domains)",
                    "evidence": "how this C2 was observed: shell_reference | served_file | file_callback",
                    "evidence_rank": "0=referenced only, 1=served us a file, 2=host found inside served malware (chain)",
                    "self_hosted": "true when c2_host == src_ip (loader-is-scanner)",
                    "file_kind": "script | binary (served_file rows only)",
                    "family": "rules-based malware family, category.family/variant e.g. trojan.mirai/mozi",
                    "content": "full script source (served_file scripts only; binaries omit it)",
                    "callbacks": "onward hosts found inside this file (script text / binary strings)",
                    "c2_via_sha256": "file_callback rows: which served file (sha256) revealed this host",
                    "hassh": "SSH client fingerprint of the observing session (attacker toolkit attribution)",
                    "src_ip": "attacker source IP",
                    "sensor_hostname": "honeypot that observed it",
                    "ts": "event time (session close)",
                },
            },
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
                "hassh": {"type": "keyword"},
                # Parity with stock stingar-* (fluentd include_tag_key).
                "fluentd_tag": {"type": "keyword"},
            },
        },
    },
}


# --- M1/M2: entity rollup (one decaying doc per C2) ---------------------------
# Written by the REASON JOB, not an ES transform: a transform owns (and
# overwrites) its dest doc on every checkpoint, which would clobber the intel
# fields the reason layer overlays (verified empirically on ES 8.19). So the
# reason job is the single writer — it computes the rollup AND the intel and
# upserts one doc per C2 (deterministic _id = c2_host), with manual 30d decay.

ENTITIES_INDEX = "c2-entities"
ENTITIES_TEMPLATE_NAME = "c2-entities"

# dynamic:true — the reason job controls all writes (no untrusted input); we map
# geo_point/typed fields explicitly and add the evidence_stage runtime field
# (max_evidence_rank -> stage). Intel never raises stage above the evidence
# ladder (GreyNoise model) — so `stage` and `evidence_stage` now coincide;
# corroboration lives in stage_signals, not the stage.
ENTITIES_TEMPLATE: dict[str, Any] = {
    "index_patterns": [ENTITIES_INDEX],
    "priority": 200,
    "template": {
        "settings": {"number_of_shards": 1},
        "mappings": {
            "_meta": {
                "owner": "c2-engine reason layer",
                "description": (
                    "One decaying doc per C2 (_id = c2_host), rebuilt by the reason "
                    "job. PRIMARY ask-me-anything surface for analysts: which C2s, "
                    "how many, what stage. Decays 30d after last_seen (C2s live "
                    "~3d). Drill into stingarc2-* for the underlying evidence rows."
                ),
                "fields": {
                    "c2_host": "the C2 host/IP (doc id; same field name on every index)",
                    "stage": "stage from the evidence ladder (max evidence_rank): unconfirmed | stage1_serving | stage2_c2. Intel never raises it — corroboration lives in stage_signals (GreyNoise model)",
                    "evidence_stage": "runtime: stage computed from max_evidence_rank at query time (coincides with `stage`)",
                    "stage_signals": "third-party corroboration (annotation, does not change stage): callback_in_malware | known_malware | hassh_toolkit | virustotal | threatfox | urlhaus | feodo",
                    "attributed_toolkit": "attacker toolkit(s) inferred from session hassh (e.g. mirai-loader)",
                    "families": "distinct malware families this C2 served (e.g. trojan.mirai/mozi)",
                    "max_evidence_rank": "strongest evidence: 0=referenced, 1=served a file, 2=found in malware",
                    "first_seen": "earliest sighting",
                    "last_seen": "most recent sighting (decay clock)",
                    "sighting_count": "ledger rows for this C2",
                    "sensor_count": "distinct honeypots that saw it",
                    "src_ip_count": "distinct attacker IPs that referenced it",
                    "distinct_files": "distinct served-file sha256s",
                    "latest.c2_asn_org": "latest ASN org (latest.c2_country, latest.c2_host_kind likewise)",
                    "max_vt_ratio": "highest VirusTotal detection ratio across served files (M3)",
                    "intel_sources": "abuse.ch feeds that matched this C2 (M6): threatfox | urlhaus | feodo. Annotation only — does not change stage",
                    "intel_malware": "malware/threat names the matching feeds attribute to this C2 (feed vocabulary, distinct from rules-based `families`)",
                    "_naming_note": "the session index stingar-* uses sensor.hostname + @timestamp; ledger+entities use sensor_hostname + ts (pass-through invariant: we don't rewrite stock session fields)",
                },
            },
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
                "intel_sources": {"type": "keyword"},
                "intel_malware": {"type": "keyword"},
                "updated_at": {"type": "date"},
            },
        },
    },
}

# How long an entity lives past its last sighting (decaying view; C2s ~3d).
ENTITY_RETENTION_DAYS = 30


# --- M3: VirusTotal verdict cache (one doc per sha256, fleet-wide) ------------
# Named OUTSIDE the stingarc2-* glob (like c2-entities) so its template never
# collides with the ledger template at the same priority. The reason job is the
# sole writer; one VT lookup per distinct file ever (until the verdict goes stale
# past VT_TTL_DAYS), deduped across the whole fleet.
VT_INDEX = "c2-vt"
VT_TEMPLATE_NAME = "c2-vt"
VT_TTL_DAYS = 30  # re-look-up a sha only after its verdict is this old

VT_TEMPLATE: dict[str, Any] = {
    "index_patterns": [VT_INDEX],
    "priority": 200,
    "template": {
        "settings": {"number_of_shards": 1},
        "mappings": {
            "_meta": {
                "owner": "c2-engine reason layer",
                "description": (
                    "VirusTotal verdict cache, one doc per served-file sha256 "
                    "(_id = sha256), fleet-wide. Deduplicates VT lookups; entities "
                    "read max_vt_ratio / vt_families from here. vt_found=false means "
                    "VT had no record of the file at checked_at."
                ),
                "fields": {
                    "sha256": "served-file hash (doc id)",
                    "vt_found": "true if VT knew the file",
                    "vt_malicious": "engines flagging malicious",
                    "vt_suspicious": "engines flagging suspicious",
                    "vt_total": "engines that scanned it",
                    "vt_ratio": "vt_malicious / vt_total (0..1)",
                    "vt_families": "VT popular threat names/labels",
                    "checked_at": "when this verdict was fetched (staleness clock)",
                },
            },
            "dynamic": False,
            "properties": {
                "sha256": {"type": "keyword"},
                "vt_found": {"type": "boolean"},
                "vt_malicious": {"type": "integer"},
                "vt_suspicious": {"type": "integer"},
                "vt_total": {"type": "integer"},
                "vt_ratio": {"type": "float"},
                "vt_families": {"type": "keyword"},
                "checked_at": {"type": "date"},
            },
        },
    },
}


# --- M6: abuse.ch intel feed cache (one doc per IOC, fleet-wide) --------------
# Named OUTSIDE the stingarc2-* glob (like c2-entities / c2-vt) so its template
# never collides with the ledger template at the same priority. The reason job
# is the sole writer: it bulk-downloads each feed's `recent` export on a TTL,
# stores the normalized IOCs here, then loads them into memory per pass to
# corroborate entities. Intel is ENRICHMENT (GreyNoise model) — a match adds a
# stage_signal, never raises stage. Disabled unless ABUSECH_AUTH_KEY is set.
INTEL_INDEX = "c2-intel"
INTEL_TEMPLATE_NAME = "c2-intel"
INTEL_TTL_HOURS = 12  # re-download a feed only after its cache is this old

INTEL_TEMPLATE: dict[str, Any] = {
    "index_patterns": [INTEL_INDEX],
    "priority": 200,
    "template": {
        "settings": {"number_of_shards": 1},
        "mappings": {
            "_meta": {
                "owner": "c2-engine reason layer",
                "description": (
                    "abuse.ch IOC cache, one doc per IOC (_id = source:value), "
                    "fleet-wide. Bulk-loaded from ThreatFox / URLhaus / Feodo "
                    "Tracker `recent` exports and matched against c2_host / "
                    "c2_resolved_ip / c2_url to add intel_sources + intel_malware "
                    "on entities. Refreshed when older than INTEL_TTL_HOURS."
                ),
                "fields": {
                    "source": "feed that supplied the IOC: threatfox | urlhaus | feodo",
                    "ioc_type": "ip | domain | url (normalized across feeds)",
                    "value": "the IOC verbatim (ip[:port] / domain / url)",
                    "host": "host/ip extracted from value for host-level matching (url netloc, or value itself)",
                    "malware": "threat/malware names the feed attributes to the IOC",
                    "tags": "feed tags (free-form)",
                    "fetched_at": "when this IOC's feed was last downloaded (staleness clock)",
                },
            },
            "dynamic": False,
            "properties": {
                "source": {"type": "keyword"},
                "ioc_type": {"type": "keyword"},
                "value": {"type": "keyword"},
                "host": {"type": "keyword"},
                "malware": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "fetched_at": {"type": "date"},
            },
        },
    },
}
