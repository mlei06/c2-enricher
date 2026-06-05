"""Session-level enrichment (DESIGN.md §4.1) — drop-in for the old proxy.

Writes the full ported field set into ``hp_data`` (same location and names the
production enrichment used, so existing Kibana keeps working) and strips the
transport-only inlined bytes. The C2 layer is complementary, not duplicative:
``hp_data.iocs_*`` come from the SAME bundle as the ledger's ``c2_host`` rows.

Field placement:
  hp_data.*           — iocs_*, banner_*, cred_*, shape_*, playbook_*,
                        payload_refs, hassh, enrich_schema_version (== old proxy)
  top-level c2_hosts  — the cross-index pivot (matches the ledger's c2_host)
  top-level enrich_version — marks the c2-engine generation
"""

from __future__ import annotations

import copy
from typing import Any

from c2engine.context import SessionContext
from c2engine.model import SessionIn

#: Marks a doc as produced by this engine (distinct from hp_data.enrich_schema_version,
#: which keeps the field-schema number the old proxy used for dashboard continuity).
ENRICH_VERSION = "c2e-1"
ENRICH_SCHEMA_VERSION = "1"


def _hp_data_fields(session: SessionIn, ctx: SessionContext) -> dict[str, Any]:
    """The flat hp_data.* enrichment fields (Tier 1+2; timing dropped)."""
    b = ctx.iocs
    fields: dict[str, Any] = {
        # IoCs — iocs_c2_hosts is the same list as the top-level c2_hosts pivot.
        "iocs_ips": b.ips,
        "iocs_urls": b.urls,
        "iocs_domains": b.domains,
        "iocs_c2_hosts": b.c2_hosts,
        "iocs_ssh_key_sha1s": b.ssh_key_sha1s,
        "iocs_file_hashes": b.file_hashes,
        "iocs_cve_ids": b.cve_ids,
        # Playbook (SHA1, matches production).
        "playbook_canonical": ctx.playbook_canonical,
        "playbook_hash": ctx.playbook_hash,
        # Credentials.
        "cred_sequence_hash": ctx.creds.sequence_hash,
        "cred_success_user": ctx.creds.success_user,
        "cred_success_pass": ctx.creds.success_pass,
        # Shape.
        "shape_duration_s": ctx.shape.duration_s,
        "shape_command_count": ctx.shape.command_count,
        "shape_unknown_command_count": ctx.shape.unknown_command_count,
        "shape_cred_attempts": ctx.shape.cred_attempts,
        "shape_failed_attempts_before_success": ctx.shape.failed_attempts_before_success,
        "shape_ttylog_bytes": ctx.shape.ttylog_bytes,
        "shape_has_pty": ctx.shape.has_pty,
        "shape_distinct_urls": ctx.shape.distinct_urls,
        "shape_distinct_file_hashes": ctx.shape.distinct_file_hashes,
        # SSH client identity (hassh copied from kex for a flat pivot).
        "hassh": session.hp_data.kex.hassh if session.hp_data.kex else None,
        # Payload pointers (full bytes live in the ledger's served_file rows).
        "payload_refs": _payload_refs(session),
        "enrich_schema_version": ENRICH_SCHEMA_VERSION,
    }
    if ctx.banner is not None:
        fields["banner_vendor"] = ctx.banner.vendor
        fields["banner_product"] = ctx.banner.product
        fields["banner_version"] = ctx.banner.version
        fields["banner_cpe23"] = ctx.banner.cpe23
    return fields


def _payload_refs(session: SessionIn) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for f in session.hp_data.files or ():
        if not f.shasum:
            continue
        refs.append(
            {
                "kind": f.action or "download",
                "attempted_url": f.url or None,
                "sha256": f.shasum,
                "status": "ok" if (f.status or "").lower() == "successful" else "failed",
            }
        )
    return refs


def enrich_session(
    raw: dict[str, Any], session: SessionIn, ctx: SessionContext
) -> dict[str, Any]:
    """``raw`` is the unmodeled inbound doc; returns the doc to write.

    Inbound doc verbatim, PLUS hp_data enrichment + top-level pivot/marker,
    MINUS hp_data.files[].content_b64 (transport-only inlined bytes).
    """
    doc = copy.deepcopy(raw)

    hp = doc.get("hp_data")
    if not isinstance(hp, dict):
        hp = {}
        doc["hp_data"] = hp
    for f in hp.get("files") or ():
        if isinstance(f, dict):
            f.pop("content_b64", None)

    hp.update(_hp_data_fields(session, ctx))

    doc["c2_hosts"] = ctx.iocs.c2_hosts  # cross-index pivot (== hp_data.iocs_c2_hosts)
    doc["enrich_version"] = ENRICH_VERSION
    return doc
