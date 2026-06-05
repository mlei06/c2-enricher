"""Session-level outputs: additive fields + byte-strip (DESIGN.md §4.1).

Milestone 2. Produces the outbound session doc:
- inbound doc verbatim (pass-through invariant — no rename/retype/rewrite)
- PLUS SessionAdditive (c2_hosts[], playbook_hash, hassh, enrich_version)
- MINUS hp_data.files[].content_b64 (transport-only bytes)

playbook_hash and hassh are re-derived fresh (reference: stingar-enrichment
branch, core/extractors/canonical.py and fields/hassh.py).
"""

from __future__ import annotations

from typing import Any

from c2engine.model import SessionIn


def enrich_session(raw: dict[str, Any], session: SessionIn) -> dict[str, Any]:
    """``raw`` is the unmodeled inbound doc; returns the doc to re-emit."""
    raise NotImplementedError("milestone 2")
