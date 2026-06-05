"""Session-level outputs: additive fields + byte-strip (DESIGN.md §4.1).

Produces the outbound session doc:
- inbound doc verbatim (pass-through invariant — no rename/retype/rewrite)
- PLUS c2_hosts[], playbook_hash, hassh (copied from hp_data.kex), enrich_version
- MINUS hp_data.files[].content_b64 (transport-only inlined bytes)
"""

from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

from c2engine.model import C2Observation, SessionAdditive, SessionIn

# Collapse the volatile bits of a command so re-runs hash identically.
_WS = re.compile(r"\s+")
_HEXISH = re.compile(r"\b[0-9a-fA-F]{8,}\b")
_NUM = re.compile(r"\b\d+\b")


def _canonical_command(cmd: str) -> str:
    c = _WS.sub(" ", cmd.strip())
    c = _HEXISH.sub("<hex>", c)
    c = _NUM.sub("<n>", c)
    return c


def playbook_hash(commands: list[str]) -> str | None:
    """Order-preserving hash of the canonicalized command sequence."""
    if not commands:
        return None
    canon = "\n".join(_canonical_command(c) for c in commands)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def enrich_session(
    raw: dict[str, Any], session: SessionIn, observations: list[C2Observation]
) -> dict[str, Any]:
    """``raw`` is the unmodeled inbound doc; returns the doc to re-emit.

    ``c2_hosts`` is the deduped set of every host that produced any evidence
    row this session — the array field the dashboard's ``c2_hosts:X`` filter
    hits on the session index.
    """
    doc = copy.deepcopy(raw)

    # Strip transport-only bytes; leave every other field exactly as received.
    for f in doc.get("hp_data", {}).get("files", []) or ():
        f.pop("content_b64", None)

    hassh = session.hp_data.kex.hassh if session.hp_data.kex else None
    c2_hosts = list(dict.fromkeys(o.c2_host for o in observations if o.c2_host))

    additive = SessionAdditive(
        c2_hosts=c2_hosts,
        playbook_hash=playbook_hash(session.hp_data.commands),
        hassh=hassh,
    )
    doc.update(additive.model_dump())
    return doc
