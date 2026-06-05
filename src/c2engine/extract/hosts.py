"""``shell_reference`` rows — hosts the attacker named in commands.

Milestone 2. Must see through the common wrappers (nohup / bash -c / eval /
echo|sh / base64|sh) the way the old extractor did — re-derive, don't copy
(reference: stingar-enrichment branch, core/extractors/iocs.py).
"""

from __future__ import annotations

from c2engine.model import C2Observation, SessionIn


def shell_references(session: SessionIn) -> list[C2Observation]:
    """One row per distinct host referenced in the session's commands.

    Hosts that also produce a ``served_file`` row are still emitted here —
    dedup/stage rollup is a query-time concern, the ledger records facts.
    """
    raise NotImplementedError("milestone 2")
