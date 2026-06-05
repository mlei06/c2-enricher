"""Rules-based malware family labels — ``category.family/format`` convention.

Milestone 2. Cheap static heuristics only (shebang, strings markers, magic +
arch patterns): e.g. ``downloader.shell``, ``miner.xmrig``,
``trojan.mirai/possible``. NO external lookups here — VT/intel escalation is
the phase-2 reason layer (DESIGN.md §9), gated on the entity index.
"""

from __future__ import annotations


def label(content: bytes, magic: str | None, interpreter: str | None) -> str | None:
    raise NotImplementedError("milestone 2")
