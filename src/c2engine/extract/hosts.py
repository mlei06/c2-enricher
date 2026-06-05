"""``shell_reference`` rows — hosts the attacker named in commands.

Rank-0 evidence: a host was *mentioned*, nothing was fetched from it. Hosts
that also produce a ``served_file`` row are still emitted here — the ledger
records facts; dedup and stage rollup are query-time concerns (DESIGN.md §4).
"""

from __future__ import annotations

from c2engine.model import C2Observation, SessionIn

from ._base import base_obs
from ._util import find_hosts


def shell_references(session: SessionIn) -> list[C2Observation]:
    """One row per distinct host referenced across the session's commands."""
    text = "\n".join(
        [
            *session.hp_data.commands,
            *session.hp_data.unknown_commands,
            *session.hp_data.urls,
        ]
    )
    out: list[C2Observation] = []
    for host, kind in find_hosts(text):
        out.append(
            base_obs(session, c2_host=host, c2_host_kind=kind, evidence="shell_reference")
        )
    return out
