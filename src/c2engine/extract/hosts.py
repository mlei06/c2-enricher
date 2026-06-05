"""``shell_reference`` rows — hosts the attacker named in commands.

Rank-0 evidence: a host was *mentioned*, nothing was fetched from it. Sourced
from the session's shared IoC bundle (``ctx.iocs.c2_hosts``) so these rows and
the session's ``c2_hosts`` field are the same set by construction. Hosts that
also produce a ``served_file`` row are still emitted here — the ledger records
facts; dedup and stage rollup are query-time concerns (DESIGN.md §4).
"""

from __future__ import annotations

from c2engine.context import SessionContext
from c2engine.model import C2Observation, SessionIn

from ._base import base_obs
from ._util import classify_host


def shell_references(session: SessionIn, ctx: SessionContext) -> list[C2Observation]:
    """One row per distinct host referenced across the session's commands."""
    return [
        base_obs(
            session,
            c2_host=host,
            c2_host_kind=classify_host(host),
            evidence="shell_reference",
        )
        for host in ctx.iocs.c2_hosts
    ]
