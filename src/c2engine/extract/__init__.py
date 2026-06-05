"""Evidence-row producers — pure functions: (session, ctx) -> list[C2Observation].

Three producers, one per evidence kind (DESIGN.md §5.1). No plugin registry:
with three kinds and two outputs, plain functions win until a fourth consumer
exists.
"""

from __future__ import annotations

from c2engine.context import SessionContext, build_context
from c2engine.model import C2Observation, SessionIn

from .chains import file_callbacks
from .files import served_files
from .hosts import shell_references

__all__ = ["all_observations", "file_callbacks", "served_files", "shell_references"]


def all_observations(
    session: SessionIn, ctx: SessionContext | None = None
) -> list[C2Observation]:
    """Run every producer over one session, in evidence-rank order.

    ``ctx`` is the shared per-session compute (built here if not supplied) — the
    same bundle the session enrichment reads, keeping ledger and session
    consistent.
    """
    if ctx is None:
        ctx = build_context(session)
    refs = shell_references(session, ctx)
    files = served_files(session)
    callbacks = file_callbacks(session, files)
    return [*refs, *files, *callbacks]
