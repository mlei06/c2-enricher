"""Evidence-row producers — pure functions: SessionIn -> list[C2Observation].

Three producers, one per evidence kind (DESIGN.md §5.1). No plugin registry:
with three kinds and two outputs, plain functions win until a fourth consumer
exists.
"""

from __future__ import annotations

from c2engine.model import C2Observation, SessionIn

from .chains import file_callbacks
from .files import served_files
from .hosts import shell_references

__all__ = ["all_observations", "file_callbacks", "served_files", "shell_references"]


def all_observations(session: SessionIn) -> list[C2Observation]:
    """Run every producer over one session, in evidence-rank order."""
    refs = shell_references(session)
    files = served_files(session)
    callbacks = file_callbacks(session, files)
    return [*refs, *files, *callbacks]
