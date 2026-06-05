"""Evidence-row producers — pure functions: SessionIn → list[C2Observation].

Milestone 2. Three producers, one per evidence kind (DESIGN.md §5.1). No
plugin registry: with three kinds and two outputs, plain functions win until
a fourth consumer exists.
"""

from .chains import file_callbacks
from .files import served_files
from .hosts import shell_references

__all__ = ["file_callbacks", "served_files", "shell_references"]


def all_observations(session):  # type: ignore[no-untyped-def]
    """Run every producer over one session, in evidence order."""
    refs = shell_references(session)
    files = served_files(session)
    return [*refs, *files, *file_callbacks(session, files)]
