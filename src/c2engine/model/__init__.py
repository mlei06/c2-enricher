"""Wire contracts (DESIGN.md §4). Written first; everything else derives from these.

Inbound:  :class:`SessionIn` — a raw Cowrie session doc as STINGAR ships it,
          plus the transport-only inlined download bytes.
Outbound: :class:`C2Observation` — one row in the ``stingar-c2-*`` ledger.
          :class:`SessionAdditive` — the additive contract for ``stingar-*``.
"""

from .observation import EVIDENCE_RANK, C2Observation, Evidence, FileKind, HostKind
from .session import FileRef, HpData, SessionAdditive, SessionIn

__all__ = [
    "C2Observation",
    "EVIDENCE_RANK",
    "Evidence",
    "FileKind",
    "FileRef",
    "HostKind",
    "HpData",
    "SessionAdditive",
    "SessionIn",
]
