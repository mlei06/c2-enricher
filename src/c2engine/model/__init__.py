"""Wire contracts (DESIGN.md §4). Written first; everything else derives from these.

Inbound:  :class:`SessionIn` — a session doc exactly as the cowrie fork's
          ``output_stingar`` plugin emits it (verified against plugin source),
          plus the planned transport-only inlined download bytes.
Outbound: :class:`C2Observation` — one row in the ``stingarc2-*`` ledger.
          :class:`SessionAdditive` — the additive contract for ``stingar-*``.
"""

from .observation import EVIDENCE_RANK, C2Observation, Evidence, FileKind, HostKind
from .session import (
    Credential,
    FileRef,
    HpData,
    Kex,
    Sensor,
    SessionAdditive,
    SessionIn,
)

__all__ = [
    "C2Observation",
    "Credential",
    "EVIDENCE_RANK",
    "Evidence",
    "FileKind",
    "FileRef",
    "HostKind",
    "HpData",
    "Kex",
    "Sensor",
    "SessionAdditive",
    "SessionIn",
]
