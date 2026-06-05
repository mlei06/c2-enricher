"""``file_callback`` rows — the chain edges (GreyNoise stage-2 analog).

Milestone 2. For every host in a served_file row's ``callbacks[]``, emit a
rank-2 row with ``c2_via_sha256`` pointing at the artifact that revealed it.
Static analog of GreyNoise's sandbox-derived stage 2: ours says "referenced
by malware", theirs says "contacted by malware" (DESIGN.md §4.3 caveat).
"""

from __future__ import annotations

from c2engine.model import C2Observation, SessionIn


def file_callbacks(
    session: SessionIn, served: list[C2Observation]
) -> list[C2Observation]:
    raise NotImplementedError("milestone 2")
