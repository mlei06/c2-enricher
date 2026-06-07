"""``file_callback`` rows — the chain edges (GreyNoise stage-2 analog).

Rank-2: for every host in a served_file's ``callbacks[]``, emit a row whose
``c2_via_sha256`` points at the artifact that revealed it. Static analog of
GreyNoise's sandbox-derived stage 2 — ours says "referenced by malware",
theirs "contacted by malware" (DESIGN.md §4.3 caveat).

Deduped per (callback host, via-sha) so one script naming a host twice yields
one edge; the same host revealed by two different files yields two edges
(distinct provenance).
"""

from __future__ import annotations

from c2engine.model import C2Observation, SessionIn

from ._base import base_obs
from ._util import classify_host


def file_callbacks(
    session: SessionIn, served: list[C2Observation]
) -> list[C2Observation]:
    out: list[C2Observation] = []
    seen: set[tuple[str, str | None]] = set()
    for f in served:
        for host in f.callbacks:
            key = (host, f.sha256)
            if key in seen:
                continue
            seen.add(key)
            obs = base_obs(
                session,
                c2_host=host,
                c2_host_kind=classify_host(host),
                evidence="file_callback",
            )
            obs.c2_via_sha256 = f.sha256
            out.append(obs)
    return out
