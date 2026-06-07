"""One row in the ``stingarc2-*`` evidence ledger (DESIGN.md §4.2).

Append-only and immutable: a row states a fact observed in one session, never
a verdict. Stage is *derived at query time* as max(evidence_rank) per
c2_host over the inspected window — there is no stage field to go stale.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, model_validator

from c2engine import SCHEMA_VERSION

Evidence = Literal["shell_reference", "served_file", "file_callback"]
HostKind = Literal["ip", "domain"]
FileKind = Literal["script", "binary"]

#: The evidence ladder (GreyNoise-adapted; DESIGN.md §4.3).
#:   0 — host seen in attacker commands; no bytes retrieved
#:   1 — we hold bytes it served (in-session download)
#:   2 — host referenced INSIDE a stage-1 artifact (chain-propagated)
EVIDENCE_RANK: dict[str, int] = {
    "shell_reference": 0,
    "served_file": 1,
    "file_callback": 2,
}


class C2Observation(BaseModel):
    schema_version: str = SCHEMA_VERSION
    ts: datetime | None = None
    sensor_uuid: str = ""
    sensor_hostname: str = ""
    src_ip: str = ""
    session_id: str = ""

    # The universal pivot — same field name on every index (DESIGN.md §4.2).
    c2_host: str = ""
    c2_host_kind: HostKind = "ip"
    c2_resolved_ip: str | None = None
    c2_url: str | None = None
    c2_port: int | None = None
    c2_path: str | None = None

    # SSH client fingerprint of the session that observed this host (denormalized
    # from hp_data.kex.hassh). Lets the reason layer attribute a known attacker
    # toolkit to the C2 without a session-index join. Null for non-SSH/no-kex.
    hassh: str | None = None

    # GeoIP/ASN (central MaxMind). Absent — never guessed — when lookup fails.
    c2_geo: dict[str, float] | None = None  # {"lat": …, "lon": …} → geo_point
    c2_country: str | None = None
    c2_asn: int | None = None
    c2_asn_org: str | None = None

    evidence: Evidence
    evidence_rank: int | None = None  # stamped from EVIDENCE_RANK if unset
    self_hosted: bool = False  # c2_host == src_ip (loader-is-scanner)

    # served_file rows only ------------------------------------------------
    file_kind: FileKind | None = None
    sha256: str | None = None
    sha1: str | None = None
    md5: str | None = None
    size: int | None = None
    magic: str | None = None  # binaries, e.g. "ELF 32-bit MIPS"
    family: str | None = None  # rules-based, "category.family/format"
    interpreter: str | None = None  # scripts: sh | bash | python | …
    content: str | None = None  # scripts only, UTF-8, ≤ CONTENT_CAP
    content_truncated: bool = False
    callbacks: list[str] = []  # hosts found inside content / binary strings

    # file_callback rows only ----------------------------------------------
    c2_via_sha256: str | None = None  # chain edge: which file revealed this host

    @model_validator(mode="after")
    def _stamp_rank(self) -> C2Observation:
        if self.evidence_rank is None:
            self.evidence_rank = EVIDENCE_RANK[self.evidence]
        return self


#: Inline cap for script content (DESIGN.md §4.2). Binaries never inline.
CONTENT_CAP = 256 * 1024
