"""Per-session credential-sequence hashing.

Pure grouping signal — no default-cred/CVE attribution (reasoning layer's job).
``sequence_hash`` (SHA1 of the ordered (user, pass) attempts) buckets sessions
by "same builder, same wordlist" independent of IP/sensor; success_user/pass
point at the pair Cowrie accepted, if any.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from c2engine.model import Credential


@dataclass
class CredEnrichment:
    pairs_seen: int = 0
    sequence_hash: str | None = None
    success_user: str | None = None
    success_pass: str | None = None


def enrich(credentials: Sequence[Credential]) -> CredEnrichment:
    out = CredEnrichment(pairs_seen=len(credentials))
    for c in credentials:
        if c.success:
            out.success_user, out.success_pass = c.username, c.password
            break
    if credentials:
        seq = "\x00".join(f"{c.username}\x01{c.password}" for c in credentials)
        out.sequence_hash = hashlib.sha1(seq.encode("utf-8")).hexdigest()
    return out
