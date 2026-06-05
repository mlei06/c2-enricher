"""Per-session computed context — built once, used by extract AND enrich.

This is what makes the session enrichment and the C2 ledger complementary:
both read the SAME IoC bundle, so ``c2_hosts`` on the session and the
``c2_host`` rows in the ledger are derived from one extraction, never two.
"""

from __future__ import annotations

from dataclasses import dataclass

from c2engine.core import banner as banner_mod
from c2engine.core import canonical as canonical_mod
from c2engine.core import credentials as cred_mod
from c2engine.core import iocs as iocs_mod
from c2engine.core import shape as shape_mod
from c2engine.core import shell as shell_mod
from c2engine.core.banner import Cpe
from c2engine.core.credentials import CredEnrichment
from c2engine.core.iocs import IocBundle
from c2engine.core.shape import ShapeFeatures
from c2engine.model import SessionIn


@dataclass
class SessionContext:
    iocs: IocBundle  # over expanded command text (folds in download URLs)
    playbook_canonical: str
    playbook_hash: str  # SHA1 — matches production
    banner: Cpe | None
    creds: CredEnrichment
    shape: ShapeFeatures


def build_context(session: SessionIn) -> SessionContext:
    hp = session.hp_data
    expanded = shell_mod.expanded_text([*hp.commands, *hp.unknown_commands])
    iocs = iocs_mod.extract(expanded, existing_urls=list(hp.urls))
    canonical, phash = canonical_mod.canonicalize_and_hash(hp.commands, hp.unknown_commands)
    return SessionContext(
        iocs=iocs,
        playbook_canonical=canonical,
        playbook_hash=phash,
        banner=banner_mod.parse(hp.version),
        creds=cred_mod.enrich(hp.credentials),
        shape=shape_mod.compute(session),
    )
