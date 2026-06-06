"""Reason layer (M2): overlays judgment onto the C2 entity index.

The SOLE writer of ``c2-entities`` — it computes the per-C2 rollup from the
immutable ledger AND the intel overlay (stage escalation, families, signals),
then upserts one doc per C2 (``_id = c2_host``) with manual 30-day decay. A
single writer avoids the transform-clobber problem (an ES transform overwrites
its dest doc each checkpoint, wiping any externally-written intel fields).

Runs out-of-band (``c2-engine reason [--interval N]``) — never on the ingest
hot path, so it can't stall sessions.
"""

from c2engine.reason.engine import compute_overlay, run, run_once

__all__ = ["compute_overlay", "run", "run_once"]
