"""Shared compute primitives — ported from the old enrichment proxy.

These are pure functions used by BOTH the C2 ledger (extract/) and the session
enrichment (enrich/), so the two can never disagree about what a session
contains. Re-derived from the abandoned stingar-enrichment branch; timing /
ttylog analysis was intentionally dropped (interpretation belongs in a future
reason layer).
"""
