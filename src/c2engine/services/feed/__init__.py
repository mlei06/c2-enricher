"""Feed layer (M4): the actionable output — a blocklist/alert feed.

A tiny read-only HTTP surface over the decaying ``c2-entities`` index that
firewalls / SIEMs can pull:

    GET /feed/blocklist.txt   plain IP list (one per line), IPs only
    GET /feed/c2.json         full entity summaries (IPs + domains)
    GET /healthz

Freshness is correct-by-construction: ``c2-entities`` already decays ~30 d after
``last_seen`` (the reason layer), and the feed window narrows further — so the
feed never carries stale C2s by design (DESIGN_PARITY.md §3 M4). Read-only;
never on the ingest hot path.
"""

from c2engine.services.feed.server import build_feed, serve

__all__ = ["build_feed", "serve"]
