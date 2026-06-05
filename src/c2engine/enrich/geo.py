"""MaxMind GeoIP/ASN → c2_geo, c2_country, c2_asn, c2_asn_org.

Milestone 2. Central by design — one .mmdb to keep updated, not N sensor
copies. Geolocates ``c2_resolved_ip`` (attack-time DNS) for domain C2s.
DB stale or missing → rows emit without geo; the map thins, the ledger
stays correct (DESIGN.md §8).
"""

from __future__ import annotations

from c2engine.model import C2Observation


def geolocate(obs: C2Observation) -> C2Observation:
    raise NotImplementedError("milestone 2")
