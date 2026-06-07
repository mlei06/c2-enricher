"""MaxMind/DB-IP GeoIP + ASN -> c2_geo, c2_country, c2_asn, c2_asn_org.

Central by design — one .mmdb to keep updated, not N sensor copies. For a
domain C2 we geolocate ``c2_resolved_ip`` (attack-time DNS). DB stale or
missing -> rows emit without geo; the map thins, the ledger stays correct
(DESIGN.md §8). geoip2 is an optional dependency: absent -> graceful no-op.

City db: the image ships DB-IP City Lite (the only no-key, current, freely
redistributable mmdb — the fluentd gem's bundled GeoLite2-City is from 2017 and
misses post-2017 allocations). geoip2 accepts it: its ``.city()`` type check is
substring-based and "DBIP-City-Lite" contains "City". A real GeoLite2-City is
picked up too if present.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any

from c2engine.model import C2Observation

try:  # optional dependency
    import geoip2.database as _geoip2_db
except ImportError:  # pragma: no cover
    _geoip2_db = None  # type: ignore[assignment]

_CITY_DBS = ("GeoLite2-City.mmdb", "dbip-city-lite.mmdb")
_ASN_DBS = ("GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb")


def _open_first(mmdb_dir: str, names: tuple[str, ...]) -> Any | None:
    for name in names:
        path = os.path.join(mmdb_dir, name)
        if os.path.exists(path):
            return _geoip2_db.Reader(path)
    return None


class GeoEnricher:
    """Holds the open MaxMind/DB-IP readers. One instance per process."""

    def __init__(self, mmdb_dir: str | None = None) -> None:
        self._city = None
        self._asn = None
        mmdb_dir = mmdb_dir or os.environ.get("C2E_MAXMIND_DIR", "")
        if not (mmdb_dir and _geoip2_db):
            return
        self._city = _open_first(mmdb_dir, _CITY_DBS)
        self._asn = _open_first(mmdb_dir, _ASN_DBS)

    @property
    def enabled(self) -> bool:
        return bool(self._city or self._asn)

    def locate(self, ip: str) -> dict[str, Any]:
        """Geo + ASN for a bare IP — {} on miss. Shared by the observation
        enricher and the reason job's entity-geo fallback."""
        out: dict[str, Any] = {}
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return out
        if self._city is not None:
            try:
                r = self._city.city(ip)
                if r.location.latitude is not None:
                    out["c2_geo"] = {"lat": r.location.latitude, "lon": r.location.longitude}
                if r.country.iso_code:
                    out["c2_country"] = r.country.iso_code
            except Exception:  # noqa: BLE001 - lookup miss is non-fatal
                pass
        if self._asn is not None:
            try:
                a = self._asn.asn(ip)
                out["c2_asn"] = a.autonomous_system_number
                out["c2_asn_org"] = a.autonomous_system_organization
            except Exception:  # noqa: BLE001
                pass
        return out

    def _ip_to_geolocate(self, obs: C2Observation) -> str | None:
        target = obs.c2_host if obs.c2_host_kind == "ip" else obs.c2_resolved_ip
        return target or None

    def enrich(self, obs: C2Observation) -> C2Observation:
        ip = self._ip_to_geolocate(obs)
        if not ip:
            return obs
        found = self.locate(ip)
        for field in ("c2_geo", "c2_country", "c2_asn", "c2_asn_org"):
            if field in found:
                setattr(obs, field, found[field])
        return obs
