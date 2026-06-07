"""MaxMind GeoIP/ASN -> c2_geo, c2_country, c2_asn, c2_asn_org.

Central by design — one .mmdb to keep updated, not N sensor copies. For a
domain C2 we geolocate ``c2_resolved_ip`` (attack-time DNS). DB stale or
missing -> rows emit without geo; the map thins, the ledger stays correct
(DESIGN.md §8). geoip2 is an optional dependency: absent -> graceful no-op.
"""

from __future__ import annotations

import ipaddress
import os

from c2engine.model import C2Observation

try:  # optional dependency
    import geoip2.database as _geoip2_db
except ImportError:  # pragma: no cover
    _geoip2_db = None  # type: ignore[assignment]


class GeoEnricher:
    """Holds the open MaxMind readers. One instance per process."""

    def __init__(self, mmdb_dir: str | None = None) -> None:
        self._city = None
        self._asn = None
        mmdb_dir = mmdb_dir or os.environ.get("C2E_MAXMIND_DIR", "")
        if not (mmdb_dir and _geoip2_db):
            return
        city = os.path.join(mmdb_dir, "GeoLite2-City.mmdb")
        asn = os.path.join(mmdb_dir, "GeoLite2-ASN.mmdb")
        if os.path.exists(city):
            self._city = _geoip2_db.Reader(city)
        if os.path.exists(asn):
            self._asn = _geoip2_db.Reader(asn)

    @property
    def enabled(self) -> bool:
        return bool(self._city or self._asn)

    def _ip_to_geolocate(self, obs: C2Observation) -> str | None:
        target = obs.c2_host if obs.c2_host_kind == "ip" else obs.c2_resolved_ip
        if not target:
            return None
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return None
        return target

    def enrich(self, obs: C2Observation) -> C2Observation:
        ip = self._ip_to_geolocate(obs)
        if not ip:
            return obs
        if self._city is not None:
            try:
                r = self._city.city(ip)
                if r.location.latitude is not None:
                    obs.c2_geo = {"lat": r.location.latitude, "lon": r.location.longitude}
                obs.c2_country = r.country.iso_code
            except Exception:  # noqa: BLE001 - lookup miss is non-fatal
                pass
        if self._asn is not None:
            try:
                a = self._asn.asn(ip)
                obs.c2_asn = a.autonomous_system_number
                obs.c2_asn_org = a.autonomous_system_organization
            except Exception:  # noqa: BLE001
                pass
        return obs
