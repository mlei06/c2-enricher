"""abuse.ch intel-feed corroboration for the reason layer (M6).

Bulk-download the ThreatFox / URLhaus / Feodo Tracker ``recent`` exports on a
TTL, cache the normalized IOCs fleet-wide in ``c2-intel``, then match them
against each entity's ``c2_host`` / ``c2_resolved_ip`` / ``c2_url`` / ``sha256``.
A match adds a ``stage_signal`` and descriptive fields (``intel_sources``,
``intel_malware``) — it is ENRICHMENT, never a classifier: the evidence ladder
alone sets ``stage`` (the GreyNoise model, same as ``vt.py``).

**Disabled unless ``ABUSECH_AUTH_KEY`` is set.** abuse.ch requires a free
Auth-Key (https://auth.abuse.ch/) on every download; absent the key this is a
no-op and entities simply carry no intel signals. Feed URLs are overridable via
``C2E_INTEL_URL_<SOURCE>`` so an endpoint change needs no code edit.

Unlike VT (per-sha256 API lookups, hence a per-item budget), these are cheap
bulk lists: we fetch the whole ``recent`` window once per TTL and match locally,
so there is no per-entity rate limit to manage — only the periodic download.
"""

from __future__ import annotations

import csv
import datetime
import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from c2engine.elastic.client import EsWriter
from c2engine.elastic.schema import INTEL_INDEX, INTEL_TTL_HOURS

log = logging.getLogger(__name__)

#: source -> (default recent-export URL, parser). URLs verified against the
#: documented abuse.ch export paths; override per-source with C2E_INTEL_URL_<S>.
_DEFAULT_URLS = {
    "threatfox": "https://threatfox.abuse.ch/export/csv/recent/",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
}
ALL_FEEDS = tuple(_DEFAULT_URLS)
_LOAD_CAP = 100_000  # max IOCs held in memory per pass (recent windows fit well under)
_LOAD_PAGE = 5_000   # search_after page size; MUST stay <= index.max_result_window (10k default)


def _norm_type(raw: str) -> str | None:
    """Map a feed's IOC-type token to our normalized vocabulary, or None to skip."""
    raw = raw.strip().lower()
    if raw in ("ip", "ip:port", "ipv4", "ipv6"):
        return "ip"
    if raw in ("domain", "hostname"):
        return "domain"
    if raw == "url":
        return "url"
    if raw.endswith("hash") or raw in ("md5", "sha1", "sha256"):
        return "hash"
    return None


def _host_of(value: str, ioc_type: str) -> str | None:
    """The host key a value matches on: url -> netloc, ip -> bare ip, domain -> itself."""
    if ioc_type == "url":
        return (urlsplit(value).hostname or "").lower() or None
    if ioc_type == "ip":
        return value.split(":", 1)[0].strip().lower() or None
    if ioc_type == "domain":
        return value.strip().lower() or None
    return None


def _clean(items: list[str]) -> list[str]:
    """Dedupe/sort, dropping blanks and abuse.ch's literal "None" placeholder
    (URLhaus/ThreatFox emit the string "None" for empty tags/aliases)."""
    return sorted({s.strip() for s in items if s and s.strip() and s.strip().lower() != "none"})


def _ioc(source: str, ioc_type: str, value: str, malware: list[str], tags: list[str]) -> dict[str, Any]:
    value = value.strip()
    if ioc_type in ("url", "domain", "hash"):
        value = value.lower()
    rec: dict[str, Any] = {
        "source": source,
        "ioc_type": ioc_type,
        "value": value,
        "malware": _clean(malware),
        "tags": _clean(tags),
    }
    host = _host_of(value, ioc_type)
    if host:
        rec["host"] = host
    return rec


def _read_abusech_csv(text: str, marker: str) -> list[dict[str, str]]:
    """Parse an abuse.ch CSV dump (commented `#` header) into header-keyed rows.

    The column header is itself a `#`-comment line; we locate the one containing
    `marker` and key every data row by it, so column reordering never breaks us.
    """
    header: list[str] | None = None
    data: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            toks = next(csv.reader([s.lstrip("# ").strip()], skipinitialspace=True), [])
            if marker in toks:
                header = [t.strip() for t in toks]
            continue
        data.append(line)
    if header is None:
        return []
    rows: list[dict[str, str]] = []
    for row in csv.reader(data, skipinitialspace=True):
        if not row:
            continue
        rows.append({header[i]: (row[i] if i < len(row) else "").strip() for i in range(len(header))})
    return rows


def _split_tags(raw: str) -> list[str]:
    return [t for t in raw.replace(";", ",").split(",") if t.strip()] if raw else []


def parse_threatfox_csv(text: str) -> list[dict[str, Any]]:
    """ThreatFox `export/csv/recent` -> normalized IOCs. Pure."""
    out: list[dict[str, Any]] = []
    for r in _read_abusech_csv(text, "ioc_value"):
        t = _norm_type(r.get("ioc_type", ""))
        val = r.get("ioc_value", "")
        if not t or not val:
            continue
        mal = [r.get("malware_printable") or r.get("malware") or ""]
        out.append(_ioc("threatfox", t, val, mal, _split_tags(r.get("tags", ""))))
    return out


def parse_urlhaus_csv(text: str) -> list[dict[str, Any]]:
    """URLhaus `downloads/csv_recent` -> normalized URL IOCs. Pure."""
    out: list[dict[str, Any]] = []
    for r in _read_abusech_csv(text, "url"):
        val = r.get("url", "")
        if not val:
            continue
        mal = [r.get("threat", "")]
        out.append(_ioc("urlhaus", "url", val, mal, _split_tags(r.get("tags", ""))))
    return out


def parse_feodo_json(text: str) -> list[dict[str, Any]]:
    """Feodo Tracker `downloads/ipblocklist.json` -> normalized IP IOCs. Pure."""
    try:
        items = json.loads(text)
    except (ValueError, TypeError):
        return []
    out: list[dict[str, Any]] = []
    for it in items if isinstance(items, list) else []:
        ip = str(it.get("ip_address", "")).strip()
        if not ip:
            continue
        out.append(_ioc("feodo", "ip", ip, [str(it.get("malware", ""))], []))
    return out


_PARSERS = {
    "threatfox": parse_threatfox_csv,
    "urlhaus": parse_urlhaus_csv,
    "feodo": parse_feodo_json,
}


def _feeds_from_env() -> list[str]:
    raw = os.environ.get("C2E_INTEL_FEEDS", "").strip()
    if not raw:
        return list(ALL_FEEDS)
    want = [s.strip().lower() for s in raw.split(",") if s.strip()]
    return [s for s in want if s in ALL_FEEDS]


class IntelClient:
    """Fetches + parses abuse.ch ``recent`` exports. ``enabled`` is False without a key."""

    def __init__(self, auth_key: str | None = None, feeds: list[str] | None = None) -> None:
        self.auth_key = auth_key if auth_key is not None else os.environ.get("ABUSECH_AUTH_KEY", "")
        self.enabled = bool(self.auth_key)
        self.feeds = feeds if feeds is not None else _feeds_from_env()

    def _url(self, source: str) -> str:
        return os.environ.get(f"C2E_INTEL_URL_{source.upper()}", _DEFAULT_URLS[source])

    def fetch(self, source: str) -> list[dict[str, Any]] | None:
        """Download + parse one feed's recent export, or None to skip this pass
        (rate-limited / transient / network — retried next refresh)."""
        req = urllib.request.Request(
            self._url(source),
            headers={"Auth-Key": self.auth_key, "Accept": "*/*"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                text = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                log.error("intel 401 unauthorized — disabling abuse.ch feeds for this process")
                self.enabled = False
                return None
            log.warning("intel %s for %s — skipping this refresh", exc.code, source)
            return None
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            log.warning("intel fetch failed for %s: %s", source, exc)
            return None
        return _PARSERS[source](text)


class IntelMatcher:
    """TTL-refreshed, cache-backed local matcher for one reason daemon.

    Constructed once and reused across passes (so the in-memory IOC indexes
    survive between passes and rebuild only after an actual feed refresh).
    """

    def __init__(
        self,
        es: EsWriter,
        client: IntelClient | None = None,
        *,
        now: datetime.datetime | None = None,
        ttl_hours: int | None = None,
    ) -> None:
        self.es = es
        self.client = client or IntelClient()
        self.now = now or datetime.datetime.now(datetime.UTC)
        self._nowiso = self.now.strftime("%Y-%m-%dT%H:%M:%SZ")
        env_ttl = _env_int("C2E_INTEL_TTL_HOURS", INTEL_TTL_HOURS)
        self._ttl = datetime.timedelta(hours=ttl_hours if ttl_hours is not None else env_ttl)
        self.refreshed: list[str] = []  # sources downloaded this pass (for logging)
        self._urls: dict[str, dict[str, Any]] = {}
        self._hosts: dict[str, list[dict[str, Any]]] = {}
        self._hashes: dict[str, dict[str, Any]] = {}
        self._loaded = False

    @property
    def enabled(self) -> bool:
        return self.client.enabled

    def _latest_fetched(self, source: str) -> datetime.datetime | None:
        body = {
            "size": 0,
            "query": {"term": {"source": source}},
            "aggs": {"m": {"max": {"field": "fetched_at"}}},
        }
        try:
            res = self.es.search(INTEL_INDEX, body)
        except RuntimeError:
            return None  # cache index not created yet (first run)
        val = (res.get("aggregations", {}).get("m", {}) or {}).get("value_as_string")
        if not val:
            return None
        try:
            return datetime.datetime.fromisoformat(val.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _is_stale(self, dt: datetime.datetime | None) -> bool:
        return dt is None or (self.now - dt) >= self._ttl

    def _store(self, source: str, recs: list[dict[str, Any]]) -> None:
        docs = [(f"{source}:{r['value']}", {**r, "fetched_at": self._nowiso}) for r in recs]
        self.es.bulk_index(INTEL_INDEX, docs)
        # Purge this source's prior generation (anything not just re-stamped).
        self.es.delete_by_query(
            INTEL_INDEX,
            {"query": {"bool": {"filter": [{"term": {"source": source}}],
                               "must_not": [{"term": {"fetched_at": self._nowiso}}]}}},
        )

    def _load_indexes(self) -> None:
        # Page with search_after: the recent windows hold tens of thousands of
        # IOCs, well over ES's default index.max_result_window (10k). A single
        # size=_LOAD_CAP request throws search_phase_execution_exception, which
        # used to be swallowed as "index missing" — silently loading an EMPTY
        # index, so matching never fired whenever c2-intel exceeded 10k docs.
        self._urls, self._hosts, self._hashes = {}, {}, {}
        after: list[Any] | None = None
        loaded = 0
        while loaded < _LOAD_CAP:
            body: dict[str, Any] = {
                "size": min(_LOAD_PAGE, _LOAD_CAP - loaded),
                "query": {"match_all": {}},
                "sort": [{"value": "asc"}, {"source": "asc"}],  # unique tiebreak (== _id)
            }
            if after is not None:
                body["search_after"] = after
            try:
                res = self.es.search(INTEL_INDEX, body)
            except RuntimeError:
                self._loaded = True  # cache index not created yet (first run)
                return
            hits = res.get("hits", {}).get("hits", [])
            if not hits:
                break
            for h in hits:
                rec = h.get("_source", {})
                t = rec.get("ioc_type")
                if t == "url":
                    self._urls[rec["value"]] = rec
                elif t == "hash":
                    self._hashes[rec["value"]] = rec
                if rec.get("host"):
                    self._hosts.setdefault(rec["host"], []).append(rec)
            loaded += len(hits)
            after = hits[-1].get("sort")
            if len(hits) < body["size"] or after is None:
                break
        if loaded >= _LOAD_CAP:
            log.warning("intel: hit %d-IOC load cap; matches may be incomplete", _LOAD_CAP)
        self._loaded = True

    def refresh(self, now: datetime.datetime | None = None) -> None:
        """Download any stale feed into the cache, then (re)build the in-memory
        indexes. No-op without a key. Safe to call once per reason pass; pass the
        pass's `now` so a long-lived matcher's staleness clock advances."""
        if now is not None:
            self.now = now
            self._nowiso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.refreshed = []
        if not self.enabled:
            return
        changed = False
        for source in self.client.feeds:
            if not self._is_stale(self._latest_fetched(source)):
                continue
            recs = self.client.fetch(source)
            if recs is None:
                continue
            self._store(source, recs)
            self.refreshed.append(source)
            changed = True
        if changed or not self._loaded:
            self._load_indexes()

    def match(
        self,
        *,
        host: str,
        resolved_ips: list[str] | None = None,
        urls: list[str] | None = None,
        shas: list[str] | None = None,
    ) -> dict[str, Any]:
        """Match one entity against the cached IOCs. Returns aggregated
        {sources, malware, tags}; empty sources means no corroboration."""
        hits: list[dict[str, Any]] = []
        for u in urls or []:
            rec = self._urls.get(u.lower())
            if rec:
                hits.append(rec)
        candidate_hosts = {host.lower()} if host else set()
        candidate_hosts.update(ip.lower() for ip in (resolved_ips or []) if ip)
        for u in urls or []:
            netloc = (urlsplit(u).hostname or "").lower()
            if netloc:
                candidate_hosts.add(netloc)
        for h in candidate_hosts:
            hits.extend(self._hosts.get(h, []))
        for sha in shas or []:
            rec = self._hashes.get(sha.lower())
            if rec:
                hits.append(rec)
        if not hits:
            return {"sources": [], "malware": [], "tags": []}
        return {
            "sources": sorted({r["source"] for r in hits}),
            "malware": sorted({m for r in hits for m in r.get("malware", [])}),
            "tags": sorted({t for r in hits for t in r.get("tags", [])}),
        }


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def apply_intel(overlay: dict[str, Any], match: dict[str, Any]) -> dict[str, Any]:
    """Overlay abuse.ch corroboration onto the entity. Intel is ENRICHMENT, not a
    classifier (the GreyNoise model): each matching feed adds its name to
    ``stage_signals`` and records ``intel_sources`` / ``intel_malware``, but never
    changes ``stage`` — the evidence ladder alone sets it."""
    sources = match.get("sources") or []
    if not sources:
        return overlay
    out = dict(overlay)
    out["intel_sources"] = sorted(sources)
    if match.get("malware"):
        out["intel_malware"] = sorted(match["malware"])
    out["stage_signals"] = sorted(set(out.get("stage_signals", [])) | set(sources))
    return out
