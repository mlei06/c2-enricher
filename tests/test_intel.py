"""M6 abuse.ch intel feeds: feed parsing, local matching, annotate-without-escalate,
TTL-bounded refresh, and disabled-without-key no-op."""

from __future__ import annotations

import datetime
from typing import Any

from c2engine.services.reason.intel import (
    IntelMatcher,
    apply_intel,
    parse_feodo_json,
    parse_threatfox_csv,
    parse_urlhaus_csv,
)

NOW = datetime.datetime(2026, 6, 7, tzinfo=datetime.UTC)

THREATFOX_CSV = """\
# Generated at 2026-06-07
# first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, malware, malware_printable, confidence_level, tags
"2026-06-01 00:00:00", "1", "1.2.3.4:443", "ip:port", "botnet_cc", "win.cobalt", "Cobalt Strike", "100", "CobaltStrike,beacon"
"2026-06-02 00:00:00", "2", "evil.example.com", "domain", "botnet_cc", "elf.mirai", "Mirai", "75", ""
"2026-06-03 00:00:00", "3", "http://tf.example.com/a", "url", "payload", "x", "Gafgyt", "50", ""
"2026-06-04 00:00:00", "4", "deadbeef00", "sha256_hash", "payload", "x", "Mozi", "90", ""
"""

URLHAUS_CSV = """\
# URLhaus database dump
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"99","2026-06-01","http://bad.example.com/x.bin","online","","malware_download","elf,mirai","https://urlhaus.abuse.ch/url/99/","abuse_ch"
"""

FEODO_JSON = '[{"ip_address":"9.9.9.9","port":447,"malware":"Emotet","hostname":""}]'


# --- pure parsers ------------------------------------------------------------

def test_threatfox_parses_all_ioc_types() -> None:
    recs = {r["value"]: r for r in parse_threatfox_csv(THREATFOX_CSV)}
    assert recs["1.2.3.4:443"]["ioc_type"] == "ip"
    assert recs["1.2.3.4:443"]["host"] == "1.2.3.4"  # port stripped for host key
    assert recs["1.2.3.4:443"]["malware"] == ["Cobalt Strike"]
    assert sorted(recs["1.2.3.4:443"]["tags"]) == ["CobaltStrike", "beacon"]
    assert recs["evil.example.com"]["ioc_type"] == "domain"
    assert recs["http://tf.example.com/a"]["ioc_type"] == "url"
    assert recs["deadbeef00"]["ioc_type"] == "hash"


def test_urlhaus_parses_url_with_host_and_threat() -> None:
    [r] = parse_urlhaus_csv(URLHAUS_CSV)
    assert r["source"] == "urlhaus"
    assert r["ioc_type"] == "url"
    assert r["host"] == "bad.example.com"  # netloc extracted for host-level match
    assert r["malware"] == ["malware_download"]
    assert sorted(r["tags"]) == ["elf", "mirai"]


def test_feodo_parses_ip_and_malware() -> None:
    [r] = parse_feodo_json(FEODO_JSON)
    assert (r["source"], r["ioc_type"], r["value"], r["host"]) == ("feodo", "ip", "9.9.9.9", "9.9.9.9")
    assert r["malware"] == ["Emotet"]


def test_parsers_tolerate_garbage() -> None:
    assert parse_feodo_json("not json") == []
    assert parse_threatfox_csv("# no header marker here\n") == []


def test_literal_none_placeholder_is_dropped() -> None:
    # URLhaus/ThreatFox emit the string "None" for empty tag/alias columns.
    csv = ('# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
           '"1","2026-06-07","http://x.example/a","online","","malware_download","None","l","r"\n')
    [r] = parse_urlhaus_csv(csv)
    assert r["tags"] == []  # "None" filtered, not carried as a tag


# --- matching ----------------------------------------------------------------

class _StubEs:
    """In-memory c2-intel: answers the max(fetched_at) agg, match_all load,
    bulk_index, and the per-source stale purge."""

    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        if "aggs" in body:
            src = body["query"]["term"]["source"]
            stamps = [d["fetched_at"] for d in self.docs.values() if d.get("source") == src]
            return {"aggregations": {"m": {"value_as_string": max(stamps) if stamps else None}}}
        # match_all load: honor sort + search_after + size so pagination is exercised.
        def key(d: dict[str, Any]) -> list[str]:
            return [d.get("value", ""), d.get("source", "")]
        items = sorted(self.docs.values(), key=key)
        after = body.get("search_after")
        if after is not None:
            items = [d for d in items if key(d) > list(after)]
        items = items[: body.get("size", len(items))]
        return {"hits": {"hits": [{"_source": d, "sort": key(d)} for d in items]}}

    def bulk_index(self, index: str, docs: list[tuple[str, dict[str, Any]]]) -> int:
        for doc_id, doc in docs:
            self.docs[doc_id] = doc
        return len(docs)

    def delete_by_query(self, index: str, body: dict[str, Any]) -> int:
        src = body["query"]["bool"]["filter"][0]["term"]["source"]
        keep = body["query"]["bool"]["must_not"][0]["term"]["fetched_at"]
        stale = [k for k, d in self.docs.items()
                 if d.get("source") == src and d.get("fetched_at") != keep]
        for k in stale:
            del self.docs[k]
        return len(stale)


class _StubClient:
    def __init__(self, feeds_recs: dict[str, list[dict[str, Any]]], *, enabled: bool = True):
        self.enabled = enabled
        self.feeds = list(feeds_recs)
        self._recs = feeds_recs
        self.calls: list[str] = []

    def fetch(self, source: str) -> list[dict[str, Any]]:
        self.calls.append(source)
        return self._recs[source]


def _loaded_matcher() -> IntelMatcher:
    es = _StubEs()
    recs = {
        "threatfox": parse_threatfox_csv(THREATFOX_CSV),
        "urlhaus": parse_urlhaus_csv(URLHAUS_CSV),
        "feodo": parse_feodo_json(FEODO_JSON),
    }
    m = IntelMatcher(es, client=_StubClient(recs), now=NOW, ttl_hours=12)
    m.refresh(now=NOW)
    return m


def test_match_url_exact() -> None:
    m = _loaded_matcher()
    got = m.match(host="tf.example.com", urls=["http://tf.example.com/a"])
    assert "threatfox" in got["sources"]
    assert "Gafgyt" in got["malware"]


def test_match_host_ip_and_domain() -> None:
    m = _loaded_matcher()
    assert m.match(host="1.2.3.4")["sources"] == ["threatfox"]
    assert m.match(host="9.9.9.9")["sources"] == ["feodo"]
    assert m.match(host="evil.example.com")["sources"] == ["threatfox"]


def test_match_resolved_ip_for_domain_host() -> None:
    m = _loaded_matcher()
    got = m.match(host="some-domain.tld", resolved_ips=["9.9.9.9"])
    assert got["sources"] == ["feodo"]


def test_match_sha256() -> None:
    m = _loaded_matcher()
    got = m.match(host="x", shas=["DEADBEEF00"])  # case-insensitive
    assert got["sources"] == ["threatfox"]
    assert "Mozi" in got["malware"]


def test_match_url_netloc_corroborates_host() -> None:
    m = _loaded_matcher()
    got = m.match(host="x", urls=["http://bad.example.com/other"])  # different path
    assert "urlhaus" in got["sources"]  # matched on the host the URL resolves to


def test_no_match_is_empty() -> None:
    m = _loaded_matcher()
    assert m.match(host="nothing.here", urls=["http://clean.example/y"])["sources"] == []


def test_load_indexes_paginates(monkeypatch) -> None:
    """c2-intel routinely exceeds ES's default 10k result window, so the IOC
    load must page with search_after — not one oversized request that throws and
    silently leaves the in-memory index empty (the live abuse.ch-matching bug)."""
    from c2engine.services.reason import intel as intel_mod

    monkeypatch.setattr(intel_mod, "_LOAD_PAGE", 2)  # force multiple pages
    recs = [{"source": "feodo", "ioc_type": "ip", "value": f"10.0.0.{i}",
             "host": f"10.0.0.{i}", "malware": [], "tags": []} for i in range(5)]
    m = IntelMatcher(_StubEs(), client=_StubClient({"feodo": recs}), now=NOW, ttl_hours=12)
    m.refresh(now=NOW)
    # all 5 IOCs loaded across 3 pages of 2
    for i in range(5):
        assert m.match(host=f"10.0.0.{i}")["sources"] == ["feodo"]


# --- annotate without escalating ---------------------------------------------

def test_apply_intel_adds_signal_never_changes_stage() -> None:
    overlay = {"stage": "stage1_serving", "stage_signals": ["known_malware"]}
    out = apply_intel(overlay, {"sources": ["threatfox", "feodo"], "malware": ["Emotet"], "tags": []})
    assert out["stage"] == "stage1_serving"  # unchanged — evidence ladder owns stage
    assert out["stage_signals"] == ["feodo", "known_malware", "threatfox"]
    assert out["intel_sources"] == ["feodo", "threatfox"]
    assert out["intel_malware"] == ["Emotet"]


def test_apply_intel_no_match_is_noop() -> None:
    overlay = {"stage": "unconfirmed", "stage_signals": []}
    assert apply_intel(overlay, {"sources": [], "malware": [], "tags": []}) is overlay


# --- refresh: TTL-bounded + disabled no-op -----------------------------------

def test_refresh_skips_fetch_within_ttl() -> None:
    es = _StubEs()
    client = _StubClient({"feodo": parse_feodo_json(FEODO_JSON)})
    m = IntelMatcher(es, client=client, now=NOW, ttl_hours=12)
    m.refresh(now=NOW)
    assert client.calls == ["feodo"]  # first pass: cache empty -> fetch
    m.refresh(now=NOW + datetime.timedelta(hours=1))
    assert client.calls == ["feodo"]  # within TTL -> no refetch
    m.refresh(now=NOW + datetime.timedelta(hours=13))
    assert client.calls == ["feodo", "feodo"]  # past TTL -> refetch


def test_refresh_purges_stale_generation() -> None:
    es = _StubEs()
    # first feed has two IPs; second download drops one — stale must be purged.
    recs1 = [{"source": "feodo", "ioc_type": "ip", "value": "1.1.1.1", "host": "1.1.1.1",
              "malware": [], "tags": []},
             {"source": "feodo", "ioc_type": "ip", "value": "2.2.2.2", "host": "2.2.2.2",
              "malware": [], "tags": []}]
    recs2 = [recs1[0]]
    client = _StubClient({"feodo": recs1})
    m = IntelMatcher(es, client=client, now=NOW, ttl_hours=12)
    m.refresh(now=NOW)
    assert m.match(host="2.2.2.2")["sources"] == ["feodo"]
    client._recs["feodo"] = recs2
    m.refresh(now=NOW + datetime.timedelta(hours=13))
    assert m.match(host="2.2.2.2")["sources"] == []  # purged
    assert m.match(host="1.1.1.1")["sources"] == ["feodo"]


def test_disabled_without_key_is_noop() -> None:
    es = _StubEs()
    client = _StubClient({"feodo": parse_feodo_json(FEODO_JSON)}, enabled=False)
    m = IntelMatcher(es, client=client, now=NOW)
    m.refresh(now=NOW)
    assert client.calls == []
    assert m.enabled is False
    assert m.match(host="9.9.9.9")["sources"] == []
