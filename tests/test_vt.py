"""M3 VirusTotal: parsing, rollup/escalation, cache + budget resolution."""

from __future__ import annotations

import datetime
from typing import Any

from c2engine.reason.vt import (
    VtResolver,
    apply_vt,
    parse_vt_file,
    summarize_vt,
)

NOW = datetime.datetime(2026, 6, 6, tzinfo=datetime.UTC)
FRESH = "2026-06-05T00:00:00Z"
STALE = "2026-01-01T00:00:00Z"


class _StubEs:
    def __init__(self, cache: dict[str, dict[str, Any]] | None = None, *, raise_search: bool = False):
        self._cache = cache or {}
        self.indexed: dict[str, dict[str, Any]] = {}
        self.raise_search = raise_search

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        if self.raise_search:
            raise RuntimeError("index_not_found_exception")
        ids = body["query"]["ids"]["values"]
        return {"hits": {"hits": [{"_id": s, "_source": self._cache[s]} for s in ids if s in self._cache]}}

    def index_doc(self, index: str, doc_id: str, doc: dict[str, Any]) -> None:
        self.indexed[doc_id] = doc


class _StubClient:
    def __init__(self, verdicts: dict[str, dict[str, Any] | None], *, enabled: bool = True):
        self.enabled = enabled
        self._v = verdicts
        self.calls: list[str] = []

    def lookup(self, sha: str, checked_at: str) -> dict[str, Any] | None:
        self.calls.append(sha)
        return self._v.get(sha)


def _verdict(sha: str, mal: int, total: int = 70, fams: list[str] | None = None) -> dict[str, Any]:
    return {"sha256": sha, "vt_found": True, "vt_malicious": mal, "vt_suspicious": 0,
            "vt_total": total, "vt_ratio": round(mal / total, 4), "vt_families": fams or [],
            "checked_at": FRESH}


# --- pure parsing / rollup -------------------------------------------------

def test_parse_vt_file() -> None:
    data = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 50, "suspicious": 2, "undetected": 18, "harmless": 0},
        "popular_threat_classification": {
            "suggested_threat_label": "trojan.mirai/elf",
            "popular_threat_name": [{"value": "mirai"}, {"value": "gafgyt"}],
        },
    }}}
    v = parse_vt_file(data, "abc", FRESH)
    assert v["vt_found"] and v["vt_malicious"] == 50 and v["vt_total"] == 70
    assert v["vt_ratio"] == round(50 / 70, 4)
    assert v["vt_families"] == ["gafgyt", "mirai", "trojan.mirai/elf"]


def test_summarize_vt_takes_max_and_unions_families() -> None:
    assert summarize_vt([]) == {}
    assert summarize_vt([{"vt_found": False}]) == {}
    s = summarize_vt([_verdict("a", 5, fams=["mirai"]), _verdict("b", 60, fams=["gafgyt"])])
    assert s["max_vt_malicious"] == 60
    assert s["vt_families"] == ["gafgyt", "mirai"]


def test_apply_vt_escalates_only_above_threshold() -> None:
    base = {"stage": "stage1_serving", "stage_signals": [], "families": []}
    # below threshold: records ratio/families, no escalation
    out = apply_vt(base, summarize_vt([_verdict("a", 0, total=70)]), min_malicious=1)
    assert out["stage"] == "stage1_serving" and "virustotal" not in out["stage_signals"]
    # at/above threshold: escalate + signal
    out = apply_vt(base, summarize_vt([_verdict("a", 40)]), min_malicious=1)
    assert out["stage"] == "stage2_c2" and "virustotal" in out["stage_signals"]


def test_apply_vt_no_summary_is_noop() -> None:
    base = {"stage": "unconfirmed", "stage_signals": [], "families": []}
    assert apply_vt(base, {}) == base


# --- resolver: cache, budget, enablement -----------------------------------

def test_resolver_uses_fresh_cache_without_lookup() -> None:
    es = _StubEs(cache={"a": _verdict("a", 40)})
    client = _StubClient({})
    r = VtResolver(es, client, now=NOW, max_per_run=4)
    out = r.verdicts_for(["a"])
    assert client.calls == [] and out[0]["vt_malicious"] == 40


def test_resolver_looks_up_on_miss_and_caches() -> None:
    es = _StubEs()
    client = _StubClient({"a": _verdict("a", 55)})
    r = VtResolver(es, client, now=NOW, max_per_run=4)
    out = r.verdicts_for(["a"])
    assert client.calls == ["a"] and es.indexed["a"]["vt_malicious"] == 55
    assert out[0]["vt_malicious"] == 55 and r.looked_up == 1


def test_resolver_re_looks_up_stale_cache() -> None:
    stale = {**_verdict("a", 10), "checked_at": STALE}
    es = _StubEs(cache={"a": stale})
    client = _StubClient({"a": _verdict("a", 60)})
    r = VtResolver(es, client, now=NOW, max_per_run=4)
    assert r.verdicts_for(["a"])[0]["vt_malicious"] == 60 and client.calls == ["a"]


def test_resolver_respects_budget() -> None:
    es = _StubEs()
    client = _StubClient({s: _verdict(s, 30) for s in ("a", "b", "c")})
    r = VtResolver(es, client, now=NOW, max_per_run=2)
    out = r.verdicts_for(["a", "b", "c"])
    assert len(client.calls) == 2 and len(out) == 2  # 3rd deferred to next run


def test_resolver_disabled_client_no_lookup() -> None:
    es = _StubEs()
    client = _StubClient({"a": _verdict("a", 99)}, enabled=False)
    r = VtResolver(es, client, now=NOW)
    assert r.verdicts_for(["a"]) == [] and client.calls == []


def test_resolver_dedupes_within_run() -> None:
    es = _StubEs()
    client = _StubClient({"a": _verdict("a", 30)})
    r = VtResolver(es, client, now=NOW, max_per_run=4)
    r.verdicts_for(["a", "a", "a"])
    assert client.calls == ["a"]


def test_resolver_tolerates_missing_cache_index() -> None:
    es = _StubEs(raise_search=True)  # c2-vt not created yet
    client = _StubClient({"a": _verdict("a", 30)})
    r = VtResolver(es, client, now=NOW, max_per_run=4)
    assert r.verdicts_for(["a"])[0]["vt_malicious"] == 30
