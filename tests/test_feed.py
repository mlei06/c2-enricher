"""M4 feed layer: blocklist query shaping + rendering."""

from __future__ import annotations

from typing import Any

from c2engine.services.feed.server import (
    _render_blocklist,
    _stages_at_or_above,
    build_feed,
)


class _StubEs:
    """Captures the search body and returns canned hits."""

    def __init__(self, hits: list[dict[str, Any]]) -> None:
        self._hits = hits
        self.body: dict[str, Any] | None = None

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        self.body = body
        return {"hits": {"hits": [{"_source": s} for s in self._hits]}}


def _hit(host: str, *, kind: str = "ip", stage: str = "stage1_serving") -> dict[str, Any]:
    return {
        "c2_host": host, "stage": stage, "families": ["downloader.shell"],
        "last_seen": "2026-06-06T00:00:00Z", "sighting_count": 3,
        "latest": {"c2_host_kind": kind, "c2_asn_org": "EvilCorp", "c2_country": "RU"},
    }


def test_stages_at_or_above() -> None:
    assert _stages_at_or_above(0) == ["unconfirmed", "stage1_serving", "stage2_c2"]
    assert _stages_at_or_above(1) == ["stage1_serving", "stage2_c2"]
    assert _stages_at_or_above(2) == ["stage2_c2"]


def test_build_feed_query_filters_stage_and_window() -> None:
    es = _StubEs([])
    build_feed(es, min_stage=2, window="3d", limit=50)
    filt = es.body["query"]["bool"]["filter"]
    assert {"terms": {"stage": ["stage2_c2"]}} in filt
    assert {"range": {"last_seen": {"gte": "now-3d"}}} in filt
    assert es.body["size"] == 50


def test_build_feed_separates_ips_from_domains() -> None:
    es = _StubEs([_hit("45.137.21.9"), _hit("evil.example.com", kind="domain"),
                  _hit("185.244.25.171", stage="stage2_c2")])
    feed = build_feed(es)
    # blocklist (ips[]) excludes the domain; entities[] keeps everything.
    assert feed["ips"] == ["45.137.21.9", "185.244.25.171"]
    assert feed["count"] == 3
    assert "evil.example.com" in [e["c2_host"] for e in feed["entities"]]


def test_build_feed_dedupes_ips() -> None:
    es = _StubEs([_hit("45.137.21.9"), _hit("45.137.21.9")])
    assert build_feed(es)["ips"] == ["45.137.21.9"]


def test_build_feed_sanitizes_bad_window_and_clamps() -> None:
    es = _StubEs([])
    feed = build_feed(es, window="; DROP", limit=999999)
    assert es.body["query"]["bool"]["filter"][1] == {"range": {"last_seen": {"gte": "now-7d"}}}
    assert feed["params"]["limit"] == 10000  # MAX_LIMIT


def test_render_blocklist_has_comment_header_and_ips() -> None:
    es = _StubEs([_hit("45.137.21.9"), _hit("1.2.3.4")])
    txt = _render_blocklist(build_feed(es))
    lines = txt.splitlines()
    assert lines[0].startswith("# c2-engine blocklist")
    assert [ln for ln in lines if not ln.startswith("#")] == ["45.137.21.9", "1.2.3.4"]
