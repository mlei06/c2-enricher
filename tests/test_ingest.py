"""Ingest: forward-frame parsing (+ack), ES index naming, bootstrap, handler."""

from __future__ import annotations

import gzip
from typing import Any

import msgpack
import pytest

from c2engine.ingest import server
from c2engine.ingest.es import EsWriter, _daily_index
from c2engine.ingest.es_assets import INDEX_TEMPLATE_NAME
from c2engine.ingest.forward import parse_frame


def _roundtrip(frame: list[Any]) -> object:
    """Pack then unpack so bytes/dict types match what msgpack hands the server."""
    return msgpack.unpackb(msgpack.packb(frame, use_bin_type=True), raw=False)


# --- parse_frame: all three carrier modes, tag always first --------------

def test_message_mode() -> None:
    frame = _roundtrip(["stingar.enrichable.cowrie", 1_700_000_000, {"src_ip": "1.2.3.4"}])
    records, option = parse_frame(frame)
    assert records == [("stingar.enrichable.cowrie", {"src_ip": "1.2.3.4"})]
    assert option is None


def test_forward_mode_with_chunk() -> None:
    frame = _roundtrip(
        [
            "stingar.enrichable.cowrie",
            [[1, {"a": 1}], [2, {"b": 2}]],
            {"chunk": "abc123"},
        ]
    )
    records, option = parse_frame(frame)
    assert [r for _, r in records] == [{"a": 1}, {"b": 2}]
    assert option == {"chunk": "abc123"}


def test_packed_forward_mode() -> None:
    payload = msgpack.packb([1, {"a": 1}]) + msgpack.packb([2, {"b": 2}])
    frame = _roundtrip(["stingar.enrichable.cowrie", payload, {"chunk": "z"}])
    records, option = parse_frame(frame)
    assert len(records) == 2
    assert option == {"chunk": "z"}


def test_packed_forward_entries_as_str_blob() -> None:
    """fluentd out_forward packs the PackedForward entries as a msgpack STR-typed
    blob of binary (not bin). The parser must handle that without a UTF-8 decode
    error — this is the real-world frame that broke the live pipeline."""
    entries = msgpack.packb([1, {"a": 1}]) + msgpack.packb([2, {"b": 2}])
    # use_bin_type=False -> the bytes blob is encoded as msgpack `str` (raw),
    # exactly how fluentd sends it.
    frame_bytes = msgpack.packb(["stingar.enrichable.cowrie", entries, {"chunk": "x"}],
                                use_bin_type=False)
    from c2engine.ingest.forward import _unpacker
    up = _unpacker()
    up.feed(frame_bytes)
    msg = next(iter(up))
    records, option = parse_frame(msg)
    assert [r for _, r in records] == [{"a": 1}, {"b": 2}]
    assert option == {"chunk": "x"}


def test_compressed_packed_forward() -> None:
    raw = msgpack.packb([1, {"a": 1}]) + msgpack.packb([2, {"b": 2}])
    frame = _roundtrip(
        ["stingar.enrichable.cowrie", gzip.compress(raw), {"compressed": "gzip"}]
    )
    records, _ = parse_frame(frame)
    assert len(records) == 2


def test_garbage_frame_is_ignored() -> None:
    assert parse_frame("not a frame") == ([], None)
    assert parse_frame([42]) == ([], None)


# --- ES index naming ------------------------------------------------------

def test_daily_index_from_end_time() -> None:
    assert _daily_index("stingar", {"end_time": "2026-06-05T12:00:00Z"}) == "stingar-2026-06-05"


# --- bootstrap installs policy + template before serving ------------------

def test_ensure_bootstrap_installs_policy_and_templates(monkeypatch) -> None:
    puts: list[str] = []
    es = EsWriter(base_url="http://es:9200")
    monkeypatch.setattr(es, "_put", lambda path, doc: puts.append(path))
    es.ensure_bootstrap()
    assert puts == [
        "_ilm/policy/stingarc2",
        f"_index_template/{INDEX_TEMPLATE_NAME}",
        "_index_template/c2-entities",  # entity index is reason-owned, no transform
    ]


def test_entities_template_shape() -> None:
    from c2engine.ingest.es_assets import ENTITIES_TEMPLATE
    props = ENTITIES_TEMPLATE["template"]["mappings"]["properties"]
    assert props["c2_geo"]["type"] == "geo_point"
    assert props["stage"]["type"] == "keyword"
    rt = ENTITIES_TEMPLATE["template"]["mappings"]["runtime"]
    assert rt["evidence_stage"]["type"] == "keyword"


def test_templates_carry_meta_docs() -> None:
    # _meta documents fields for humans AND LLM agents (read via get_index_mapping).
    from c2engine.ingest.es_assets import ENTITIES_TEMPLATE, INDEX_TEMPLATE
    for tmpl in (INDEX_TEMPLATE, ENTITIES_TEMPLATE):
        meta = tmpl["template"]["mappings"]["_meta"]
        assert meta["description"] and meta["fields"]["c2_host"]


# --- handler failure semantics (at-least-once) ----------------------------

class _RecordingES:
    def __init__(self, fail_session: bool = False) -> None:
        self.fail_session = fail_session
        self.sessions: list[dict[str, Any]] = []
        self.obs: list[list[dict[str, Any]]] = []

    def write_session(self, doc: dict[str, Any], *, source_tag: str = "") -> None:
        if self.fail_session:
            raise RuntimeError("ES down")
        self.sessions.append(doc)

    def write_observations(self, rows: list[dict[str, Any]], *, source_tag: str = "") -> None:
        self.obs.append(rows)


class _NullGeo:
    enabled = False

    def enrich(self, obs):  # pragma: no cover - never called when disabled
        return obs


def test_non_enrichable_tag_ignored() -> None:
    es = _RecordingES()
    server._handle_record("stingar.events.cowrie", {"x": 1}, geo=_NullGeo(), es=es)
    assert es.sessions == [] and es.obs == []


def test_es_failure_propagates_so_frame_is_not_acked() -> None:
    es = _RecordingES(fail_session=True)
    with pytest.raises(RuntimeError):
        server._handle_record(
            "stingar.enrichable.cowrie", {"hp_data": {}}, geo=_NullGeo(), es=es
        )


def test_enrichment_failure_writes_stripped_session() -> None:
    """A malformed record (hp_data not a dict) must still write a stripped
    session and ack — never wedge the chunk in an infinite retry."""
    es = _RecordingES()
    server._handle_record(
        "stingar.enrichable.cowrie", {"hp_data": "broken"}, geo=_NullGeo(), es=es
    )
    assert len(es.sessions) == 1
    assert es.obs == []  # no ledger rows from a failed enrichment
