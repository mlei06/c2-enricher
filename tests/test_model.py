"""Milestone 1: the wire contracts hold against the golden fixture.

The fixture mirrors ``output_stingar`` (stingar.py) exactly; these tests pin
the field names the engine reads, so a sensor-side wire change breaks loudly
here first.
"""

import base64
import json
from pathlib import Path

import pytest

from c2engine.model import EVIDENCE_RANK, C2Observation, SessionIn

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def raw_session() -> dict:
    return json.loads((FIXTURES / "session_basic.json").read_text())


def test_session_parses(raw_session: dict) -> None:
    s = SessionIn.model_validate(raw_session)
    assert s.sensor_uuid == "a82be2b776ab4161911eb9114b8b1234"
    assert s.sensor_hostname == "sensor-dmz-1"
    assert s.session_id == "c0ffee010203"
    assert s.src_ip == "59.96.137.61"
    assert s.protocol == "ssh"
    assert s.hp_data.commands and "wget" in s.hp_data.commands[1]
    assert s.hp_data.credentials[0].success is True
    assert s.hp_data.kex and s.hp_data.kex.hassh == "92674389fa1e47a27ddd8d9b63ecd42b"


def test_file_entry_matches_plugin_shape(raw_session: dict) -> None:
    f = SessionIn.model_validate(raw_session).hp_data.files[0]
    assert f.action == "download" and f.status == "successful"
    assert f.shasum.startswith("8c1bd271")
    assert f.resolved_ip == "59.96.137.61"  # sensor-side addition (pending)


def test_empty_end_time_tolerated(raw_session: dict) -> None:
    """The plugin initializes end_time to "" — parse must not choke on it."""
    raw_session["end_time"] = ""
    assert SessionIn.model_validate(raw_session).end_time is None


def test_unknown_fields_survive_roundtrip(raw_session: dict) -> None:
    """The pass-through invariant: fields we don't model ride along verbatim."""
    s = SessionIn.model_validate(raw_session)
    dumped = s.model_dump()
    assert dumped["hp_data"]["unknown_stock_field"] == "must pass through verbatim"
    assert dumped["sensor"]["tags"]["area"] == "dmz"


def test_inlined_bytes_decode_to_dropper(raw_session: dict) -> None:
    s = SessionIn.model_validate(raw_session)
    content = base64.b64decode(s.hp_data.files[0].content_b64).decode()
    assert content.startswith("#!/bin/sh")
    assert "5.6.7.8" in content  # the onward callback the chain extractor must find


def test_evidence_rank_stamped() -> None:
    obs = C2Observation(c2_host="59.96.137.61", evidence="served_file")
    assert obs.evidence_rank == 1
    assert EVIDENCE_RANK["file_callback"] == 2


def test_self_hosted_default_and_chain_edge() -> None:
    obs = C2Observation(
        c2_host="5.6.7.8",
        evidence="file_callback",
        c2_via_sha256="8c1bd2718a3f3ba16b34a9aa05ea0ec9968fc1d402ca6f33323fbd0a1f06b1a1",
    )
    assert obs.evidence_rank == 2
    assert obs.self_hosted is False
    assert obs.content is None  # only served_file script rows carry content
