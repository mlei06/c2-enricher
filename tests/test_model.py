"""Milestone 1: the wire contracts hold against the golden fixture."""

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
    assert s.ident == "a82be2b776ab4161911eb9114b8b1234"
    assert s.src_ip == "59.96.137.61"
    assert s.hp_data.commands and "wget" in s.hp_data.commands[1]
    assert s.hp_data.files and s.hp_data.files[0].resolved_ip == "59.96.137.61"


def test_unknown_fields_survive_roundtrip(raw_session: dict) -> None:
    """The pass-through invariant: fields we don't model ride along verbatim."""
    s = SessionIn.model_validate(raw_session)
    dumped = s.model_dump()
    assert dumped["hp_data"]["unknown_stock_field"] == "must pass through verbatim"
    assert dumped["app"] == "cowrie"


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
