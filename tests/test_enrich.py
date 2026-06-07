"""Ported session enrichment (Tier 1+2) and its consistency with the C2 ledger."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from c2engine.context import build_context
from c2engine.pipeline.extract import all_observations
from c2engine.model import SessionIn
from c2engine.pipeline import process

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def raw() -> dict:
    return json.loads((FIXTURES / "session_basic.json").read_text())


def test_iocs_fields(raw: dict) -> None:
    hp = process(raw).session_doc["hp_data"]
    assert hp["iocs_ips"] == ["59.96.137.61"]
    assert "http://59.96.137.61/bins/x.sh" in hp["iocs_urls"]
    # eTLD+1 grouping form on the soft field; full host on the pivot
    assert "example.com" in hp["iocs_domains"]
    assert hp["iocs_c2_hosts"] == ["59.96.137.61", "evil.example.com"]


def test_playbook_is_sha1_and_stable(raw: dict) -> None:
    hp = process(raw).session_doc["hp_data"]
    assert len(hp["playbook_hash"]) == 40  # SHA1, production-compatible
    assert hp["playbook_canonical"]  # canonical text present
    # canonicalization squashes volatile bits (URLs/IPs) so reruns hash identically
    canon = hp["playbook_canonical"]
    assert "<url>" in canon and "59.96.137.61" not in canon


def test_banner_cpe(raw: dict) -> None:
    hp = process(raw).session_doc["hp_data"]
    # fixture banner: SSH-2.0-libssh2_1.4.3
    assert hp["banner_product"] == "libssh2"
    assert hp["banner_version"] == "1.4.3"
    assert hp["banner_cpe23"].startswith("cpe:2.3:a:")


def test_shape_and_creds(raw: dict) -> None:
    hp = process(raw).session_doc["hp_data"]
    assert hp["shape_command_count"] == 3
    assert hp["shape_cred_attempts"] == 1
    assert hp["cred_success_user"] == "root"
    assert hp["cred_sequence_hash"] and len(hp["cred_sequence_hash"]) == 40


def test_timing_dropped(raw: dict) -> None:
    hp = process(raw).session_doc["hp_data"]
    assert not any(k.startswith("timing_") for k in hp)  # deferred to reason layer


def test_ledger_and_session_share_one_source(raw: dict) -> None:
    """The complementary guarantee: session c2_hosts == the shell_reference
    rows' hosts, because both read the same IoC bundle."""
    session = SessionIn.model_validate(raw)
    ctx = build_context(session)
    obs = all_observations(session, ctx)
    shell_hosts = {o.c2_host for o in obs if o.evidence == "shell_reference"}
    assert shell_hosts == set(ctx.iocs.c2_hosts)
    assert process(raw).session_doc["c2_host"] == ctx.iocs.c2_hosts
