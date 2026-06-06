"""M2 reason layer: stage/signal overlay logic."""

from __future__ import annotations

from c2engine.reason.engine import _rank_to_stage, compute_overlay, load_known_shas

KNOWN = {"6f52dccd62f25ee71277c6b39b1604ab379e4d2080c90fe6194e77cda54a854c"}


def test_rank_to_stage() -> None:
    assert _rank_to_stage(0) == "unconfirmed"
    assert _rank_to_stage(1) == "stage1_serving"
    assert _rank_to_stage(2) == "stage2_c2"


def test_referenced_only_is_unconfirmed() -> None:
    ov = compute_overlay(0, [], [], KNOWN)
    assert ov["stage"] == "unconfirmed"
    assert ov["stage_signals"] == []


def test_served_file_is_stage1() -> None:
    ov = compute_overlay(1, ["downloader.shell"], ["deadbeef"], KNOWN)
    assert ov["stage"] == "stage1_serving"
    assert ov["stage_signals"] == []
    assert ov["families"] == ["downloader.shell"]


def test_callback_is_stage2() -> None:
    ov = compute_overlay(2, [], [], KNOWN)
    assert ov["stage"] == "stage2_c2"
    assert "callback_in_malware" in ov["stage_signals"]


def test_known_malware_escalates_stage1_to_stage2() -> None:
    """A served file whose sha is known malware lifts a stage1 host to stage2."""
    sha = next(iter(KNOWN))
    ov = compute_overlay(1, ["trojan.mirai/mozi"], [sha.upper()], KNOWN)  # case-insensitive
    assert ov["stage"] == "stage2_c2"
    assert "known_malware" in ov["stage_signals"]


def test_known_shas_seed_loads() -> None:
    known = load_known_shas()
    assert isinstance(known, set) and len(known) >= 1
    assert all(s == s.lower() for s in known)
