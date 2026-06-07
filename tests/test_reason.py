"""M2 reason layer: stage/signal overlay logic."""

from __future__ import annotations

from c2engine.services.reason.engine import (
    _rank_to_stage,
    compute_overlay,
    load_hassh_toolkits,
    load_known_shas,
)

KNOWN = {"6f52dccd62f25ee71277c6b39b1604ab379e4d2080c90fe6194e77cda54a854c"}
TOOLKITS = {"92674389fa1e47a27ddd8d9b63ecd42b": "mirai-loader"}


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


def test_known_malware_annotates_without_escalating() -> None:
    """A known-malware sha adds the signal but does NOT change the stage — the
    evidence ladder alone sets stage (GreyNoise model)."""
    sha = next(iter(KNOWN))
    ov = compute_overlay(1, ["trojan.mirai/mozi"], [sha.upper()], KNOWN)  # case-insensitive
    assert ov["stage"] == "stage1_serving"  # unchanged by intel
    assert "known_malware" in ov["stage_signals"]


def test_known_shas_seed_loads() -> None:
    known = load_known_shas()
    assert isinstance(known, set) and len(known) >= 1
    assert all(s == s.lower() for s in known)


def test_hassh_attributes_toolkit_without_escalating() -> None:
    """A known-toolkit HASSH annotates (attributed_toolkit + signal) but does
    NOT promote the stage — it identifies the attacker's client, not the host."""
    hassh = next(iter(TOOLKITS))
    ov = compute_overlay(0, [], [], KNOWN, [hassh.upper()], TOOLKITS)  # case-insensitive
    assert ov["stage"] == "unconfirmed"  # floor unchanged
    assert ov["attributed_toolkit"] == ["mirai-loader"]
    assert "hassh_toolkit" in ov["stage_signals"]


def test_unknown_hassh_no_attribution() -> None:
    ov = compute_overlay(1, [], [], KNOWN, ["deadbeefdeadbeefdeadbeefdeadbeef"], TOOLKITS)
    assert "attributed_toolkit" not in ov
    assert "hassh_toolkit" not in ov["stage_signals"]


def test_hassh_args_optional() -> None:
    """Existing callers that omit the hassh args still work (no attribution)."""
    ov = compute_overlay(1, [], [], KNOWN)
    assert "attributed_toolkit" not in ov


def test_hassh_toolkits_seed_loads() -> None:
    tk = load_hassh_toolkits()
    assert isinstance(tk, dict) and len(tk) >= 1
    assert all(k == k.lower() for k in tk)
