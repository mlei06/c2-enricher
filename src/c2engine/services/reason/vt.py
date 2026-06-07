"""VirusTotal enrichment for the reason layer (M3).

One VT lookup per distinct served-file ``sha256`` ever (cached fleet-wide in
``c2-vt``), bounded per run, **disabled unless ``VT_API_KEY`` is set**. VT's rate
limits and latency must never touch ingestion — this runs inside the out-of-band
reason job, and a missing/slow/over-budget VT simply means the verdict is filled
in on a later pass (DESIGN_PARITY.md §3 M3).

Public-tier safety: the default per-run cap (4) matches VT's 4 req/min free limit
(the reason loop sleeps minutes between runs), and the per-file cache means each
hash is fetched once until its verdict goes stale (``VT_TTL_DAYS``), keeping well
under the 500/day quota for normal honeypot file volume.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from c2engine.elastic.client import EsWriter
from c2engine.elastic.schema import VT_INDEX, VT_TTL_DAYS

log = logging.getLogger(__name__)

VT_URL = "https://www.virustotal.com/api/v3/files/"
DEFAULT_MAX_PER_RUN = 4  # == VT public 4/min; loop sleeps between runs
DEFAULT_MIN_MALICIOUS = 1  # engines flagging malicious needed to escalate stage


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def parse_vt_file(data: dict[str, Any], sha256: str, checked_at: str) -> dict[str, Any]:
    """VT v3 /files/{id} JSON -> our cache doc. Pure (no IO)."""
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    mal = int(stats.get("malicious", 0) or 0)
    susp = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values())
    ptc = attrs.get("popular_threat_classification") or {}
    fams: list[str] = []
    if ptc.get("suggested_threat_label"):
        fams.append(ptc["suggested_threat_label"])
    fams += [n["value"] for n in ptc.get("popular_threat_name", []) if n.get("value")]
    return {
        "sha256": sha256,
        "vt_found": True,
        "vt_malicious": mal,
        "vt_suspicious": susp,
        "vt_total": total,
        "vt_ratio": round(mal / total, 4) if total else 0.0,
        "vt_families": sorted(set(fams)),
        "checked_at": checked_at,
    }


def _not_found(sha256: str, checked_at: str) -> dict[str, Any]:
    return {
        "sha256": sha256, "vt_found": False, "vt_malicious": 0, "vt_suspicious": 0,
        "vt_total": 0, "vt_ratio": 0.0, "vt_families": [], "checked_at": checked_at,
    }


class VtClient:
    """Thin VT v3 file-report client. ``enabled`` is False without an API key."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("VT_API_KEY", "")
        self.enabled = bool(self.api_key)

    def lookup(self, sha256: str, checked_at: str) -> dict[str, Any] | None:
        """Return a verdict dict (found or not-found), or None to skip this pass
        (rate-limited / transient error / network — retried next run)."""
        req = urllib.request.Request(
            VT_URL + sha256, headers={"x-apikey": self.api_key, "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return parse_vt_file(json.loads(resp.read().decode("utf-8")), sha256, checked_at)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return _not_found(sha256, checked_at)  # VT doesn't know it (yet)
            if exc.code == 401:
                log.error("VT 401 unauthorized — disabling VT for this process")
                self.enabled = False
                return None
            log.warning("VT %s for %s — skipping this pass", exc.code, sha256[:12])
            return None
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            log.warning("VT lookup failed for %s: %s", sha256[:12], exc)
            return None


class VtResolver:
    """Cache-first, budget-bounded VT resolution for a single reason pass."""

    def __init__(
        self,
        es: EsWriter,
        client: VtClient | None = None,
        *,
        now: datetime.datetime | None = None,
        max_per_run: int | None = None,
    ) -> None:
        self.es = es
        self.client = client or VtClient()
        self.now = now or datetime.datetime.now(datetime.UTC)
        self._checked_at = self.now.strftime("%Y-%m-%dT%H:%M:%SZ")
        self._ttl = datetime.timedelta(days=VT_TTL_DAYS)
        self.budget = max_per_run if max_per_run is not None else _env_int(
            "C2E_VT_MAX_PER_RUN", DEFAULT_MAX_PER_RUN
        )
        self.looked_up = 0
        self._mem: dict[str, dict[str, Any] | None] = {}  # sha -> verdict|None (this run)

    def _is_fresh(self, checked_at: str | None) -> bool:
        if not checked_at:
            return False
        try:
            dt = datetime.datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        return (self.now - dt) < self._ttl

    def _read_cache(self, shas: list[str]) -> dict[str, dict[str, Any]]:
        try:
            res = self.es.search(VT_INDEX, {"size": len(shas), "query": {"ids": {"values": shas}}})
        except RuntimeError:
            return {}  # cache index not created yet (first run) — treat as empty
        fresh: dict[str, dict[str, Any]] = {}
        for h in res.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            sha = src.get("sha256") or h.get("_id")
            if sha and self._is_fresh(src.get("checked_at")):
                fresh[sha] = src
        return fresh

    def verdicts_for(self, shas: list[str]) -> list[dict[str, Any]]:
        """Resolve verdicts for `shas` (cache-first, then bounded live lookups).
        Returns only the verdicts we have (found or not-found); skipped ones omitted."""
        want = [s for s in dict.fromkeys(shas) if s and s not in self._mem]
        if want:
            fresh = self._read_cache(want)
            self._mem.update(fresh)
            for s in want:
                if s in self._mem:
                    continue
                if not self.client.enabled or self.budget <= 0:
                    self._mem[s] = None  # try next run
                    continue
                v = self.client.lookup(s, self._checked_at)
                self.budget -= 1
                self.looked_up += 1
                if v is not None:
                    self.es.index_doc(VT_INDEX, s, v)
                self._mem[s] = v
        return [v for s in shas if (v := self._mem.get(s))]


def summarize_vt(verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-entity VT rollup across its files' verdicts. Pure."""
    known = [v for v in verdicts if v.get("vt_found")]
    if not known:
        return {}
    fams = sorted({f for v in known for f in (v.get("vt_families") or [])})
    return {
        "max_vt_ratio": max(float(v.get("vt_ratio", 0.0)) for v in known),
        "max_vt_malicious": max(int(v.get("vt_malicious", 0)) for v in known),
        "vt_families": fams,
    }


def apply_vt(
    overlay: dict[str, Any], summary: dict[str, Any], min_malicious: int = DEFAULT_MIN_MALICIOUS
) -> dict[str, Any]:
    """Overlay VT onto the stage/signals overlay. Escalates (never demotes)."""
    if not summary:
        return overlay
    out = dict(overlay)
    out["max_vt_ratio"] = summary["max_vt_ratio"]
    if summary["vt_families"]:
        out["vt_families"] = summary["vt_families"]
    if summary["max_vt_malicious"] >= min_malicious:
        out["stage"] = "stage2_c2"
        out["stage_signals"] = sorted(set(out.get("stage_signals", [])) | {"virustotal"})
    return out
