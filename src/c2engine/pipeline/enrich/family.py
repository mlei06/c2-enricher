"""Rules-based malware family labels — ``category.family/format`` convention.

Cheap static heuristics only (shebang, strings markers, magic + arch). NO
external lookups — VT/intel escalation is the phase-2 reason layer
(DESIGN.md §9). A miss returns None; over-labelling is worse than silence,
so every label carries ``/possible`` unless the marker is unambiguous.
"""

from __future__ import annotations

import re

# (compiled marker, label) — first match wins, order = specificity.
_BINARY_MARKERS: list[tuple[re.Pattern[bytes], str]] = [
    (re.compile(rb"(?i)\bmozi\b"), "trojan.mirai/mozi"),
    (re.compile(rb"(?i)gafgyt|bashlite"), "trojan.gafgyt/possible"),
    (re.compile(rb"(?i)/bin/busybox\s+MIRAI|\bMIRAI\b"), "trojan.mirai/possible"),
    (re.compile(rb"(?i)stratum\+tcp://|xmrig|minerd"), "miner.xmrig"),
]

_SCRIPT_MARKERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)stratum\+tcp://|xmrig|minerd"), "miner.shell"),
    (
        # fetch + make-executable + run = a classic dropper chain
        re.compile(r"(?i)(wget|curl|tftp)\b.*(chmod|\./|sh\b)", re.DOTALL),
        "downloader.shell",
    ),
]


def label(content: bytes, magic: str | None, interpreter: str | None) -> str | None:
    if magic and magic.startswith("ELF"):
        for pat, name in _BINARY_MARKERS:
            if pat.search(content):
                return name
        # An ELF that fetches nothing identifiable is still a suspect binary,
        # tagged by arch so the dashboard can group it.
        arch = magic.split()[-1].lower()
        return f"trojan.elf/{arch}"

    if interpreter is not None:
        try:
            text = content.decode("utf-8", "ignore")
        except Exception:  # pragma: no cover - decode never raises with errors=ignore
            return None
        for pat, name in _SCRIPT_MARKERS:
            if pat.search(text):
                return name

    return None
