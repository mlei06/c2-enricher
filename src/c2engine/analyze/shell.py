"""Recursive shell payload unwrapping.

Attackers hide the real payload inside ``echo "..." | sh``,
``base64 -d <<< "..."``, or ``eval $(...)``. ``expand_commands`` returns every
command's wrapper text plus any decoded inner payloads, so the IoC and
canonical passes see what the attacker tried to hide. Regex-only (no bashlex
dependency) — the parse-argv path the old taggers needed is gone with timing.
"""

from __future__ import annotations

import base64
import binascii
import re

_BASE64_PATTERNS = [
    re.compile(
        r"""base64\s+(?:-d|--decode)\s+<<<\s*["']?([A-Za-z0-9+/=]+)["']?""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""echo\s+["']([A-Za-z0-9+/=]+)["']\s*\|\s*base64\s+(?:-d|--decode)""",
        re.IGNORECASE,
    ),
]
_ECHO_PIPE_SH = re.compile(
    r"""echo\s+["'](.+?)["']\s*\|\s*(?:sh|bash|/bin/sh|/bin/bash)\b""",
    re.IGNORECASE | re.DOTALL,
)
_EVAL_SUBSHELL = re.compile(r"""eval\s+["`$(]+(.+?)[`)"]+""", re.IGNORECASE | re.DOTALL)

_MAX_RECURSION = 4


def _try_b64_decode(blob: str) -> str | None:
    blob = blob.strip()
    blob += "=" * ((-len(blob)) % 4)
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def _unwrap_once(text: str) -> list[str]:
    out: list[str] = []
    for pattern in _BASE64_PATTERNS:
        for m in pattern.finditer(text):
            decoded = _try_b64_decode(m.group(1))
            if decoded:
                out.append(decoded)
    out.extend(m.group(1) for m in _ECHO_PIPE_SH.finditer(text))
    out.extend(m.group(1) for m in _EVAL_SUBSHELL.finditer(text))
    return out


def expanded_text(commands: list[str]) -> str:
    """Every command's wrapper + all decoded inner payloads, newline-joined.

    The single string the regex IoC passes run against.
    """
    lines: list[str] = []
    for raw in commands:
        lines.append(raw)
        seen: set[str] = {raw}
        queue = [raw]
        depth = 0
        while queue and depth < _MAX_RECURSION:
            depth += 1
            nxt: list[str] = []
            for text in queue:
                for decoded in _unwrap_once(text):
                    if decoded not in seen:
                        seen.add(decoded)
                        lines.append(decoded)
                        nxt.append(decoded)
            queue = nxt
    return "\n".join(lines)
