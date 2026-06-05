"""Shared extraction primitives: host/URL parsing, command unwrapping, sniffing.

Re-derived for c2-engine (reference only: the abandoned stingar-enrichment
branch's core/extractors/iocs.py and core/parsers). Pure, dependency-free.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


def classify_host(host: str) -> str:
    """``"ip"`` for an IPv4/IPv6 literal, else ``"domain"``."""
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"


def split_url(url: str) -> tuple[str, int | None, str]:
    """``url`` -> (host, port, path). Host is lowercased; port may be None."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    return host, parts.port, parts.path or ""


def find_hosts(text: str) -> list[tuple[str, str]]:
    """Every (host, kind) referenced in ``text`` — IPs and full hostnames.

    Delegates to the shared :mod:`c2engine.core.iocs` extractor (expanding
    shell wrappers first) so file-content callbacks and the session's
    ``c2_hosts`` come from one source. Order-preserving, de-duplicated.
    """
    from c2engine.core import iocs as iocs_mod
    from c2engine.core import shell as shell_mod

    bundle = iocs_mod.extract(shell_mod.expanded_text([text]))
    return [(h, classify_host(h)) for h in bundle.c2_hosts]


# --- file sniffing -------------------------------------------------------

# ELF e_machine values we expect from IoT-botnet droppers.
_ELF_MACHINES = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    40: "ARM",
    42: "SuperH",
    62: "x86-64",
    183: "AArch64",
}


def sniff_magic(data: bytes) -> str | None:
    """A short human magic string for the common honeypot-payload types."""
    if data[:4] == b"\x7fELF":
        bits = {1: "32-bit", 2: "64-bit"}.get(data[4], "?")
        little = data[5] == 1
        e_machine = int.from_bytes(data[18:20], "little" if little else "big")
        arch = _ELF_MACHINES.get(e_machine, f"machine {e_machine}")
        return f"ELF {bits} {arch}"
    if data[:2] == b"#!":
        return "script (shebang)"
    if data[:2] == b"MZ":
        return "PE/DOS executable"
    if data[:4] in (b"\x1f\x8b\x08\x08", b"\x1f\x8b\x08\x00"):
        return "gzip"
    return None


def interpreter_of(content: str) -> str | None:
    """The interpreter named on a script's shebang, e.g. ``sh``/``bash``/``python``."""
    if not content.startswith("#!"):
        return None
    first = content.splitlines()[0]
    # "#!/usr/bin/env python3" -> python3 ; "#!/bin/sh -e" -> sh
    tokens = first[2:].strip().split()
    if not tokens:
        return None
    exe = tokens[0].rsplit("/", 1)[-1]
    if exe == "env" and len(tokens) > 1:
        exe = tokens[1].rsplit("/", 1)[-1]
    return re.sub(r"\d+(\.\d+)*$", "", exe) or exe


def strings(data: bytes, minimum: int = 6) -> str:
    """Printable-ASCII runs from binary ``data``, joined by newlines.

    Lets :func:`find_hosts` mine hardcoded C2 URLs/IPs out of ELF droppers
    (Mirai variants frequently embed them in plaintext).
    """
    runs = re.findall(rb"[\x20-\x7e]{%d,}" % minimum, data)
    return "\n".join(r.decode("ascii") for r in runs)
