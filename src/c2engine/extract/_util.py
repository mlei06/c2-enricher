"""Shared extraction primitives: host/URL parsing, command unwrapping, sniffing.

Re-derived for c2-engine (reference only: the abandoned stingar-enrichment
branch's core/extractors/iocs.py and core/parsers). Pure, dependency-free.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from urllib.parse import urlsplit

# A URL with an explicit scheme. Deliberately permissive on the path.
_URL_RE = re.compile(r"""\b(?:https?|ftp|tftp)://[^\s'"`)>;|\\]+""", re.IGNORECASE)

# A bare IPv4 literal (optionally :port). Domains are NOT matched bare —
# too noisy in shell text; we only take domains that appear inside a URL.
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# A base64-ish run long enough to plausibly carry a wrapped command.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


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


def _b64_expansions(text: str) -> list[str]:
    """Decoded UTF-8 strings for every base64-looking run that decodes cleanly.

    Catches the ``echo <b64> | base64 -d | sh`` wrapper without trying to
    actually parse the shell. One level deep — enough in practice.
    """
    out: list[str] = []
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        if len(blob) % 4:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            out.append(decoded.decode("utf-8"))
        except UnicodeDecodeError:
            continue
    return out


def find_hosts(text: str) -> list[tuple[str, str]]:
    """Every (host, kind) referenced in ``text`` and its base64 expansions.

    Order-preserving, de-duplicated. Sees through ``nohup``/``bash -c``/
    ``eval``/``echo|sh`` simply because they leave the URL/IP in the literal
    text; the only wrapper that hides it is base64, handled explicitly.
    """
    seen: dict[str, tuple[str, str]] = {}
    haystacks = [text, *_b64_expansions(text)]
    for hay in haystacks:
        for url in _URL_RE.findall(hay):
            host, _, _ = split_url(url)
            if host:
                seen.setdefault(host, (host, classify_host(host)))
        for ip in _IPV4_RE.findall(hay):
            seen.setdefault(ip, (ip, "ip"))
    return list(seen.values())


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
