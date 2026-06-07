"""Canonicalize a session's command list into a stable playbook hash.

Two sessions running the same attack produce the same ``playbook_hash`` even
when the attacker rotates IPs, tmp paths, and SSH keys. SHA1 — matching the
production enrichment so historical playbook grouping stays continuous (the
c2-engine replaces the old proxy without re-keying the field).
"""

from __future__ import annotations

import hashlib
import re

_RE_URL = re.compile(r"https?://[^\s\"'`>]+", re.IGNORECASE)
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{1,4}\b")
_RE_TMPRAND = re.compile(r"(?:/tmp|/var/tmp|/dev/shm)/(?:\.)?[A-Za-z0-9_.-]{6,}")
_RE_SSHKEY = re.compile(
    r"(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521))\s+([A-Za-z0-9+/=]{64,})"
)
_RE_B64BLOB = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")
_RE_WS = re.compile(r"\s+")


def _hash_short(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:12]


def canonicalize_command(cmd: str) -> str:
    out = cmd
    out = _RE_SSHKEY.sub(lambda m: f"{m.group(1)} <SSH_KEY:{_hash_short(m.group(2))}>", out)
    out = _RE_URL.sub("<URL>", out)
    out = _RE_IPV6.sub("<IP>", out)
    out = _RE_IPV4.sub("<IP>", out)
    out = _RE_TMPRAND.sub(lambda m: f"{m.group(0).rsplit('/', 1)[0]}/<RAND>", out)
    out = _RE_B64BLOB.sub(lambda m: f"<B64:{_hash_short(m.group(0))}>", out)
    return _RE_WS.sub(" ", out).strip().lower()


def canonicalize_and_hash(commands: list[str], unknown_commands: list[str]) -> tuple[str, str]:
    """Return (canonical_text, sha1_hash). Command order is preserved (it's
    semantically meaningful); unknown_commands are tagged so they canonicalize
    apart from successful ones."""
    lines = [canonicalize_command(c) for c in commands]
    lines.extend(f"[unknown] {canonicalize_command(c)}" for c in unknown_commands)
    canonical = "\n".join(lines)
    return canonical, hashlib.sha1(canonical.encode("utf-8")).hexdigest()
