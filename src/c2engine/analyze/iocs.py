"""Extract raw IoCs from attacker text — the ONE host/IoC source.

Used by the session enrichment (``iocs_*`` fields) and the C2 ledger
(``shell_reference`` rows, file callbacks), so ``c2_hosts`` on a session and
the ``c2_host`` rows in the ledger are guaranteed consistent.

Pure structuring: every value is a literal substring lifted from the text. No
CVE/family/threat-intel mapping — that's the reasoning layer's job.

Note the deliberate split (diverging from the old proxy, to keep the C2 pivot
clean):
  * ``hostnames`` / ``c2_hosts`` — FULL hosts (IPs + FQDNs as seen). The pivot.
  * ``domains``                  — eTLD+1 grouping form (sub.evil.com -> evil.com).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

_RE_URL = re.compile(r"\b(?:https?|ftp|tftp)://[^\s\"'`<>|]+", re.IGNORECASE)
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){4,}[0-9a-fA-F]{1,4}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_RE_SSHKEY = re.compile(
    r"(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521))\s+([A-Za-z0-9+/=]{64,})"
)


@dataclass
class IocBundle:
    ips: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)  # eTLD+1 grouping form
    hostnames: list[str] = field(default_factory=list)  # full hosts (FQDNs)
    file_hashes: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    ssh_key_sha1s: list[str] = field(default_factory=list)

    @property
    def c2_hosts(self) -> list[str]:
        """IPs + full hostnames — the actual C2 endpoints. NOT eTLD+1 domains
        (those live in ``domains`` for grouping)."""
        return _dedupe([*self.ips, *self.hostnames])


def _dedupe(seq) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def _etld1(host: str) -> str | None:
    if is_ip(host):
        return None
    parts = host.rsplit(".", 2)
    return ".".join(parts[-2:]) if len(parts) >= 2 else None


def _strip_url_punct(url: str) -> str:
    return url.rstrip(").],};\"'>")


def extract(text: str, existing_urls: list[str] | None = None) -> IocBundle:
    """Run every IoC pass over ``text``; ``existing_urls`` (Cowrie downloads)
    are folded in so callers don't merge."""
    b = IocBundle()
    blob = text or ""

    urls = [_strip_url_punct(u) for u in _RE_URL.findall(blob)]
    if existing_urls:
        urls = [*existing_urls, *urls]
    b.urls = _dedupe(urls)

    ips_raw = _RE_IPV4.findall(blob) + _RE_IPV6.findall(blob)
    b.ips = _dedupe(ip.split(":")[0] if ip.count(":") == 1 else ip for ip in ips_raw)

    # hostnames feed the c2_hosts PIVOT, so take them only from real URLs —
    # clear intent. Bare _RE_DOMAIN matches over shell text are too noisy for a
    # pivot (file names like "x.sh" match, since .sh is a TLD); they feed only
    # the softer iocs_domains grouping field below.
    hostnames: list[str] = []
    domains: list[str] = []
    for u in b.urls:
        h = (urlparse(u).hostname or "") if "://" in u else ""
        if h and not is_ip(h):
            hostnames.append(h)
            d = _etld1(h)
            if d:
                domains.append(d)
    for cand in _RE_DOMAIN.findall(blob):
        if is_ip(cand):
            continue
        d = _etld1(cand)
        if d:
            domains.append(d)
    b.hostnames = _dedupe(hostnames)
    b.domains = _dedupe(domains)

    hashes = _RE_SHA256.findall(blob) + _RE_SHA1.findall(blob) + _RE_MD5.findall(blob)
    b.file_hashes = _dedupe(h.lower() for h in hashes)
    b.cve_ids = _dedupe(m.upper() for m in _RE_CVE.findall(blob))
    b.ssh_key_sha1s = _dedupe(
        hashlib.sha1(m.group(1).encode("ascii")).hexdigest()
        for m in _RE_SSHKEY.finditer(blob)
    )
    return b
