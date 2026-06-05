# Copyright (C) 2026 Forewarned, Inc.
#
# SPDX-License-Identifier: BSD-3-Clause

"""In-session URL fetcher for Cowrie.

Listens for ``cowrie.command.input`` events. For every command an
attacker types, this plugin extracts URLs (including ones hidden inside
``nohup $SHELL -c "..."``, ``bash -c``, ``eval``, ``echo "..." | sh``,
and ``base64 -d <<< "..."`` | sh`` wrappers), then fetches each URL using
Cowrie's network identity and writes the bytes into Cowrie's downloads
directory keyed by SHA256.

Cowrie's built-in ``curl``/``wget``/``tftp``/``ftpget``/``scp`` emulators
already handle this when the parser dispatches successfully. This plugin
fills the gap for wrapper-hidden URLs and for tools Cowrie doesn't
emulate (e.g. ``aria2c``, custom loaders) — the bytes still end up in
the same downloads dir so the rest of the pipeline (the Stingar plugin,
the central c2-engine) treats them identically.

Why in-session and not after-the-fact:

* The fetch goes out from Cowrie's own network identity — the C2 sees
  the same victim IP the attacker targeted, not a different scanner IP.
* The fetch happens at attack time, so we capture content the attacker
  would have received (C2s often rotate / serve decoys later).
* Cowrie's existing downloads-dir infrastructure does the rest.

The resolved IP of each fetched host is recorded on the
``cowrie.session.file_download`` event (``resolved_ip``) so the central
engine can geolocate domain-named C2s on the address actually contacted
at attack time.

Hard-coded safety guards:

* Scheme allowlist: ``http``/``https``/``ftp``/``tftp`` only.
* SSRF / private-network skip: RFC 1918, RFC 5737, loopback, link-local,
  multicast, IMDS — never fetch from these.
* No redirects (SSRF defense).
* TLS verification off (attacker C2s use self-signed certs); bytes
  treated as opaque blob, never executed.
* 50 MB size cap, 5 s connect / 10 s read timeout.
* Per-URL in-process cache so a hot C2 only gets one fetch per Cowrie
  process lifetime.
* Fetches run on a worker thread (``reactor.callInThread``) so the
  Cowrie session loop is not blocked while the fetch is in flight.

Config (under ``[output_urlfetcher]`` in ``cowrie.cfg``)::

    enabled       = true
    download_path = ${honeypot:download_path}    # use Cowrie's normal dir
    timeout_s     = 10
    max_bytes     = 52428800
    user_agent    = Wget/1.21.2
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import logging
import os
import re
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from twisted.internet import reactor
from twisted.python import log as twisted_log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

logger = logging.getLogger("cowrie.output.urlfetcher")


# ---------------------------------------------------------------------------
# URL extraction + wrapper unwrapping
# ---------------------------------------------------------------------------

_RE_URL = re.compile(r"\b(?:https?|ftp|tftp)://[^\s\"'`<>|]+", re.IGNORECASE)

# Cowrie has native command emulators for these downloaders. When the
# attacker types one of them directly, Cowrie fetches the bytes itself
# and emits cowrie.session.file_download — we must NOT fetch again or
# the payload index gets duplicate entries. The plugin only kicks in
# when the URL is hidden inside a wrapper Cowrie's parser can't unfurl
# (bash -c "...", echo "..."|sh, base64 -d <<<..., eval ..., or a
# command name Cowrie doesn't emulate).
_NATIVE_DOWNLOADER_BASENAMES = frozenset(
    {"wget", "curl", "tftp", "ftpget", "scp"}
)

# Split on shell separators so `cd /tmp && wget X; rm Y` is analyzed
# segment-by-segment — each side of `&&`/`||`/`;`/`|` is one dispatch.
_SHELL_SEPARATORS_RE = re.compile(r"&&|\|\||[;&|\n]+")


def _segment_dispatches_to_native(segment: str) -> bool:
    """True if Cowrie's parser will dispatch ``segment`` to a downloader.

    Only the segment's first token matters: ``nohup wget X`` dispatches
    to ``nohup`` (a no-op), not to ``wget``, so its URL is in our gap;
    ``wget X`` and ``/usr/bin/wget X`` both dispatch to ``wget`` and we
    leave them to native.
    """
    tokens = segment.strip().split()
    if not tokens:
        return False
    basename = tokens[0].rsplit("/", 1)[-1]
    return basename in _NATIVE_DOWNLOADER_BASENAMES

# Wrapper patterns: each captures the inner shell text we should re-scan.
_RE_BASE64_HERESTRING = re.compile(
    r"""base64\s+(?:-d|--decode)\s+<<<\s*["']?([A-Za-z0-9+/=]+)["']?""",
    re.IGNORECASE,
)
_RE_BASE64_ECHO_PIPE = re.compile(
    r"""echo\s+["']([A-Za-z0-9+/=]+)["']\s*\|\s*base64\s+(?:-d|--decode)""",
    re.IGNORECASE,
)
_RE_ECHO_PIPE_SH = re.compile(
    r"""echo\s+["'](.+?)["']\s*\|\s*(?:sh|bash|/bin/sh|/bin/bash)\b""",
    re.IGNORECASE | re.DOTALL,
)
_RE_EVAL_SUBSHELL = re.compile(
    r"""eval\s+["`$(]+(.+?)[`)"]+""", re.IGNORECASE | re.DOTALL
)
_RE_SHELL_DASH_C = re.compile(
    r"""(?:nohup\s+)?(?:bash|sh|\$SHELL|/bin/bash|/bin/sh)\s+-c\s+["'](.+?)["']""",
    re.IGNORECASE | re.DOTALL,
)

_MAX_UNWRAP_DEPTH = 4


def _try_b64_decode(blob: str) -> str | None:
    blob = blob.strip()
    pad = (-len(blob)) % 4
    try:
        raw = base64.b64decode(blob + ("=" * pad), validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def _unwrap_once(text: str) -> list[str]:
    """Return any payloads hidden inside ``text``. Empty list if nothing matched."""
    out: list[str] = []
    for pat in (_RE_BASE64_HERESTRING, _RE_BASE64_ECHO_PIPE):
        for m in pat.finditer(text):
            decoded = _try_b64_decode(m.group(1))
            if decoded:
                out.append(decoded)
    for m in _RE_ECHO_PIPE_SH.finditer(text):
        out.append(m.group(1))
    for m in _RE_EVAL_SUBSHELL.finditer(text):
        out.append(m.group(1))
    for m in _RE_SHELL_DASH_C.finditer(text):
        out.append(m.group(1))
    return out


def extract_urls(cmd: str) -> list[str]:
    """Pull every URL out of ``cmd`` and any wrapper-hidden inner payloads.

    The OUTER command is scanned segment-by-segment: segments that
    Cowrie's parser will dispatch to a native downloader (``wget``,
    ``curl``, etc.) are skipped — native captures those bytes and we
    must not double-fetch. UNWRAPPED inner shell texts are always
    scanned in full, because Cowrie's parser never saw them.
    """
    seen_text: set[str] = {cmd}
    queue = [cmd]
    inner_texts: list[str] = []
    depth = 0
    while queue and depth < _MAX_UNWRAP_DEPTH:
        depth += 1
        next_queue: list[str] = []
        for text in queue:
            for decoded in _unwrap_once(text):
                if decoded not in seen_text:
                    seen_text.add(decoded)
                    inner_texts.append(decoded)
                    next_queue.append(decoded)
        queue = next_queue

    urls: list[str] = []
    seen: set[str] = set()

    def _take(u: str) -> None:
        u = u.rstrip(").],};\"'>")
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    # Outer cmd: only segments that Cowrie's parser will NOT dispatch
    # to a native downloader. URLs in segments dispatched to native
    # downloaders are captured by Cowrie's wget/curl/… emulators.
    for segment in _SHELL_SEPARATORS_RE.split(cmd):
        if _segment_dispatches_to_native(segment):
            continue
        for u in _RE_URL.findall(segment):
            _take(u)

    # Unwrapped layers: Cowrie's parser never saw these. Extract URLs
    # from the full text — natives can't have captured them.
    for text in inner_texts:
        for u in _RE_URL.findall(text):
            _take(u)

    return urls


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

_SKIP_IPV4 = [
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
]
_SKIP_IPV6 = [
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("ff00::/8"),
    ipaddress.IPv6Network("2001:db8::/32"),
]


def _ip_is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in _SKIP_IPV4)
    return any(addr in net for net in _SKIP_IPV6)


def _host_is_private(host: str) -> bool:
    return _ip_is_private(host)


def _resolve(host: str) -> str | None:
    """Resolve ``host`` to an IPv4 string (or pass an IP literal through).

    Blocking — only ever called from the fetch worker thread. Returns None
    on resolution failure.
    """
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def url_is_fetchable(url: str) -> bool:
    """Strict allowlist + SSRF check. Returns False for anything we won't fetch."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme.lower() not in {"http", "https", "ftp", "tftp"}:
        return False
    host = parsed.hostname
    if not host:
        return False
    if _host_is_private(host):
        return False
    return True


# ---------------------------------------------------------------------------
# Cowrie output plugin
# ---------------------------------------------------------------------------


class Output(cowrie.core.output.Output):
    """Cowrie output plugin — fetches attacker-referenced URLs in-session."""

    def __init__(self) -> None:
        self.download_path = CowrieConfig.get(
            "output_urlfetcher",
            "download_path",
            fallback=CowrieConfig.get(
                "honeypot",
                "download_path",
                fallback="var/lib/cowrie/downloads",
            ),
        )
        self.timeout_s = CowrieConfig.getint(
            "output_urlfetcher", "timeout_s", fallback=10
        )
        self.max_bytes = CowrieConfig.getint(
            "output_urlfetcher", "max_bytes", fallback=50 * 1024 * 1024
        )
        self.user_agent = CowrieConfig.get(
            "output_urlfetcher", "user_agent", fallback="Wget/1.21.2"
        )
        # In-process URL cache so identical URLs across sessions only fetch once.
        self._fetched: set[str] = set()
        super().__init__()

    def start(self) -> None:
        os.makedirs(self.download_path, exist_ok=True)

    def stop(self) -> None:
        pass

    def write(self, entry: dict[str, Any]) -> None:
        if entry.get("eventid") != "cowrie.command.input":
            return
        cmd = entry.get("input", "")
        if not cmd:
            return
        # We need the session id so the downstream file_download event we
        # emit later can be tied back to this attacker session.
        session_id = entry.get("session", "")
        for url in extract_urls(cmd):
            if url in self._fetched:
                continue
            self._fetched.add(url)
            if not url_is_fetchable(url):
                logger.info("url_fetcher: skipping %s (guard)", url)
                continue
            # Fetch off the reactor thread so a slow C2 doesn't stall the
            # attacker's session UX.
            reactor.callInThread(self._fetch_and_store, url, session_id)

    def _fetch_and_store(self, url: str, session_id: str) -> None:
        """Synchronous fetch + write. Called on a worker thread."""
        # Resolve the host to the address actually contacted at attack time.
        # Re-check the resolved address against the SSRF skip-list to defend
        # against a DNS name that points into private space.
        host = urlparse(url).hostname or ""
        resolved_ip = _resolve(host)
        if resolved_ip and _ip_is_private(resolved_ip):
            logger.info("url_fetcher: skipping %s (resolves to private %s)", url, resolved_ip)
            return

        try:
            content = self._do_get(url)
        except Exception as exc:
            logger.info("url_fetcher: failed to GET %s: %s", url, exc)
            return
        if not content:
            return
        sha = hashlib.sha256(content).hexdigest()
        target = os.path.join(self.download_path, sha)
        new_file = not os.path.exists(target)
        if new_file:
            tmp = target + ".tmp"
            try:
                with open(tmp, "wb") as f:
                    f.write(content)
                os.rename(tmp, target)
            except OSError as exc:
                logger.warning("url_fetcher: write failed for %s: %s", target, exc)
                return
            logger.info(
                "url_fetcher: %s -> %s (%d bytes)", url, sha[:12], len(content)
            )
        else:
            logger.info(
                "url_fetcher: %s already cached as %s", url, sha[:12]
            )

        # Emit cowrie.session.file_download from the reactor thread so the
        # Stingar plugin (and any other output plugin listening for
        # file_download) sees the URL as a captured file in
        # hp_data.files[]. The Stingar plugin then inlines the bytes from
        # the downloads dir at session close.
        if session_id:
            reactor.callFromThread(
                self._emit_file_download,
                session_id, url, target, sha, len(content), resolved_ip or "",
            )

    def _emit_file_download(
        self,
        session_id: str,
        url: str,
        outfile: str,
        sha: str,
        size: int,
        resolved_ip: str,
    ) -> None:
        twisted_log.msg(
            eventid="cowrie.session.file_download",
            format="downloaded %(url)s -> %(outfile)s (sha=%(shasum)s)",
            session=session_id,
            url=url,
            outfile=outfile,
            shasum=sha,
            size=size,
            resolved_ip=resolved_ip,
        )

    def _do_get(self, url: str) -> bytes | None:
        """Blocking HTTP GET (called from a worker thread).

        Uses stdlib urllib so the plugin works against any Cowrie image
        without extra dependencies.
        """
        # Disable TLS verification — attacker C2s commonly use self-signed
        # certs. Bytes are stored as opaque blob; nothing is executed.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            headers={"User-Agent": self.user_agent, "Accept": "*/*"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s, context=ctx) as r:
                # Cap by accumulated bytes; servers can lie about Content-Length.
                chunks: list[bytes] = []
                total = 0
                while total < self.max_bytes:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
        except urllib.error.HTTPError as exc:
            if exc.code >= 400:
                return None
            raise
        return b"".join(chunks)[: self.max_bytes]
