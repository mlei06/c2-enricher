"""``served_file`` rows — the payload IS the strongest evidence kind.

Rank-1: we hold bytes the host served, fetched in-session from Cowrie's IP.
Per downloaded file with inlined bytes:

- hashes ×3 (sha256/sha1/md5), size, magic
- script vs binary: UTF-8-decodable -> ``script``, content inlined (≤ cap);
  else ``binary``, content NEVER inlined (binaries are first-class evidence
  via hashes + strings, not bytes — DESIGN.md §2)
- ``callbacks[]``: hosts found in script content, or in a binary's strings
- ``family`` (rules-based) and ``interpreter`` (shebang)

Uploads and failed/!download entries are skipped: this index is the
"retrieved from a C2" side only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib

from c2engine.enrich.family import label as family_label
from c2engine.model import C2Observation, FileRef, SessionIn
from c2engine.model.observation import CONTENT_CAP

from ._base import base_obs
from ._util import classify_host, find_hosts, interpreter_of, sniff_magic, split_url, strings


def _decode_bytes(f: FileRef) -> bytes | None:
    if not f.content_b64:
        return None
    try:
        return base64.b64decode(f.content_b64, validate=True)
    except (binascii.Error, ValueError):
        return None


def served_files(session: SessionIn) -> list[C2Observation]:
    out: list[C2Observation] = []
    for f in session.hp_data.files:
        if f.action != "download" or f.status != "successful":
            continue
        host, port, path = split_url(f.url)
        host = host or (f.resolved_ip or "")
        if not host:
            continue

        obs = base_obs(
            session,
            c2_host=host,
            c2_host_kind=classify_host(host),
            evidence="served_file",
        )
        obs.c2_url = f.url or None
        obs.c2_port = port
        obs.c2_path = path or None
        obs.c2_resolved_ip = f.resolved_ip
        obs.sha256 = f.shasum or None

        data = _decode_bytes(f)
        if data is not None:
            obs.size = len(data)
            obs.sha1 = hashlib.sha1(data).hexdigest()
            obs.md5 = hashlib.md5(data).hexdigest()
            if not obs.sha256:
                obs.sha256 = hashlib.sha256(data).hexdigest()
            obs.magic = sniff_magic(data)
            _classify_payload(obs, data)

        out.append(obs)
    return out


def _classify_payload(obs: C2Observation, data: bytes) -> None:
    """Set file_kind, content/interpreter (scripts), callbacks, family."""
    try:
        text = data.decode("utf-8")
        obs.file_kind = "script"
    except UnicodeDecodeError:
        obs.file_kind = "binary"
        text = strings(data)  # mine plaintext URLs/IPs from the binary

    if obs.file_kind == "script":
        obs.interpreter = interpreter_of(text)
        if len(data) > CONTENT_CAP:
            obs.content = data[:CONTENT_CAP].decode("utf-8", "ignore")
            obs.content_truncated = True
        else:
            obs.content = text

    # Onward callbacks — exclude the serving host itself.
    obs.callbacks = [h for h, _ in find_hosts(text) if h != obs.c2_host]
    obs.family = family_label(data, obs.magic, obs.interpreter)
