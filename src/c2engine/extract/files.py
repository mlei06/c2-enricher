"""``served_file`` rows — the payload IS the strongest evidence kind.

Milestone 2. Consumes ``hp_data.files[].content_b64`` (transport-only inlined
bytes). Per file:

- hashes ×3 (sha256/sha1/md5), size, magic
- script vs binary split: UTF-8-decodable → ``file_kind=script``, content
  inlined (≤ CONTENT_CAP); else ``file_kind=binary``, content NEVER inlined
  (binaries are first-class evidence — hashes + strings, not bytes;
  DESIGN.md §2 "Binaries")
- ``callbacks[]`` extracted from script content (regex) or binary strings
- ``family`` via enrich.family rules; ``interpreter`` via shebang
"""

from __future__ import annotations

from c2engine.model import C2Observation, SessionIn


def served_files(session: SessionIn) -> list[C2Observation]:
    raise NotImplementedError("milestone 2")
