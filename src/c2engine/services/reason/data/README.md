# reason/data

Static intel the reason layer (M2) matches against. Plain data, no code.

- **`known_sha.json`** — array of sha256 hashes known to be malware. A served
  file whose sha256 is in this list escalates its C2 to `stage2_c2` with the
  `known_malware` signal. Seeded with one entry (the test `mozi.elf`) to
  demonstrate escalation; replace/extend with a real feed (MalwareBazaar export,
  your own confirmed samples, etc.).

Deferred to a later milestone: `hassh_toolkits.json` (HASSH → toolkit
attribution) — needs a session-index join, so it's not wired into M2 core yet.
