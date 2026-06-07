# reason/data

Static intel the reason layer (M2) matches against. Plain data, no code.

- **`known_sha.json`** — array of sha256 hashes known to be malware. A served
  file whose sha256 is in this list adds the `known_malware` signal to its C2.
  This is an *annotation*, not a stage change (the GreyNoise model — like VT,
  hash reputation is corroboration; the evidence ladder alone sets `stage`).
  Seeded with one entry (the test `mozi.elf`) to demonstrate the signal;
  replace/extend with a real feed (MalwareBazaar export, your own samples, etc.).

- **`hassh_toolkits.json`** — object mapping a HASSH (attacker SSH client
  fingerprint) to a toolkit name. A C2 observed in any session using a listed
  HASSH gets that toolkit recorded in `attributed_toolkit` plus the
  `hassh_toolkit` signal. This is an *annotation*, not a stage escalation: a
  HASSH attributes the attacker's client, not the host's C2 role, so it never
  promotes a host's stage on its own. The session-index join the attribution
  once needed is avoided by denormalizing `hassh` onto each ledger row at
  extraction time (`extract/_base.py`), so the reason job still reads only the
  ledger. Seeded with the test fixture's HASSH (`mirai-loader`) to demonstrate
  the path; replace/extend with a real HASSH corpus.
