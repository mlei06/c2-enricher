# sensor — enrichment-enabled Cowrie build

The honeypot side of the C2-detection pipeline. A near-stock Cowrie plus the
two changes the central [c2-engine](../DESIGN.md) needs. `cowrie/` is a clean
upstream clone (commit `bca2869c`); `stingar.py` at this level is the
**current production plugin** kept for reference/diffing.

## What was added to the clone

The vanilla clone ships with no STINGAR plumbing. This build adds:

| File | Purpose |
|---|---|
| `cowrie/src/cowrie/plugins/stingar.py` | Stingar output plugin, enrichment build |
| `cowrie/src/cowrie/output/stingar.py` | loader shim (`cowrie.output.stingar` → the plugin) |
| `cowrie/src/cowrie/output/url_fetcher.py` | in-session URL fetcher |
| `cowrie/src/cowrie/data/etc/cowrie.cfg.dist` | `[output_stingar]` + `[output_url_fetcher]` sections |

## The gaps it fills (vs. the production plugin)

The production `stingar.py` already emits sessions on the `enrichable.cowrie`
tag, but the central engine has **no disk access** — so the plugin gained:

1. **Byte inlining** — on `cowrie.session.closed`, each successful download is
   read off disk (via the `outfile` path Cowrie already records) and inlined as
   `hp_data.files[].content_b64` (base64, ≤ `inline_max_bytes` / 5 MB). Both
   scripts and binaries; the engine hashes/sniffs/`strings`-scans them and
   strips the field before the session reaches Elasticsearch. Oversized files
   ship hash-only (engine degrades to a metadata sighting). Toggle with
   `inline_download_bytes`.
2. **`resolved_ip`** — `url_fetcher` records the attack-time DNS resolution of
   each fetched host and threads it onto the `file_download` event →
   `hp_data.files[].resolved_ip`, so domain-named C2s geolocate on the address
   actually contacted.

`url_fetcher` itself is the gap-filler for capture: native `wget`/`curl`/etc.
are left to Cowrie's own emulators (no double-fetch); this plugin handles
wrapper-hidden URLs (`bash -c`, `eval`, `echo|sh`, quoted `base64 -d`) and
non-emulated loaders, fetching from Cowrie's network identity at attack time
behind a strict scheme allowlist + SSRF guard (including a post-resolution
private-IP recheck).

## Contract with c2-engine

The inlined-bytes shape is what `c2engine.model.SessionIn` reads and what the
golden fixture (`../tests/fixtures/session_basic.json`) encodes. Keep the two
in sync — `sensor/tests/` asserts the inlining round-trips to the exact dropper
that fixture expects.

## Tests

```bash
pytest sensor/tests/      # pure-logic: inlining + URL extraction (stubs cowrie deps)
```

These don't require a full Cowrie install. End-to-end (real Cowrie + fluentbit
+ engine) is exercised by the dev stack — see `../deploy/`.
