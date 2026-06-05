# Integration smoke test

`smoke.py` drives the full ingest path against a **live Elasticsearch** — the
seams unit tests can't reach (real socket framing, the ack handshake, ES
mappings). It is intentionally not collected by `pytest` (run it by hand).

## Run

```bash
# 1. Start a throwaway ES
docker run -d --name c2e-smoke-es -p 19200:9200 \
  -e discovery.type=single-node -e xpack.security.enabled=false \
  -e "ES_JAVA_OPTS=-Xms1g -Xmx1g" \
  docker.elastic.co/elasticsearch/elasticsearch:9.4.2

# 2. Wait for green, then run the smoke test
C2E_ES_HOST=localhost C2E_ES_PORT=19200 python tests/integration/smoke.py

# 3. Teardown
docker rm -f c2e-smoke-es
```

## What it verifies

1. `ensure_bootstrap` installs the ILM policy + index template
2. `ForwardServer` parses a real PackedForward frame (tag-first, `chunk` option)
3. the engine **acks** the chunk (at-least-once handshake)
4. `stingar-c2-*` `c2_geo` is mapped `geo_point` (template applied, not dynamic)
5. one session → `shell_reference` + `served_file` + `file_callback` rows with
   the chain (`5.6.7.8`) intact, `family=downloader.shell`
6. the enriched session lands in `stingar-*` with `c2_hosts` set, `hassh`
   copied, and `content_b64` stripped

## Still unverified (needs the 4warned images)

- The full `deploy/fluent.conf` loading inside `4warned/fluentd:v2.3` (geoip
  filters + `out_conf` includes). The ack handshake itself is exercised here
  with the exact frame shape Fluentd `out_forward` sends.
- The vendored Cowrie plugin emitting `content_b64` from a real download.
