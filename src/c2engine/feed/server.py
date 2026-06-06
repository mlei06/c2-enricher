"""HTTP blocklist/alert feed over ``c2-entities`` (M4). Stdlib-only."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from c2engine.ingest.es import EsWriter
from c2engine.ingest.es_assets import ENTITIES_INDEX

log = logging.getLogger(__name__)

# Final-stage ordering (reason layer): the feed filters on the escalated `stage`,
# not raw evidence_rank, so intel-confirmed C2s are included.
STAGE_ORDER = ("unconfirmed", "stage1_serving", "stage2_c2")
STAGE_RANK = {name: i for i, name in enumerate(STAGE_ORDER)}

_WINDOW_RE = re.compile(r"^\d+[smhd]$")
DEFAULT_WINDOW = "7d"
DEFAULT_MIN_STAGE = 1  # stage1_serving — fresh, has served us a file
DEFAULT_LIMIT = 5000
MAX_LIMIT = 10000

# Fields pulled from the entity doc (mirrors c2-entities _meta).
_SOURCE = [
    "c2_host", "stage", "stage_signals", "families",
    "first_seen", "last_seen", "sighting_count", "sensor_count",
    "src_ip_count", "distinct_files", "max_evidence_rank", "max_vt_ratio",
    "latest.c2_host_kind", "latest.c2_country", "latest.c2_asn_org",
]


def _stages_at_or_above(min_rank: int) -> list[str]:
    return [s for s, r in STAGE_RANK.items() if r >= min_rank]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def build_feed(
    es: EsWriter,
    *,
    min_stage: int = DEFAULT_MIN_STAGE,
    window: str = DEFAULT_WINDOW,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    """Query c2-entities and return {params, count, ips[], entities[]}.

    `window` is validated (``<int>[smhd]``) then passed to ES date math
    (``now-<window>``). Entities are sorted newest-last_seen first.
    """
    if not _WINDOW_RE.match(window):
        window = DEFAULT_WINDOW
    min_stage = max(0, min(min_stage, len(STAGE_ORDER) - 1))
    limit = max(1, min(limit, MAX_LIMIT))

    body = {
        "size": limit,
        "_source": _SOURCE,
        "query": {
            "bool": {
                "filter": [
                    {"terms": {"stage": _stages_at_or_above(min_stage)}},
                    {"range": {"last_seen": {"gte": f"now-{window}"}}},
                ]
            }
        },
        "sort": [{"last_seen": "desc"}],
    }
    hits = es.search(ENTITIES_INDEX, body).get("hits", {}).get("hits", [])

    entities: list[dict[str, Any]] = []
    ips: list[str] = []
    seen_ip: set[str] = set()
    for h in hits:
        src = h.get("_source", {})
        host = src.get("c2_host")
        if not host:
            continue
        latest = src.get("latest", {}) or {}
        entities.append(
            {
                "c2_host": host,
                "kind": latest.get("c2_host_kind"),
                "stage": src.get("stage"),
                "stage_signals": src.get("stage_signals", []),
                "families": src.get("families", []),
                "first_seen": src.get("first_seen"),
                "last_seen": src.get("last_seen"),
                "sighting_count": src.get("sighting_count"),
                "sensor_count": src.get("sensor_count"),
                "src_ip_count": src.get("src_ip_count"),
                "distinct_files": src.get("distinct_files"),
                "max_evidence_rank": src.get("max_evidence_rank"),
                "max_vt_ratio": src.get("max_vt_ratio"),
                "country": latest.get("c2_country"),
                "asn_org": latest.get("c2_asn_org"),
            }
        )
        if _is_ip(host) and host not in seen_ip:
            seen_ip.add(host)
            ips.append(host)

    return {
        "params": {"min_stage": STAGE_ORDER[min_stage], "window": window, "limit": limit},
        "count": len(entities),
        "ips": ips,
        "entities": entities,
    }


def _render_blocklist(feed: dict[str, Any]) -> str:
    p = feed["params"]
    head = [
        "# c2-engine blocklist — active C2 IPs from honeypot-observed evidence",
        f"# stage>={p['min_stage']}  window=last {p['window']}  "
        f"ips={len(feed['ips'])}  entities={feed['count']}",
        "# source: c2-engine /feed/blocklist.txt (decaying c2-entities view)",
    ]
    return "\n".join(head + feed["ips"]) + "\n"


class _FeedHandler(BaseHTTPRequestHandler):
    server_version = "c2-engine-feed/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # route to logging
        log.info("feed %s - %s", self.address_string(), fmt % args)

    def _send(self, code: int, body: str, ctype: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _params(self, qs: dict[str, list[str]]) -> dict[str, Any]:
        def _int(key: str, default: int) -> int:
            try:
                return int(qs.get(key, [str(default)])[0])
            except (ValueError, IndexError):
                return default

        return {
            "min_stage": _int("stage", DEFAULT_MIN_STAGE),
            "window": qs.get("window", [DEFAULT_WINDOW])[0],
            "limit": _int("limit", DEFAULT_LIMIT),
        }

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        qs = parse_qs(parts.query)

        if path == "/healthz":
            self._send(200, "ok\n", "text/plain; charset=utf-8")
            return
        if path in ("/", "/feed"):
            self._send(
                200,
                "c2-engine feed\n"
                "  GET /feed/blocklist.txt   active C2 IPs (one per line)\n"
                "  GET /feed/c2.json         full entity summaries\n"
                "  params: ?stage=1|2 ?window=7d ?limit=N\n",
                "text/plain; charset=utf-8",
            )
            return
        if path not in ("/feed/blocklist.txt", "/feed/c2.json"):
            self._send(404, "not found\n", "text/plain; charset=utf-8")
            return

        try:
            feed = build_feed(EsWriter(), **self._params(qs))
        except Exception as exc:  # noqa: BLE001 — surface as 503, don't crash
            log.warning("feed query failed: %s", exc)
            self._send(503, f"feed unavailable: {exc}\n", "text/plain; charset=utf-8")
            return

        if path == "/feed/blocklist.txt":
            self._send(200, _render_blocklist(feed), "text/plain; charset=utf-8")
        else:
            self._send(200, json.dumps(feed, default=str) + "\n", "application/json")


def serve() -> None:
    host = os.environ.get("C2E_FEED_HOST", "0.0.0.0")
    port = int(os.environ.get("C2E_FEED_PORT", "8088"))
    httpd = ThreadingHTTPServer((host, port), _FeedHandler)
    log.info("c2-engine feed listening on %s:%d (source=%s)", host, port, ENTITIES_INDEX)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
