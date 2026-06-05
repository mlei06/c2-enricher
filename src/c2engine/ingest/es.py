"""Direct Elasticsearch writer — mirrors fluentd logstash_format index naming."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any

from c2engine.ingest.es_assets import (
    ILM_POLICY,
    ILM_POLICY_NAME,
    INDEX_TEMPLATE,
    INDEX_TEMPLATE_NAME,
)

log = logging.getLogger(__name__)

DEFAULT_HOST = "elasticsearch"
DEFAULT_PORT = 9200
SESSION_PREFIX = "stingar"
C2_PREFIX = "stingar-c2"


def _es_base() -> str:
    host = os.environ.get("C2E_ES_HOST", DEFAULT_HOST)
    port = os.environ.get("C2E_ES_PORT", str(DEFAULT_PORT))
    return f"http://{host}:{port}"


def _daily_index(prefix: str, record: dict[str, Any]) -> str:
    """Pick YYYY-MM-DD from end_time / @timestamp / now (logstash_format)."""
    raw = record.get("end_time") or record.get("@timestamp") or record.get("ts")
    if isinstance(raw, (int, float)):
        dt = datetime.fromtimestamp(raw, tz=UTC)
    elif isinstance(raw, str) and raw:
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
        except ValueError:
            dt = datetime.now(UTC)
    else:
        dt = datetime.now(UTC)
    return f"{prefix}-{dt.strftime('%Y-%m-%d')}"


class EsWriter:
    """Bulk-index session docs and C2 ledger rows."""

    def __init__(self, base_url: str | None = None) -> None:
        self._base = (base_url or _es_base()).rstrip("/")

    def index(self, index: str, doc: dict[str, Any]) -> None:
        url = f"{self._base}/{index}/_doc"
        body = json.dumps(doc).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    if resp.status >= 300:
                        raise urllib.error.HTTPError(url, resp.status, "", resp.headers, None)
                return
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 502, 503, 504) and attempt < 4:
                    log.warning("ES %s on %s, retry %s", exc.code, index, attempt + 1)
                    continue
                raise
            except urllib.error.URLError as exc:
                if attempt < 4:
                    log.warning("ES unreachable (%s), retry %s", exc.reason, attempt + 1)
                    continue
                raise

    def _put(self, path: str, doc: dict[str, Any]) -> None:
        url = f"{self._base}/{path}"
        req = urllib.request.Request(
            url,
            data=json.dumps(doc).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        for attempt in range(10):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    if resp.status >= 300:
                        raise urllib.error.HTTPError(url, resp.status, "", resp.headers, None)
                return
            except urllib.error.URLError as exc:
                # ES may not be up yet at engine start; back off and retry.
                if attempt < 9:
                    log.warning("ES not ready for PUT %s (%s), retry %s", path, exc, attempt + 1)
                    import time

                    time.sleep(min(2 ** attempt, 15))
                    continue
                raise

    def ensure_bootstrap(self) -> None:
        """Idempotently install the ILM policy + index template before first write.

        Correctness can't depend on an operator running a README curl: the
        ``stingar-c2-*`` mapping declares ``geo_point``/``ip`` types that never
        dynamic-map, so a missing template silently breaks the C2 map with no
        clean fix but a reindex. PUT is idempotent — safe on every startup.
        """
        self._put(f"_ilm/policy/{ILM_POLICY_NAME}", ILM_POLICY)
        self._put(f"_index_template/{INDEX_TEMPLATE_NAME}", INDEX_TEMPLATE)
        log.info("ES bootstrap ok: ILM policy + index template %s installed", INDEX_TEMPLATE_NAME)

    def write_session(self, doc: dict[str, Any], *, source_tag: str = "") -> None:
        if source_tag:
            doc = {**doc, "fluentd_tag": source_tag}
        self.index(_daily_index(SESSION_PREFIX, doc), doc)

    def write_observations(self, rows: list[dict[str, Any]], *, source_tag: str = "") -> None:
        for row in rows:
            if source_tag:
                row = {**row, "fluentd_tag": source_tag}
            self.index(_daily_index(C2_PREFIX, row), row)
