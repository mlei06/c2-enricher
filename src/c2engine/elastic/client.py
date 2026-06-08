"""Direct Elasticsearch writer — mirrors fluentd logstash_format index naming."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any

from urllib.parse import quote

from c2engine.elastic.schema import (
    ENTITIES_TEMPLATE,
    ENTITIES_TEMPLATE_NAME,
    ILM_POLICY,
    ILM_POLICY_NAME,
    INDEX_TEMPLATE,
    INDEX_TEMPLATE_NAME,
    INTEL_TEMPLATE,
    INTEL_TEMPLATE_NAME,
    VT_TEMPLATE,
    VT_TEMPLATE_NAME,
)

log = logging.getLogger(__name__)

DEFAULT_HOST = "elasticsearch"
DEFAULT_PORT = 9200
SESSION_PREFIX = "stingar"
C2_PREFIX = "stingarc2"


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
                if exc.code >= 400:
                    # Surface ES's rejection reason (mapping conflict, etc.) —
                    # otherwise a 400 is opaque and undebuggable.
                    try:
                        detail = exc.read().decode("utf-8", "replace")[:600]
                    except Exception:  # noqa: BLE001
                        detail = "<no body>"
                    log.error("ES %s indexing into %s: %s", exc.code, index, detail)
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
        import time

        for attempt in range(10):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    if resp.status >= 300:
                        raise urllib.error.HTTPError(url, resp.status, "", resp.headers, None)
                return
            except urllib.error.HTTPError as exc:
                # 5xx = ES still warming up -> retry. 4xx = our request is wrong
                # (e.g. malformed template) -> fail fast with the reason; retrying
                # a 400 just loops forever.
                if exc.code in (502, 503, 504) and attempt < 9:
                    log.warning("ES %s for PUT %s, retry %s", exc.code, path, attempt + 1)
                    time.sleep(min(2 ** attempt, 15))
                    continue
                body = exc.read().decode("utf-8", "replace")[:400] if exc.code >= 400 else ""
                log.error("ES %s on PUT %s: %s", exc.code, path, body)
                raise
            except urllib.error.URLError as exc:
                # connection refused / DNS — ES not up yet at engine start; retry.
                if attempt < 9:
                    log.warning("ES not ready for PUT %s (%s), retry %s", path, exc, attempt + 1)
                    time.sleep(min(2 ** attempt, 15))
                    continue
                raise

    def ensure_bootstrap(self) -> None:
        """Idempotently install the ILM policy + index template before first write.

        Correctness can't depend on an operator running a README curl: the
        ``stingarc2-*`` mapping declares ``geo_point``/``ip`` types that never
        dynamic-map, so a missing template silently breaks the C2 map with no
        clean fix but a reindex. PUT is idempotent — safe on every startup.
        """
        self._put(f"_ilm/policy/{ILM_POLICY_NAME}", ILM_POLICY)
        self._put(f"_index_template/{INDEX_TEMPLATE_NAME}", INDEX_TEMPLATE)
        # entity index mappings (geo_point + evidence_stage runtime); the reason
        # job is the sole writer of this index.
        self._put(f"_index_template/{ENTITIES_TEMPLATE_NAME}", ENTITIES_TEMPLATE)
        # VirusTotal verdict cache (M3); reason job is the sole writer.
        self._put(f"_index_template/{VT_TEMPLATE_NAME}", VT_TEMPLATE)
        # abuse.ch intel feed cache (M6); reason job is the sole writer.
        self._put(f"_index_template/{INTEL_TEMPLATE_NAME}", INTEL_TEMPLATE)
        log.info("ES bootstrap ok: ILM + index templates (%s, %s, %s, %s) installed",
                 INDEX_TEMPLATE_NAME, ENTITIES_TEMPLATE_NAME, VT_TEMPLATE_NAME,
                 INTEL_TEMPLATE_NAME)

    def _send(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, str]:
        """One-shot request returning (status, body) — tolerates 4xx (caller decides)."""
        url = f"{self._base}/{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")

    # --- helpers used by the reason job (entity index is reason-owned) --------

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        code, resp = self._send("POST", f"{index}/_search", body)
        if code >= 300:
            raise RuntimeError(f"ES search {index} -> {code}: {resp[:300]}")
        return json.loads(resp)

    def index_doc(self, index: str, doc_id: str, doc: dict[str, Any]) -> None:
        code, resp = self._send("PUT", f"{index}/_doc/{quote(doc_id, safe='')}", doc)
        if code >= 300:
            raise RuntimeError(f"ES index {index}/{doc_id} -> {code}: {resp[:300]}")

    def delete_by_query(self, index: str, body: dict[str, Any]) -> int:
        code, resp = self._send("POST", f"{index}/_delete_by_query?refresh=true", body)
        if code >= 300:
            raise RuntimeError(f"ES delete_by_query {index} -> {code}: {resp[:300]}")
        return json.loads(resp).get("deleted", 0)

    def bulk_index(self, index: str, docs: list[tuple[str, dict[str, Any]]]) -> int:
        """Bulk-index (id, doc) pairs into `index`. Used by the reason job to load
        intel feeds (thousands of IOCs) in one round-trip instead of N PUTs."""
        if not docs:
            return 0
        lines: list[str] = []
        for doc_id, doc in docs:
            lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
            lines.append(json.dumps(doc))
        ndjson = "\n".join(lines) + "\n"
        code, resp = self._send_raw("POST", "_bulk?refresh=true", ndjson)
        if code >= 300:
            raise RuntimeError(f"ES bulk {index} -> {code}: {resp[:300]}")
        return len(docs)

    def _send_raw(self, method: str, path: str, ndjson: str) -> tuple[int, str]:
        """Like _send but for an x-ndjson body (the _bulk API)."""
        req = urllib.request.Request(
            f"{self._base}/{path}",
            data=ndjson.encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson"},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")

    def write_session(self, doc: dict[str, Any], *, source_tag: str = "") -> None:
        if source_tag:
            doc = {**doc, "fluentd_tag": source_tag}
        self.index(_daily_index(SESSION_PREFIX, doc), doc)

    def write_observations(self, rows: list[dict[str, Any]], *, source_tag: str = "") -> None:
        for row in rows:
            if source_tag:
                row = {**row, "fluentd_tag": source_tag}
            self.index(_daily_index(C2_PREFIX, row), row)
