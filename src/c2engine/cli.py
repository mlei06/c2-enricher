"""Offline replay & backfill CLI (milestone 2).

    c2-engine replay sessions.ndjson[.gz] > envelopes.ndjson

Reads session docs (one JSON per line, or an ES export), runs the same
extract+enrich pipeline as the server, writes {tag, record} envelopes — one
JSON per line. This is the backfill tool: logic upgrade -> ES export ->
replay -> reinject (DESIGN.md §8).
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import logging
import os
import sys
from collections.abc import Iterator
from typing import Any

from c2engine.enrich.geo import GeoEnricher
from c2engine.ingest import serve
from c2engine.pipeline import process


def _open(path: str) -> io.TextIOBase:
    if path == "-":
        return sys.stdin  # type: ignore[return-value]
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8")
    return open(path, encoding="utf-8")


def _iter_sessions(path: str) -> Iterator[dict[str, Any]]:
    """Yield session docs from NDJSON, or unwrap an ES ``hits.hits[]`` export."""
    with _open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            doc = json.loads(line)
            if isinstance(doc, dict) and "_source" in doc:  # ES hit
                doc = doc["_source"]
            yield doc


def _cmd_replay(args: argparse.Namespace) -> int:
    geo = GeoEnricher(args.maxmind_dir)
    sessions = errors = rows = 0
    out = sys.stdout
    for raw in _iter_sessions(args.path):
        sessions += 1
        try:
            enriched = process(raw, geo)
        except Exception as exc:  # noqa: BLE001 - report and continue
            errors += 1
            print(f"skip session: {exc}", file=sys.stderr)
            continue
        for tag, record in enriched.envelopes():
            out.write(json.dumps({"tag": tag, "record": record}) + "\n")
            rows += 1
    print(f"{sessions} sessions, {rows} envelopes, {errors} errors", file=sys.stderr)
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=os.environ.get("C2E_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    parser = argparse.ArgumentParser(prog="c2-engine")
    sub = parser.add_subparsers(dest="command", required=True)

    replay = sub.add_parser("replay", help="replay session NDJSON through the pipeline")
    replay.add_argument("path", help="session NDJSON file (.gz ok), or - for stdin")
    replay.add_argument("--maxmind-dir", default=None, help="dir with GeoLite2-*.mmdb")
    replay.set_defaults(func=_cmd_replay)

    sub.add_parser("serve", help="run forward server + direct ES writer").set_defaults(
        func=_cmd_serve
    )

    reason = sub.add_parser("reason", help="rebuild the c2-entities rollup + intel overlay")
    reason.add_argument(
        "--interval", type=int, default=None,
        help="seconds between passes (omit = run once and exit)",
    )
    reason.set_defaults(func=_cmd_reason)

    sub.add_parser(
        "feed", help="serve the blocklist/alert feed over c2-entities (HTTP)"
    ).set_defaults(func=_cmd_feed)

    args = parser.parse_args(argv)
    return int(args.func(args))


def _cmd_serve(_args: argparse.Namespace) -> int:
    serve()
    return 0


def _cmd_reason(args: argparse.Namespace) -> int:
    from c2engine.reason import run

    run(interval=args.interval)
    return 0


def _cmd_feed(_args: argparse.Namespace) -> int:
    from c2engine.feed import serve as serve_feed

    serve_feed()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
