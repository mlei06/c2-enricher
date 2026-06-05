"""Offline replay & backfill CLI (milestone 2).

    c2-engine replay sessions.ndjson[.gz] > evidence.ndjson

Reads session docs (one JSON per line, or an ES export), runs the same
extract+enrich pipeline as the server, writes {tag, record} envelopes.
This is the backfill tool: logic upgrade → ES export → replay → reinject
(DESIGN.md §8).
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="c2-engine")
    sub = parser.add_subparsers(dest="command", required=True)

    replay = sub.add_parser("replay", help="replay session NDJSON through the pipeline")
    replay.add_argument("path", help="session NDJSON file (.gz ok), or - for stdin")

    sub.add_parser("serve", help="run the Fluent forward hop (milestone 3)")

    args = parser.parse_args(argv)
    print(f"c2-engine {args.command}: not implemented yet (see DESIGN.md §6)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
