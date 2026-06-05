"""Fluent forward-protocol server for events from central Fluentd.

Implements the three carrier modes (Message / Forward / PackedForward, plus
gzip-compressed PackedForward) — in all of them the tag is the first element.

At-least-once: when a frame carries a ``chunk`` option (Fluentd out_forward
with ``require_ack_response``), the ack is sent ONLY after every record in the
frame has been handled without raising. If the handler raises (e.g. ES is
down), no ack is sent and the connection is dropped, so Fluentd retries the
chunk. This closes the engine-up/ES-down loss window that plain TCP delivery
leaves open.
"""

from __future__ import annotations

import gzip
import logging
import socketserver
from collections.abc import Callable
from typing import Any

import msgpack

log = logging.getLogger(__name__)

RecordHandler = Callable[[str, dict[str, Any]], None]

# Inlined download bytes (≤5 MB base64) make frames large; allow generous chunks.
_MAX_BUFFER = 256 * 1024 * 1024


def parse_frame(msg: object) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, Any] | None]:
    """Return ([(tag, record), ...], option) for one forward-protocol frame.

    option is the trailing map (carries ``chunk`` for ack); None if absent.
    """
    if not isinstance(msg, list) or len(msg) < 2 or not isinstance(msg[0], str):
        return [], None
    tag = msg[0]
    second = msg[1]
    records: list[tuple[str, dict[str, Any]]] = []
    option: dict[str, Any] | None = None

    if isinstance(second, list):
        # Forward mode: [tag, [[time, record], ...], option?]
        for entry in second:
            if isinstance(entry, list) and len(entry) >= 2 and isinstance(entry[1], dict):
                records.append((tag, entry[1]))
        if len(msg) >= 3 and isinstance(msg[2], dict):
            option = msg[2]
    elif isinstance(second, (bytes, bytearray)):
        # PackedForward / CompressedPackedForward: [tag, <bytes>, option?]
        if len(msg) >= 3 and isinstance(msg[2], dict):
            option = msg[2]
        data = bytes(second)
        if option and option.get("compressed") == "gzip":
            data = gzip.decompress(data)
        up = msgpack.Unpacker(raw=False, max_buffer_size=_MAX_BUFFER)
        up.feed(data)
        for entry in up:
            if isinstance(entry, list) and len(entry) >= 2 and isinstance(entry[1], dict):
                records.append((tag, entry[1]))
    elif len(msg) >= 3 and isinstance(msg[2], dict):
        # Message mode: [tag, time, record, option?]  (second is the timestamp)
        records.append((tag, msg[2]))
        if len(msg) >= 4 and isinstance(msg[3], dict):
            option = msg[3]

    return records, option


def _pong_response(ping: list[Any]) -> bytes:
    tag = ping[1] if len(ping) > 1 else ""
    ts = ping[2] if len(ping) > 2 else 0
    return msgpack.packb(["PONG", tag, ts, {}], use_bin_type=True)


class _ForwardHandler(socketserver.BaseRequestHandler):
    handler: RecordHandler | None = None

    def handle(self) -> None:
        assert _ForwardHandler.handler is not None
        # Feed bytes as they arrive — do NOT hand the socket file to Unpacker:
        # a blocking read() would wait to fill its buffer and never yield the
        # frame, so the ack would never be sent.
        unpacker = msgpack.Unpacker(raw=False, max_buffer_size=_MAX_BUFFER)
        while True:
            data = self.request.recv(65536)
            if not data:
                break
            unpacker.feed(data)
            for msg in unpacker:
                self._dispatch(msg)

    def _dispatch(self, msg: object) -> None:
        if isinstance(msg, list) and msg and msg[0] == "PING":
            self.request.sendall(_pong_response(msg))
            return

        records, option = parse_frame(msg)
        # Process the whole frame; a handler error means "not delivered" —
        # propagate so we skip the ack and Fluentd resends the chunk.
        for tag, record in records:
            _ForwardHandler.handler(tag, record)  # type: ignore[misc]

        if option and "chunk" in option:
            self.request.sendall(msgpack.packb({"ack": option["chunk"]}, use_bin_type=True))


class ForwardServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str, port: int, handler: RecordHandler) -> None:
        _ForwardHandler.handler = handler
        super().__init__((host, port), _ForwardHandler)

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        log.info("forward server listening on %s:%s", *self.server_address)
        with self:
            super().serve_forever(poll_interval)
