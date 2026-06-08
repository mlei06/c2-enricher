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

# fluentd out_forward sends PackedForward entries as a msgpack STR-typed blob of
# raw binary, not bin. Decoding with strict utf-8 dies on it, so we decode the
# whole stream with surrogateescape (lossless str<->bytes round-trip) and turn
# the blob back into bytes before unpacking the inner [time, record] entries.
def _unpacker() -> msgpack.Unpacker:
    return msgpack.Unpacker(raw=False, unicode_errors="surrogateescape", max_buffer_size=_MAX_BUFFER)


def _as_bytes(blob: Any) -> bytes:
    return blob if isinstance(blob, (bytes, bytearray)) else blob.encode("utf-8", "surrogateescape")


def _normalize(obj: Any) -> Any:
    """Coerce any ``bytes`` map keys/scalars in a decoded record to ``str``.

    The hop chain (Cowrie -> Fluent Bit -> Fluentd -> here) can pack a map key
    or scalar as a msgpack BIN type, which ``raw=False`` faithfully decodes to
    ``bytes``. The engine forwards the stock session doc VERBATIM (enrich/
    session.py deep-copies it), so a single bytes key reaches ``json.dumps`` and
    raises ``TypeError: keys must be str ... not bytes`` — crashing every
    enrichable session on write and wedging the unacked chunk in Fluentd's
    retry loop. JSON/ES need ``str`` keys, so normalize here at the boundary
    (same place this module already absorbs the surrogateescape blob quirk)."""
    if isinstance(obj, dict):
        return {_normalize(k): _normalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalize(v) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", "surrogateescape")
    return obj


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
                records.append((tag, _normalize(entry[1])))
        if len(msg) >= 3 and isinstance(msg[2], dict):
            option = msg[2]
    elif isinstance(second, (bytes, bytearray, str)):
        # PackedForward / CompressedPackedForward: [tag, <blob>, option?]
        # (blob arrives as str under surrogateescape; convert back to bytes)
        if len(msg) >= 3 and isinstance(msg[2], dict):
            option = msg[2]
        data = _as_bytes(second)
        if option and option.get("compressed") == "gzip":
            data = gzip.decompress(data)
        up = _unpacker()
        up.feed(data)
        for entry in up:
            if isinstance(entry, list) and len(entry) >= 2 and isinstance(entry[1], dict):
                records.append((tag, _normalize(entry[1])))
    elif len(msg) >= 3 and isinstance(msg[2], dict):
        # Message mode: [tag, time, record, option?]  (second is the timestamp)
        records.append((tag, _normalize(msg[2])))
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
        unpacker = _unpacker()
        while True:
            data = self.request.recv(65536)
            if not data:
                break
            unpacker.feed(data)
            for msg in unpacker:
                try:
                    self._dispatch(msg)
                except Exception:
                    # Log the real cause, then close without acking so Fluentd
                    # retries (at-least-once). Without this the handler error is
                    # invisible and the chunk loops forever.
                    log.exception("error handling frame from %s", self.client_address)
                    return

    def _dispatch(self, msg: object) -> None:
        if isinstance(msg, list) and msg and msg[0] == "PING":
            self.request.sendall(_pong_response(msg))
            return

        records, option = parse_frame(msg)
        log.debug(
            "frame: top=%s records=%d chunk=%s",
            type(msg).__name__ if not isinstance(msg, list) else f"list[{len(msg)}]",
            len(records),
            (option or {}).get("chunk"),
        )
        # Process the whole frame; a handler error means "not delivered" —
        # propagate so we skip the ack and Fluentd resends the chunk.
        for tag, record in records:
            _ForwardHandler.handler(tag, record)  # type: ignore[misc]

        if option and "chunk" in option:
            self.request.sendall(msgpack.packb({"ack": option["chunk"]}, use_bin_type=True))
            log.debug("acked chunk %s", option["chunk"])


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
