"""Fluent forward in/out — the engine's only I/O (milestone 3).

In:  Fluent forward server (msgpack) receiving ``stingar.events.cowrie``
     from central Fluentd.
Out: Fluent forward client re-emitting:
       enriched.events.cowrie  — session doc (bytes stripped, + additive)
       enriched.c2.cowrie      — C2Observation rows

Failure contract (DESIGN.md §8): a per-session processing error logs and
re-emits the session UNENRICHED (bytes still stripped) — the engine never
blocks or drops the session stream. Non-session payloads (if any are ever
routed here) pass through untouched.
"""
