"""Cheap derived session-shape features — arithmetic on the session doc only."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from c2engine.model import SessionIn


@dataclass
class ShapeFeatures:
    duration_s: float | None = None
    command_count: int = 0
    unknown_command_count: int = 0
    cred_attempts: int = 0
    failed_attempts_before_success: int | None = None
    ttylog_bytes: int = 0
    has_pty: bool = False
    distinct_urls: int = 0
    distinct_file_hashes: int = 0


def _duration(start: datetime | None, end: datetime | None) -> float | None:
    return (end - start).total_seconds() if start and end else None


def _failed_before_success(creds) -> int | None:
    failed = 0
    for c in creds:
        if c.success:
            return failed
        failed += 1
    return None  # never succeeded


def compute(session: SessionIn) -> ShapeFeatures:
    hp = session.hp_data
    return ShapeFeatures(
        duration_s=_duration(session.start_time, session.end_time),
        command_count=len(hp.commands),
        unknown_command_count=len(hp.unknown_commands),
        cred_attempts=len(hp.credentials),
        failed_attempts_before_success=_failed_before_success(hp.credentials),
        ttylog_bytes=len(hp.ttylog or "") // 2,  # hex-encoded
        has_pty=(hp.client_width or 0) > 0 and (hp.client_height or 0) > 0,
        distinct_urls=len({u for u in hp.urls if u}),
        distinct_file_hashes=len({f.shasum for f in (hp.files or []) if f.shasum}),
    )
