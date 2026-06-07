"""Base observation factory — common ledger-row fields from a session."""

from __future__ import annotations

from c2engine.model import C2Observation, Evidence, SessionIn
from c2engine.model.observation import HostKind


def base_obs(
    session: SessionIn,
    *,
    c2_host: str,
    c2_host_kind: HostKind,
    evidence: Evidence,
) -> C2Observation:
    """A C2Observation pre-filled with the per-session common columns.

    ``self_hosted`` (loader-is-scanner) is set here: it is purely
    ``c2_host == src_ip``, independent of evidence kind. ``hassh`` is
    denormalized from the session's SSH KEX so the reason layer can attribute
    an attacker toolkit per c2_host without a session-index join.
    """
    return C2Observation(
        ts=session.end_time or session.start_time,
        sensor_uuid=session.sensor_uuid,
        sensor_hostname=session.sensor_hostname,
        src_ip=session.src_ip,
        session_id=session.session_id,
        c2_host=c2_host,
        c2_host_kind=c2_host_kind,
        evidence=evidence,
        self_hosted=(c2_host == session.src_ip),
        hassh=(session.hp_data.kex.hassh if session.hp_data.kex else None),
    )
