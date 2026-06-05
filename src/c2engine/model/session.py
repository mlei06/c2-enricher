"""Inbound Cowrie/STINGAR session doc, and the additive outbound contract.

The pass-through invariant (DESIGN.md §4.1): the engine never renames,
retypes, or rewrites a stock field. ``SessionIn`` therefore keeps
``extra="allow"`` everywhere — unknown fields ride through untouched and are
re-emitted verbatim. We only *model* the fields the engine reads.

TODO(milestone 1 exit): validate every modeled field name against a real
stock STINGAR v2.3 session doc (dev-stack NDJSON dump or live ES). The names
below follow the cowrie ``output_stingar`` plugin but have not yet been
checked against the wire.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class FileRef(BaseModel):
    """One entry in ``hp_data.files[]`` — a file the attacker referenced.

    ``content_b64`` is the transport-only inlined bytes added by the sensor's
    ``output_stingar`` plugin (≤5 MB per file). The engine consumes it and
    strips it before the session doc lands in ``stingar-*``.
    ``resolved_ip`` is the attack-time DNS resolution recorded by
    ``url_fetcher`` — ground truth that a central lookup hours later can't
    reproduce.
    """

    model_config = ConfigDict(extra="allow")

    url: str | None = None
    shasum: str | None = None  # sha256, Cowrie's downloads-dir key
    resolved_ip: str | None = None
    content_b64: str | None = None  # transport-only; never reaches ES


class HpData(BaseModel):
    """The ``hp_data`` envelope. Only engine-read fields are modeled."""

    model_config = ConfigDict(extra="allow")

    commands: list[str] | None = None
    credentials: list[dict[str, object]] | None = None
    files: list[FileRef] | None = None
    # SSH client fingerprint inputs (hassh) — exact key names TBD vs wire.
    kex: dict[str, object] | None = None
    client_version: str | None = None


class SessionIn(BaseModel):
    """A raw session doc as received from central Fluentd."""

    model_config = ConfigDict(extra="allow")

    ident: str = ""  # sensor uuid (HONEYPOT_IDENT)
    hostname: str = ""  # sensor hostname
    src_ip: str = ""
    session: str = ""  # session id
    start_time: datetime | None = None
    end_time: datetime | None = None
    hp_data: HpData = HpData()


class SessionAdditive(BaseModel):
    """Fields the engine ADDS to the session doc (DESIGN.md §4.1).

    Merged top-level into the outbound session; everything else in the doc is
    the inbound doc verbatim, minus ``hp_data.files[].content_b64``.
    """

    c2_hosts: list[str] = []
    playbook_hash: str | None = None
    hassh: str | None = None
    enrich_version: str = "1"
