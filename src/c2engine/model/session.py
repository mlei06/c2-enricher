"""Inbound Cowrie/STINGAR session doc, and the additive outbound contract.

Field names match what the cowrie fork's ``output_stingar`` plugin
(``src/cowrie/plugins/stingar.py``, Forewarned) emits on
``cowrie.session.closed`` — verified against the plugin source 2026-06-05.
One doc per session. New sensors tag ``<app>.enrichable.cowrie``; stock
sensors still use ``<app>.events.cowrie``.

The pass-through invariant (DESIGN.md §4.1): the engine never renames,
retypes, or rewrites a stock field. ``extra="allow"`` everywhere — unknown
fields ride through untouched and are re-emitted verbatim. We only *model*
the fields the engine reads.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


class Sensor(BaseModel):
    """``sensor`` envelope — the honeypot's identity."""

    model_config = ConfigDict(extra="allow")

    uuid: str = ""  # HONEYPOT_IDENT
    hostname: str = ""
    tags: dict[str, object] = {}  # colon pairs + "misc" list
    asn: str = ""


class Credential(BaseModel):
    """One ``hp_data.credentials[]`` entry (login.success / login.failed)."""

    model_config = ConfigDict(extra="allow")

    username: str = ""
    password: str = ""
    success: bool = False


class Kex(BaseModel):
    """``hp_data.kex`` — SSH client KEX; hassh is precomputed by Cowrie.

    The algorithm lists are typed ``Any``: real Cowrie emits them as JSON
    arrays on some versions and ``;``-joined strings on others (verified
    against the live deployment). The engine only reads ``hassh``, so we accept
    either rather than over-constrain a field we don't parse.
    """

    model_config = ConfigDict(extra="allow")

    hassh: str | None = None
    hassh_algorithms: Any = None
    kex_algorithms: Any = None
    key_algorithms: Any = None
    enc_cs: Any = None
    mac_cs: Any = None
    comp_cs: Any = None
    lang_cs: Any = None


class FileRef(BaseModel):
    """One ``hp_data.files[]`` entry (file_download / file_upload events).

    ``content_b64`` and ``resolved_ip`` are NOT stock — they are the planned
    sensor-side additions (DESIGN.md §5.2): inlined download bytes (≤5 MB,
    stripped by the engine before the session lands in ES) and url_fetcher's
    attack-time DNS resolution. Optional so stock docs parse today.
    """

    model_config = ConfigDict(extra="allow")

    url: str = ""
    outfile: str = ""
    shasum: str = ""  # sha256, Cowrie's downloads-dir key
    action: str = ""  # "download" | "upload"
    status: str = ""  # "successful" | "failed"
    resolved_ip: str | None = None  # sensor-side addition (pending)
    content_b64: str | None = None  # sensor-side addition (pending); never reaches ES


class HpData(BaseModel):
    """The ``hp_data`` envelope. Only engine-read fields are modeled."""

    model_config = ConfigDict(extra="allow")

    con_type: str = "accept"
    transport: str = "tcp"
    session: str = ""  # the session id
    credentials: list[Credential] = []
    commands: list[str] = []
    unknown_commands: list[str] = []
    urls: list[str] = []
    files: list[FileRef] = []
    uploads: list[object] = []
    version: str | None = None  # SSH client banner, e.g. "SSH-2.0-libssh2_1.4.3"
    ttylog: str | None = None  # hex-encoded ttylog bytes
    arch: str | None = None
    client_height: int | None = None
    client_width: int | None = None
    key_fingerprint: str | None = None  # attacker-supplied pubkey fingerprint
    kex: Kex | None = None


class SessionIn(BaseModel):
    """A raw session doc as received from central Fluentd."""

    model_config = ConfigDict(extra="allow")

    app: str = "cowrie"
    sensor: Sensor = Sensor()
    protocol: str = ""
    start_time: datetime | None = None
    end_time: datetime | None = None  # "" until session close; always set on the wire
    src_ip: str = ""
    src_port: int | None = None
    dst_ip: str = ""
    dst_port: int | None = None
    hp_data: HpData = HpData()

    @field_validator("start_time", "end_time", mode="before")
    @classmethod
    def _empty_str_is_none(cls, v: object) -> object:
        return None if v == "" else v

    # Convenience accessors for ledger-row stamping -------------------------
    @property
    def session_id(self) -> str:
        return self.hp_data.session

    @property
    def sensor_uuid(self) -> str:
        return self.sensor.uuid

    @property
    def sensor_hostname(self) -> str:
        return self.sensor.hostname


class SessionAdditive(BaseModel):
    """Fields the engine ADDS to the session doc (DESIGN.md §4.1).

    Merged top-level into the outbound session; everything else in the doc is
    the inbound doc verbatim, minus ``hp_data.files[].content_b64``.
    ``hassh`` is a top-level copy of ``hp_data.kex.hassh`` for direct Kibana
    pivots — the nested original is untouched.
    """

    c2_hosts: list[str] = []
    playbook_hash: str | None = None
    hassh: str | None = None
    enrich_version: str = "1"
