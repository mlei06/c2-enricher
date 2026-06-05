# Copyright (C) 2025 Forewarned, Inc.
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Output plugin for the Stingar project using Fluentd.

Roughly based on the hpfeeds message format. Cowrie aggregates session
events in memory and emits one message to a local Fluent Bit / Fluentd
forwarder when the session closes.

Enrichment-enabled build (for the central c2-engine):

* Emits on the ``enrichable.cowrie`` tag family so central Fluentd can route
  these to c2-engine while stock sensors keep ``events.cowrie`` unchanged.
* On session close, inlines each successfully-downloaded file's bytes into
  ``hp_data.files[].content_b64`` (base64), capped at ``CONTENT_INLINE_MAX``.
  The central engine has no disk access — bytes must ride the wire. It hashes,
  sniffs, and ``strings``-scans them, then strips ``content_b64`` before the
  session lands in Elasticsearch. Files over the cap are shipped hash-only
  (the engine degrades to a valid metadata sighting). Both scripts and
  binaries are inlined; persistence of script text vs. binary metadata is the
  engine's decision, not the sensor's.
* Carries ``hp_data.files[].resolved_ip`` (attack-time DNS, from
  ``url_fetcher``) so domain-named C2s can be geolocated on the truth the
  attacker hit, not a later re-resolution.
"""

from __future__ import annotations

import base64
import logging
import os
from typing import Any

from fluent import sender

import cowrie.core.output
from cowrie.core.config import CowrieConfig

logger = logging.getLogger("cowrie.plugins.stingar")

# New sensors use the enrichable tag family so central Fluentd can route only
# these to c2-engine while stock sensors keep emitting events.cowrie unchanged.
COWRIE_TOPIC = "enrichable.cowrie"

# Wire cap for inlined download bytes. Distinct from the engine's ES-side
# content cap (≤256 KB, scripts only): the sensor ships, the engine decides
# what to persist. 5 MB covers ~all real honeypot payloads (Mirai ELFs ~130 KB,
# scripts tiny); larger files ship hash-only.
CONTENT_INLINE_MAX = 5 * 1024 * 1024


class Output(cowrie.core.output.Output):
    """
    Output plugin for Stingar via Fluent forward protocol.
    """

    def __init__(self) -> None:
        self.identifier = CowrieConfig.get("output_stingar", "identifier")
        self.ip_addr = CowrieConfig.get("output_stingar", "ip_addr")
        self.hostname = CowrieConfig.get("output_stingar", "hostname")
        self.asn = CowrieConfig.get("output_stingar", "asn")
        self.tags = self.build_tags(CowrieConfig.get("output_stingar", "tags"))
        self.inline_bytes = CowrieConfig.getboolean(
            "output_stingar", "inline_download_bytes", fallback=True
        )
        self.inline_max = CowrieConfig.getint(
            "output_stingar", "inline_max_bytes", fallback=CONTENT_INLINE_MAX
        )
        self.meta: dict[str, dict[str, Any]] = {}
        self.sender: sender.FluentSender | None = None
        super().__init__()

    @staticmethod
    def build_tags(tag_str: str) -> dict[str, Any]:
        tags: dict[str, Any] = {}
        for tag in tag_str.split(","):
            tag = tag.strip()
            if not tag:
                continue
            try:
                k, v = tag.split(":", 1)
                tags[k.strip()] = v.strip()
            except ValueError:
                tags.setdefault("misc", []).append(tag)
        return tags

    def start(self) -> None:
        host = CowrieConfig.get("output_stingar", "fluent_host")
        port = CowrieConfig.getint("output_stingar", "fluent_port")
        app = CowrieConfig.get("output_stingar", "app")
        self.sender = sender.FluentSender(app, host=host, port=port)

    def stop(self) -> None:
        if self.sender is not None:
            self.sender.close()

    def write(self, entry: dict[str, Any]) -> None:
        session = entry.get("session")
        if session is None or session not in self.meta:
            if entry["eventid"] != "cowrie.session.connect":
                return

        eventid = entry["eventid"]

        if eventid == "cowrie.session.connect":
            self.meta[session] = {
                "app": "cowrie",
                "sensor": {
                    "uuid": self.identifier,
                    "hostname": self.hostname,
                    "tags": self.tags,
                    "asn": self.asn,
                },
                "protocol": entry["protocol"],
                "start_time": entry["timestamp"],
                "end_time": "",
                "src_ip": entry["src_ip"],
                "src_port": entry["src_port"],
                "dst_ip": self.ip_addr or entry["dst_ip"],
                "dst_port": entry["dst_port"],
                "hp_data": {
                    "con_type": "accept",
                    "transport": "tcp",
                    "session": session,
                    "credentials": [],
                    "commands": [],
                    "unknown_commands": [],
                    "urls": [],
                    "files": [],
                    "uploads": [],
                    "version": None,
                    "ttylog": None,
                    "arch": None,
                    "client_height": None,
                    "client_width": None,
                    "key_fingerprint": None,
                    "kex": None,
                },
            }

        elif eventid == "cowrie.login.success":
            u, p = entry["username"], entry["password"]
            self.meta[session]["hp_data"]["credentials"].append(
                {"username": u, "password": p, "success": True}
            )

        elif eventid == "cowrie.login.failed":
            u, p = entry["username"], entry["password"]
            self.meta[session]["hp_data"]["credentials"].append(
                {"username": u, "password": p, "success": False}
            )

        elif eventid == "cowrie.command.input":
            self.meta[session]["hp_data"]["commands"].append(entry["input"])

        elif eventid == "cowrie.command.failed":
            self.meta[session]["hp_data"]["unknown_commands"].append(entry["input"])

        elif eventid in (
            "cowrie.session.file_download",
            "cowrie.session.file_download.failed",
            "cowrie.session.file_upload",
        ):
            action = "download" if "download" in eventid else "upload"
            status = "failed" if eventid.endswith(".failed") else "successful"
            url = entry.get("url", "")
            file_data = {
                "url": url,
                "outfile": entry.get("outfile", ""),
                "shasum": entry.get("shasum", ""),
                "action": action,
                "status": status,
                # Attack-time DNS resolution from url_fetcher (empty for
                # native-emulated downloaders, which don't truly connect).
                "resolved_ip": entry.get("resolved_ip", ""),
            }
            if url:
                self.meta[session]["hp_data"]["urls"].append(url)
            self.meta[session]["hp_data"]["files"].append(file_data)

        elif eventid == "cowrie.session.params":
            self.meta[session]["hp_data"]["arch"] = entry.get("arch")

        elif eventid == "cowrie.client.size":
            self.meta[session]["hp_data"]["client_width"] = entry.get("width")
            self.meta[session]["hp_data"]["client_height"] = entry.get("height")

        elif eventid == "cowrie.client.fingerprint":
            self.meta[session]["hp_data"]["key_fingerprint"] = entry.get("fingerprint")

        elif eventid == "cowrie.client.kex":
            self.meta[session]["hp_data"]["kex"] = {
                "hassh": entry.get("hassh"),
                "hassh_algorithms": entry.get("hasshAlgorithms"),
                "kex_algorithms": entry.get("kexAlgs"),
                "key_algorithms": entry.get("keyAlgs"),
                "enc_cs": entry.get("encCS"),
                "mac_cs": entry.get("macCS"),
                "comp_cs": entry.get("compCS"),
                "lang_cs": entry.get("langCS"),
            }

        elif eventid == "cowrie.client.version":
            self.meta[session]["hp_data"]["version"] = entry.get("version")

        elif eventid == "cowrie.log.closed":
            ttylog_path = entry.get("ttylog")
            if ttylog_path:
                with open(ttylog_path, "rb") as ttylog:
                    self.meta[session]["hp_data"]["ttylog"] = ttylog.read().hex()

        elif eventid == "cowrie.session.closed":
            meta = self.meta.pop(session, None)
            if meta is not None and self.sender is not None:
                meta["end_time"] = entry["timestamp"]
                if self.inline_bytes:
                    self._inline_download_bytes(meta["hp_data"])
                self.sender.emit(COWRIE_TOPIC, meta)

    def _inline_download_bytes(self, hp_data: dict[str, Any]) -> None:
        """Read each successful download off disk and inline it as base64.

        Best-effort: a missing/oversized/unreadable file is skipped (no
        ``content_b64`` key), and the central engine degrades that file to a
        hash-only sighting. Never raises into the session-close path.
        """
        for f in hp_data.get("files", []):
            if f.get("action") != "download" or f.get("status") != "successful":
                continue
            path = f.get("outfile")
            if not path:
                continue
            try:
                if os.path.getsize(path) > self.inline_max:
                    continue
                with open(path, "rb") as fh:
                    f["content_b64"] = base64.b64encode(fh.read()).decode("ascii")
            except OSError as exc:
                logger.info("stingar: could not inline %s: %s", path, exc)
