# Copyright (C) 2025 Forewarned, Inc.
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Output plugin for the Stingar project using Fluentd.

Roughly based on the hpfeeds message format. Cowrie aggregates session
events in memory and emits one message to a local Fluent Bit / Fluentd
forwarder when the session closes.
"""

from __future__ import annotations

from typing import Any

from fluent import sender

import cowrie.core.output
from cowrie.core.config import CowrieConfig

# New sensors use the enrichable tag family so central Fluentd can route only
# these to c2-engine while stock sensors keep emitting events.cowrie unchanged.
COWRIE_TOPIC = "enrichable.cowrie"


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
                self.sender.emit(COWRIE_TOPIC, meta)
