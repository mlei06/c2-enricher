#!/usr/bin/env python3
# Copyright (C) 2026 Forewarned, Inc.
# SPDX-License-Identifier: BSD-3-Clause
"""STINGAR sensor entrypoint (distroless-friendly, pure Python).

Replaces the stock 4warned bash entrypoint — the upstream Cowrie runtime is
distroless (no shell). On start it:

  1. renders etc/cowrie.cfg from etc/cowrie.cfg.dist using the stingar-hp.env
     vars (configure.py), so [output_stingar]/[output_url_fetcher] are filled in
  2. sends one "sensor" check-in heartbeat (checkin.py) — best-effort, so a
     transient Fluent Bit outage never blocks the honeypot from starting
  3. exec's Cowrie (twistd) as PID 1's child

All knobs come from the environment (the stingar-hp.env the compose passes).
"""

from __future__ import annotations

import os
import subprocess
import sys

BASE = "/cowrie/cowrie-git"
STINGAR = "/cowrie/cowrie-git/stingar"
PY = sys.executable


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _configure() -> None:
    subprocess.run(
        [
            PY, f"{STINGAR}/configure.py",
            "--fluent-host", _env("FLUENTBIT_HOST", "fluentbit"),
            "--fluent-port", _env("FLUENTBIT_PORT", "24284"),
            "--fluent-app", _env("FLUENTBIT_APP", "stingar"),
            "--hostname", _env("HONEYPOT_HOST", "stingar"),
            "--ip-addr", _env("HONEYPOT_IP", ""),
            "--asn", _env("HONEYPOT_ASN", ""),
            "--ident", _env("HONEYPOT_IDENT", ""),
            "--tags", _env("TAGS", ""),
            "--reported-ssh-port", _env("REPORTED_SSH_PORT", "22"),
            "--reported-telnet-port", _env("REPORTED_TELNET_PORT", "23"),
            # Cowrie's packaged defaults live under src/.../data/etc; cowrie
            # reads etc/cowrie.cfg as the override layer on top of them.
            "--template-file", f"{BASE}/src/cowrie/data/etc/cowrie.cfg.dist",
            "--config-file", f"{BASE}/etc/cowrie.cfg",
        ],
        check=True,
    )


def _checkin() -> None:
    try:
        subprocess.run(
            [
                PY, f"{STINGAR}/checkin.py",
                "-i", _env("HONEYPOT_IDENT", ""),
                "-n", _env("HONEYPOT_HOST", ""),
                "-a", _env("HONEYPOT_IP", ""),
                "-t", "cowrie",
                "--asn", _env("HONEYPOT_ASN", ""),
                "--tags", _env("TAGS", ""),
                "--fluent-host", _env("FLUENTBIT_HOST", "fluentbit"),
                "--fluent-port", _env("FLUENTBIT_PORT", "24284"),
                "--fluent-app", _env("FLUENTBIT_APP", "stingar"),
            ],
            check=False,
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001 - heartbeat must never block startup
        print(f"entrypoint: checkin skipped ({exc})", file=sys.stderr)


def main() -> None:
    os.chdir(BASE)
    _configure()
    _checkin()
    twistd = "/cowrie/cowrie-env/bin/twistd"
    os.execv(twistd, [twistd, "-n", "--umask=0022", "--pidfile=", "cowrie"])


if __name__ == "__main__":
    main()
