"""Parse the SSH client banner into a CPE tuple.

Banner format is ``SSH-2.0-<software>_<version> [comment]`` (RFC 4253). We lift
the software id + version and map known ids to NVD CPE vendor/product strings.
Unknown ids pass through verbatim for fuzzy downstream matching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_BANNER_RE = re.compile(
    r"^SSH-\d+\.\d+-([A-Za-z0-9][A-Za-z0-9._-]*?)(?:[_-]([A-Za-z0-9._-]+))?(?:\s|$)"
)

_KNOWN: dict[str, tuple[str, str]] = {
    "openssh": ("openbsd", "openssh"),
    "libssh": ("libssh", "libssh"),
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
    "paramiko": ("paramiko", "paramiko"),
    "russh": ("russh_project", "russh"),
    "go": ("golang", "go"),
    "golang": ("golang", "go"),
    "putty": ("putty", "putty"),
    "winscp": ("winscp", "winscp"),
    "jsch": ("jcraft", "jsch"),
    "asyncssh": ("asyncssh_project", "asyncssh"),
    "trilead": ("trilead", "ssh-2"),
}


@dataclass
class Cpe:
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    cpe23: str | None = None


def parse(banner: str | None) -> Cpe | None:
    """None when the banner is missing; a Cpe (possibly version-less) otherwise."""
    if not banner:
        return None
    m = _BANNER_RE.match(banner.strip())
    if not m:
        return Cpe()
    software = m.group(1)
    version = m.group(2) or ""
    vendor, product = _KNOWN.get(software.lower(), (software.lower(), software.lower()))
    cpe23 = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*" if version else None
    return Cpe(vendor=vendor, product=product, version=version or None, cpe23=cpe23)
