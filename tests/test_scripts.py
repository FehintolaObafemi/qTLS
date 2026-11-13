"""The vector-extraction scripts fail loudly and parse the formats they claim to."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str):  # noqa: ANN202
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_trim_acvp_refuses_an_empty_source(tmp_path: Path) -> None:
    trim = _load("trim_acvp")
    with pytest.raises(SystemExit, match="no ACVP input files"):
        trim.main(tmp_path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_extract_rfc8448_joins_wrapped_titles_and_checks_lengths() -> None:
    extract = _load("extract_rfc8448")
    lines = [
        "   {client}  extract secret \"handshake\" (same as server handshake",
        "         secret)",
        "",
        "   {server}  derive secret for handshake \"tls13 derived\":",
        "",
        "      PRK (4 octets):  01 02 03",
        "         04",
        "",
        "      salt:  0 (all zero octets)",
    ]
    events = extract.parse(lines)
    assert events[0]["step"] == 'extract secret "handshake" (same as server handshake secret)'
    assert events[1]["values"] == {"PRK": "01020304", "salt": ""}
    with pytest.raises(ValueError, match="declared 5 octets"):
        extract.parse(["   {server}  x:", "", "      PRK (5 octets):  01 02 03 04"])
