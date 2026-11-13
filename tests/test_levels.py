"""qtls/levels.py is exact, consistent with specs.md, and the only pairing source."""

from __future__ import annotations

import re
from pathlib import Path

from qtls import crypto
from qtls.levels import BASELINE_SIGNATURE, KEY_EXCHANGE_GROUP, LEVELS

ROOT = Path(__file__).resolve().parent.parent


def test_levels_are_exactly_the_planned_pairs() -> None:
    table = {
        name: (lvl.auth_kem, lvl.leaf_signatures, lvl.issuer_signatures, lvl.mtc_cosigner)
        for name, lvl in LEVELS.items()
    }
    assert table == {
        "cat1-2": ("ML-KEM-512", ("ML-DSA-44", "Falcon-512"), ("ML-DSA-44", "Falcon-512"), "ML-DSA-44"),
        "cat3": ("ML-KEM-768", ("ML-DSA-65",), ("ML-DSA-65",), "ML-DSA-65"),
    }
    assert KEY_EXCHANGE_GROUP == 0x11EC
    assert BASELINE_SIGNATURE == "ECDSA-P256-SHA256"


def test_every_paired_algorithm_exists_and_matches_its_level() -> None:
    supported_kems = crypto.supported("openssl")[0] | crypto.supported("liboqs")[0]
    supported_sigs = crypto.supported("openssl")[1] | crypto.supported("liboqs")[1]
    allowed = {"cat1-2": {1, 2}, "cat3": {3}}
    for name, lvl in LEVELS.items():
        assert lvl.auth_kem in supported_kems
        assert crypto.KEMS[lvl.auth_kem].nist_category in allowed[name]
        for alg in (*lvl.leaf_signatures, *lvl.issuer_signatures, lvl.mtc_cosigner):
            assert alg in supported_sigs
            assert crypto.SIGNATURES[alg].nist_category in allowed[name], (name, alg)


def test_only_crypto_reads_nist_category() -> None:
    offenders = [
        str(p.relative_to(ROOT))
        for p in (ROOT / "qtls").rglob("*.py")
        if p.name != "crypto.py" and re.search(r"\bnist_category\b", p.read_text())
    ]
    assert offenders == []
