"""NIST ACVP known-answer tests (tests/vectors/acvp, see SOURCE there).

Round-trip and size tests pass for any self-consistent scheme: round-3 Kyber768
has exactly ML-KEM-768's sizes, and Dilithium2 has ML-DSA-44's. Only
known answers prove the backends run the FIPS 203 / FIPS 204 algorithms.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from qtls import crypto
from qtls.crypto import InvalidSignature

VECTORS = Path(__file__).parent / "vectors" / "acvp"


def _load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


KEYGEN = _load("mlkem_keygen.json")
DECAP = _load("mlkem_decap.json")
SIGVER = _load("mldsa_sigver.json")


def _ids(tests: list[dict]) -> list[str]:
    return [f"{t['parameterSet']}-tc{t['tcId']}" for t in tests]


def test_vector_files_cover_every_case() -> None:
    """Guards against a trimming change silently dropping categories."""
    assert {t["parameterSet"] for t in KEYGEN["tests"]} == {"ML-KEM-512", "ML-KEM-768"}
    decap = Counter((t["parameterSet"], t["reason"]) for t in DECAP["tests"])
    for ps in ("ML-KEM-512", "ML-KEM-768"):
        assert decap[(ps, "modified ciphertext")] >= 1
        assert decap[(ps, "valid decapsulation")] + decap[(ps, "valid")] >= 1
    sig = Counter((t["parameterSet"], t["testPassed"]) for t in SIGVER["tests"])
    for ps in ("ML-DSA-44", "ML-DSA-65"):
        assert sig[(ps, True)] >= 1
        assert sig[(ps, False)] >= 4  # modified message, z, hint, commitment


KEYGEN_CASES = [
    pytest.param(b, t, id=f"{b}-{t['parameterSet']}-tc{t['tcId']}")
    for b in crypto.BACKENDS
    for t in KEYGEN["tests"]
    if t["parameterSet"] in crypto.supported(b)[0]
]


@pytest.mark.parametrize(("backend_name", "vector"), KEYGEN_CASES)
def test_mlkem_keygen(request: pytest.FixtureRequest, backend_name: str, vector: dict) -> None:
    if backend_name == "liboqs":
        request.getfixturevalue("require_liboqs")
    backend = backend_name
    alg = vector["parameterSet"]
    seed = bytes.fromhex(vector["d"] + vector["z"])
    sk = crypto.kem_generate(alg, backend, seed=seed)  # type: ignore[arg-type]
    assert sk.public_key.hex().upper() == vector["ek"].upper()


@pytest.mark.usefixtures("require_liboqs")
@pytest.mark.parametrize("vector", DECAP["tests"], ids=_ids(DECAP["tests"]))
def test_mlkem_decapsulation(vector: dict) -> None:
    """Includes implicit-rejection vectors: a modified ciphertext must give K̄, not an error."""
    sk = crypto.kem_from_decapsulation_key(
        vector["parameterSet"], bytes.fromhex(vector["dk"]), "liboqs"
    )
    assert sk.decapsulate(bytes.fromhex(vector["c"])).hex().upper() == vector["k"].upper()
    # The public key extracted from dk must be the real encapsulation key.
    ct, ss = crypto.kem_encapsulate(vector["parameterSet"], sk.public_key, "liboqs")
    assert sk.decapsulate(ct) == ss


@pytest.mark.parametrize("vector", SIGVER["tests"], ids=_ids(SIGVER["tests"]))
def test_mldsa_sigver(backend: str, vector: dict) -> None:
    args = (
        vector["parameterSet"],
        bytes.fromhex(vector["pk"]),
        bytes.fromhex(vector["message"]),
        bytes.fromhex(vector["signature"]),
        backend,
    )
    context = bytes.fromhex(vector["context"])
    if vector["testPassed"]:
        crypto.sig_verify(*args, context=context)  # type: ignore[arg-type]
    else:
        with pytest.raises(InvalidSignature):
            crypto.sig_verify(*args, context=context)  # type: ignore[arg-type]


def test_openssl_refuses_expanded_decapsulation_keys() -> None:
    with pytest.raises(crypto.BackendUnavailable, match="seeds"):
        crypto.kem_from_decapsulation_key("ML-KEM-768", bytes(2400), "openssl")


@pytest.mark.usefixtures("require_liboqs")
def test_expanded_key_wrong_length_rejected() -> None:
    with pytest.raises(ValueError, match="decapsulation key"):
        crypto.kem_from_decapsulation_key("ML-KEM-768", bytes(2399), "liboqs")
