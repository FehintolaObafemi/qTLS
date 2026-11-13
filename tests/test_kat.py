"""NIST ACVP known-answer tests (tests/vectors/acvp, see SOURCE there).

Round-trip and size tests pass for any self-consistent scheme: round-3 Kyber768
has exactly ML-KEM-768's sizes, and Dilithium2 has ML-DSA-44's. Only
known answers prove the backends run the FIPS 203 / FIPS 204 algorithms.
"""

from __future__ import annotations

import hashlib
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


# --------------------------------------------------------------------------- #
# Phase 2a: ML-DSA key generation, ML-KEM encapsulation, liboqs signature KATs
# --------------------------------------------------------------------------- #


MLDSA_KEYGEN = _load("mldsa_keygen.json")
LIBOQS_KATS = json.loads((VECTORS.parent / "liboqs" / "sig_kats.json").read_text())


@pytest.mark.parametrize("vector", MLDSA_KEYGEN["tests"], ids=_ids(MLDSA_KEYGEN["tests"]))
def test_mldsa_keygen(backend: str, vector: dict) -> None:
    """FIPS 204 ξ → pk on both backends; liboqs also matches the expanded sk."""
    key = crypto.sig_generate(vector["parameterSet"], backend, seed=bytes.fromhex(vector["seed"]))  # type: ignore[arg-type]
    assert key.public_key.hex().upper() == vector["pk"].upper()
    assert key.seed is not None and key.seed.hex().upper() == vector["seed"].upper()
    if backend == "liboqs":
        assert key.expanded_private_key().hex().upper() == vector["sk"].upper()
    else:
        with pytest.raises(crypto.BackendUnavailable):
            key.expanded_private_key()


ENCAP_VECTORS = [t for t in DECAP["tests"] if t["function"] == "encapsulation"]


@pytest.mark.usefixtures("require_liboqs")
@pytest.mark.parametrize("vector", ENCAP_VECTORS, ids=_ids(ENCAP_VECTORS))
def test_mlkem_encapsulation(vector: dict) -> None:
    """FIPS 203 encapsulation with fixed m: (ek, m) → (c, K)."""
    ct, ss = crypto.kem_encapsulate(
        vector["parameterSet"], bytes.fromhex(vector["ek"]), "liboqs", seed=bytes.fromhex(vector["m"])
    )
    assert ct.hex().upper() == vector["c"].upper()
    assert ss.hex().upper() == vector["k"].upper()


def test_openssl_refuses_derandomised_encapsulation() -> None:
    sk = crypto.kem_generate("ML-KEM-768", "openssl")
    with pytest.raises(crypto.BackendUnavailable):
        crypto.kem_encapsulate("ML-KEM-768", sk.public_key, "openssl", seed=bytes(32))


def _rsp_count(alg: str, count: int, outer: object) -> str:
    """One entry of liboqs tests/kat_sig.c output, produced through the qtls.crypto API."""
    seed = outer.random(48)  # type: ignore[attr-defined]
    msg = outer.random(33 * (count + 1))  # type: ignore[attr-defined]
    with crypto.deterministic_rng(seed):
        key = crypto.sig_generate(alg, "liboqs")
        sig = key.sign(msg)
    crypto.sig_verify(alg, key.public_key, msg, sig, "liboqs")
    if alg == "Falcon-512":
        sm = (len(sig) - 40).to_bytes(2, "big") + sig[1:41] + msg + b"\x29" + sig[41:]
    else:
        sm = sig + msg

    def bstr(label: str, b: bytes) -> str:
        return label + (b.hex().upper() if b else "00") + "\n"

    return (
        f"count = {count}\n" + bstr("seed = ", seed) + f"mlen = {len(msg)}\n" + bstr("msg = ", msg)
        + bstr("pk = ", key.public_key) + bstr("sk = ", key.expanded_private_key())
        + f"smlen = {len(sm)}\n" + bstr("sm = ", sm)
    )


def _liboqs_kat_hash(alg: str, counts: int) -> str:
    outer = crypto._NistDrbg(bytes(range(48)))
    entries = [_rsp_count(alg, c, outer) for c in range(counts)]
    return hashlib.sha256("\n".join(entries).encode()).hexdigest()


@pytest.mark.usefixtures("require_liboqs")
@pytest.mark.parametrize("alg", ["Falcon-512", "ML-DSA-44", "ML-DSA-65"])
def test_liboqs_signature_kat_single(alg: str) -> None:
    """Count 0 of liboqs's KAT, reproduced through sig_generate/sign/expanded_private_key."""
    assert _liboqs_kat_hash(alg, 1) == LIBOQS_KATS[alg]["single"]


@pytest.mark.usefixtures("require_liboqs")
@pytest.mark.parametrize("alg", ["Falcon-512", "ML-DSA-44"])
def test_liboqs_signature_kat_all(alg: str) -> None:
    """All 100 counts: message lengths 33..3300 and many Falcon signature lengths."""
    assert _liboqs_kat_hash(alg, 100) == LIBOQS_KATS[alg]["all"]


def test_padded_falcon_has_a_different_kat() -> None:
    """The vendored hashes really distinguish Falcon-512 from its padded look-alike."""
    assert LIBOQS_KATS["Falcon-512"]["single"] != LIBOQS_KATS["Falcon-padded-512"]["single"]


@pytest.mark.usefixtures("require_liboqs")
def test_seeded_keygen_matches_the_drbg_kat() -> None:
    """The seeded entry points derive the same keys as the KAT's DRBG path."""
    outer = crypto._NistDrbg(bytes(range(48)))
    seed = outer.random(48)
    with crypto.deterministic_rng(seed):
        falcon_kat_pk = crypto.sig_generate("Falcon-512", "liboqs").public_key
        mldsa_kat_pk = crypto.sig_generate("ML-DSA-44", "liboqs").public_key
    assert crypto.sig_generate("Falcon-512", "liboqs", seed=seed).public_key == falcon_kat_pk
    # ML-DSA keygen draws ξ as its first 32 random bytes. (Above, it drew after
    # Falcon's keygen, so take a fresh stream for the comparison.)
    xi = crypto._NistDrbg(seed).random(32)
    with crypto.deterministic_rng(seed):
        mldsa_first = crypto.sig_generate("ML-DSA-44", "liboqs").public_key
    assert crypto.sig_generate("ML-DSA-44", "liboqs", seed=xi).public_key == mldsa_first
    assert crypto.sig_generate("ML-DSA-44", "openssl", seed=xi).public_key == mldsa_first
    assert mldsa_kat_pk != mldsa_first
