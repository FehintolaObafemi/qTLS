"""Differential tests: two independent implementations must agree.

OpenSSL (via ``cryptography``) and liboqs share no code for ML-KEM or ML-DSA, so
agreement here rules out a backend that silently uses the wrong algorithm.
For example, round-3 Kyber768 has the same sizes as ML-KEM-768 but a different
key generation, so it would fail the seeded-keygen test.
"""

from __future__ import annotations

import hashlib

import pytest

from qtls import crypto
from qtls.crypto import InvalidSignature

pytestmark = pytest.mark.usefixtures("require_liboqs")

SEEDS = [bytes(64), bytes(range(64)), hashlib.sha512(b"qtls").digest()]
SHARED_KEMS = sorted(crypto.supported("openssl")[0] & crypto.supported("liboqs")[0])
SHARED_SIGS = sorted(crypto.supported("openssl")[1] & crypto.supported("liboqs")[1])


def test_shared_algorithms_are_the_expected_ones() -> None:
    assert SHARED_KEMS == ["ML-KEM-768"]
    assert SHARED_SIGS == ["ML-DSA-44", "ML-DSA-65"]


@pytest.mark.parametrize("alg", SHARED_KEMS)
@pytest.mark.parametrize("seed", SEEDS, ids=["zeros", "counting", "sha512"])
def test_seeded_keygen_agrees(alg: str, seed: bytes) -> None:
    a = crypto.kem_generate(alg, "openssl", seed=seed)
    b = crypto.kem_generate(alg, "liboqs", seed=seed)
    assert a.public_key == b.public_key


@pytest.mark.parametrize("alg", SHARED_KEMS)
@pytest.mark.parametrize(("enc", "dec"), [("openssl", "liboqs"), ("liboqs", "openssl")])
def test_encapsulate_in_one_decapsulate_in_other(alg: str, enc: str, dec: str) -> None:
    seed = SEEDS[2]
    receiver = crypto.kem_generate(alg, dec, seed=seed)  # type: ignore[arg-type]
    ct, ss = crypto.kem_encapsulate(alg, receiver.public_key, enc)  # type: ignore[arg-type]
    assert receiver.decapsulate(ct) == ss


@pytest.mark.parametrize("alg", SHARED_KEMS)
def test_implicit_rejection_agrees(alg: str) -> None:
    """Both backends derive the same rejection secret for the same bad ciphertext."""
    seed = SEEDS[1]
    a = crypto.kem_generate(alg, "openssl", seed=seed)
    b = crypto.kem_generate(alg, "liboqs", seed=seed)
    ct, ss = crypto.kem_encapsulate(alg, a.public_key, "openssl")
    bad = bytearray(ct)
    bad[17] ^= 0x80
    rejected_a = a.decapsulate(bytes(bad))
    assert rejected_a != ss
    assert rejected_a == b.decapsulate(bytes(bad))


@pytest.mark.parametrize("alg", SHARED_SIGS)
@pytest.mark.parametrize(("signer", "verifier"), [("openssl", "liboqs"), ("liboqs", "openssl")])
@pytest.mark.parametrize("context", [b"", b"tls13 qtls"])
def test_sign_in_one_verify_in_other(alg: str, signer: str, verifier: str, context: bytes) -> None:
    sk = crypto.sig_generate(alg, signer)  # type: ignore[arg-type]
    msg = b"cross-backend" * 7
    sig = sk.sign(msg, context=context)
    crypto.sig_verify(alg, sk.public_key, msg, sig, verifier, context=context)  # type: ignore[arg-type]
    with pytest.raises(InvalidSignature):
        crypto.sig_verify(alg, sk.public_key, msg + b"!", sig, verifier, context=context)  # type: ignore[arg-type]
