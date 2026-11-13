"""SHA-256, HMAC, HKDF and AES-128-GCM through qtls.crypto: behaviour, errors, counting.

Correctness against independent vectors is in test_rfc_vectors.py (RFC 8448).
"""

from __future__ import annotations

import pytest

from qtls import crypto
from qtls.crypto import AeadFailure

KEY, NONCE, AAD, PT = bytes(range(16)), bytes(range(12)), b"\x17\x03\x03\x00\x20", b"secret payload"


def test_sha256_known_answers() -> None:
    """FIPS 180-4 examples."""
    assert crypto.sha256().digest().hex() == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert crypto.sha256(b"abc").digest().hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_incremental_hash_snapshots_are_independent() -> None:
    running = crypto.sha256(b"a")
    snap = running.copy()
    running.update(b"bc")
    assert snap.digest() == crypto.sha256(b"a").digest()
    assert running.digest() == crypto.sha256(b"abc").digest()
    assert running.digest() == running.digest()  # digest() is repeatable


def test_hkdf_expand_length_bounds() -> None:
    prk = bytes(32)
    assert len(crypto.hkdf_expand(prk, b"", 255 * 32)) == 255 * 32
    for bad in (0, -1, 255 * 32 + 1):
        with pytest.raises(ValueError, match="length"):
            crypto.hkdf_expand(prk, b"", bad)
    with pytest.raises(ValueError, match="PRK"):
        crypto.hkdf_expand(bytes(31), b"", 32)


def test_aead_round_trip() -> None:
    aead = crypto.aead_key(KEY)
    ct = aead.seal(NONCE, PT, AAD)
    assert len(ct) == len(PT) + 16
    assert aead.open(NONCE, ct, AAD) == PT


def _flip(b: bytes, i: int) -> bytes:
    out = bytearray(b)
    out[i] ^= 1
    return bytes(out)


def test_aead_tampering_raises_aead_failure() -> None:
    aead = crypto.aead_key(KEY)
    ct = aead.seal(NONCE, PT, AAD)
    cases = {
        "tag": (NONCE, _flip(ct, -1), AAD),
        "ciphertext": (NONCE, _flip(ct, 0), AAD),
        "aad": (NONCE, ct, _flip(AAD, 0)),
        "nonce": (_flip(NONCE, 0), ct, AAD),
        "truncated below tag": (NONCE, ct[:15], AAD),
        "empty": (NONCE, b"", AAD),
    }
    with crypto.count_ops() as ops:
        for label, args in cases.items():
            with pytest.raises(AeadFailure):
                aead.open(*args)
                pytest.fail(label)
    # Each rejection is a real decryption attempt, counted on its own.
    assert ops == {("openssl", "AES-128-GCM", "open_failed"): len(cases)}
    assert not issubclass(AeadFailure, ValueError)
    assert not issubclass(AeadFailure, crypto.InvalidSignature)


def test_aead_wrong_key_or_nonce_length_is_a_usage_error() -> None:
    for bad in (bytes(15), bytes(32)):
        with pytest.raises(ValueError, match="key"):
            crypto.aead_key(bad)
    aead = crypto.aead_key(KEY)
    with pytest.raises(ValueError, match="nonce"):
        aead.seal(bytes(11), PT, AAD)
    with pytest.raises(ValueError, match="nonce"):
        aead.open(bytes(13), bytes(32), AAD)


@pytest.mark.parametrize("bad", [5, "text", memoryview(b"abc"), None], ids=lambda v: type(v).__name__)
def test_symmetric_inputs_must_be_bytes(bad: object) -> None:
    aead = crypto.aead_key(KEY)
    calls = [
        lambda: crypto.sha256().update(bad),  # type: ignore[arg-type]
        lambda: crypto.hmac_sha256(bad, b"x"),  # type: ignore[arg-type]
        lambda: crypto.hmac_sha256(b"k", bad),  # type: ignore[arg-type]
        lambda: crypto.hkdf_extract(bad, b"x"),  # type: ignore[arg-type]
        lambda: crypto.hkdf_expand(bytes(32), bad, 32),  # type: ignore[arg-type]
        lambda: aead.seal(NONCE, bad, AAD),  # type: ignore[arg-type]
        lambda: aead.open(NONCE, bad, AAD),  # type: ignore[arg-type]
        lambda: crypto.aead_key(bad),  # type: ignore[arg-type]
    ]
    for call in calls:
        with pytest.raises(TypeError):
            call()


def test_symmetric_operations_are_counted_with_bytes() -> None:
    aead = crypto.aead_key(KEY)
    with crypto.count_ops() as ops:
        running = crypto.sha256(b"x" * 100)
        running.digest()
        crypto.hmac_sha256(b"k", b"y" * 10)
        crypto.hkdf_extract(b"", b"z")
        crypto.hkdf_expand(bytes(32), b"info", 48)
        ct = aead.seal(NONCE, PT, AAD)
        aead.open(NONCE, ct, AAD)
        crypto.x25519_from_private_bytes(bytes(32))
    assert ops == {
        ("openssl", "SHA-256", "bytes"): 100,
        ("openssl", "SHA-256", "digest"): 1,
        ("openssl", "HMAC-SHA256", "mac"): 1,
        ("openssl", "HMAC-SHA256", "bytes"): 10,
        ("openssl", "HKDF-SHA256", "extract"): 1,
        ("openssl", "HKDF-SHA256", "bytes"): 1,  # input keying material
        ("openssl", "HKDF-SHA256", "expand"): 1,
        ("openssl", "HKDF-SHA256", "blocks"): 2,  # 48 bytes = 2 HMAC blocks
        ("openssl", "AES-128-GCM", "seal"): 1,
        ("openssl", "AES-128-GCM", "open"): 1,
        ("openssl", "AES-128-GCM", "bytes"): 2 * len(PT),  # plaintext, on seal and on open
        ("openssl", "X25519", "import"): 1,
    }


def test_failed_symmetric_operations_are_not_counted() -> None:
    with crypto.count_ops() as ops:
        with pytest.raises(ValueError):
            crypto.hkdf_expand(bytes(32), b"", 0)
        with pytest.raises(ValueError):
            crypto.aead_key(bytes(3))
    assert ops == {}


def test_aead_empty_aad_and_empty_plaintext() -> None:
    aead = crypto.aead_key(KEY)
    for pt, aad in ((PT, b""), (b"", AAD), (b"", b"")):
        ct = aead.seal(NONCE, pt, aad)
        assert aead.open(NONCE, ct, aad) == pt
        with pytest.raises(AeadFailure):
            aead.open(NONCE, ct, aad + b"x")


@pytest.mark.parametrize("length", [1, 31, 32, 33, 64, 65, 255, 8160])
def test_hkdf_expand_matches_an_independent_implementation(length: int) -> None:
    """Multi-block chaining and the block counter, checked against cryptography's HKDFExpand.

    RFC 8448 never expands more than 32 bytes, so it can't catch a broken T(i-1)
    chain or counter. (RFC 5869's own vectors weren't among the approved downloads.)
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

    prk, info = bytes(range(32)), b"tls13 qtls multi-block"
    expected = HKDFExpand(hashes.SHA256(), length, info).derive(prk)
    assert crypto.hkdf_expand(prk, info, length) == expected


@pytest.mark.parametrize("bad", [True, False, 32.0, "32"], ids=repr)
def test_hkdf_expand_rejects_non_int_lengths(bad: object) -> None:
    with pytest.raises(ValueError, match="length"):
        crypto.hkdf_expand(bytes(32), b"", bad)  # type: ignore[arg-type]


def test_hmac_matches_an_independent_implementation() -> None:
    """Including a key longer than the 64-byte block (hashed first, RFC 2104)."""
    import hashlib
    import hmac as stdlib_hmac

    for key in (b"", b"k", bytes(64), bytes(range(100))):
        data = b"message" * 10
        assert crypto.hmac_sha256(key, data) == stdlib_hmac.new(key, data, hashlib.sha256).digest()


def test_aead_empty_plaintext_is_exactly_a_tag() -> None:
    aead = crypto.aead_key(KEY)
    ct = aead.seal(NONCE, b"", AAD)
    assert len(ct) == 16
    assert aead.open(NONCE, ct, AAD) == b""
