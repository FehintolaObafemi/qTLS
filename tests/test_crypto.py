"""Behaviour of qtls.crypto on each backend: sizes, round trips, rejections."""

from __future__ import annotations

import pytest

from qtls import crypto
from qtls.crypto import InvalidSignature, UnknownAlgorithm

# FIPS 203 Table 3 / FIPS 204 Table 2 / Falcon round-3 spec.
EXPECTED_KEM_SIZES = {  # pk, ct, ss
    "ML-KEM-512": (800, 768, 32),
    "ML-KEM-768": (1184, 1088, 32),
}
EXPECTED_SIG_SIZES = {  # pk, sig (max for variable-length)
    "ML-DSA-44": (1312, 2420),
    "ML-DSA-65": (1952, 3309),
    "Falcon-512": (897, 752),
    "ECDSA-P256-SHA256": (65, 72),
}


def flip(data: bytes, index: int = 0) -> bytes:
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


def kem_algs(backend: str) -> list[str]:
    return sorted(crypto.supported(backend)[0])  # type: ignore[arg-type]


def sig_algs(backend: str) -> list[str]:
    return sorted(crypto.supported(backend)[1])  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Parameter tables
# --------------------------------------------------------------------------- #


def test_parameter_tables_match_standards() -> None:
    for name, (pk, ct, ss) in EXPECTED_KEM_SIZES.items():
        p = crypto.KEMS[name]
        assert (p.public_key_len, p.ciphertext_len, p.shared_secret_len) == (pk, ct, ss)
    for name, (pk, sig) in EXPECTED_SIG_SIZES.items():
        p = crypto.SIGNATURES[name]
        assert (p.public_key_len, p.max_signature_len) == (pk, sig)
    assert set(crypto.KEMS) == set(EXPECTED_KEM_SIZES)
    assert set(crypto.SIGNATURES) == set(EXPECTED_SIG_SIZES)


def test_backends_cover_the_plan_matrix() -> None:
    """Level-matched pairs (docs/PLAN.md §3) need both backends together."""
    openssl_kems, openssl_sigs = crypto.supported("openssl")
    oqs_kems, oqs_sigs = crypto.supported("liboqs")
    assert openssl_kems | oqs_kems == set(crypto.KEMS)
    assert openssl_sigs | oqs_sigs == set(crypto.SIGNATURES)


# --------------------------------------------------------------------------- #
# KEMs
# --------------------------------------------------------------------------- #


def test_kem_round_trip_and_sizes(backend: str) -> None:
    for alg in kem_algs(backend):
        pk_len, ct_len, ss_len = EXPECTED_KEM_SIZES[alg]
        sk = crypto.kem_generate(alg, backend)  # type: ignore[arg-type]
        assert len(sk.public_key) == pk_len
        ct, ss = crypto.kem_encapsulate(alg, sk.public_key, backend)  # type: ignore[arg-type]
        assert (len(ct), len(ss)) == (ct_len, ss_len)
        assert sk.decapsulate(ct) == ss


def test_kem_encapsulation_is_randomised(backend: str) -> None:
    for alg in kem_algs(backend):
        sk = crypto.kem_generate(alg, backend)  # type: ignore[arg-type]
        ct1, ss1 = crypto.kem_encapsulate(alg, sk.public_key, backend)  # type: ignore[arg-type]
        ct2, ss2 = crypto.kem_encapsulate(alg, sk.public_key, backend)  # type: ignore[arg-type]
        assert ct1 != ct2
        assert ss1 != ss2


@pytest.mark.parametrize("position", [0, 500, -1])
def test_kem_tampered_ciphertext_gives_different_secret_without_error(
    backend: str, position: int
) -> None:
    """FIPS 203 implicit rejection: tampering is detected later, at Finished."""
    for alg in kem_algs(backend):
        sk = crypto.kem_generate(alg, backend)  # type: ignore[arg-type]
        ct, ss = crypto.kem_encapsulate(alg, sk.public_key, backend)  # type: ignore[arg-type]
        bad = sk.decapsulate(flip(ct, position))
        assert len(bad) == 32
        assert bad != ss


def test_kem_decapsulation_under_another_key_differs(backend: str) -> None:
    for alg in kem_algs(backend):
        sk = crypto.kem_generate(alg, backend)  # type: ignore[arg-type]
        other = crypto.kem_generate(alg, backend)  # type: ignore[arg-type]
        ct, ss = crypto.kem_encapsulate(alg, sk.public_key, backend)  # type: ignore[arg-type]
        assert other.decapsulate(ct) != ss


def test_kem_seeded_keygen_is_deterministic(backend: str) -> None:
    seed = bytes(range(64))
    for alg in kem_algs(backend):
        a = crypto.kem_generate(alg, backend, seed=seed)  # type: ignore[arg-type]
        b = crypto.kem_generate(alg, backend, seed=seed)  # type: ignore[arg-type]
        c = crypto.kem_generate(alg, backend, seed=flip(seed))  # type: ignore[arg-type]
        assert a.public_key == b.public_key
        assert a.public_key != c.public_key


@pytest.mark.parametrize("delta", [-1, +1])
def test_kem_wrong_length_inputs_are_rejected(backend: str, delta: int) -> None:
    for alg in kem_algs(backend):
        pk_len, ct_len, _ = EXPECTED_KEM_SIZES[alg]
        sk = crypto.kem_generate(alg, backend)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="public key"):
            crypto.kem_encapsulate(alg, bytes(pk_len + delta), backend)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="ciphertext"):
            sk.decapsulate(bytes(ct_len + delta))
        with pytest.raises(ValueError, match="seed"):
            crypto.kem_generate(alg, backend, seed=bytes(64 + delta))  # type: ignore[arg-type]


def test_kem_empty_inputs_are_rejected(backend: str) -> None:
    for alg in kem_algs(backend):
        sk = crypto.kem_generate(alg, backend)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            crypto.kem_encapsulate(alg, b"", backend)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            sk.decapsulate(b"")


# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #

MESSAGE = b"TLS 1.3, server CertificateVerify\x00" + bytes(range(48))


def test_sig_round_trip_and_sizes(backend: str) -> None:
    for alg in sig_algs(backend):
        pk_len, max_sig = EXPECTED_SIG_SIZES[alg]
        sk = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
        sig = sk.sign(MESSAGE)
        assert len(sk.public_key) == pk_len
        if crypto.SIGNATURES[alg].fixed_length:
            assert len(sig) == max_sig
        else:
            assert 0 < len(sig) <= max_sig
        crypto.sig_verify(alg, sk.public_key, MESSAGE, sig, backend)  # type: ignore[arg-type]


def _corruptions(msg: bytes, sig: bytes) -> dict[str, tuple[bytes, bytes]]:
    return {
        "flipped message bit": (flip(msg), sig),
        "flipped first signature bit": (msg, flip(sig, 0)),
        "flipped last signature bit": (msg, flip(sig, -1)),
        "truncated signature": (msg, sig[:-1]),
        "empty signature": (msg, b""),
        "extended signature": (msg, sig + b"\x00"),
        "empty message": (b"", sig),
    }


def test_sig_rejects_corruptions(backend: str) -> None:
    for alg in sig_algs(backend):
        sk = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
        sig = sk.sign(MESSAGE)
        for label, (msg, bad_sig) in _corruptions(MESSAGE, sig).items():
            try:
                crypto.sig_verify(alg, sk.public_key, msg, bad_sig, backend)  # type: ignore[arg-type]
            except InvalidSignature:
                continue
            pytest.fail(f"{alg} on {backend} accepted: {label}")


def test_sig_rejects_another_keys_signature(backend: str) -> None:
    for alg in sig_algs(backend):
        sk = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
        other = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
        with pytest.raises(InvalidSignature):
            crypto.sig_verify(alg, other.public_key, MESSAGE, sk.sign(MESSAGE), backend)  # type: ignore[arg-type]


def test_sig_wrong_length_public_key_is_a_usage_error(backend: str) -> None:
    for alg in sig_algs(backend):
        sk = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
        sig = sk.sign(MESSAGE)
        with pytest.raises(ValueError, match="public key"):
            crypto.sig_verify(alg, sk.public_key[:-1], MESSAGE, sig, backend)  # type: ignore[arg-type]


def test_mldsa_context_strings_bind(backend: str) -> None:
    for alg in ("ML-DSA-44", "ML-DSA-65"):
        sk = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
        plain = sk.sign(MESSAGE)
        with_ctx = sk.sign(MESSAGE, context=b"x")
        crypto.sig_verify(alg, sk.public_key, MESSAGE, with_ctx, backend, context=b"x")  # type: ignore[arg-type]
        with pytest.raises(InvalidSignature):
            crypto.sig_verify(alg, sk.public_key, MESSAGE, plain, backend, context=b"x")  # type: ignore[arg-type]
        with pytest.raises(InvalidSignature):
            crypto.sig_verify(alg, sk.public_key, MESSAGE, with_ctx, backend)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            sk.sign(MESSAGE, context=bytes(256))


def test_context_rejected_for_algorithms_without_context(backend: str) -> None:
    for alg in sig_algs(backend):
        if crypto.SIGNATURES[alg].supports_context:
            continue
        sk = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="context"):
            sk.sign(MESSAGE, context=b"x")
        with pytest.raises(ValueError, match="context"):
            crypto.sig_verify(alg, sk.public_key, MESSAGE, sk.sign(MESSAGE), backend, context=b"x")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Names: no aliases, no fallbacks
# --------------------------------------------------------------------------- #

NOT_SUPPORTED = ["Kyber768", "Kyber512", "Dilithium2", "ml-kem-768", "ML-KEM-1024", "FN-DSA-512", ""]


@pytest.mark.parametrize("name", NOT_SUPPORTED)
def test_unknown_names_raise(backend: str, name: str) -> None:
    with pytest.raises(UnknownAlgorithm):
        crypto.kem_generate(name, backend)  # type: ignore[arg-type]
    with pytest.raises(UnknownAlgorithm):
        crypto.sig_generate(name, backend)  # type: ignore[arg-type]


def test_openssl_does_not_fall_back_for_liboqs_only_algorithms() -> None:
    with pytest.raises(UnknownAlgorithm):
        crypto.kem_generate("ML-KEM-512", "openssl")
    with pytest.raises(UnknownAlgorithm):
        crypto.sig_generate("Falcon-512", "openssl")


def test_liboqs_does_not_claim_ecdsa() -> None:
    with pytest.raises(UnknownAlgorithm):
        crypto.sig_generate("ECDSA-P256-SHA256", "liboqs")


def test_unknown_backend_raises() -> None:
    with pytest.raises(crypto.BackendUnavailable):
        crypto.kem_generate("ML-KEM-768", "boringssl")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# X25519
# --------------------------------------------------------------------------- #


def test_x25519_agreement() -> None:
    a, b = crypto.x25519_generate(), crypto.x25519_generate()
    assert len(a.public_key) == 32
    assert a.exchange(b.public_key) == b.exchange(a.public_key)


def test_x25519_wrong_length_is_rejected() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        crypto.x25519_generate().exchange(bytes(31))


# --------------------------------------------------------------------------- #
# Operation counting
# --------------------------------------------------------------------------- #


def test_op_counting_per_block(backend: str) -> None:
    alg = "ML-KEM-768"
    with crypto.count_ops() as server:
        sk = crypto.kem_generate(alg, backend)  # type: ignore[arg-type]
    with crypto.count_ops() as client:
        ct, _ = crypto.kem_encapsulate(alg, sk.public_key, backend)  # type: ignore[arg-type]
    with crypto.count_ops() as server2:
        sk.decapsulate(ct)
    assert server == {(backend, alg, "keygen"): 1}
    assert client == {(backend, alg, "encap"): 1}
    assert server2 == {(backend, alg, "decap"): 1}


def test_op_counting_nests_and_ignores_outside_calls() -> None:
    crypto.sig_generate("ML-DSA-44", "openssl")  # not counted anywhere
    with crypto.count_ops() as outer:
        sk = crypto.sig_generate("ML-DSA-44", "openssl")
        with crypto.count_ops() as inner:
            sk.sign(b"m")
    assert inner == {("openssl", "ML-DSA-44", "sign"): 1}
    assert outer == {("openssl", "ML-DSA-44", "keygen"): 1, ("openssl", "ML-DSA-44", "sign"): 1}


# --------------------------------------------------------------------------- #
# Added after the Phase 1 fleet review: each test kills a surviving mutant.
# --------------------------------------------------------------------------- #


def test_every_message_byte_is_signed(backend: str) -> None:
    """Kills 'sign/verify only a prefix of the message' (ECDSA, Falcon)."""
    msg = bytes(range(200))
    for alg in sig_algs(backend):
        sk = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
        sig = sk.sign(msg)
        for position in (16, 100, -1):
            with pytest.raises(InvalidSignature):
                crypto.sig_verify(alg, sk.public_key, flip(msg, position), sig, backend)  # type: ignore[arg-type]


def test_ecdsa_rfc6979_known_answer() -> None:
    """RFC 6979 A.2.5: P-256, SHA-256, message "sample". Pins the curve and hash."""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    pk = bytes.fromhex(
        "04"
        "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
        "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
    )
    sig = encode_dss_signature(
        int("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", 16),
        int("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", 16),
    )
    crypto.sig_verify("ECDSA-P256-SHA256", pk, b"sample", sig, "openssl")
    with pytest.raises(InvalidSignature):
        crypto.sig_verify("ECDSA-P256-SHA256", pk, b"samplf", sig, "openssl")


@pytest.mark.usefixtures("require_liboqs")
def test_falcon_signatures_are_variable_length() -> None:
    """Kills an alias to Falcon-padded-512, whose signatures are always 666 bytes."""
    sk = crypto.sig_generate("Falcon-512", "liboqs")
    lengths = {len(sk.sign(bytes([i]))) for i in range(40)}
    assert len(lengths) > 1, lengths


def test_unsupported_names_raise_from_every_entry_point(backend: str) -> None:
    other = "liboqs" if backend == "openssl" else "openssl"
    only_other_kems = crypto.supported(other)[0] - crypto.supported(backend)[0]  # type: ignore[arg-type]
    only_other_sigs = crypto.supported(other)[1] - crypto.supported(backend)[1]  # type: ignore[arg-type]
    for alg in only_other_kems | {"Kyber768"}:
        with pytest.raises(UnknownAlgorithm):
            crypto.kem_encapsulate(alg, bytes(crypto.KEMS.get(alg, crypto.KEMS["ML-KEM-768"]).public_key_len), backend)  # type: ignore[arg-type]
        with pytest.raises(UnknownAlgorithm):
            crypto.kem_from_decapsulation_key(alg, b"", backend)  # type: ignore[arg-type]
    for alg in only_other_sigs | {"Dilithium2"}:
        params = crypto.SIGNATURES.get(alg, crypto.SIGNATURES["ML-DSA-44"])
        with pytest.raises(UnknownAlgorithm):
            crypto.sig_verify(alg, bytes(params.public_key_len), b"m", b"s", backend)  # type: ignore[arg-type]


BAD_TYPES = [5, "text", memoryview(b"abc"), None]


@pytest.mark.parametrize("bad", BAD_TYPES, ids=lambda v: type(v).__name__)
def test_non_bytes_inputs_raise_type_error(backend: str, bad: object) -> None:
    for alg in sig_algs(backend):
        sk = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
        sig = sk.sign(MESSAGE)
        with pytest.raises(TypeError):
            sk.sign(bad)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            crypto.sig_verify(alg, sk.public_key, bad, sig, backend)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            crypto.sig_verify(alg, sk.public_key, MESSAGE, bad, backend)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            crypto.sig_verify(alg, bad, MESSAGE, sig, backend)  # type: ignore[arg-type]
        if crypto.SIGNATURES[alg].supports_context:
            with pytest.raises(TypeError):
                sk.sign(MESSAGE, context=bad)  # type: ignore[arg-type]
    for alg in kem_algs(backend):
        sk = crypto.kem_generate(alg, backend)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            crypto.kem_encapsulate(alg, bad, backend)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            sk.decapsulate(bad)  # type: ignore[arg-type]
        if bad is not None:  # seed=None means "no seed"
            with pytest.raises(TypeError):
                crypto.kem_generate(alg, backend, seed=bad)  # type: ignore[arg-type]


def test_invalid_mlkem_public_key_raises_the_same_error_on_every_backend(backend: str) -> None:
    """Coefficients >= q fail FIPS 203 §7.2 input validation."""
    for alg in kem_algs(backend):
        bad = b"\xff" * EXPECTED_KEM_SIZES[alg][0]
        with pytest.raises(crypto.InvalidPublicKey):
            crypto.kem_encapsulate(alg, bad, backend)  # type: ignore[arg-type]


def test_malformed_signer_public_key_is_an_invalid_signature() -> None:
    sk = crypto.sig_generate("ECDSA-P256-SHA256", "openssl")
    off_curve = b"\x04" + bytes(64)
    with pytest.raises(InvalidSignature):
        crypto.sig_verify("ECDSA-P256-SHA256", off_curve, MESSAGE, sk.sign(MESSAGE), "openssl")


def test_x25519_low_order_point_is_invalid_public_key() -> None:
    with pytest.raises(crypto.InvalidPublicKey):
        crypto.x25519_generate().exchange(bytes(32))


def test_op_counting_covers_every_operation(backend: str) -> None:
    for alg in sig_algs(backend):
        sk = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
        sig = sk.sign(MESSAGE)
        with crypto.count_ops() as ops:
            crypto.sig_verify(alg, sk.public_key, MESSAGE, sig, backend)  # type: ignore[arg-type]
        assert ops == {(backend, alg, "verify"): 1}
    with crypto.count_ops() as ops:
        a, b = crypto.x25519_generate(), crypto.x25519_generate()
        a.exchange(b.public_key)
    assert ops == {("openssl", "X25519", "keygen"): 2, ("openssl", "X25519", "exchange"): 1}


def test_failed_operations_are_not_counted(backend: str) -> None:
    sk = crypto.sig_generate("ML-DSA-44", backend)  # type: ignore[arg-type]
    kem = crypto.kem_generate("ML-KEM-768", backend)  # type: ignore[arg-type]
    with crypto.count_ops() as ops:
        with pytest.raises(InvalidSignature):
            crypto.sig_verify("ML-DSA-44", sk.public_key, MESSAGE, bytes(2420), backend)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            crypto.sig_verify("ML-DSA-44", sk.public_key[:-1], MESSAGE, bytes(2420), backend)  # type: ignore[arg-type]
        with pytest.raises(crypto.InvalidPublicKey):
            crypto.kem_encapsulate("ML-KEM-768", b"\xff" * 1184, backend)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            kem.decapsulate(b"short")
        with pytest.raises(UnknownAlgorithm):
            crypto.kem_generate("Kyber768", backend)  # type: ignore[arg-type]
    # Usage and framing errors cost nothing; a rejected signature is a real
    # verification and is counted separately (it costs CPU in attack paths).
    assert ops == {(backend, "ML-DSA-44", "verify_failed"): 1}


def test_count_ops_needs_a_block_inside_each_thread() -> None:
    """Documented: context variables don't propagate into new threads."""
    import threading

    inner: list[object] = []

    def role() -> None:
        crypto.x25519_generate()  # outside any block in this thread: not counted
        with crypto.count_ops() as mine:
            crypto.x25519_generate()
        inner.append(dict(mine))

    with crypto.count_ops() as outer:
        t = threading.Thread(target=role)
        t.start()
        t.join()
    assert outer == {}
    assert inner == [{("openssl", "X25519", "keygen"): 1}]


def test_backend_info_records_versions(backend: str) -> None:
    info = crypto.backend_info()
    assert info["cryptography"] == __import__("cryptography").__version__
    assert info["openssl"].startswith("OpenSSL")
    if backend == "liboqs":
        assert info["liboqs"] == crypto.LIBOQS_VERSION
        assert info["liboqs_sha"] == crypto.LIBOQS_SHA
        assert info["liboqs_cmake_flags"] == crypto.LIBOQS_CMAKE_FLAGS


def test_malformed_pq_signer_public_keys_are_invalid_signatures(backend: str) -> None:
    """A correctly sized but garbage ML-DSA or Falcon key from the wire can't verify anything."""
    for alg in sig_algs(backend):
        if alg == "ECDSA-P256-SHA256":
            continue  # covered by test_malformed_signer_public_key_is_an_invalid_signature
        sk = crypto.sig_generate(alg, backend)  # type: ignore[arg-type]
        sig = sk.sign(MESSAGE)
        pk_len = EXPECTED_SIG_SIZES[alg][0]
        for garbage in (bytes(pk_len), b"\xff" * pk_len):
            with pytest.raises(InvalidSignature):
                crypto.sig_verify(alg, garbage, MESSAGE, sig, backend)  # type: ignore[arg-type]
