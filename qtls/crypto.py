"""The only module in qTLS that touches a cryptographic library.

Every primitive the handshake uses goes through here so that:

* the two backends (OpenSSL via ``cryptography``, and liboqs) look identical:
  bytes in, bytes out, and the same exception for the same failure (see
  "Errors" below);
* input types and lengths are checked before any library sees them;
* an algorithm name means exactly one algorithm: there are no aliases and no
  fallback from one backend or algorithm to another;
* completed primitive operations are counted per caller (see
  :func:`count_ops`), which the benchmark's CPU method relies on
  (docs/PLAN.md, Phase 5).

Errors
------
``TypeError``
    A non-``bytes``/``bytearray`` input. A programming error.
``ValueError``
    A key, ciphertext or seed of the wrong length, or a bad context string.
    A programming or framing error: callers must length-check wire data
    before calling in (TLS: ``decode_error``).
:class:`InvalidPublicKey` (a ``ValueError``)
    A correctly sized KEM encapsulation key that fails validation, such as
    ML-KEM coefficients that aren't reduced mod q (FIPS 203 §7.2). Raised the
    same way by both backends (TLS: ``illegal_parameter``).
:class:`InvalidSignature`
    Any signature that doesn't verify, including a wrong-length signature or a
    malformed signer public key. Signatures and certificate keys come off the
    wire, so this is never a usage error (TLS: ``decrypt_error``).

liboqs is used only when built by ``scripts/build_liboqs.sh`` at the pinned
commit with the pinned flags. ``liboqs-python`` would otherwise download and
build liboqs on import, or exit the interpreter if it can't, so this module
verifies the build (including the library's SHA-256) before importing ``oqs``.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import os
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend as _openssl_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, mlkem, x25519

__all__ = [
    "BACKENDS",
    "KEMS",
    "LIBOQS_CMAKE_FLAGS",
    "LIBOQS_SHA",
    "LIBOQS_VERSION",
    "SIGNATURES",
    "BackendUnavailable",
    "InvalidPublicKey",
    "InvalidSignature",
    "KEMParams",
    "KEMPrivateKey",
    "SigParams",
    "SigPrivateKey",
    "UnknownAlgorithm",
    "backend_info",
    "count_ops",
    "kem_encapsulate",
    "kem_from_decapsulation_key",
    "kem_generate",
    "sig_generate",
    "sig_verify",
    "supported",
    "x25519_generate",
]

Backend = Literal["openssl", "liboqs"]
BACKENDS: tuple[Backend, ...] = ("openssl", "liboqs")

# Must match scripts/build_liboqs.sh (tests/test_environment.py checks this).
LIBOQS_VERSION = "0.16.0"
LIBOQS_SHA = "5a1a854b0dc9f2141bdc771c555ee60c37950183"
LIBOQS_CMAKE_FLAGS = (
    "-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_LIBDIR=lib "
    "-DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON -DOQS_USE_OPENSSL=OFF"
)


class UnknownAlgorithm(ValueError):
    """The algorithm name is not one qTLS supports on the requested backend."""


class BackendUnavailable(RuntimeError):
    """The requested backend can't be used in this environment."""


class InvalidPublicKey(ValueError):
    """A correctly sized KEM public key that fails validation."""


# --------------------------------------------------------------------------- #
# Algorithm parameters (FIPS 203 / FIPS 204 / Falcon round-3 spec)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class KEMParams:
    name: str
    nist_category: int
    public_key_len: int
    ciphertext_len: int
    shared_secret_len: int


@dataclass(frozen=True)
class SigParams:
    name: str
    nist_category: int
    public_key_len: int
    max_signature_len: int
    fixed_length: bool
    supports_context: bool


KEMS: dict[str, KEMParams] = {
    "ML-KEM-512": KEMParams("ML-KEM-512", 1, 800, 768, 32),
    "ML-KEM-768": KEMParams("ML-KEM-768", 3, 1184, 1088, 32),
}

SIGNATURES: dict[str, SigParams] = {
    "ML-DSA-44": SigParams("ML-DSA-44", 2, 1312, 2420, True, True),
    "ML-DSA-65": SigParams("ML-DSA-65", 3, 1952, 3309, True, True),
    # Round-3 Falcon, the stand-in for FN-DSA-512 until FIPS 206 is final.
    # Signatures are variable length, at most 752 bytes.
    "Falcon-512": SigParams("Falcon-512", 1, 897, 752, False, False),
    # Config A only. DER-encoded, so 70-72 bytes in practice.
    "ECDSA-P256-SHA256": SigParams("ECDSA-P256-SHA256", 0, 65, 72, False, False),
}

_OPENSSL_KEMS = {"ML-KEM-768": (mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey)}
_OPENSSL_MLDSA = {
    "ML-DSA-44": (mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey),
    "ML-DSA-65": (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey),
}
_ECDSA = "ECDSA-P256-SHA256"
_LIBOQS_KEMS = {"ML-KEM-512", "ML-KEM-768"}
_LIBOQS_SIGS = {"ML-DSA-44", "ML-DSA-65", "Falcon-512"}


def supported(backend: Backend) -> tuple[set[str], set[str]]:
    """Return (KEM names, signature names) the backend implements in qTLS."""
    if backend == "openssl":
        return set(_OPENSSL_KEMS), set(_OPENSSL_MLDSA) | {_ECDSA}
    if backend == "liboqs":
        return set(_LIBOQS_KEMS), set(_LIBOQS_SIGS)
    raise BackendUnavailable(f"unknown backend {backend!r}")


def _kem_params(alg: str, backend: Backend) -> KEMParams:
    if alg not in KEMS or alg not in supported(backend)[0]:
        raise UnknownAlgorithm(f"KEM {alg!r} is not supported on backend {backend!r}")
    return KEMS[alg]


def _sig_params(alg: str, backend: Backend) -> SigParams:
    if alg not in SIGNATURES or alg not in supported(backend)[1]:
        raise UnknownAlgorithm(f"signature {alg!r} is not supported on backend {backend!r}")
    return SIGNATURES[alg]


def _check_bytes(what: str, value: object) -> bytes:
    if not isinstance(value, bytes | bytearray):
        raise TypeError(f"{what} must be bytes, got {type(value).__name__}")
    return bytes(value)


def _check_len(what: str, value: object, expected: int) -> bytes:
    data = _check_bytes(what, value)
    if len(data) != expected:
        raise ValueError(f"{what} must be {expected} bytes, got {len(data)}")
    return data


def _check_context(params: SigParams, context: object) -> bytes:
    ctx = _check_bytes("context", context)
    if len(ctx) > 255:
        raise ValueError("signature context must be at most 255 bytes")
    if ctx and not params.supports_context:
        raise ValueError(f"{params.name} does not support a context string")
    return ctx


# --------------------------------------------------------------------------- #
# Operation counting
# --------------------------------------------------------------------------- #

_op_counter: contextvars.ContextVar[Counter[tuple[str, str, str]] | None] = (
    contextvars.ContextVar("qtls_op_counter", default=None)
)


@contextlib.contextmanager
def count_ops() -> Iterator[Counter[tuple[str, str, str]]]:
    """Count primitive operations that *complete* inside the block.

    Keys are ``(backend, algorithm, operation)``. Operations that raise are
    not counted. Counters nest: an outer block also sees an inner block's
    counts.

    Context variables don't propagate into new ``threading.Thread`` objects,
    so a role running in its own thread must open its own block there.
    """
    ops: Counter[tuple[str, str, str]] = Counter()
    parent = _op_counter.get()
    token = _op_counter.set(ops)
    try:
        yield ops
    finally:
        _op_counter.reset(token)
        if parent is not None:
            parent.update(ops)


def _record(backend: str, alg: str, op: str) -> None:
    ops = _op_counter.get()
    if ops is not None:
        ops[(backend, alg, op)] += 1


# --------------------------------------------------------------------------- #
# liboqs loading
# --------------------------------------------------------------------------- #

_oqs_module: Any = None
_oqs_build_info: dict[str, str] = {}


def _read_build_info(install_path: Path) -> dict[str, str]:
    info = install_path / "BUILD_INFO"
    if not info.is_file():
        return {}
    pairs = (line.split("=", 1) for line in info.read_text().splitlines() if "=" in line)
    return {k: v for k, v in pairs}


def _oqs() -> Any:
    """Import ``oqs`` only after verifying the pinned build is what will load."""
    global _oqs_module, _oqs_build_info
    if _oqs_module is not None:
        return _oqs_module

    install = os.environ.get("OQS_INSTALL_PATH")
    if not install:
        raise BackendUnavailable(
            "liboqs backend needs OQS_INSTALL_PATH pointing at a build from "
            "scripts/build_liboqs.sh"
        )
    install_path = Path(install).resolve()
    info = _read_build_info(install_path)
    expected = {"tag": LIBOQS_VERSION, "sha": LIBOQS_SHA, "cmake_flags": LIBOQS_CMAKE_FLAGS}
    mismatched = [k for k, v in expected.items() if info.get(k) != v]
    if mismatched:
        raise BackendUnavailable(
            f"{install_path} is not a liboqs {LIBOQS_VERSION} build from "
            f"scripts/build_liboqs.sh (BUILD_INFO missing or mismatched: {', '.join(mismatched)})"
        )

    # Check the library exists *before* importing oqs: if it's missing,
    # liboqs-python would start its own download-and-build.
    library = (install_path / info.get("lib", "")).resolve()
    if not info.get("lib") or not library.is_file() or not library.is_relative_to(install_path):
        raise BackendUnavailable(f"liboqs library missing from {install_path}; rebuild it")
    digest = hashlib.sha256(library.read_bytes()).hexdigest()
    if digest != info.get("lib_sha256"):
        raise BackendUnavailable(f"{library} does not match the SHA-256 in BUILD_INFO; rebuild it")

    try:
        import oqs  # noqa: PLC0415 - deliberately lazy, see module docstring
    except (SystemExit, Exception) as exc:  # liboqs-python exits on failure
        raise BackendUnavailable(f"importing liboqs-python failed: {exc!r}") from None

    loaded_name = Path(oqs.native()._name)
    if not loaded_name.is_absolute():
        raise BackendUnavailable(
            f"liboqs-python loaded {loaded_name} by bare name, so it can't be verified "
            f"as the pinned build in {install_path}. Remove other liboqs installs."
        )
    if loaded_name.resolve() != library:
        raise BackendUnavailable(
            f"liboqs-python loaded {loaded_name.resolve()}, not the pinned build {library}. "
            "Remove the other liboqs from the library search path."
        )
    if oqs.oqs_version() != LIBOQS_VERSION:
        raise BackendUnavailable(
            f"liboqs version {oqs.oqs_version()} loaded, expected {LIBOQS_VERSION}"
        )
    _oqs_module = oqs
    _oqs_build_info = info
    return oqs


def backend_info() -> dict[str, str]:
    """Versions and build facts to record alongside every result."""
    info = {
        "cryptography": cryptography.__version__,
        "openssl": _openssl_backend.openssl_version_text(),
    }
    if _oqs_module is not None:
        info["liboqs"] = _oqs_module.oqs_version()
        info.update({f"liboqs_{k}": v for k, v in _oqs_build_info.items()})
    return info


def _free(handle: Any) -> None:
    with contextlib.suppress(Exception):
        handle.free()


# --------------------------------------------------------------------------- #
# KEMs
# --------------------------------------------------------------------------- #


class KEMPrivateKey:
    """A KEM decapsulation key. ``public_key`` is the raw encapsulation key."""

    def __init__(self, alg: str, backend: Backend, public_key: bytes, handle: Any) -> None:
        self.alg = alg
        self.backend = backend
        self.public_key = public_key
        self._handle = handle

    def __del__(self) -> None:
        if self.backend == "liboqs" and getattr(self, "_handle", None) is not None:
            _free(self._handle)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Return the shared secret.

        ML-KEM uses implicit rejection (FIPS 203, Alg. 18): a tampered
        ciphertext yields an unrelated pseudorandom secret, never an error.
        Callers detect tampering later, at Finished.
        """
        ct = _check_len("ciphertext", ciphertext, KEMS[self.alg].ciphertext_len)
        if self.backend == "openssl":
            ss = self._handle.decapsulate(ct)
        else:
            ss = self._handle.decap_secret(ct)
        _record(self.backend, self.alg, "decap")
        return ss


def kem_generate(alg: str, backend: Backend, seed: bytes | None = None) -> KEMPrivateKey:
    """Generate a key pair. ``seed`` is the 64-byte FIPS 203 seed d‖z."""
    params = _kem_params(alg, backend)
    if seed is not None:
        seed = _check_len("seed", seed, 64)
    if backend == "openssl":
        priv_cls, _ = _OPENSSL_KEMS[alg]
        sk = priv_cls.from_seed_bytes(seed) if seed is not None else priv_cls.generate()
        key = KEMPrivateKey(alg, backend, sk.public_key().public_bytes_raw(), sk)
    else:
        kem = _oqs().KeyEncapsulation(alg)
        pk = kem.generate_keypair_seed(seed) if seed is not None else kem.generate_keypair()
        key = KEMPrivateKey(alg, backend, pk, kem)
    if len(key.public_key) != params.public_key_len:  # pragma: no cover - library bug
        raise AssertionError(f"{backend} returned a {len(key.public_key)}-byte {alg} key")
    _record(backend, alg, "keygen")
    return key


def kem_from_decapsulation_key(alg: str, dk: bytes, backend: Backend) -> KEMPrivateKey:
    """Load a FIPS 203 expanded decapsulation key (used by known-answer tests).

    Only liboqs accepts expanded keys; OpenSSL (via ``cryptography``) loads
    ML-KEM keys only from 64-byte seeds, so use ``kem_generate(seed=...)``.
    """
    params = _kem_params(alg, backend)
    if backend != "liboqs":
        raise BackendUnavailable(f"{backend} loads ML-KEM keys only from seeds")
    # FIPS 203: dk = dk_PKE (384k bytes) || ek || H(ek) || z, and |ek| = 384k + 32.
    dk = _check_len("decapsulation key", dk, 2 * params.public_key_len + 32)
    ek_start = params.public_key_len - 32
    pk = dk[ek_start : ek_start + params.public_key_len]
    return KEMPrivateKey(alg, backend, pk, _oqs().KeyEncapsulation(alg, secret_key=dk))


def kem_encapsulate(alg: str, public_key: bytes, backend: Backend) -> tuple[bytes, bytes]:
    """Return ``(ciphertext, shared_secret)``.

    Raises :class:`InvalidPublicKey` for a correctly sized key that fails
    FIPS 203 input validation.
    """
    params = _kem_params(alg, backend)
    pk = _check_len("public key", public_key, params.public_key_len)
    if backend == "openssl":
        _, pub_cls = _OPENSSL_KEMS[alg]
        try:
            ss, ct = pub_cls.from_public_bytes(pk).encapsulate()
        except ValueError:
            raise InvalidPublicKey(f"invalid {alg} encapsulation key") from None
    else:
        with _oqs().KeyEncapsulation(alg) as kem:
            try:
                ct, ss = kem.encap_secret(pk)
            except RuntimeError:
                raise InvalidPublicKey(f"invalid {alg} encapsulation key") from None
    _record(backend, alg, "encap")
    return ct, ss


# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #


class SigPrivateKey:
    """A signing key. ``public_key`` is raw (ML-DSA, Falcon) or SEC1 uncompressed (ECDSA)."""

    def __init__(self, alg: str, backend: Backend, public_key: bytes, handle: Any) -> None:
        self.alg = alg
        self.backend = backend
        self.public_key = public_key
        self._handle = handle

    def __del__(self) -> None:
        if self.backend == "liboqs" and getattr(self, "_handle", None) is not None:
            _free(self._handle)

    def sign(self, message: bytes, context: bytes = b"") -> bytes:
        params = SIGNATURES[self.alg]
        msg = _check_bytes("message", message)
        ctx = _check_context(params, context)
        if self.alg == _ECDSA:
            sig = self._handle.sign(msg, ec.ECDSA(hashes.SHA256()))
        elif self.backend == "openssl":
            sig = self._handle.sign(msg, ctx or None)
        elif params.supports_context:
            sig = self._handle.sign_with_ctx_str(msg, ctx)
        else:
            sig = self._handle.sign(msg)
        _record(self.backend, self.alg, "sign")
        return sig


def sig_generate(alg: str, backend: Backend) -> SigPrivateKey:
    params = _sig_params(alg, backend)
    if alg == _ECDSA:
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        key = SigPrivateKey(alg, backend, pk, sk)
    elif backend == "openssl":
        priv_cls, _ = _OPENSSL_MLDSA[alg]
        sk = priv_cls.generate()
        key = SigPrivateKey(alg, backend, sk.public_key().public_bytes_raw(), sk)
    else:
        signer = _oqs().Signature(alg)
        key = SigPrivateKey(alg, backend, signer.generate_keypair(), signer)
    if len(key.public_key) != params.public_key_len:  # pragma: no cover - library bug
        raise AssertionError(f"{backend} returned a {len(key.public_key)}-byte {alg} key")
    _record(backend, alg, "keygen")
    return key


def sig_verify(
    alg: str,
    public_key: bytes,
    message: bytes,
    signature: bytes,
    backend: Backend,
    context: bytes = b"",
) -> None:
    """Verify a signature, raising :class:`InvalidSignature` on any failure.

    A wrong-length or malformed signature, or a correctly sized but malformed
    public key, is attacker-controlled input and raises ``InvalidSignature``.
    A public key of the wrong length is a framing error and raises ``ValueError``.
    """
    params = _sig_params(alg, backend)
    pk = _check_len("public key", public_key, params.public_key_len)
    msg = _check_bytes("message", message)
    sig = _check_bytes("signature", signature)
    ctx = _check_context(params, context)
    if params.fixed_length:
        if len(sig) != params.max_signature_len:
            raise InvalidSignature
    elif not 0 < len(sig) <= params.max_signature_len:
        raise InvalidSignature

    if alg == _ECDSA:
        try:
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk)
        except ValueError:
            raise InvalidSignature from None
        pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    elif backend == "openssl":
        _, pub_cls = _OPENSSL_MLDSA[alg]
        try:
            mldsa_pub = pub_cls.from_public_bytes(pk)
        except ValueError:
            raise InvalidSignature from None
        mldsa_pub.verify(sig, msg, ctx or None)
    else:
        with _oqs().Signature(alg) as verifier:
            if params.supports_context:
                ok = verifier.verify_with_ctx_str(msg, sig, ctx, pk)
            else:
                ok = verifier.verify(msg, sig, pk)
        if ok is not True:
            raise InvalidSignature
    _record(backend, alg, "verify")


# --------------------------------------------------------------------------- #
# X25519 (the classical half of X25519MLKEM768)
# --------------------------------------------------------------------------- #


class X25519PrivateKey:
    def __init__(self, handle: x25519.X25519PrivateKey) -> None:
        self._handle = handle
        self.public_key = handle.public_key().public_bytes_raw()

    def exchange(self, peer_public_key: bytes) -> bytes:
        """Return the shared secret. Raises :class:`InvalidPublicKey` for low-order points."""
        peer = _check_len("X25519 public key", peer_public_key, 32)
        try:
            ss = self._handle.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
        except ValueError:
            raise InvalidPublicKey("X25519 shared secret is all zeros (low-order point)") from None
        _record("openssl", "X25519", "exchange")
        return ss


def x25519_generate() -> X25519PrivateKey:
    key = X25519PrivateKey(x25519.X25519PrivateKey.generate())
    _record("openssl", "X25519", "keygen")
    return key
