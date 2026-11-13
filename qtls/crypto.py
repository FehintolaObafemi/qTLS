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
:class:`AeadFailure`
    An AEAD record that doesn't authenticate (TLS: ``bad_record_mac``).
    Deliberately *not* a ``ValueError``, so it can't be mistaken for a framing
    error.
:class:`RandomnessError`
    Misuse of deterministic randomness: nesting, or a fixed byte string that
    was over- or under-consumed. The result produced inside the block must be
    discarded.

Deterministic randomness (liboqs only)
--------------------------------------
liboqs draws randomness through a process-global ``OQS_randombytes``. For
known-answer tests and reproducible fixtures, qTLS installs a ctypes callback
that serves deterministic bytes **only to the execution context (thread or
asyncio task) that opened the block**; every other context gets
``os.urandom``. Blocks in different contexts can be open at once. The callback never raises into C: if
it can't serve the bytes it fills from ``os.urandom`` and poisons the block,
which then raises :class:`RandomnessError` on exit. Outside a block liboqs
uses its ``system`` RNG. :func:`backend_info` reports the caller's mode and
how many deterministic blocks the process has ever opened.

liboqs is used only when built by ``scripts/build_liboqs.sh`` at the pinned
commit with the pinned flags. ``liboqs-python`` would otherwise download and
build liboqs on import, or exit the interpreter if it can't, so this module
verifies the build (including the library's SHA-256) before importing ``oqs``.
"""

from __future__ import annotations

import contextlib
import contextvars
import ctypes
import hashlib
import os
import threading
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import cryptography
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.backends.openssl import backend as _openssl_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import hmac as _hmac
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, mlkem, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "BACKENDS",
    "KEMS",
    "LIBOQS_CMAKE_FLAGS",
    "LIBOQS_SHA",
    "LIBOQS_VERSION",
    "SIGNATURES",
    "AeadFailure",
    "AeadKey",
    "BackendUnavailable",
    "DeterministicSource",
    "InvalidPublicKey",
    "InvalidSignature",
    "RandomnessError",
    "Sha256",
    "aead_key",
    "deterministic_rng",
    "hkdf_expand",
    "hkdf_extract",
    "hmac_sha256",
    "sha256",
    "X25519PrivateKey",
    "x25519_from_private_bytes",
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


class AeadFailure(Exception):
    """An AEAD ciphertext that doesn't authenticate. Not a ValueError on purpose."""


class RandomnessError(RuntimeError):
    """Deterministic randomness was misused; discard whatever the block produced."""


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
    """Signature algorithm parameters.

    ``seed_len`` is the length of ``sig_generate(seed=...)`` and
    ``sign_seed_len`` of ``sign(seed=...)``. ``seed_mode`` says how a seed is
    used (``exact``, ``drbg`` or ``scalar``), and differs by family:

    * ML-DSA: the FIPS 204 key-generation seed ξ (32 bytes), and the signing
      randomness ``rnd`` (32 bytes; liboqs only).
    * Falcon: entropy for a NIST AES-256-CTR DRBG (48 bytes) that supplies all
      the randomness keygen draws. For signing, the DRBG is keyed with
      SHA-384(seed ‖ public key ‖ message), so one seed never reuses a salt
      across messages. How many bytes liboqs draws is an implementation
      detail, so fixtures pin their outputs by hash.
    * ECDSA: the private scalar, big-endian, in [1, n-1] (32 bytes); signing
      is RFC 6979 deterministic and takes an empty seed.
    """

    name: str
    nist_category: int
    public_key_len: int
    max_signature_len: int
    fixed_length: bool
    supports_context: bool
    seed_len: int
    sign_seed_len: int
    seed_mode: Literal["exact", "drbg", "scalar"]


KEMS: dict[str, KEMParams] = {
    "ML-KEM-512": KEMParams("ML-KEM-512", 1, 800, 768, 32),
    "ML-KEM-768": KEMParams("ML-KEM-768", 3, 1184, 1088, 32),
}

SIGNATURES: dict[str, SigParams] = {
    "ML-DSA-44": SigParams("ML-DSA-44", 2, 1312, 2420, True, True, 32, 32, "exact"),
    "ML-DSA-65": SigParams("ML-DSA-65", 3, 1952, 3309, True, True, 32, 32, "exact"),
    # Round-3 Falcon, the stand-in for FN-DSA-512 until FIPS 206 is final.
    # Signatures are variable length, at most 752 bytes.
    "Falcon-512": SigParams("Falcon-512", 1, 897, 752, False, False, 48, 48, "drbg"),
    # Config A only. DER-encoded, so 70-72 bytes in practice.
    "ECDSA-P256-SHA256": SigParams("ECDSA-P256-SHA256", 0, 65, 72, False, False, 32, 0, "scalar"),
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


def _record(backend: str, alg: str, op: str, n: int = 1) -> None:
    """Count ``n`` of ``op``. Hashing, MAC and AEAD also record ``"bytes"``."""
    ops = _op_counter.get()
    if ops is not None:
        ops[(backend, alg, op)] += n


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


class _NistDrbg:
    """The NIST PQC known-answer-test AES-256-CTR DRBG (``rng.c`` in the submission kit).

    liboqs 0.16 no longer ships it in the library, so it lives here. It is
    for reproducibility only and must never key anything that matters.
    """

    def __init__(self, entropy: bytes) -> None:
        self._key, self._v = bytes(32), bytes(16)
        self._update(entropy)

    def _block(self) -> bytes:
        self._v = ((int.from_bytes(self._v, "big") + 1) % (1 << 128)).to_bytes(16, "big")
        enc = Cipher(algorithms.AES(self._key), modes.ECB()).encryptor()
        return enc.update(self._v) + enc.finalize()

    def _update(self, provided: bytes | None) -> None:
        temp = self._block() + self._block() + self._block()
        if provided is not None:
            temp = bytes(a ^ b for a, b in zip(temp, provided, strict=True))
        self._key, self._v = temp[:32], temp[32:]

    def random(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += self._block()
        self._update(None)
        return out[:n]


class DeterministicSource:
    """Deterministic bytes for one execution context: a DRBG stream, or an exact byte string.

    ``bytes_served`` reports how much randomness liboqs drew from it.
    """

    def __init__(self, *, drbg: _NistDrbg | None = None, exact: bytes | None = None) -> None:
        self._drbg = drbg
        self._exact = exact
        self.bytes_served = 0
        self.poisoned = False
        # Set when the block exits. A context copied while the block was open
        # (e.g. an asyncio task created inside it) still holds this source, so
        # a closed source must behave exactly like no source.
        self.closed = False

    def draw(self, n: int) -> bytes:
        if self._drbg is not None:
            data = self._drbg.random(n)
        else:
            assert self._exact is not None
            if self.bytes_served + n > len(self._exact):
                self.poisoned = True  # over-draw: never hand out short or repeated bytes
                return os.urandom(n)
            data = self._exact[self.bytes_served : self.bytes_served + n]
        self.bytes_served += n
        return data

    def unconsumed(self) -> int:
        return 0 if self._exact is None else len(self._exact) - self.bytes_served


# The source for the *current execution context* (thread or asyncio task).
# New threads start with no value; asyncio tasks inherit the context they were
# created in, so work a block spawns inside itself shares the block.
_rng_owner: contextvars.ContextVar[DeterministicSource | None] = contextvars.ContextVar(
    "qtls_rng_owner", default=None
)


def _active_source() -> DeterministicSource | None:
    source = _rng_owner.get()
    return source if source is not None and not source.closed else None
_RANDOMBYTES_CB = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
_rng_lock = threading.Lock()  # guards the counters and hook installation only, never a whole block
_rng_open_blocks = 0
_rng_blocks_ever = 0


def _rng_callback_impl(buf: Any, n: int) -> None:
    # Runs inside liboqs, in the calling thread and context. It must never
    # raise: ctypes would swallow the exception and liboqs would use whatever
    # is in the buffer. Every failure poisons the source and serves os.urandom.
    source = None
    try:
        source = _active_source()
        data = source.draw(n) if source is not None else os.urandom(n)
        ctypes.memmove(buf, data, n)
    except BaseException:  # noqa: BLE001
        if source is not None:
            source.poisoned = True
        with contextlib.suppress(BaseException):
            ctypes.memmove(buf, os.urandom(n), n)


# Module-level reference: the C side keeps only a raw pointer to this.
_rng_callback = _RANDOMBYTES_CB(_rng_callback_impl)


def _set_liboqs_rng(native: Any, install: bool) -> None:
    if install:
        native.OQS_randombytes_custom_algorithm(_rng_callback)
        return
    native.OQS_randombytes_switch_algorithm.restype = ctypes.c_int
    status = native.OQS_randombytes_switch_algorithm(ctypes.c_char_p(b"system"))
    if status != 0:
        raise RandomnessError(f"could not restore liboqs's system RNG (status {status})")


@contextlib.contextmanager
def _deterministic(source: DeterministicSource) -> Iterator[DeterministicSource]:
    global _rng_open_blocks, _rng_blocks_ever
    if _active_source() is not None:
        raise RandomnessError("deterministic randomness blocks can't be nested")
    native = _oqs().native()  # the build verified by _oqs(), never a separate dlopen
    token = None
    entered = False
    try:
        with _rng_lock:
            if _rng_open_blocks == 0:
                _set_liboqs_rng(native, install=True)
            _rng_open_blocks += 1
            _rng_blocks_ever += 1
            entered = True
        token = _rng_owner.set(source)
        yield source
    finally:
        source.closed = True
        if token is not None:
            _rng_owner.reset(token)
        if entered:
            with _rng_lock:
                _rng_open_blocks -= 1
                if _rng_open_blocks == 0:
                    _set_liboqs_rng(native, install=False)
    if source.poisoned:
        raise RandomnessError("deterministic randomness ran out or failed; result discarded")
    if source.unconsumed():
        raise RandomnessError(
            f"{source.unconsumed()} fixed random bytes were not consumed; result discarded"
        )


@contextlib.contextmanager
def deterministic_rng(entropy: bytes) -> Iterator[DeterministicSource]:
    """Serve liboqs operations in this execution context from a NIST KAT DRBG.

    For known-answer tests and fixtures only. Other threads and asyncio
    tasks, and the OpenSSL backend, are unaffected; blocks in different
    contexts may be open at the same time. Nesting in one context raises.
    """
    entropy = _check_len("DRBG entropy", entropy, 48)
    with _deterministic(DeterministicSource(drbg=_NistDrbg(entropy))) as source:
        yield source


def _fixed_randomness(data: bytes) -> contextlib.AbstractContextManager[DeterministicSource]:
    """Serve exactly ``data`` to liboqs in this context; it must be consumed exactly."""
    return _deterministic(DeterministicSource(exact=data))


def backend_info() -> dict[str, str]:
    """Versions and build facts to record alongside every result."""
    info = {
        "cryptography": cryptography.__version__,
        "openssl": _openssl_backend.openssl_version_text(),
        # This context's RNG, and whether any deterministic block was ever
        # opened in this process (a result produced after one is suspect).
        "liboqs_rng": "deterministic" if _active_source() is not None else "system",
        "liboqs_deterministic_blocks": str(_rng_blocks_ever),
    }
    if _oqs_module is not None:
        info["liboqs"] = _oqs_module.oqs_version()
        info.update({f"liboqs_{k}": v for k, v in _oqs_build_info.items()})
    return info


def _free(handle: Any) -> None:
    with contextlib.suppress(Exception):
        handle.free()


@contextlib.contextmanager
def _owned(handle: Any) -> Iterator[Any]:
    """Free a liboqs handle if building the key around it fails."""
    try:
        yield handle
    except BaseException:
        _free(handle)
        raise


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
        with _owned(_oqs().KeyEncapsulation(alg)) as kem:
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


def kem_encapsulate(
    alg: str, public_key: bytes, backend: Backend, *, seed: bytes | None = None
) -> tuple[bytes, bytes]:
    """Return ``(ciphertext, shared_secret)``.

    Raises :class:`InvalidPublicKey` for a correctly sized key that fails
    FIPS 203 input validation. ``seed`` is the FIPS 203 encapsulation
    randomness ``m`` (32 bytes), for known-answer tests; liboqs only.
    """
    params = _kem_params(alg, backend)
    pk = _check_len("public key", public_key, params.public_key_len)
    if seed is not None:
        seed = _check_len("encapsulation seed", seed, 32)
        if backend != "liboqs":
            raise BackendUnavailable(f"{backend} has no derandomised ML-KEM encapsulation")
    if backend == "openssl":
        _, pub_cls = _OPENSSL_KEMS[alg]
        try:
            ss, ct = pub_cls.from_public_bytes(pk).encapsulate()
        except ValueError:
            raise InvalidPublicKey(f"invalid {alg} encapsulation key") from None
    else:
        rng = _fixed_randomness(seed) if seed is not None else contextlib.nullcontext()
        with rng, _oqs().KeyEncapsulation(alg) as kem:
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
    """A signing key. ``public_key`` is raw (ML-DSA, Falcon) or SEC1 uncompressed (ECDSA).

    ``seed`` is the seed the key was generated from, if any (see SigParams);
    it is the portable way to recreate the key on either backend.
    """

    def __init__(
        self, alg: str, backend: Backend, public_key: bytes, handle: Any, seed: bytes | None = None
    ) -> None:
        self.alg = alg
        self.backend = backend
        self.public_key = public_key
        self.seed = seed
        self._handle = handle

    def __del__(self) -> None:
        if self.backend == "liboqs" and getattr(self, "_handle", None) is not None:
            _free(self._handle)

    def sign(self, message: bytes, context: bytes = b"", *, seed: bytes | None = None) -> bytes:
        """Sign ``message``. With ``seed`` the signature is deterministic (see SigParams)."""
        params = SIGNATURES[self.alg]
        msg = _check_bytes("message", message)
        ctx = _check_context(params, context)
        if seed is not None:
            seed = _check_len("signing seed", seed, params.sign_seed_len)
            if self.backend == "openssl" and params.seed_mode != "scalar":
                raise BackendUnavailable("OpenSSL has no deterministic ML-DSA signing")
        if self.alg == _ECDSA:
            sig = self._handle.sign(
                msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=seed is not None)
            )
        elif self.backend == "openssl":
            sig = self._handle.sign(msg, ctx or None)
        elif seed is None:
            sig = self._liboqs_sign(msg, ctx, params)
        elif params.seed_mode == "exact":
            with _fixed_randomness(seed):
                sig = self._liboqs_sign(msg, ctx, params)
        else:
            # A DRBG stream: bind it to the key and message so one seed never
            # reuses a Falcon salt or sampler randomness across messages.
            entropy = hashlib.sha384(seed + self.public_key + msg).digest()
            with deterministic_rng(entropy):
                sig = self._liboqs_sign(msg, ctx, params)
        _record(self.backend, self.alg, "sign")
        return sig

    def _liboqs_sign(self, msg: bytes, ctx: bytes, params: SigParams) -> bytes:
        if params.supports_context:
            return self._handle.sign_with_ctx_str(msg, ctx)
        return self._handle.sign(msg)

    def expanded_private_key(self) -> bytes:
        """liboqs's expanded private key (the FIPS 204 ``sk`` for ML-DSA). liboqs only."""
        if self.backend != "liboqs":
            raise BackendUnavailable(f"{self.backend} keys have no expanded private-key export")
        return self._handle.export_secret_key()


_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def sig_generate(alg: str, backend: Backend, seed: bytes | None = None) -> SigPrivateKey:
    """Generate a signing key; with ``seed`` it is deterministic (see SigParams)."""
    params = _sig_params(alg, backend)
    if seed is not None:
        seed = _check_len("seed", seed, params.seed_len)
    if alg == _ECDSA:
        if seed is None:
            sk = ec.generate_private_key(ec.SECP256R1())
        else:
            scalar = int.from_bytes(seed, "big")
            if not 0 < scalar < _P256_ORDER:
                raise ValueError("ECDSA P-256 private scalar must be in [1, n-1]")
            sk = ec.derive_private_key(scalar, ec.SECP256R1())
        pk = sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        key = SigPrivateKey(alg, backend, pk, sk, seed)
    elif backend == "openssl":
        priv_cls, _ = _OPENSSL_MLDSA[alg]
        sk = priv_cls.from_seed_bytes(seed) if seed is not None else priv_cls.generate()
        key = SigPrivateKey(alg, backend, sk.public_key().public_bytes_raw(), sk, seed)
    else:
        with _owned(_oqs().Signature(alg)) as signer:
            if seed is None:
                pk = signer.generate_keypair()
            else:
                rng = _fixed_randomness(seed) if params.seed_mode == "exact" else deterministic_rng(seed)
                with rng:
                    pk = signer.generate_keypair()
            key = SigPrivateKey(alg, backend, pk, signer, seed)
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
    Rejections are counted as ``verify_failed`` (they cost CPU too).
    """
    params = _sig_params(alg, backend)
    pk = _check_len("public key", public_key, params.public_key_len)
    msg = _check_bytes("message", message)
    sig = _check_bytes("signature", signature)
    ctx = _check_context(params, context)
    try:
        _verify(alg, params, pk, msg, sig, ctx, backend)
    except InvalidSignature:
        _record(backend, alg, "verify_failed")
        raise
    _record(backend, alg, "verify")


def _verify(
    alg: str, params: SigParams, pk: bytes, msg: bytes, sig: bytes, ctx: bytes, backend: Backend
) -> None:
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


# --------------------------------------------------------------------------- #
# X25519 (the classical half of X25519MLKEM768)
# --------------------------------------------------------------------------- #


class X25519PrivateKey:
    def __init__(self, handle: x25519.X25519PrivateKey) -> None:
        self._handle = handle
        self.public_key = handle.public_key().public_bytes_raw()

    def private_bytes(self) -> bytes:
        """The raw 32-byte private key, loadable with :func:`x25519_from_private_bytes`."""
        return self._handle.private_bytes_raw()

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


def x25519_from_private_bytes(private_key: bytes) -> X25519PrivateKey:
    """Load a 32-byte X25519 private key (RFC 7748 clamping is applied by the library)."""
    sk = _check_len("X25519 private key", private_key, 32)
    key = X25519PrivateKey(x25519.X25519PrivateKey.from_private_bytes(sk))
    _record("openssl", "X25519", "import")
    return key


# --------------------------------------------------------------------------- #
# Hashing, HMAC, HKDF and AEAD (the TLS_AES_128_GCM_SHA256 suite, specs.md D16)
#
# Counting: "bytes" is the data processed: bytes hashed or MACed, HKDF input
# keying material, and AEAD plaintext (on both seal and open, so the tag isn't
# counted twice). HKDF-Expand counts the HMAC "blocks" it computes.
# --------------------------------------------------------------------------- #

HASH_LEN = 32


class Sha256:
    """An incremental SHA-256, for running transcript hashes.

    ``digest()`` doesn't finalise the running state, so a transcript can be
    snapshotted at each stage. Bytes hashed and digests taken are counted.
    """

    def __init__(self, _state: Any = None) -> None:
        self._state = _state if _state is not None else hashes.Hash(hashes.SHA256())

    def update(self, data: bytes) -> Sha256:
        data = _check_bytes("data", data)
        self._state.update(data)
        _record("openssl", "SHA-256", "bytes", len(data))
        return self

    def copy(self) -> Sha256:
        return Sha256(self._state.copy())

    def digest(self) -> bytes:
        out = self._state.copy().finalize()
        _record("openssl", "SHA-256", "digest")
        return out


def sha256(data: bytes = b"") -> Sha256:
    h = Sha256()
    if data:
        h.update(data)
    return h


def _raw_hmac(key: bytes, data: bytes) -> bytes:
    mac = _hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    key, data = _check_bytes("key", key), _check_bytes("data", data)
    out = _raw_hmac(key, data)
    _record("openssl", "HMAC-SHA256", "mac")
    _record("openssl", "HMAC-SHA256", "bytes", len(data))
    return out


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869 §2.2). An empty salt means HashLen zero bytes."""
    salt, ikm = _check_bytes("salt", salt), _check_bytes("IKM", ikm)
    out = _raw_hmac(salt or bytes(HASH_LEN), ikm)
    _record("openssl", "HKDF-SHA256", "extract")
    _record("openssl", "HKDF-SHA256", "bytes", len(ikm))
    return out


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869 §2.3)."""
    prk, info = _check_bytes("PRK", prk), _check_bytes("info", info)
    if len(prk) < HASH_LEN:
        raise ValueError(f"PRK must be at least {HASH_LEN} bytes")
    if type(length) is not int or not 0 < length <= 255 * HASH_LEN:
        raise ValueError(f"HKDF-Expand length must be an int in [1, {255 * HASH_LEN}]")
    blocks = -(-length // HASH_LEN)
    out, block = b"", b""
    for i in range(1, blocks + 1):
        block = _raw_hmac(prk, block + info + bytes([i]))
        out += block
    _record("openssl", "HKDF-SHA256", "expand")
    _record("openssl", "HKDF-SHA256", "blocks", blocks)
    return out[:length]


class AeadKey:
    """AES-128-GCM with a fixed key; one object per traffic key."""

    KEY_LEN, NONCE_LEN, TAG_LEN = 16, 12, 16

    def __init__(self, key: bytes) -> None:
        self._aead = AESGCM(_check_len("AES-128-GCM key", key, self.KEY_LEN))

    def seal(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        nonce = _check_len("nonce", nonce, self.NONCE_LEN)
        pt, aad = _check_bytes("plaintext", plaintext), _check_bytes("AAD", aad)
        out = self._aead.encrypt(nonce, pt, aad)
        _record("openssl", "AES-128-GCM", "seal")
        _record("openssl", "AES-128-GCM", "bytes", len(pt))
        return out

    def open(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """Decrypt and authenticate; raises :class:`AeadFailure` on any failure.

        Rejections are counted as ``open_failed``.
        """
        nonce = _check_len("nonce", nonce, self.NONCE_LEN)
        ct, aad = _check_bytes("ciphertext", ciphertext), _check_bytes("AAD", aad)
        try:
            pt = self._aead.decrypt(nonce, ct, aad)
        except InvalidTag:
            _record("openssl", "AES-128-GCM", "open_failed")
            raise AeadFailure("AEAD authentication failed") from None
        _record("openssl", "AES-128-GCM", "open")
        _record("openssl", "AES-128-GCM", "bytes", len(pt))
        return pt


def aead_key(key: bytes) -> AeadKey:
    return AeadKey(key)
