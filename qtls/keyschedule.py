"""TLS 1.3 key schedule (RFC 8446 §7.1), staged so AuthKEM can add a stage.

Stages are explicit and must run in order (specs.md D4):

    early(ikm)            ES  = Extract(0, ikm)          ikm = 0^32, or SSs (D12)
    handshake(ss)         HS  = Extract(Derive(ES, "derived"), ss)
    authenticated(ssS)    AHS = Extract(Derive(HS, "derived"), ssS)     AuthKEM only
    main(ikm)             MS  = Extract(Derive(prev, "derived"), ikm)  ikm = 0^32 (D3)

Traffic secrets are ``derive(secret, label, transcript_hash)``. The caller
passes the transcript hash for the range the spec names (specs.md §3); the
:class:`Transcript` hashes exact wire bytes.
"""

from __future__ import annotations

import hmac

from qtls import crypto
from qtls.alerts import Alert, AlertError, CodecUsageError

HASH_LEN = crypto.HASH_LEN
ZERO_IKM = bytes(HASH_LEN)

# Labels, without the "tls13 " prefix HKDF-Expand-Label adds (RFC 8446 §7.1).
DERIVED = b"derived"
C_HS_TRAFFIC = b"c hs traffic"
S_HS_TRAFFIC = b"s hs traffic"
C_E_HS_TRAFFIC = b"c e hs traffic"  # pre-distributed AuthKEM (specs.md D12)
C_AHS_TRAFFIC = b"c ahs traffic"  # AuthKEM (specs.md D4)
S_AHS_TRAFFIC = b"s ahs traffic"
C_AP_TRAFFIC = b"c ap traffic"
S_AP_TRAFFIC = b"s ap traffic"
EXP_MASTER = b"exp master"
RES_MASTER = b"res master"
FINISHED = b"finished"
CLIENT_FINISHED = b"client finished"  # AuthKEM Finished keys (specs.md D18)
SERVER_FINISHED = b"server finished"
KEY = b"key"
IV = b"iv"

LABEL_PREFIX = b"tls13 "


def hkdf_label(label: bytes, context: bytes, length: int) -> bytes:
    """The HkdfLabel structure (RFC 8446 §7.1)."""
    full = LABEL_PREFIX + label
    if not label or len(full) > 255:
        raise CodecUsageError(f"label must be 1..{255 - len(LABEL_PREFIX)} bytes")
    if len(context) > 255:
        raise CodecUsageError("context must be at most 255 bytes")
    if not 0 < length < 1 << 16:
        raise CodecUsageError("length must fit in a uint16")
    return length.to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    return crypto.hkdf_expand(secret, hkdf_label(label, context, length), length)


def derive_secret(secret: bytes, label: bytes, transcript_hash: bytes) -> bytes:
    if len(transcript_hash) != HASH_LEN:
        raise CodecUsageError(f"transcript hash must be {HASH_LEN} bytes")
    return hkdf_expand_label(secret, label, transcript_hash, HASH_LEN)


EMPTY_HASH = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


class Transcript:
    """Running SHA-256 over handshake messages exactly as sent or received."""

    def __init__(self) -> None:
        self._hash = crypto.sha256()

    def add(self, raw_message: bytes) -> None:
        self._hash.update(raw_message)

    def hash(self) -> bytes:
        """The hash so far; doesn't disturb the running state."""
        return self._hash.digest()


class KeySchedule:
    """The secret chain. Each stage runs once, in order; misuse is a local bug."""

    def __init__(self) -> None:
        self.early_secret: bytes | None = None
        self.handshake_secret: bytes | None = None
        self.authenticated_secret: bytes | None = None
        self.main_secret: bytes | None = None
        self._stage = "start"

    def _advance(self, allowed: tuple[str, ...], to: str) -> None:
        if self._stage not in allowed:
            raise CodecUsageError(f"key schedule: can't run {to!r} after {self._stage!r}")
        self._stage = to

    def early(self, ikm: bytes = ZERO_IKM) -> bytes:
        self._advance(("start",), "early")
        self.early_secret = crypto.hkdf_extract(b"", ikm)
        return self.early_secret

    def handshake(self, shared_secret: bytes) -> bytes:
        self._advance(("early",), "handshake")
        assert self.early_secret is not None
        salt = derive_secret(self.early_secret, DERIVED, EMPTY_HASH)
        self.handshake_secret = crypto.hkdf_extract(salt, shared_secret)
        return self.handshake_secret

    def authenticated(self, ss_s: bytes) -> bytes:
        self._advance(("handshake",), "authenticated")
        assert self.handshake_secret is not None
        salt = derive_secret(self.handshake_secret, DERIVED, EMPTY_HASH)
        self.authenticated_secret = crypto.hkdf_extract(salt, ss_s)
        return self.authenticated_secret

    def main(self, ikm: bytes = ZERO_IKM) -> bytes:
        self._advance(("handshake", "authenticated"), "main")
        previous = self.authenticated_secret or self.handshake_secret
        assert previous is not None
        salt = derive_secret(previous, DERIVED, EMPTY_HASH)
        self.main_secret = crypto.hkdf_extract(salt, ikm)
        return self.main_secret


def finished_key(base_secret: bytes, label: bytes = FINISHED) -> bytes:
    """RFC 8446 §4.4.4; AuthKEM passes the Main Secret and its own labels (D5, D18)."""
    return hkdf_expand_label(base_secret, label, b"", HASH_LEN)


def verify_data(key: bytes, transcript_hash: bytes) -> bytes:
    return crypto.hmac_sha256(key, transcript_hash)


def verify_finished(key: bytes, transcript_hash: bytes, received: bytes) -> None:
    """Constant-time check of a peer's Finished; a mismatch is ``decrypt_error`` (D10)."""
    if not hmac.compare_digest(verify_data(key, transcript_hash), received):
        raise AlertError(Alert.decrypt_error, "Finished verify_data mismatch")


def traffic_keys(secret: bytes) -> tuple[bytes, bytes]:
    """(write_key, write_iv) for AES-128-GCM (RFC 8446 §7.3)."""
    return (
        hkdf_expand_label(secret, KEY, b"", 16),
        hkdf_expand_label(secret, IV, b"", 12),
    )
