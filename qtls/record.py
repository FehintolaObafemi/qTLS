"""TLS 1.3 record layer (RFC 8446 §5) with the receive rules of specs.md D22.

* :func:`split_records` frames a byte stream (sans-I/O).
* :func:`encode_plaintext` / :func:`decode_plaintext` handle the unprotected
  records before keys exist.
* :class:`RecordProtection` protects one direction under one traffic key, with
  its own 64-bit sequence number.
* :func:`receive` routes an incoming record by the current receive state, so
  a plaintext handshake record after the key change can't slip through.
"""

from __future__ import annotations

from enum import IntEnum

from qtls import crypto
from qtls.alerts import Alert, AlertError, CodecUsageError, alert_for
from qtls.keyschedule import traffic_keys

MAX_FRAGMENT = 1 << 14
MAX_INNER = MAX_FRAGMENT + 1
MAX_CIPHERTEXT = MAX_FRAGMENT + 256
HEADER_LEN = 5
LEGACY_VERSION = 0x0303
INITIAL_CLIENT_HELLO_VERSION = 0x0301  # RFC 8446 §5.1 allows this for the first ClientHello
SEQ_LIMIT = 1 << 64


class ContentType(IntEnum):
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23


_MUST_NOT_BE_EMPTY = (ContentType.handshake, ContentType.alert)
_PROTECTED_TYPES = (ContentType.alert, ContentType.handshake, ContentType.application_data)


def _header(content_type: int, version: int, length: int) -> bytes:
    return bytes([content_type]) + version.to_bytes(2, "big") + length.to_bytes(2, "big")


def split_records(buffer: bytes) -> tuple[list[bytes], bytes]:
    """Split complete records off ``buffer``; return them and the incomplete rest."""
    records = []
    pos = 0
    while len(buffer) - pos >= HEADER_LEN:
        length = int.from_bytes(buffer[pos + 3 : pos + 5], "big")
        if length > MAX_CIPHERTEXT:
            raise AlertError(Alert.record_overflow, f"record of {length} bytes announced")
        if len(buffer) - pos < HEADER_LEN + length:
            break
        records.append(buffer[pos : pos + HEADER_LEN + length])
        pos += HEADER_LEN + length
    return records, buffer[pos:]


def _parse(record: bytes) -> tuple[int, bytes, bytes]:
    if len(record) < HEADER_LEN or int.from_bytes(record[3:5], "big") != len(record) - HEADER_LEN:
        raise CodecUsageError("not a single framed record; use split_records")
    return record[0], record[:HEADER_LEN], record[HEADER_LEN:]


def fragment(content: bytes, limit: int = MAX_FRAGMENT) -> list[bytes]:
    """Split ``content`` into record-sized pieces. Empty content gives no pieces."""
    return [content[i : i + limit] for i in range(0, len(content), limit)]


# --------------------------------------------------------------------------- #
# Unprotected records
# --------------------------------------------------------------------------- #


def encode_plaintext(content_type: ContentType, payload: bytes, version: int = LEGACY_VERSION) -> bytes:
    if len(payload) > MAX_FRAGMENT:
        raise CodecUsageError(f"plaintext fragment of {len(payload)} bytes exceeds 2^14")
    if not payload and content_type in _MUST_NOT_BE_EMPTY:
        raise CodecUsageError(f"zero-length {content_type.name} fragment")
    return _header(content_type, version, len(payload)) + payload


def decode_plaintext(record: bytes) -> tuple[ContentType, bytes]:
    """An unprotected record. legacy_record_version is ignored (RFC 8446 §5.1).

    ChangeCipherSpec is returned only if its body is exactly 0x01 (D22); the
    handshake decides whether one is allowed at this point and drops it.
    """
    outer, _, payload = _parse(record)
    if outer not in (ContentType.handshake, ContentType.alert, ContentType.change_cipher_spec):
        raise AlertError(Alert.unexpected_message, f"unprotected record of type {outer}")
    content_type = ContentType(outer)
    if len(payload) > MAX_FRAGMENT:
        raise AlertError(Alert.record_overflow, f"plaintext fragment of {len(payload)} bytes")
    if content_type is ContentType.change_cipher_spec and payload != b"\x01":
        raise AlertError(Alert.unexpected_message, "ChangeCipherSpec body must be 0x01")
    if not payload and content_type in _MUST_NOT_BE_EMPTY:
        raise AlertError(Alert.unexpected_message, f"zero-length {content_type.name} fragment")
    return content_type, payload


# --------------------------------------------------------------------------- #
# Protected records
# --------------------------------------------------------------------------- #


class RecordProtection:
    """AES-128-GCM protection for one direction under one traffic key."""

    def __init__(self, key: bytes, iv: bytes) -> None:
        self._aead = crypto.aead_key(key)
        if len(iv) != crypto.AeadKey.NONCE_LEN:
            raise CodecUsageError("IV must be 12 bytes")
        self._iv = int.from_bytes(iv, "big")
        self.seq = 0

    @classmethod
    def from_secret(cls, traffic_secret: bytes) -> RecordProtection:
        return cls(*traffic_keys(traffic_secret))

    def _nonce(self) -> bytes:
        if self.seq >= SEQ_LIMIT:
            raise CodecUsageError("sequence number exhausted; the key must be updated")
        return (self._iv ^ self.seq).to_bytes(12, "big")

    def seal(self, content_type: ContentType, content: bytes, padding: int = 0) -> bytes:
        if content_type not in _PROTECTED_TYPES:
            raise CodecUsageError(f"content type {content_type!r} is never sent protected")
        if padding < 0 or len(content) + 1 + padding > MAX_INNER:
            raise CodecUsageError("content + type + padding exceeds 2^14 + 1")
        if not content and content_type in _MUST_NOT_BE_EMPTY:
            raise CodecUsageError(f"zero-length {content_type.name} record")
        nonce = self._nonce()
        inner = content + bytes([content_type]) + bytes(padding)
        header = _header(ContentType.application_data, LEGACY_VERSION, len(inner) + crypto.AeadKey.TAG_LEN)
        body = self._aead.seal(nonce, inner, header)
        self.seq += 1
        return header + body

    def open(self, record: bytes) -> tuple[ContentType, bytes]:
        outer, header, body = _parse(record)
        if outer != ContentType.application_data:
            raise AlertError(Alert.unexpected_message, f"protected record has outer type {outer}")
        if len(body) > MAX_CIPHERTEXT:
            raise AlertError(Alert.record_overflow, f"ciphertext of {len(body)} bytes")
        nonce = self._nonce()
        try:
            inner = self._aead.open(nonce, body, header)  # AAD is the header as received
        except crypto.AeadFailure as exc:
            # The sequence number doesn't advance (D22); the connection is torn down anyway.
            raise AlertError(alert_for(exc), "record failed authentication") from None
        self.seq += 1
        if len(inner) > MAX_INNER:
            raise AlertError(Alert.record_overflow, f"inner plaintext of {len(inner)} bytes")
        end = len(inner.rstrip(b"\x00"))
        if end == 0:
            raise AlertError(Alert.unexpected_message, "record has no content type (all zeros)")
        inner_type, content = inner[end - 1], inner[: end - 1]
        if inner_type not in _PROTECTED_TYPES:
            raise AlertError(Alert.unexpected_message, f"protected record of inner type {inner_type}")
        content_type = ContentType(inner_type)
        if not content and content_type in _MUST_NOT_BE_EMPTY:
            raise AlertError(Alert.unexpected_message, f"zero-length {content_type.name} record")
        return content_type, content


# --------------------------------------------------------------------------- #
# Receive routing (specs.md D22)
# --------------------------------------------------------------------------- #


def receive(
    record: bytes,
    protection: RecordProtection | None,
    *,
    ccs_allowed: bool,
    plain_alerts_allowed: bool = False,
) -> tuple[ContentType, bytes] | None:
    """Decode one framed record under the current receive state.

    * Before receive keys exist (``protection is None``) only plaintext
      handshake and alert records are accepted.
    * Afterwards everything must be protected, except an unprotected
      ChangeCipherSpec of exactly 0x01, which is dropped (``None``) while
      ``ccs_allowed`` (between the first ClientHello and the peer's Finished,
      RFC 8446 §5) and is ``unexpected_message`` otherwise.
    * ``plain_alerts_allowed`` admits an unprotected alert after the receive
      keys are installed. A server opens it when it sends ServerHello and
      closes it on the client's first protected record: a client rejecting
      the ServerHello has no keys yet, so its alert arrives in plaintext.
    """
    outer = record[0] if record else None
    if outer == ContentType.change_cipher_spec:
        decode_plaintext(record)  # validates the 0x01 body
        if not ccs_allowed:
            raise AlertError(Alert.unexpected_message, "ChangeCipherSpec outside the handshake")
        return None
    if protection is None or (plain_alerts_allowed and outer == ContentType.alert):
        return decode_plaintext(record)
    if outer != ContentType.application_data:
        raise AlertError(Alert.unexpected_message, f"unprotected record of type {outer} after the key change")
    return protection.open(record)
