"""TLS 1.3 handshake message codec (RFC 8446 §4, as revised by RFC 9846).

* Decoding is strict: every length is bounds-checked and trailing bytes are
  rejected, with the alert the peer should receive (:class:`AlertError`).
* Encoding refuses out-of-range values with :class:`CodecUsageError` (a local
  bug, never peer input).
* :class:`HandshakeReader` reassembles messages across records and yields each
  message's exact wire bytes, which is what the transcript hashes. Nothing is
  ever re-encoded for hashing.
* Extensions are kept in wire order. Unknown extensions stay opaque; the ones
  qTLS uses have typed codecs that know which message they're in, because the
  same extension has different bodies in different messages. Asking a codec
  for a message the extension can't appear in is a local error; deciding
  whether a received extension is *allowed* in a message (RFC 8446 §4.2,
  ``illegal_parameter``) is the handshake's job.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum, IntEnum

from qtls.alerts import Alert, AlertError, CodecUsageError

HASH_LEN = 32  # TLS_AES_128_GCM_SHA256 (specs.md D16)

# RFC 8446 §4.1.3: a ServerHello with this random is a HelloRetryRequest.
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


class HandshakeType(IntEnum):
    client_hello = 1
    server_hello = 2
    new_session_ticket = 4
    end_of_early_data = 5
    encrypted_extensions = 8
    certificate = 11
    certificate_request = 13
    certificate_verify = 15
    finished = 20
    key_update = 24
    kem_encapsulation = 30  # AuthKEM -08 §4.2; experimental, not IANA-registered
    message_hash = 254


class ExtensionType(IntEnum):
    server_name = 0
    supported_groups = 10
    signature_algorithms = 13
    supported_versions = 43
    signature_algorithms_cert = 50
    key_share = 51


TLS13 = 0x0304


# --------------------------------------------------------------------------- #
# Low-level reading and writing
# --------------------------------------------------------------------------- #


def _decode_error(what: str) -> AlertError:
    return AlertError(Alert.decode_error, what)


class Reader:
    """A bounded cursor. Running out of bytes is a ``decode_error``."""

    def __init__(self, data: bytes, what: str) -> None:
        self._data = bytes(data)
        self._pos = 0
        self._what = what

    def remaining(self) -> int:
        return len(self._data) - self._pos

    def take(self, n: int) -> bytes:
        if n > self.remaining():
            raise _decode_error(f"{self._what}: truncated")
        out = self._data[self._pos : self._pos + n]
        self._pos += n
        return out

    def uint(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def vector(self, len_size: int, lo: int, hi: int, field: str) -> bytes:
        n = self.uint(len_size)
        if not lo <= n <= hi:
            raise _decode_error(f"{self._what}: {field} length {n} outside [{lo}, {hi}]")
        return self.take(n)

    def done(self) -> None:
        if self.remaining():
            raise _decode_error(f"{self._what}: {self.remaining()} trailing bytes")


def uint(value: int, size: int) -> bytes:
    if not 0 <= value < 1 << (8 * size):
        raise CodecUsageError(f"{value} doesn't fit in {size} bytes")
    return value.to_bytes(size, "big")


def vector(data: bytes, len_size: int, lo: int, hi: int, field: str) -> bytes:
    if not lo <= len(data) <= hi:
        raise CodecUsageError(f"{field} length {len(data)} outside [{lo}, {hi}]")
    return uint(len(data), len_size) + data


def _u16_list(raw: bytes, field: str, what: str) -> tuple[int, ...]:
    if len(raw) % 2:
        raise _decode_error(f"{what}: {field} has an odd length")
    return tuple(int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw), 2))


def _encode_u16_list(values: Sequence[int]) -> bytes:
    return b"".join(uint(v, 2) for v in values)


# --------------------------------------------------------------------------- #
# Handshake framing
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RawHandshake:
    """One handshake message as received: ``raw`` is header ‖ body, exactly."""

    msg_type: int
    body: bytes
    raw: bytes


# Large enough for every certificate chain in the matrix (post-quantum chains
# with SCTs are under 32 KiB); anything bigger is refused at its header (D23).
DEFAULT_MAX_MESSAGE = 1 << 17


class HandshakeReader:
    """Reassembles handshake messages from record payloads (sans-I/O).

    Feed it one record's handshake payload at a time; ``feed`` returns the
    messages that record completed. A message still missing bytes is
    *pending*, not an error. An unknown type, or a length over
    ``max_message`` (specs.md D23), is rejected as soon as the 4-byte header
    arrives. Buffering is linear in the bytes received.

    Key changes: RFC 8446 §5.1 requires a message that precedes a key change
    (ServerHello, Finished, ...) to end its record, so call
    :meth:`require_record_end` with the messages ``feed`` just returned and
    the index of that message.
    """

    def __init__(self, max_message: int = DEFAULT_MAX_MESSAGE) -> None:
        self._buffer = bytearray()
        self._max = max_message

    def feed(self, fragment: bytes) -> list[RawHandshake]:
        self._buffer += fragment
        out = []
        pos = 0
        while len(self._buffer) - pos >= 4:
            msg_type = self._buffer[pos]
            if msg_type not in HandshakeType._value2member_map_:
                raise AlertError(Alert.unexpected_message, f"unknown handshake type {msg_type}")
            length = int.from_bytes(self._buffer[pos + 1 : pos + 4], "big")
            if length > self._max:
                raise AlertError(Alert.illegal_parameter, f"handshake message of {length} bytes announced")
            if len(self._buffer) - pos < 4 + length:
                break
            raw = bytes(self._buffer[pos : pos + 4 + length])
            pos += 4 + length
            out.append(RawHandshake(msg_type, raw[4:], raw))
        del self._buffer[:pos]
        return out

    def pending(self) -> bool:
        return bool(self._buffer)

    def check_key_change(self) -> None:
        """Nothing may be left over (partially received) when the key changes."""
        if self._buffer:
            raise AlertError(Alert.unexpected_message, "handshake message spans a key change")

    def require_record_end(self, messages: Sequence[RawHandshake], index: int) -> None:
        """``messages[index]`` precedes a key change, so it must end its record."""
        if not 0 <= index < len(messages):
            raise CodecUsageError(f"index {index} is not one of the {len(messages)} messages")
        if index != len(messages) - 1:
            raise AlertError(Alert.unexpected_message, "more data after a key-changing message in its record")
        self.check_key_change()


def encode_handshake(msg: HandshakeMessage) -> bytes:
    body = msg.encode()
    return uint(msg.msg_type, 1) + vector(body, 3, 0, (1 << 24) - 1, "handshake body")


# --------------------------------------------------------------------------- #
# Extensions
# --------------------------------------------------------------------------- #


class Context(Enum):
    """Which message an extension block belongs to."""

    client_hello = "ClientHello"
    server_hello = "ServerHello"
    encrypted_extensions = "EncryptedExtensions"
    certificate_entry = "CertificateEntry"


@dataclass(frozen=True)
class Extension:
    ext_type: int
    data: bytes


def decode_extensions(raw: bytes, what: str) -> tuple[Extension, ...]:
    """Parse an extension block. A repeated type is ``illegal_parameter`` (specs.md D21)."""
    r = Reader(raw, what)
    out, seen = [], set()
    while r.remaining():
        ext_type = r.uint(2)
        data = r.vector(2, 0, 0xFFFF, f"extension {ext_type}")
        if ext_type in seen:
            raise AlertError(Alert.illegal_parameter, f"{what}: duplicate extension {ext_type}")
        seen.add(ext_type)
        out.append(Extension(ext_type, data))
    return tuple(out)


def encode_extensions(exts: Sequence[Extension]) -> bytes:
    types = [e.ext_type for e in exts]
    if len(types) != len(set(types)):
        raise CodecUsageError("duplicate extension type")
    return b"".join(uint(e.ext_type, 2) + vector(e.data, 2, 0, 0xFFFF, "extension") for e in exts)


def find_extension(exts: Sequence[Extension], ext_type: int) -> bytes | None:
    for e in exts:
        if e.ext_type == ext_type:
            return e.data
    return None


# server_name (RFC 6066 §3)


def _check_host_name(host: str) -> bytes:
    """RFC 6066 §3 sender rules: ASCII, no trailing dot, no IP literals."""
    import ipaddress

    try:
        name = host.encode("ascii")
    except UnicodeEncodeError:
        raise CodecUsageError("host name must be ASCII (use the A-label form)") from None
    if not host or host.endswith(".") or any(c <= 0x20 or c == 0x7F for c in name):
        raise CodecUsageError(f"invalid host name {host!r}")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return name
    raise CodecUsageError("IP address literals are not allowed in server_name")


def encode_server_name(host: str | None, context: Context) -> bytes:
    if context is Context.client_hello:
        if not host:
            raise CodecUsageError("ClientHello server_name needs a host name")
        name = _check_host_name(host)
        entry = b"\x00" + vector(name, 2, 1, 0xFFFF, "host_name")
        return vector(entry, 2, 1, 0xFFFF, "server_name_list")
    if context is not Context.encrypted_extensions:
        raise CodecUsageError(f"server_name doesn't appear in {context.value}")
    if host is not None:
        raise CodecUsageError(f"{context.value} server_name has an empty body")
    return b""


def decode_server_name(data: bytes, context: Context) -> str | None:
    what = f"{context.value} server_name"
    if context not in (Context.client_hello, Context.encrypted_extensions):
        raise CodecUsageError(f"server_name doesn't appear in {context.value}")
    if context is Context.encrypted_extensions:
        # Server acknowledgement: the body must be empty (RFC 6066 §3).
        if data:
            raise _decode_error(f"{what}: must be empty")
        return None
    r = Reader(data, what)
    lst = Reader(r.vector(2, 1, 0xFFFF, "server_name_list"), what)
    r.done()
    name_type = lst.uint(1)
    if name_type != 0:
        raise AlertError(Alert.illegal_parameter, f"{what}: unsupported name type {name_type}")
    host = lst.vector(2, 1, 0xFFFF, "host_name")
    lst.done()  # qTLS sends and accepts exactly one host_name
    try:
        return host.decode("ascii")
    except UnicodeDecodeError:
        raise AlertError(Alert.illegal_parameter, f"{what}: host name is not ASCII") from None


# supported_groups (RFC 8446 §4.2.7)


def encode_supported_groups(groups: Sequence[int]) -> bytes:
    return vector(_encode_u16_list(groups), 2, 2, 0xFFFF, "named_group_list")


def decode_supported_groups(data: bytes) -> tuple[int, ...]:
    r = Reader(data, "supported_groups")
    groups = _u16_list(r.vector(2, 2, 0xFFFF, "named_group_list"), "named_group_list", "supported_groups")
    r.done()
    return groups


# signature_algorithms / signature_algorithms_cert (RFC 8446 §4.2.3)


def encode_signature_algorithms(schemes: Sequence[int]) -> bytes:
    return vector(_encode_u16_list(schemes), 2, 2, 0xFFFE, "supported_signature_algorithms")


def decode_signature_algorithms(data: bytes) -> tuple[int, ...]:
    r = Reader(data, "signature_algorithms")
    raw = r.vector(2, 2, 0xFFFE, "supported_signature_algorithms")
    r.done()
    return _u16_list(raw, "supported_signature_algorithms", "signature_algorithms")


# supported_versions (RFC 8446 §4.2.1)


def encode_supported_versions(versions: Sequence[int] | int, context: Context) -> bytes:
    if context is Context.client_hello and not isinstance(versions, int):
        return vector(_encode_u16_list(versions), 1, 2, 254, "versions")
    if context is Context.server_hello and isinstance(versions, int):
        return uint(versions, 2)
    raise CodecUsageError(f"supported_versions doesn't appear in {context.value}")


def decode_supported_versions(data: bytes, context: Context) -> tuple[int, ...] | int:
    if context not in (Context.client_hello, Context.server_hello):
        raise CodecUsageError(f"supported_versions doesn't appear in {context.value}")
    what = f"{context.value} supported_versions"
    r = Reader(data, what)
    if context is Context.client_hello:
        versions = _u16_list(r.vector(1, 2, 254, "versions"), "versions", what)
        r.done()
        return versions
    selected = r.uint(2)
    r.done()
    return selected


# key_share (RFC 8446 §4.2.8)


@dataclass(frozen=True)
class KeyShareEntry:
    group: int
    key_exchange: bytes

    def encode(self) -> bytes:
        return uint(self.group, 2) + vector(self.key_exchange, 2, 1, 0xFFFF, "key_exchange")

    @staticmethod
    def read(r: Reader) -> KeyShareEntry:
        return KeyShareEntry(r.uint(2), r.vector(2, 1, 0xFFFF, "key_exchange"))


def encode_key_share(shares: Sequence[KeyShareEntry] | KeyShareEntry, context: Context) -> bytes:
    if context is Context.client_hello and not isinstance(shares, KeyShareEntry):
        return vector(b"".join(s.encode() for s in shares), 2, 0, 0xFFFF, "client_shares")
    if context is Context.server_hello and isinstance(shares, KeyShareEntry):
        return shares.encode()
    raise CodecUsageError(f"key_share doesn't appear in {context.value}")


def decode_key_share(data: bytes, context: Context) -> tuple[KeyShareEntry, ...] | KeyShareEntry:
    if context not in (Context.client_hello, Context.server_hello):
        raise CodecUsageError(f"key_share doesn't appear in {context.value}")
    what = f"{context.value} key_share"
    r = Reader(data, what)
    if context is Context.client_hello:
        lst = Reader(r.vector(2, 0, 0xFFFF, "client_shares"), what)
        r.done()
        shares = []
        while lst.remaining():
            shares.append(KeyShareEntry.read(lst))
        return tuple(shares)
    entry = KeyShareEntry.read(r)
    r.done()
    return entry


# --------------------------------------------------------------------------- #
# Handshake messages
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ClientHello:
    msg_type = HandshakeType.client_hello
    random: bytes
    legacy_session_id: bytes
    cipher_suites: tuple[int, ...]
    extensions: tuple[Extension, ...]

    def encode(self) -> bytes:
        if len(self.random) != 32:
            raise CodecUsageError("random must be 32 bytes")
        return (
            uint(0x0303, 2)
            + self.random
            + vector(self.legacy_session_id, 1, 0, 32, "legacy_session_id")
            + vector(_encode_u16_list(self.cipher_suites), 2, 2, 0xFFFE, "cipher_suites")
            + vector(b"\x00", 1, 1, 255, "legacy_compression_methods")
            + vector(encode_extensions(self.extensions), 2, 7, 0xFFFF, "extensions")
        )

    @staticmethod
    def decode(body: bytes) -> ClientHello:
        r = Reader(body, "ClientHello")
        r.uint(2)  # legacy_version: ignored, supported_versions decides (RFC 8446 §4.2.1)
        random = r.take(32)
        session_id = r.vector(1, 0, 32, "legacy_session_id")
        suites = _u16_list(r.vector(2, 2, 0xFFFE, "cipher_suites"), "cipher_suites", "ClientHello")
        compression = r.vector(1, 1, 255, "legacy_compression_methods")
        if compression != b"\x00":
            raise AlertError(Alert.illegal_parameter, "ClientHello: compression methods must be [null]")
        exts = decode_extensions(r.vector(2, 7, 0xFFFF, "extensions"), "ClientHello extensions")  # RFC 9846
        r.done()
        return ClientHello(random, session_id, suites, exts)


@dataclass(frozen=True)
class ServerHello:
    msg_type = HandshakeType.server_hello
    random: bytes
    legacy_session_id_echo: bytes
    cipher_suite: int
    extensions: tuple[Extension, ...]

    @property
    def is_hrr(self) -> bool:
        return self.random == HRR_RANDOM

    def encode(self) -> bytes:
        if len(self.random) != 32:
            raise CodecUsageError("random must be 32 bytes")
        return (
            uint(0x0303, 2)
            + self.random
            + vector(self.legacy_session_id_echo, 1, 0, 32, "legacy_session_id_echo")
            + uint(self.cipher_suite, 2)
            + b"\x00"
            + vector(encode_extensions(self.extensions), 2, 6, 0xFFFF, "extensions")
        )

    @staticmethod
    def decode(body: bytes) -> ServerHello:
        r = Reader(body, "ServerHello")
        r.uint(2)  # legacy_version
        random = r.take(32)
        if random == HRR_RANDOM:
            raise AlertError(Alert.unexpected_message, "HelloRetryRequest is not supported (D16)")
        session_id = r.vector(1, 0, 32, "legacy_session_id_echo")
        suite = r.uint(2)
        if r.uint(1) != 0:
            raise AlertError(Alert.illegal_parameter, "ServerHello: compression method must be null")
        exts = decode_extensions(r.vector(2, 6, 0xFFFF, "extensions"), "ServerHello extensions")
        r.done()
        return ServerHello(random, session_id, suite, exts)


@dataclass(frozen=True)
class EncryptedExtensions:
    msg_type = HandshakeType.encrypted_extensions
    extensions: tuple[Extension, ...]

    def encode(self) -> bytes:
        return vector(encode_extensions(self.extensions), 2, 0, 0xFFFF, "extensions")

    @staticmethod
    def decode(body: bytes) -> EncryptedExtensions:
        r = Reader(body, "EncryptedExtensions")
        exts = decode_extensions(r.vector(2, 0, 0xFFFF, "extensions"), "EncryptedExtensions")
        r.done()
        return EncryptedExtensions(exts)


@dataclass(frozen=True)
class CertificateEntry:
    cert_data: bytes
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class Certificate:
    msg_type = HandshakeType.certificate
    certificate_request_context: bytes
    certificate_list: tuple[CertificateEntry, ...]

    def encode(self) -> bytes:
        entries = b"".join(
            vector(e.cert_data, 3, 1, (1 << 24) - 1, "cert_data")
            + vector(encode_extensions(e.extensions), 2, 0, 0xFFFF, "entry extensions")
            for e in self.certificate_list
        )
        return vector(self.certificate_request_context, 1, 0, 255, "certificate_request_context") + vector(
            entries, 3, 0, (1 << 24) - 1, "certificate_list"
        )

    @staticmethod
    def decode(body: bytes) -> Certificate:
        r = Reader(body, "Certificate")
        context = r.vector(1, 0, 255, "certificate_request_context")
        lst = Reader(r.vector(3, 0, (1 << 24) - 1, "certificate_list"), "Certificate list")
        r.done()
        entries = []
        while lst.remaining():
            cert = lst.vector(3, 1, (1 << 24) - 1, "cert_data")
            exts = decode_extensions(lst.vector(2, 0, 0xFFFF, "entry extensions"), "CertificateEntry")
            entries.append(CertificateEntry(cert, exts))
        return Certificate(context, tuple(entries))


@dataclass(frozen=True)
class CertificateVerify:
    msg_type = HandshakeType.certificate_verify
    algorithm: int
    signature: bytes

    def encode(self) -> bytes:
        return uint(self.algorithm, 2) + vector(self.signature, 2, 0, 0xFFFF, "signature")

    @staticmethod
    def decode(body: bytes) -> CertificateVerify:
        r = Reader(body, "CertificateVerify")
        cv = CertificateVerify(r.uint(2), r.vector(2, 0, 0xFFFF, "signature"))
        r.done()
        return cv


@dataclass(frozen=True)
class Finished:
    msg_type = HandshakeType.finished
    verify_data: bytes

    def encode(self) -> bytes:
        if len(self.verify_data) != HASH_LEN:
            raise CodecUsageError(f"verify_data must be {HASH_LEN} bytes")
        return self.verify_data

    @staticmethod
    def decode(body: bytes) -> Finished:
        if len(body) != HASH_LEN:
            raise _decode_error(f"Finished: verify_data is {len(body)} bytes, expected {HASH_LEN}")
        return Finished(body)


HandshakeMessage = ClientHello | ServerHello | EncryptedExtensions | Certificate | CertificateVerify | Finished

_DECODERS = {
    HandshakeType.client_hello: ClientHello.decode,
    HandshakeType.server_hello: ServerHello.decode,
    HandshakeType.encrypted_extensions: EncryptedExtensions.decode,
    HandshakeType.certificate: Certificate.decode,
    HandshakeType.certificate_verify: CertificateVerify.decode,
    HandshakeType.finished: Finished.decode,
}


def decode_message(msg: RawHandshake) -> HandshakeMessage:
    """Decode a framed message. Types qTLS doesn't implement are ``unexpected_message``.

    That includes NewSessionTicket, CertificateRequest, EndOfEarlyData and
    KeyUpdate (no resumption, client auth, 0-RTT or key update in scope);
    the handshake state machine decides whether to ignore any of them.
    """
    decoder = _DECODERS.get(msg.msg_type)  # type: ignore[call-overload]
    if decoder is None:
        name = HandshakeType(msg.msg_type).name
        raise AlertError(Alert.unexpected_message, f"{name} is not supported")
    return decoder(msg.body)


# --------------------------------------------------------------------------- #
# Alert records (RFC 8446 §6)
# --------------------------------------------------------------------------- #


WARNING, FATAL = 1, 2


def encode_alert(description: Alert) -> bytes:
    """close_notify and user_canceled are warnings; every other alert is fatal (RFC 8446 §6)."""
    level = WARNING if description in (Alert.close_notify, Alert.user_canceled) else FATAL
    return uint(level, 1) + uint(int(description), 1)


def decode_alert(data: bytes) -> tuple[int, int]:
    """Return ``(level, description)``; descriptions qTLS doesn't know stay ints."""
    if len(data) != 2:
        raise _decode_error(f"alert is {len(data)} bytes, expected 2")
    return data[0], data[1]
