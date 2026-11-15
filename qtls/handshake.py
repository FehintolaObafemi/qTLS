"""Sans-I/O TLS 1.3 handshake for signature authentication (configs A and B).

A :class:`Client` or :class:`Server` takes bytes with :meth:`Connection.receive`
and hands back :class:`Event` objects; bytes to send come out of
:meth:`Connection.data_to_send`. Nothing here touches a socket or the clock.

How it's organised, so AuthKEM (Phase 4) and MTC (Phase 3) are additions:

* **Dispatch** is a ``(state, message type) → handler`` table per role. A
  message with no row is ``unexpected_message``.
* **Secrets** are derived at the transcript point each one names: the
  handler calls :func:`keyschedule.derive_secret` with that point's hash, so
  a mode with different points (specs.md D4) supplies its own.
* **Application data** is gated on application keys being installed, not on
  a state name, so data before the peer's Finished (D9) is a flag, not a fork.
* **Flights** are tagged by the protocol: a side starts a new flight when it
  queues output after receiving the peer's input. Drain timing never matters.
  Each record is labelled with its content type and key (``Flight.labels``),
  so handshake bytes, early data and application data can be told apart.
  A transport that writes one flight at a time reads ``flights``;
  ``data_to_send`` simply drains everything queued.
* **Alerts** go out under the key the peer can read in the current state,
  from an explicit per-state table (specs.md D17).
* **Errors:** a peer-caused failure becomes a ``ConnectionFailed`` event with
  the alert queued; ``receive`` doesn't raise. Anything else is a local bug:
  ``internal_error`` is queued, the connection fails, and the exception is
  re-raised (events from earlier in that call are lost).

Randomness is injected (:class:`SystemRandomness`, :class:`SeededRandomness`)
as bytes and seeds only; the ``backends`` map in each config picks the crypto
library, so the randomness mode never changes which backend is measured.
"""

from __future__ import annotations

import datetime as dt
import enum
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol

from qtls import crypto, hybrid, x509
from qtls import keyschedule as ks
from qtls import messages as m
from qtls import record
from qtls.alerts import Alert, AlertError, CodecUsageError, alert_for
from qtls.messages import Context, ExtensionType, HandshakeType
from qtls.record import ContentType, RecordProtection

CIPHER_SUITE = 0x1301  # TLS_AES_128_GCM_SHA256 (specs.md D16)
SERVER_CV_CONTEXT = b"TLS 1.3, server CertificateVerify"
DOWNGRADE_SENTINELS = (b"DOWNGRD\x01", b"DOWNGRD\x00")  # RFC 8446 §4.1.3
MLKEM = hybrid.MLKEM

DEFAULT_BACKENDS: Mapping[str, crypto.Backend] = MappingProxyType({**x509.DEFAULT_BACKENDS, MLKEM: "openssl"})

# Every check that peer input can fail raises AlertError (the record layer, the
# codec, x509 and hybrid convert crypto exceptions themselves). Anything else
# reaching the top of ``receive`` is a local bug.
_PEER_ERRORS = (AlertError,)
PRE_SHARED_KEY = 41  # RFC 8446 §4.2.11


# --------------------------------------------------------------------------- #
# Randomness
# --------------------------------------------------------------------------- #


class RandomStream(Protocol):
    """What one connection draws. ``None`` seeds mean "let the backend choose"."""

    def random32(self) -> bytes: ...
    def x25519_seed(self) -> bytes | None: ...
    def kem_seed(self, alg: str) -> bytes | None: ...
    def encap_seed(self, alg: str) -> bytes | None: ...
    def sign_seed(self, alg: str) -> bytes | None: ...


class Randomness(Protocol):
    seeded: bool

    def for_connection(self, role: str) -> RandomStream: ...


class _SystemStream:
    def random32(self) -> bytes:
        return os.urandom(32)

    def x25519_seed(self) -> None:
        return None

    def kem_seed(self, alg: str) -> None:
        return None

    def encap_seed(self, alg: str) -> None:
        return None

    def sign_seed(self, alg: str) -> None:
        return None


class SystemRandomness:
    """Fresh randomness from the OS and the backends."""

    seeded = False

    def for_connection(self, role: str) -> RandomStream:
        return _SystemStream()


SEEDED_PREFIX = b"qtls handshake rng v1"


def seeded_bytes(seed: bytes, role: str, label: str, index: int, n: int) -> bytes:
    """The seeded stream, specified so tests can recompute it independently.

    Block ``i`` is SHA-256(prefix ‖ len(seed) ‖ seed ‖ role ‖ 0 ‖ label ‖ 0 ‖
    index (4 bytes) ‖ i (4 bytes)); the output is the first ``n`` bytes.
    """
    out = b""
    block = 0
    head = SEEDED_PREFIX + len(seed).to_bytes(2, "big") + seed + role.encode() + b"\x00" + label.encode() + b"\x00"
    while len(out) < n:
        out += crypto.sha256(head + index.to_bytes(4, "big") + block.to_bytes(4, "big")).digest()
        block += 1
    return out[:n]


class _SeededStream:
    def __init__(self, seed: bytes, role: str) -> None:
        self._seed, self._role = seed, role
        self.calls: dict[str, int] = {}

    def _draw(self, label: str, n: int) -> bytes:
        index = self.calls.get(label, 0)
        self.calls[label] = index + 1
        return seeded_bytes(self._seed, self._role, label, index, n)

    def random32(self) -> bytes:
        return self._draw("random", 32)

    def x25519_seed(self) -> bytes:
        return self._draw("x25519", 32)

    def kem_seed(self, alg: str) -> bytes:
        return self._draw(f"kem/{alg}", 64)

    def encap_seed(self, alg: str) -> bytes:
        return self._draw(f"encap/{alg}", 32)

    def sign_seed(self, alg: str) -> bytes:
        return self._draw(f"sign/{alg}", crypto.SIGNATURES[alg].sign_seed_len)


class SeededRandomness:
    """Deterministic randomness for tests and reproducible runs.

    One stream per role; asking for a role twice raises, so two connections
    never share key shares (RFC 9846 forbids reusing them).
    """

    seeded = True

    def __init__(self, seed: bytes) -> None:
        self.seed = seed
        self.streams: dict[str, _SeededStream] = {}

    def for_connection(self, role: str) -> RandomStream:
        if role in self.streams:
            raise CodecUsageError(f"this SeededRandomness already gave out its {role!r} stream")
        self.streams[role] = _SeededStream(self.seed, role)
        return self.streams[role]


# --------------------------------------------------------------------------- #
# Configuration, events, flights
# --------------------------------------------------------------------------- #


class CertificateVerifier(Protocol):
    """Validates the server's certificate_list and returns its leaf (specs.md D30).

    The state machine keeps the message checks (context, empty list, entry
    extensions), the transcript and the state; a verifier owns only its trust
    policy (anchors, time; MTC landmarks in Phase 3). It is told what the
    handshake needs and must enforce it, and the state machine re-checks the
    returned leaf anyway (P8). It reports a bad chain by raising AlertError;
    anything else is a local bug (internal_error, re-raised).
    """

    def verify(
        self,
        cert_data: tuple[bytes, ...],
        *,
        server_name: str,
        accepted: frozenset[int],
        expected_kind: x509.Kind,
        backends: Mapping[str, crypto.Backend],
    ) -> x509.VerifiedLeaf: ...


@dataclass(frozen=True)
class X509Verifier:
    """The default verifier: X.509 path validation to a trust anchor (D24)."""

    anchors: tuple[x509.TrustAnchor, ...]
    now: dt.datetime  # injected; the clock is never read

    def verify(
        self,
        cert_data: tuple[bytes, ...],
        *,
        server_name: str,
        accepted: frozenset[int],
        expected_kind: x509.Kind,
        backends: Mapping[str, crypto.Backend],
    ) -> x509.VerifiedLeaf:
        return x509.verify_chain(
            list(cert_data), self.anchors, server_name=server_name, now=self.now,
            accepted=accepted, expected_kind=expected_kind, backends=backends,
        )  # fmt: skip


@dataclass(frozen=True)
class ClientConfig:
    anchors: tuple[x509.TrustAnchor, ...]  # for the default X509Verifier
    signature_algorithms: tuple[int, ...]  # CertificateVerify schemes offered
    now: dt.datetime  # injected; the clock is never read
    server_name: str = "qtls.test"
    signature_algorithms_cert: tuple[int, ...] | None = None  # sent only when set
    randomness: Randomness = field(default_factory=SystemRandomness)
    backends: Mapping[str, crypto.Backend] = field(default_factory=lambda: DEFAULT_BACKENDS)
    certificate_verifier: CertificateVerifier | None = None  # None: X509Verifier(anchors, now)


@dataclass(frozen=True)
class ServerConfig:
    cert_data: tuple[bytes, ...]  # leaf first; the root isn't sent
    signing_key: crypto.SigPrivateKey
    randomness: Randomness = field(default_factory=SystemRandomness)
    backends: Mapping[str, crypto.Backend] = field(default_factory=lambda: DEFAULT_BACKENDS)


class Event:
    """Base class for what :meth:`Connection.receive` reports."""


@dataclass(frozen=True)
class ServerAuthenticated(Event):
    """The client verified the server explicitly (certificate, CV, Finished)."""

    leaf: x509.VerifiedLeaf


@dataclass(frozen=True)
class HandshakeComplete(Event):
    """Both directions have application keys."""


@dataclass(frozen=True)
class ApplicationData(Event):
    data: bytes


@dataclass(frozen=True)
class ConnectionClosed(Event):
    """The peer sent close_notify.

    Before ``HandshakeComplete`` this is an abandoned handshake, not a
    success: during the handshake close_notify can arrive unprotected (D22).
    """


@dataclass(frozen=True)
class PeerAlerted(Event):
    """The peer sent an error alert. It is never answered."""

    level: int
    description: int


@dataclass(frozen=True)
class ConnectionFailed(Event):
    """We failed: ``alert`` was queued (``None``: nothing could be sent)."""

    alert: Alert | None
    error: BaseException | None
    reason: str | None


@dataclass
class Flight:
    sender: str
    records: list[bytes]
    labels: list[tuple[str, str]] = field(default_factory=list)  # (content type, key name or "plaintext")

    @property
    def size(self) -> int:
        return sum(len(r) for r in self.records)


class State(enum.Enum):
    START = "start"
    WAIT_SH = "wait ServerHello"
    WAIT_EE = "wait EncryptedExtensions"
    WAIT_CERT = "wait Certificate"
    WAIT_CV = "wait CertificateVerify"
    WAIT_FINISHED = "wait server Finished"
    WAIT_CH = "wait ClientHello"
    WAIT_CLIENT_FINISHED = "wait client Finished"
    CONNECTED = "connected"
    CLOSED = "closed"
    FAILED = "failed"


# --------------------------------------------------------------------------- #
# Pieces the RFC 8448 oracle tests directly (the machine calls these)
# --------------------------------------------------------------------------- #


def pack(
    content_type: ContentType,
    content: bytes,
    protection: RecordProtection | None,
    version: int = record.LEGACY_VERSION,
) -> list[bytes]:
    """Records for content under one key: fragmented at 2^14, no padding (D17)."""
    pieces = record.fragment(content) or [b""]
    if protection is None:
        return [record.encode_plaintext(content_type, p, version) for p in pieces]
    return [protection.seal(content_type, p) for p in pieces]


def signed_content(context: bytes, transcript_hash: bytes) -> bytes:
    """What CertificateVerify signs (RFC 8446 §4.4.3)."""
    return b"\x20" * 64 + context + b"\x00" + transcript_hash


def _fail(alert: Alert, message: str, reason: str) -> AlertError:
    return AlertError(alert, message, reason)


# --------------------------------------------------------------------------- #
# The connection
# --------------------------------------------------------------------------- #

Handler = Callable[["Connection", m.RawHandshake, list[m.RawHandshake], int, list[Event]], None]

_TERMINAL = (State.CLOSED, State.FAILED)


class Connection:
    role: str
    _HANDLERS: dict[tuple[State, int], Handler] = {}
    # Which write key an alert goes under in each state (specs.md D17).
    _ALERT_KEYS: dict[State, str | None] = {}

    def __init__(self, randomness: Randomness, backends: Mapping[str, crypto.Backend]) -> None:
        self.state = State.START
        self._rng = randomness.for_connection(self.role)
        self._seeded = randomness.seeded
        self._backends = backends
        self._buffer = bytearray()
        self._reader = m.HandshakeReader()
        self._read: RecordProtection | None = None
        self._writers: dict[str, RecordProtection] = {}
        self._write_key: str | None = None
        self._out: list[bytes] = []
        self.flights: list[Flight] = []
        self._peer_spoke = True
        self._transcript = ks.Transcript()
        self._schedule = ks.KeySchedule()
        self._ccs_allowed = False
        self._plain_alerts = False
        self._app_read = self._app_write = False
        self._write_closed = False
        self.keylog: dict[str, bytes] = {}
        self._client_random = b""

    # ----- public API ------------------------------------------------------ #

    def data_to_send(self) -> bytes:
        out = b"".join(self._out)
        self._out.clear()
        return out

    def receive(self, data: bytes) -> list[Event]:
        events: list[Event] = []
        if self.state in _TERMINAL:
            return events
        self._buffer += data
        try:
            records, rest = record.split_records(bytes(self._buffer))
            self._buffer = bytearray(rest)
            for rec in records:
                self._peer_spoke = True
                self._receive_record(rec, events)
                if self.state in _TERMINAL:
                    break
        except Exception as exc:
            self._abort(exc, events)
            if not isinstance(exc, _PEER_ERRORS):
                raise
        return events

    def receive_eof(self) -> list[Event]:
        """The transport closed without close_notify: truncation (specs.md D26)."""
        if self.state in _TERMINAL:
            return []
        self.state = State.FAILED
        return [ConnectionFailed(None, None, "truncated")]

    def send(self, data: bytes) -> None:
        # Gated on the application write key, not a state name: a server may
        # send after its Finished (RFC 8446 §2), and an AuthKEM client before
        # the server's (D9).
        if self.state in _TERMINAL or not self._app_write or self._write_closed:
            raise CodecUsageError(f"can't send application data in state {self.state.name}")
        for rec in pack(ContentType.application_data, data, self._writer()):
            self._emit(rec, ContentType.application_data)

    def close(self) -> None:
        """Send close_notify. Data from the peer is still delivered until its own."""
        if self.state in _TERMINAL or self._write_closed:
            raise CodecUsageError(f"can't close in state {self.state.name}")
        self._send_alert(Alert.close_notify)
        self._write_closed = True
        if self.state is not State.CONNECTED:
            self.state = State.CLOSED  # an abandoned handshake doesn't continue

    def keylog_lines(self) -> list[str]:
        """SSLKEYLOGFILE lines, for the test oracle and (2e) Wireshark."""
        return [f"{label} {self._client_random.hex()} {secret.hex()}" for label, secret in self.keylog.items()]

    # ----- sending --------------------------------------------------------- #

    def _writer(self) -> RecordProtection | None:
        return self._writers[self._write_key] if self._write_key else None

    def _emit(self, rec: bytes, content_type: ContentType, key: str | None = None) -> None:
        if self._peer_spoke:
            self.flights.append(Flight(self.role, []))
            self._peer_spoke = False
        key = key if key is not None else (self._write_key or "plaintext")
        self.flights[-1].records.append(rec)
        self.flights[-1].labels.append((content_type.name, key))
        self._out.append(rec)

    def _send_handshake(self, raws: list[bytes], version: int = record.LEGACY_VERSION) -> None:
        for rec in pack(ContentType.handshake, b"".join(raws), self._writer(), version):
            self._emit(rec, ContentType.handshake)

    def _send_alert(self, alert: Alert, state: State | None = None) -> None:
        state = state or self.state
        if state not in self._ALERT_KEYS:
            raise CodecUsageError(f"no alert key for state {state.name}")
        key = self._ALERT_KEYS[state]
        protection = self._writers[key] if key else None
        for rec in pack(ContentType.alert, m.encode_alert(alert), protection):
            self._emit(rec, ContentType.alert, key or "plaintext")

    def _install_writer(self, name: str, secret: bytes) -> None:
        self._writers[name] = RecordProtection.from_secret(secret)
        self._write_key = name

    def _abort(self, exc: BaseException, events: list[Event]) -> None:
        alert = alert_for(exc)
        failed_in, self.state = self.state, State.FAILED  # failed first, whatever happens next
        if self._write_closed:
            alert = None  # our close_notify was the last thing we send
        elif alert is not None:
            self._send_alert(alert, failed_in)  # a missing alert-key row is a local bug and propagates
        events.append(ConnectionFailed(alert, exc, getattr(exc, "reason", None)))

    # ----- receiving ------------------------------------------------------- #

    def _receive_record(self, rec: bytes, events: list[Event]) -> None:
        outer = rec[0]
        if self._reader.pending() and outer == ContentType.change_cipher_spec:
            raise _fail(Alert.unexpected_message, "ChangeCipherSpec inside a handshake message", "interleaved")
        if self._plain_alerts and outer == ContentType.application_data:
            self._plain_alerts = False  # the peer's first protected record closes the window (D22)
        result = record.receive(rec, self._read, ccs_allowed=self._ccs_allowed, plain_alerts_allowed=self._plain_alerts)
        if result is None:
            return  # a valid ChangeCipherSpec, dropped
        content_type, content = result
        if content_type is ContentType.alert:
            self._on_alert(content, events)
        elif content_type is ContentType.handshake:
            messages = self._reader.feed(content)
            for index, raw in enumerate(messages):
                self._on_handshake(raw, messages, index, events)
                if self.state in _TERMINAL:
                    return
        else:
            if self._reader.pending():
                raise _fail(Alert.unexpected_message, "application data inside a handshake message", "interleaved")
            if not self._app_read:
                raise _fail(Alert.unexpected_message, "application data before the handshake finished", "early-data")
            events.append(ApplicationData(content))

    def _on_alert(self, content: bytes, events: list[Event]) -> None:
        level, description = m.decode_alert(content)
        if description == Alert.close_notify:
            events.append(ConnectionClosed())
            if not self._write_closed:
                self._send_alert(Alert.close_notify)
                self._write_closed = True
            self.state = State.CLOSED
        else:  # every other alert ends the connection, whatever its level (D26)
            events.append(PeerAlerted(level, description))
            self.state = State.FAILED

    def _on_handshake(self, raw: m.RawHandshake, messages: list[m.RawHandshake], index: int, events: list[Event]) -> None:
        handler = self._HANDLERS.get((self.state, raw.msg_type))
        if handler is None:
            if self._drop_post_handshake(raw):
                return
            name = HandshakeType(raw.msg_type).name
            raise _fail(Alert.unexpected_message, f"{name} in state {self.state.name}", "unexpected-message")
        handler(self, raw, messages, index, events)

    def _drop_post_handshake(self, raw: m.RawHandshake) -> bool:
        return False

    def _derive(self, secret: bytes, label: bytes, transcript_hash: bytes, keylog: str | None = None) -> bytes:
        out = ks.derive_secret(secret, label, transcript_hash)
        if keylog:
            self.keylog[keylog] = out
        return out


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class Client(Connection):
    role = "client"

    def __init__(self, config: ClientConfig) -> None:
        if not config.signature_algorithms:
            raise CodecUsageError("offer at least one signature algorithm")
        if config.certificate_verifier is None and not config.anchors:
            raise CodecUsageError("a client needs at least one trust anchor")
        schemes = set(config.signature_algorithms) | set(config.signature_algorithms_cert or ())
        _check_backends(config.backends, [MLKEM] + [_scheme_alg(s) for s in sorted(schemes)])
        super().__init__(config.randomness, config.backends)
        self.config = config
        self._kx: hybrid.ClientKeyExchange | None = None
        self._offered: set[int] = set()
        self._c_hs = self._s_hs = b""
        self.leaf: x509.VerifiedLeaf | None = None
        self._verifier = config.certificate_verifier or X509Verifier(config.anchors, config.now)

    def start(self) -> None:
        if self.state is not State.START:
            raise CodecUsageError("start() runs once")
        cfg = self.config
        x_seed = self._rng.x25519_seed()
        x_key = crypto.x25519_from_private_bytes(x_seed) if x_seed else crypto.x25519_generate()
        kem = crypto.kem_generate(MLKEM, self._backends[MLKEM], seed=self._rng.kem_seed(MLKEM))
        self._kx = hybrid.ClientKeyExchange(kem, x_key)
        exts = [
            m.Extension(ExtensionType.server_name, m.encode_server_name(cfg.server_name, Context.client_hello)),
            m.Extension(ExtensionType.supported_versions, m.encode_supported_versions([m.TLS13], Context.client_hello)),
            m.Extension(ExtensionType.supported_groups, m.encode_supported_groups([hybrid.GROUP])),
            m.Extension(ExtensionType.key_share, m.encode_key_share([m.KeyShareEntry(hybrid.GROUP, self._kx.share)], Context.client_hello)),
            m.Extension(ExtensionType.signature_algorithms, m.encode_signature_algorithms(cfg.signature_algorithms)),
        ]  # fmt: skip
        if cfg.signature_algorithms_cert is not None:
            exts.append(m.Extension(ExtensionType.signature_algorithms_cert, m.encode_signature_algorithms(cfg.signature_algorithms_cert)))
        self._offered = {e.ext_type for e in exts}
        self._client_random = self._rng.random32()
        hello = m.ClientHello(self._client_random, b"", (CIPHER_SUITE,), tuple(exts))
        raw = m.encode_handshake(hello)
        self._transcript.add(raw)
        self._schedule.early()
        self._send_handshake([raw], version=record.INITIAL_CLIENT_HELLO_VERSION)
        self._ccs_allowed = True
        self.state = State.WAIT_SH

    def _on_server_hello(self, raw: m.RawHandshake, messages: list[m.RawHandshake], index: int, events: list[Event]) -> None:
        body = raw.body
        # The downgrade sentinel and HRR are checked before the strict TLS 1.3 decode (specs.md D27).
        if len(body) >= 34 and body[26:34] in DOWNGRADE_SENTINELS:
            raise _fail(Alert.illegal_parameter, "ServerHello carries a downgrade sentinel", "downgrade")
        if body[2:34] == m.HRR_RANDOM:  # the codec refuses it too; here it must come before the version checks
            raise _fail(Alert.unexpected_message, "HelloRetryRequest is not supported (D16)", "hrr")
        hello = m.ServerHello.decode(body)
        # The version first: a TLS 1.2 ServerHello is protocol_version, whatever else it says (D27).
        versions = m.find_extension(hello.extensions, ExtensionType.supported_versions)
        if versions is None:
            raise _fail(Alert.protocol_version, "ServerHello negotiates TLS 1.2 or older", "version")
        if m.decode_supported_versions(versions, Context.server_hello) != m.TLS13:
            raise _fail(Alert.illegal_parameter, "ServerHello selects a version that wasn't offered", "version-value")
        if hello.legacy_session_id_echo != b"":
            raise _fail(Alert.illegal_parameter, "legacy_session_id_echo doesn't match", "session-id")
        if hello.cipher_suite != CIPHER_SUITE:
            raise _fail(Alert.illegal_parameter, f"cipher suite {hello.cipher_suite:#06x} wasn't offered", "cipher-suite")
        for ext in hello.extensions:
            if ext.ext_type not in (ExtensionType.supported_versions, ExtensionType.key_share):
                self._reject_extension(ext.ext_type, "ServerHello")
        share_data = m.find_extension(hello.extensions, ExtensionType.key_share)
        if share_data is None:
            raise _fail(Alert.missing_extension, "ServerHello has no key_share", "no-key-share")
        share = m.decode_key_share(share_data, Context.server_hello)
        assert isinstance(share, m.KeyShareEntry)
        if share.group != hybrid.GROUP:
            raise _fail(Alert.illegal_parameter, f"group {share.group:#06x} wasn't offered (D16)", "group")
        assert self._kx is not None
        shared_secret = self._kx.finish(share.key_exchange)
        self._kx = None  # never reused
        self._transcript.add(raw.raw)
        self._reader.require_record_end(messages, index)
        hs = self._schedule.handshake(shared_secret)
        th = self._transcript.hash()
        self._c_hs = self._derive(hs, ks.C_HS_TRAFFIC, th, "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
        self._s_hs = self._derive(hs, ks.S_HS_TRAFFIC, th, "SERVER_HANDSHAKE_TRAFFIC_SECRET")
        self._read = RecordProtection.from_secret(self._s_hs)
        self._install_writer("hs", self._c_hs)
        self.state = State.WAIT_EE

    def _reject_extension(self, ext_type: int, where: str) -> None:
        """RFC 8446 §4.2: offered but not allowed here vs never offered."""
        if ext_type in self._offered:
            raise _fail(Alert.illegal_parameter, f"extension {ext_type} isn't allowed in {where}", "extension-not-allowed")
        raise _fail(Alert.unsupported_extension, f"extension {ext_type} in {where} wasn't offered", "extension-not-offered")

    def _on_encrypted_extensions(self, raw: m.RawHandshake, messages: list[m.RawHandshake], index: int, events: list[Event]) -> None:
        ee = m.EncryptedExtensions.decode(raw.body)
        for ext in ee.extensions:
            if ext.ext_type == ExtensionType.server_name:
                m.decode_server_name(ext.data, Context.encrypted_extensions)  # must be empty
            elif ext.ext_type == ExtensionType.supported_groups:
                m.decode_supported_groups(ext.data)  # allowed and ignored (RFC 8446 §4.2.7)
            else:
                self._reject_extension(ext.ext_type, "EncryptedExtensions")
        self._transcript.add(raw.raw)
        self.state = State.WAIT_CERT

    def _on_certificate(self, raw: m.RawHandshake, messages: list[m.RawHandshake], index: int, events: list[Event]) -> None:
        cert = m.Certificate.decode(raw.body)
        if cert.certificate_request_context:
            raise _fail(Alert.illegal_parameter, "server certificate_request_context must be empty", "certificate-context")
        if not cert.certificate_list:
            raise _fail(Alert.decode_error, "empty server Certificate (RFC 8446 §4.4.2.4)", "empty-certificate")
        for entry in cert.certificate_list:
            for ext in entry.extensions:
                self._reject_extension(ext.ext_type, "CertificateEntry")
        cfg = self.config
        accepted = cfg.signature_algorithms_cert if cfg.signature_algorithms_cert is not None else cfg.signature_algorithms
        leaf = self._verifier.verify(
            tuple(e.cert_data for e in cert.certificate_list), server_name=cfg.server_name,
            accepted=frozenset(accepted), expected_kind="sig", backends=self._backends,
        )  # fmt: skip
        # Postconditions, whatever the verifier: the leaf is the certificate the
        # server sent, a signature leaf (P8), and a key a scheme we offered can
        # use. CertificateVerify then uses this leaf.
        if leaf.certificate.raw != cert.certificate_list[0].cert_data:
            raise _fail(Alert.bad_certificate, "the verifier's leaf isn't the certificate the server sent", "leaf-mismatch")
        if leaf.kind != "sig":
            raise _fail(Alert.unsupported_certificate, f"{leaf.alg} leaf under signature authentication (P8)", "leaf-kind")
        if not set(x509.BY_NAME[leaf.alg].codepoints) & set(cfg.signature_algorithms):
            raise _fail(Alert.unsupported_certificate, f"no offered scheme fits the {leaf.alg} leaf", "leaf-alg")
        self.leaf = leaf
        self._transcript.add(raw.raw)
        self.state = State.WAIT_CV

    def _on_certificate_verify(self, raw: m.RawHandshake, messages: list[m.RawHandshake], index: int, events: list[Event]) -> None:
        cv = m.CertificateVerify.decode(raw.body)
        leaf = self.leaf
        assert leaf is not None
        if cv.algorithm not in self.config.signature_algorithms:
            raise _fail(Alert.illegal_parameter, f"CertificateVerify scheme {cv.algorithm:#06x} wasn't offered", "cv-scheme-not-offered")
        if cv.algorithm not in x509.BY_NAME[leaf.alg].codepoints:
            raise _fail(Alert.illegal_parameter, f"CertificateVerify scheme {cv.algorithm:#06x} doesn't fit the {leaf.alg} key", "cv-scheme-mismatch")
        content = signed_content(SERVER_CV_CONTEXT, self._transcript.hash())
        try:
            crypto.sig_verify(leaf.alg, leaf.public_key, content, cv.signature, self._backends[leaf.alg])
        except crypto.InvalidSignature:
            raise _fail(Alert.decrypt_error, "CertificateVerify signature doesn't verify", "cv-signature") from None
        self._transcript.add(raw.raw)
        self.state = State.WAIT_FINISHED

    def _on_server_finished(self, raw: m.RawHandshake, messages: list[m.RawHandshake], index: int, events: list[Event]) -> None:
        fin = m.Finished.decode(raw.body)
        _check_finished(self._s_hs, self._transcript.hash(), fin.verify_data, "server-finished")
        self._transcript.add(raw.raw)
        self._reader.require_record_end(messages, index)
        th_server_finished = self._transcript.hash()
        ms = self._schedule.main()
        c_ap = self._derive(ms, ks.C_AP_TRAFFIC, th_server_finished, "CLIENT_TRAFFIC_SECRET_0")
        s_ap = self._derive(ms, ks.S_AP_TRAFFIC, th_server_finished, "SERVER_TRAFFIC_SECRET_0")
        self._derive(ms, ks.EXP_MASTER, th_server_finished, "EXPORTER_SECRET")
        self._read = RecordProtection.from_secret(s_ap)
        self._ccs_allowed = False
        assert self.leaf is not None
        events.append(ServerAuthenticated(self.leaf))
        finished = m.Finished(ks.verify_data(ks.finished_key(self._c_hs), th_server_finished))
        raw_fin = m.encode_handshake(finished)
        self._transcript.add(raw_fin)
        self._send_handshake([raw_fin])  # under c hs traffic
        self._install_writer("ap", c_ap)
        self._app_read = self._app_write = True
        self.state = State.CONNECTED
        events.append(HandshakeComplete())

    def _drop_post_handshake(self, raw: m.RawHandshake) -> bool:
        # NewSessionTicket is framed and dropped, never hashed (D26).
        return self.state is State.CONNECTED and raw.msg_type == HandshakeType.new_session_ticket

    _HANDLERS = {
        (State.WAIT_SH, HandshakeType.server_hello): _on_server_hello,
        (State.WAIT_EE, HandshakeType.encrypted_extensions): _on_encrypted_extensions,
        (State.WAIT_CERT, HandshakeType.certificate): _on_certificate,
        (State.WAIT_CV, HandshakeType.certificate_verify): _on_certificate_verify,
        (State.WAIT_FINISHED, HandshakeType.finished): _on_server_finished,
    }
    _ALERT_KEYS = {
        State.START: None,
        State.WAIT_SH: None,
        State.WAIT_EE: "hs",
        State.WAIT_CERT: "hs",
        State.WAIT_CV: "hs",
        State.WAIT_FINISHED: "hs",
        State.CONNECTED: "ap",
    }


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #


class Server(Connection):
    role = "server"

    def __init__(self, config: ServerConfig) -> None:
        if not config.cert_data:
            raise CodecUsageError("a server needs a certificate chain")
        alg = config.signing_key.alg
        _check_backends(config.backends, [MLKEM, alg])
        if config.signing_key.backend != config.backends[alg]:
            raise CodecUsageError(f"the {alg} signing key is on {config.signing_key.backend}, but backends says {config.backends[alg]}")
        if config.randomness.seeded:
            if config.backends[MLKEM] != "liboqs":
                raise CodecUsageError("seeded ML-KEM encapsulation needs the liboqs backend")
            if config.signing_key.backend == "openssl" and crypto.SIGNATURES[alg].seed_mode != "scalar":
                raise CodecUsageError(f"seeded {alg} signing needs the liboqs backend")
        leaf = x509.parse(config.cert_data[0])
        if x509.parse_spki(leaf.spki_raw)[1] != config.signing_key.public_key:
            raise CodecUsageError("the signing key doesn't match the leaf certificate")
        super().__init__(config.randomness, config.backends)
        self.config = config
        self.state = State.WAIT_CH
        self._schemes = x509.BY_NAME[alg].codepoints
        self._c_hs = b""
        self._c_ap = b""
        self._th_server_finished = b""
        self.server_name: str | None = None

    def _on_client_hello(self, raw: m.RawHandshake, messages: list[m.RawHandshake], index: int, events: list[Event]) -> None:
        hello = m.ClientHello.decode(raw.body)
        self._reader.require_record_end(messages, index)
        exts = hello.extensions
        if any(e.ext_type == PRE_SHARED_KEY for e in exts[:-1]):
            raise _fail(Alert.illegal_parameter, "pre_shared_key must be the last extension", "psk-not-last")
        versions = m.find_extension(exts, ExtensionType.supported_versions)
        if versions is None or m.TLS13 not in m.decode_supported_versions(versions, Context.client_hello):  # type: ignore[operator]
            raise _fail(Alert.protocol_version, "client doesn't offer TLS 1.3", "version")
        if CIPHER_SUITE not in hello.cipher_suites:
            raise _fail(Alert.handshake_failure, "TLS_AES_128_GCM_SHA256 not offered", "cipher-suite")
        groups_data = m.find_extension(exts, ExtensionType.supported_groups)
        shares_data = m.find_extension(exts, ExtensionType.key_share)
        sig_data = m.find_extension(exts, ExtensionType.signature_algorithms)
        # RFC 8446 §9.2: without pre_shared_key all three are mandatory (missing_extension first).
        if groups_data is None or shares_data is None:
            raise _fail(Alert.missing_extension, "supported_groups and key_share must both be present", "groups-and-shares")
        if sig_data is None:
            raise _fail(Alert.missing_extension, "ClientHello has no signature_algorithms", "signature-algorithms")
        groups = m.decode_supported_groups(groups_data)
        shares = m.decode_key_share(shares_data, Context.client_hello)
        assert isinstance(shares, tuple)
        seen: set[int] = set()
        for entry in shares:  # RFC 8446 §4.2.8
            if entry.group in seen:
                raise _fail(Alert.illegal_parameter, f"two key shares for group {entry.group:#06x}", "duplicate-share")
            if entry.group not in groups:
                raise _fail(Alert.illegal_parameter, f"key share for unoffered group {entry.group:#06x}", "share-not-offered")
            seen.add(entry.group)
        if hybrid.GROUP not in groups:
            raise _fail(Alert.handshake_failure, "X25519MLKEM768 not offered", "group")
        share = next((e for e in shares if e.group == hybrid.GROUP), None)
        if share is None:
            raise _fail(Alert.handshake_failure, "no X25519MLKEM768 key share, and no HelloRetryRequest (D16)", "no-share")
        offered = m.decode_signature_algorithms(sig_data)
        scheme = next((s for s in self._schemes if s in offered), None)
        if scheme is None:
            raise _fail(Alert.handshake_failure, "client doesn't accept the certificate key's scheme", "signature-scheme")
        sni = m.find_extension(exts, ExtensionType.server_name)
        if sni is not None:
            self.server_name = m.decode_server_name(sni, Context.client_hello)
        # signature_algorithms_cert isn't checked: the chain is sent anyway and the client decides (D25).

        # Everything is computed before anything is queued, so a failure here sends a plaintext alert.
        cfg = self.config
        x_seed = self._rng.x25519_seed()
        x_key = crypto.x25519_from_private_bytes(x_seed) if x_seed else crypto.x25519_generate()

        def encapsulate(ek: bytes) -> tuple[bytes, bytes]:
            return crypto.kem_encapsulate(MLKEM, ek, self._backends[MLKEM], seed=self._rng.encap_seed(MLKEM))

        server_share, shared_secret = hybrid.server_respond(share.key_exchange, x_key, encapsulate)
        self._client_random = hello.random
        self._transcript.add(raw.raw)
        server_hello = m.ServerHello(self._rng.random32(), hello.legacy_session_id, CIPHER_SUITE, (
            m.Extension(ExtensionType.key_share, m.encode_key_share(m.KeyShareEntry(hybrid.GROUP, server_share), Context.server_hello)),
            m.Extension(ExtensionType.supported_versions, m.encode_supported_versions(m.TLS13, Context.server_hello)),
        ))  # fmt: skip
        raw_sh = m.encode_handshake(server_hello)
        self._transcript.add(raw_sh)
        self._schedule.early()
        hs = self._schedule.handshake(shared_secret)
        th = self._transcript.hash()
        self._c_hs = self._derive(hs, ks.C_HS_TRAFFIC, th, "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
        s_hs = self._derive(hs, ks.S_HS_TRAFFIC, th, "SERVER_HANDSHAKE_TRAFFIC_SECRET")

        ee_exts = (m.Extension(ExtensionType.server_name, b""),) if sni is not None else ()
        raw_ee = m.encode_handshake(m.EncryptedExtensions(ee_exts))
        self._transcript.add(raw_ee)
        raw_cert = m.encode_handshake(m.Certificate(b"", tuple(m.CertificateEntry(c) for c in cfg.cert_data)))
        self._transcript.add(raw_cert)
        alg = cfg.signing_key.alg
        signature = cfg.signing_key.sign(signed_content(SERVER_CV_CONTEXT, self._transcript.hash()), seed=self._rng.sign_seed(alg))
        raw_cv = m.encode_handshake(m.CertificateVerify(scheme, signature))
        self._transcript.add(raw_cv)
        raw_fin = m.encode_handshake(m.Finished(ks.verify_data(ks.finished_key(s_hs), self._transcript.hash())))
        self._transcript.add(raw_fin)
        self._th_server_finished = self._transcript.hash()
        ms = self._schedule.main()
        self._c_ap = self._derive(ms, ks.C_AP_TRAFFIC, self._th_server_finished, "CLIENT_TRAFFIC_SECRET_0")
        s_ap = self._derive(ms, ks.S_AP_TRAFFIC, self._th_server_finished, "SERVER_TRAFFIC_SECRET_0")
        self._derive(ms, ks.EXP_MASTER, self._th_server_finished, "EXPORTER_SECRET")

        self._send_handshake([raw_sh])
        self._read = RecordProtection.from_secret(self._c_hs)
        self._ccs_allowed = True
        self._plain_alerts = True
        self._install_writer("hs", s_hs)
        self._send_handshake([raw_ee, raw_cert, raw_cv, raw_fin])
        self._install_writer("ap", s_ap)
        self._app_write = True  # 0.5-RTT data is allowed (RFC 8446 §2)
        self.state = State.WAIT_CLIENT_FINISHED

    def _on_client_finished(self, raw: m.RawHandshake, messages: list[m.RawHandshake], index: int, events: list[Event]) -> None:
        fin = m.Finished.decode(raw.body)
        _check_finished(self._c_hs, self._th_server_finished, fin.verify_data, "client-finished")
        self._transcript.add(raw.raw)
        self._reader.require_record_end(messages, index)
        self._read = RecordProtection.from_secret(self._c_ap)
        self._ccs_allowed = False
        self._app_read = True
        self.state = State.CONNECTED
        events.append(HandshakeComplete())

    _HANDLERS = {
        (State.WAIT_CH, HandshakeType.client_hello): _on_client_hello,
        (State.WAIT_CLIENT_FINISHED, HandshakeType.finished): _on_client_finished,
    }
    _ALERT_KEYS = {
        State.WAIT_CH: None,
        State.WAIT_CLIENT_FINISHED: "ap",
        State.CONNECTED: "ap",
    }


_BY_CODEPOINT = {cp: a.name for a in x509.ALGORITHMS if a.kind == "sig" for cp in a.codepoints}


def _scheme_alg(codepoint: int) -> str:
    if codepoint not in _BY_CODEPOINT:
        raise CodecUsageError(f"signature scheme {codepoint:#06x} isn't one qTLS implements")
    return _BY_CODEPOINT[codepoint]


def _check_backends(backends: Mapping[str, crypto.Backend], algs: list[str]) -> None:
    missing = [a for a in algs if a not in backends]
    if missing:
        raise CodecUsageError(f"backends has no entry for {', '.join(missing)}")
    unknown = sorted({b for a, b in backends.items() if b not in crypto.BACKENDS})
    if unknown:
        raise CodecUsageError(f"unknown backend(s) {', '.join(map(str, unknown))}")


def _check_finished(base_secret: bytes, transcript_hash: bytes, received: bytes, reason: str) -> None:
    try:
        ks.verify_finished(ks.finished_key(base_secret), transcript_hash, received)
    except AlertError as exc:
        raise _fail(exc.alert, str(exc), reason) from None
