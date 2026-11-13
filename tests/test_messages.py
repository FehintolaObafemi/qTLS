"""Handshake codec: built from typed fields against RFC 8448, plus strict rejection.

Round trips alone prove little (an all-opaque codec re-encodes anything), so
each message is *constructed* from typed values taken from outside the message
(the RFC's key pairs, the IANA codepoints written out here) and compared to the
RFC bytes, and decoded fields are cross-checked independently (the
CertificateVerify signature really verifies; the certificate really parses).
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from qtls import messages as m
from qtls.alerts import Alert, AlertError, CodecUsageError
from rfc8448_trace import CERT, CFIN, CH, CLIENT_X25519_PUBLIC, CV, EE, NST, SERVER_X25519_PUBLIC, SFIN, SH, event, h

C, S, E = m.Context.client_hello, m.Context.server_hello, m.Context.encrypted_extensions
X25519, TLS13 = 0x001D, 0x0304
GROUPS = (0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104)
SIG_ALGS = (
    0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401,
    0x0501, 0x0601, 0x0201, 0x0402, 0x0502, 0x0602, 0x0202,
)  # fmt: skip
SUITES = (0x1301, 0x1303, 0x1302)


def ext(t: int, data: bytes) -> m.Extension:
    return m.Extension(t, data)


def frame(msg: m.HandshakeMessage) -> bytes:
    return m.encode_handshake(msg)


def body(raw: bytes) -> bytes:
    return raw[4:]


def assert_no_raw_fields(cls: type) -> None:
    fields = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
    assert not fields & {"raw", "body", "_raw", "encoded"}, cls


# --------------------------------------------------------------------------- #
# Construction from typed fields
# --------------------------------------------------------------------------- #


def test_client_hello_built_from_typed_fields() -> None:
    hello = m.ClientHello(
        random=CH[6:38],
        legacy_session_id=b"",
        cipher_suites=SUITES,
        extensions=(
            ext(0, m.encode_server_name("server", C)),
            ext(0xFF01, b"\x00"),  # renegotiation_info (opaque to qTLS)
            ext(10, m.encode_supported_groups(GROUPS)),
            ext(35, b""),  # session_ticket
            ext(51, m.encode_key_share([m.KeyShareEntry(X25519, CLIENT_X25519_PUBLIC)], C)),
            ext(43, m.encode_supported_versions([TLS13], C)),
            ext(13, m.encode_signature_algorithms(SIG_ALGS)),
            ext(45, b"\x01\x01"),  # psk_key_exchange_modes
            ext(28, b"\x40\x01"),  # record_size_limit
        ),
    )
    assert frame(hello) == CH
    assert_no_raw_fields(m.ClientHello)


def test_server_hello_built_from_typed_fields() -> None:
    hello = m.ServerHello(
        random=SH[6:38],
        legacy_session_id_echo=b"",
        cipher_suite=0x1301,
        extensions=(
            ext(51, m.encode_key_share(m.KeyShareEntry(X25519, SERVER_X25519_PUBLIC), S)),
            ext(43, m.encode_supported_versions(TLS13, S)),
        ),
    )
    assert frame(hello) == SH
    assert not hello.is_hrr


def test_encrypted_extensions_built_from_typed_fields() -> None:
    ee = m.EncryptedExtensions((
        ext(10, m.encode_supported_groups(GROUPS)),
        ext(28, b"\x40\x01"),
        ext(0, m.encode_server_name(None, E)),  # empty acknowledgement
    ))
    assert frame(ee) == EE


def _rfc_certificate_der() -> bytes:
    # Certificate body: context<1> ‖ list<3> ‖ cert_data<3> ‖ DER ‖ extensions<2>
    n = int.from_bytes(CERT[8:11], "big")
    return CERT[11 : 11 + n]


def test_certificate_built_from_typed_fields() -> None:
    cert = m.Certificate(b"", (m.CertificateEntry(_rfc_certificate_der(), ()),))
    assert frame(cert) == CERT


def test_certificate_verify_and_finished_built_from_typed_fields() -> None:
    assert frame(m.CertificateVerify(0x0804, CV[8:])) == CV
    server_fin = h(event("server", 'calculate finished "tls13 finished"')["finished"])
    client_fin = h(event("client", 'calculate finished "tls13 finished"')["finished"])
    assert frame(m.Finished(server_fin)) == SFIN
    assert frame(m.Finished(client_fin)) == CFIN


# --------------------------------------------------------------------------- #
# Decoding, with independent cross-checks
# --------------------------------------------------------------------------- #


def test_client_hello_decodes_to_typed_values() -> None:
    hello = m.ClientHello.decode(body(CH))
    assert hello.cipher_suites == SUITES
    assert hello.legacy_session_id == b""
    assert [e.ext_type for e in hello.extensions] == [0, 0xFF01, 10, 35, 51, 43, 13, 45, 28]
    get = lambda t: m.find_extension(hello.extensions, t)  # noqa: E731
    assert m.decode_server_name(get(0), C) == "server"
    assert m.decode_supported_groups(get(10)) == GROUPS
    assert m.decode_key_share(get(51), C) == (m.KeyShareEntry(X25519, CLIENT_X25519_PUBLIC),)
    assert m.decode_supported_versions(get(43), C) == (TLS13,)
    assert m.decode_signature_algorithms(get(13)) == SIG_ALGS
    assert m.encode_handshake(hello) == CH


def test_server_hello_and_ee_decode_to_typed_values() -> None:
    hello = m.ServerHello.decode(body(SH))
    assert hello.cipher_suite == 0x1301
    assert m.decode_key_share(m.find_extension(hello.extensions, 51), S) == m.KeyShareEntry(
        X25519, SERVER_X25519_PUBLIC
    )
    assert m.decode_supported_versions(m.find_extension(hello.extensions, 43), S) == TLS13
    ee = m.EncryptedExtensions.decode(body(EE))
    assert [e.ext_type for e in ee.extensions] == [10, 28, 0]
    assert m.decode_server_name(m.find_extension(ee.extensions, 0), E) is None
    assert m.decode_supported_groups(m.find_extension(ee.extensions, 10)) == GROUPS


def test_certificate_and_certificate_verify_are_semantically_right() -> None:
    """Independent oracle: the RFC's CertificateVerify verifies over RFC 8446 §4.4.3 content."""
    cert = m.Certificate.decode(body(CERT))
    assert cert.certificate_request_context == b""
    assert len(cert.certificate_list) == 1 and cert.certificate_list[0].extensions == ()
    parsed = x509.load_der_x509_certificate(cert.certificate_list[0].cert_data)
    assert parsed.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "rsa"

    cv = m.CertificateVerify.decode(body(CV))
    assert cv.algorithm == 0x0804  # rsa_pss_rsae_sha256
    transcript = hashes.Hash(hashes.SHA256())
    for msg in (CH, SH, EE, CERT):
        transcript.update(msg)
    content = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + transcript.finalize()
    parsed.public_key().verify(  # type: ignore[union-attr]
        cv.signature, content, padding.PSS(padding.MGF1(hashes.SHA256()), 32), hashes.SHA256()
    )


def test_server_flight_is_split_into_exact_messages() -> None:
    payload = h(event("server", "send handshake record", 1)["payload"])
    whole = m.HandshakeReader().feed(payload)
    assert [x.msg_type for x in whole] == [8, 11, 15, 20]
    assert [x.raw for x in whole] == [EE, CERT, CV, SFIN]
    reader = m.HandshakeReader()
    byte_by_byte = [msg for i in range(len(payload)) for msg in reader.feed(payload[i : i + 1])]
    assert byte_by_byte == whole
    assert not reader.pending()


def test_partial_messages_are_pending_and_may_not_span_a_key_change() -> None:
    reader = m.HandshakeReader()
    assert reader.feed(EE[:3]) == [] and reader.pending()  # partial header
    assert reader.feed(EE[3:10]) == [] and reader.pending()  # partial body
    with pytest.raises(AlertError) as exc:
        reader.check_key_change()
    assert exc.value.alert is Alert.unexpected_message
    m.HandshakeReader().check_key_change()  # nothing pending: fine


@pytest.mark.parametrize("msg_type", [0, 3, 6, 255])
def test_unknown_handshake_type_is_unexpected(msg_type: int) -> None:
    with pytest.raises(AlertError) as exc:
        m.HandshakeReader().feed(bytes([msg_type, 0, 0, 0]))
    assert exc.value.alert is Alert.unexpected_message


@pytest.mark.parametrize(
    "raw",
    [NST, bytes([13, 0, 0, 0]), bytes([5, 0, 0, 0]), bytes([24, 0, 0, 1, 0]), bytes([30, 0, 0, 0])],
    ids=["NewSessionTicket", "CertificateRequest", "EndOfEarlyData", "KeyUpdate", "KEMEncapsulation"],
)
def test_unsupported_messages_are_unexpected(raw: bytes) -> None:
    [msg] = m.HandshakeReader().feed(raw)
    with pytest.raises(AlertError) as exc:
        m.decode_message(msg)
    assert exc.value.alert is Alert.unexpected_message


def test_hello_retry_request_is_recognised() -> None:
    """RFC 8446 §4.1.3: the HRR random is SHA-256("HelloRetryRequest"), computed independently here."""
    import hashlib

    hrr_random = hashlib.sha256(b"HelloRetryRequest").digest()
    hrr = m.ServerHello(hrr_random, b"", 0x1301, (ext(43, m.encode_supported_versions(TLS13, S)),))
    assert hrr.is_hrr
    assert not m.ServerHello.decode(body(SH)).is_hrr
    # qTLS never accepts one (D16), and says so before parsing HRR-specific bodies.
    with pytest.raises(AlertError) as exc:
        m.ServerHello.decode(hrr.encode())
    assert exc.value.alert is Alert.unexpected_message
    hrr_key_share = m.Extension(51, b"\x11\xec")  # an HRR key_share is just the selected group
    raw = m.encode_handshake(m.ServerHello(hrr_random, b"", 0x1301, (hrr_key_share,)))
    [msg] = m.HandshakeReader().feed(raw)
    with pytest.raises(AlertError) as exc:
        m.decode_message(msg)
    assert exc.value.alert is Alert.unexpected_message


def test_alert_body() -> None:
    payload = h(event("client", "send alert record")["payload"])
    assert m.decode_alert(payload) == (1, Alert.close_notify)
    for bad in (b"", b"\x01", b"\x01\x00\x00"):
        with pytest.raises(AlertError) as exc:
            m.decode_alert(bad)
        assert exc.value.alert is Alert.decode_error


# --------------------------------------------------------------------------- #
# Strict decoding
# --------------------------------------------------------------------------- #

DECODERS = {
    "ClientHello": (m.ClientHello.decode, CH),
    "ServerHello": (m.ServerHello.decode, SH),
    "EncryptedExtensions": (m.EncryptedExtensions.decode, EE),
    "Certificate": (m.Certificate.decode, CERT),
    "CertificateVerify": (m.CertificateVerify.decode, CV),
    "Finished": (m.Finished.decode, SFIN),
}


@pytest.mark.parametrize("name", DECODERS)
def test_every_truncation_is_a_decode_error(name: str) -> None:
    decode, raw = DECODERS[name]
    b = body(raw)
    for cut in range(len(b)):
        with pytest.raises(AlertError) as exc:
            decode(b[:cut])
        assert exc.value.alert is Alert.decode_error, (name, cut)


@pytest.mark.parametrize("name", DECODERS)
def test_trailing_bytes_are_a_decode_error(name: str) -> None:
    decode, raw = DECODERS[name]
    with pytest.raises(AlertError) as exc:
        decode(body(raw) + b"\x00")
    assert exc.value.alert is Alert.decode_error


def test_trailing_bytes_inside_extension_bodies() -> None:
    hello = m.ClientHello.decode(body(CH))
    get = lambda t: m.find_extension(hello.extensions, t)  # noqa: E731
    cases = [
        lambda: m.decode_server_name(get(0) + b"\x00", C),
        lambda: m.decode_supported_groups(get(10) + b"\x00"),
        lambda: m.decode_key_share(get(51) + b"\x00", C),
        lambda: m.decode_supported_versions(get(43) + b"\x00", C),
        lambda: m.decode_signature_algorithms(get(13) + b"\x00"),
        lambda: m.decode_supported_versions(b"\x03\x04\x00", S),
        lambda: m.decode_server_name(b"\x00", E),  # an acknowledgement must be empty
    ]
    for case in cases:
        with pytest.raises(AlertError) as exc:
            case()
        assert exc.value.alert is Alert.decode_error


def _ch(**overrides: object) -> bytes:
    hello = m.ClientHello.decode(body(CH))
    random = overrides.get("random", hello.random)
    session = overrides.get("session_id", b"")
    suites = overrides.get("suites", m._encode_u16_list(hello.cipher_suites))
    compression = overrides.get("compression", b"\x00")
    exts = overrides.get("exts", m.encode_extensions(hello.extensions))
    return (
        b"\x03\x03" + random + bytes([len(session)]) + session  # type: ignore[operator]
        + len(suites).to_bytes(2, "big") + suites  # type: ignore[arg-type]
        + bytes([len(compression)]) + compression  # type: ignore[arg-type]
        + len(exts).to_bytes(2, "big") + exts  # type: ignore[arg-type]
    )  # fmt: skip


@pytest.mark.parametrize(
    ("overrides", "alert"),
    [
        ({"suites": b""}, Alert.decode_error),
        ({"suites": b"\x13\x01\x13"}, Alert.decode_error),  # odd length
        ({"session_id": bytes(33)}, Alert.decode_error),
        ({"compression": b""}, Alert.decode_error),
        ({"compression": b"\x01"}, Alert.illegal_parameter),
        ({"compression": b"\x00\x00"}, Alert.illegal_parameter),
        ({"exts": b"\x00\x2b\x00\x02\x03\x04"}, Alert.decode_error),  # well-formed, below RFC 9846's 7
        ({"exts": m.encode_extensions((ext(43, b"\x02\x03\x04"), ext(51, b"\x00\x00")))
          + b"\x00\x2b\x00\x00"}, Alert.illegal_parameter),  # duplicate supported_versions
    ],
    ids=["no-suites", "odd-suites", "session-33", "no-compression", "compression-1",
         "compression-two", "short-extensions", "duplicate-extension"],
)  # fmt: skip
def test_client_hello_rejections(overrides: dict, alert: Alert) -> None:
    with pytest.raises(AlertError) as exc:
        m.ClientHello.decode(_ch(**overrides))
    assert exc.value.alert is alert


def test_client_hello_bounds_that_are_allowed() -> None:
    m.ClientHello.decode(_ch(session_id=bytes(32)))
    # RFC 9846 corrected the minimum to 7: a lone supported_versions extension.
    seven = b"\x00\x2b\x00\x03\x02\x03\x04"
    hello = m.ClientHello.decode(_ch(exts=seven))
    assert hello.extensions == (ext(43, b"\x02\x03\x04"),)
    assert m.ClientHello(hello.random, b"", SUITES, hello.extensions).encode()[-9:] == b"\x00\x07" + seven


def test_server_hello_rejections() -> None:
    b = bytearray(body(SH))
    b[2 + 32 + 1 + 2] = 1  # compression method
    with pytest.raises(AlertError) as exc:
        m.ServerHello.decode(bytes(b))
    assert exc.value.alert is Alert.illegal_parameter
    block = m.encode_extensions((ext(43, b"\x03\x04"),)) * 2
    dup = b"\x03\x03" + SH[6:38] + b"\x00" + b"\x13\x01" + b"\x00" + len(block).to_bytes(2, "big") + block
    with pytest.raises(AlertError) as exc:
        m.ServerHello.decode(dup)
    assert exc.value.alert is Alert.illegal_parameter


def test_duplicate_extension_in_encrypted_extensions() -> None:
    block = b"\x00\x1c\x00\x02\x40\x01" * 2
    with pytest.raises(AlertError) as exc:
        m.EncryptedExtensions.decode(len(block).to_bytes(2, "big") + block)
    assert exc.value.alert is Alert.illegal_parameter


@pytest.mark.parametrize(
    ("decode", "data"),
    [
        (m.decode_supported_groups, b"\x00\x00"),  # empty list (minimum 2)
        (m.decode_supported_groups, b"\x00\x03\x00\x1d\x00"),  # odd length
        (m.decode_signature_algorithms, b"\x00\x00"),
        (m.decode_signature_algorithms, b"\x00\x03\x04\x03\x05"),
        (lambda d: m.decode_key_share(d, C), b"\x00\x04\x00\x1d\x00\x00"),  # empty key_exchange
        (lambda d: m.decode_key_share(d, S), b"\x00\x1d\x00\x00"),
    ],
    ids=["groups-empty", "groups-odd", "sigalgs-empty", "sigalgs-odd", "ch-share-empty", "sh-share-empty"],
)
def test_extension_body_bounds(decode, data: bytes) -> None:  # noqa: ANN001
    with pytest.raises(AlertError) as exc:
        decode(data)
    assert exc.value.alert is Alert.decode_error


def test_supported_versions_bounds() -> None:
    for bad in (b"\x01\x03", b"\xff" + bytes(255)):
        with pytest.raises(AlertError) as exc:
            m.decode_supported_versions(bad, C)
        assert exc.value.alert is Alert.decode_error
    assert m.decode_supported_versions(b"\x02\x03\x04", C) == (TLS13,)


@pytest.mark.parametrize("n", [31, 33])
def test_finished_length(n: int) -> None:
    with pytest.raises(AlertError) as exc:
        m.Finished.decode(bytes(n))
    assert exc.value.alert is Alert.decode_error


def test_server_name_rejections() -> None:
    other_type = (5).to_bytes(2, "big") + b"\x01\x00\x02ab"
    with pytest.raises(AlertError) as exc:
        m.decode_server_name(other_type, C)
    assert exc.value.alert is Alert.illegal_parameter
    two_names = m.encode_server_name("a", C)[2:] * 2
    with pytest.raises(AlertError) as exc:
        m.decode_server_name(len(two_names).to_bytes(2, "big") + two_names, C)
    assert exc.value.alert is Alert.decode_error


# --------------------------------------------------------------------------- #
# Encoding refuses out-of-range values (local bugs, not alerts)
# --------------------------------------------------------------------------- #


def test_encoding_out_of_range_is_a_usage_error() -> None:
    hello = m.ClientHello.decode(body(CH))
    bad = [
        lambda: m.ClientHello(bytes(31), b"", SUITES, hello.extensions).encode(),
        lambda: m.ClientHello(hello.random, bytes(33), SUITES, hello.extensions).encode(),
        lambda: m.ClientHello(hello.random, b"", (), hello.extensions).encode(),
        lambda: m.ClientHello(hello.random, b"", SUITES, ()).encode(),
        lambda: m.Finished(bytes(31)).encode(),
        lambda: m.encode_extensions((ext(1, b""), ext(1, b""))),
        lambda: m.encode_server_name(None, C),
        lambda: m.encode_server_name("x", E),
        lambda: m.encode_supported_versions([], C),
        lambda: m.uint(1 << 16, 2),
    ]
    for call in bad:
        with pytest.raises(CodecUsageError):
            call()
    assert not issubclass(CodecUsageError, (ValueError, AlertError))


# --------------------------------------------------------------------------- #
# Added after the Phase 2b review
# --------------------------------------------------------------------------- #


def test_decode_message_dispatches_every_supported_type() -> None:
    expected = [
        (CH, m.ClientHello), (SH, m.ServerHello), (EE, m.EncryptedExtensions),
        (CERT, m.Certificate), (CV, m.CertificateVerify), (SFIN, m.Finished),
    ]  # fmt: skip
    for raw, cls in expected:
        [msg] = m.HandshakeReader().feed(raw)
        decoded = m.decode_message(msg)
        assert type(decoded) is cls
        assert decoded == cls.decode(body(raw))
        assert m.encode_handshake(decoded) == raw


def test_certificate_entry_extensions() -> None:
    sct = ext(18, b"\x00\x02ab")  # signed_certificate_timestamp, opaque to qTLS
    cert = m.Certificate(b"", (m.CertificateEntry(b"\x30\x00", (sct,)),))
    expected = b"\x00" + b"\x00\x00\x0f" + b"\x00\x00\x02\x30\x00" + b"\x00\x08" + b"\x00\x12\x00\x04\x00\x02ab"
    assert cert.encode() == expected
    assert m.Certificate.decode(expected) == cert


def test_duplicate_extension_in_a_certificate_entry() -> None:
    entry_exts = b"\x00\x12\x00\x00" * 2
    entry = b"\x00\x00\x02\x30\x00" + len(entry_exts).to_bytes(2, "big") + entry_exts
    raw = b"\x00" + len(entry).to_bytes(3, "big") + entry
    with pytest.raises(AlertError) as exc:
        m.Certificate.decode(raw)
    assert exc.value.alert is Alert.illegal_parameter


def test_empty_cert_data_is_a_decode_error() -> None:
    entry = b"\x00\x00\x00" + b"\x00\x00"
    with pytest.raises(AlertError) as exc:
        m.Certificate.decode(b"\x00" + len(entry).to_bytes(3, "big") + entry)
    assert exc.value.alert is Alert.decode_error


def test_server_hello_extension_minimum() -> None:
    def sh(exts: bytes) -> bytes:
        return b"\x03\x03" + SH[6:38] + b"\x00\x13\x01\x00" + len(exts).to_bytes(2, "big") + exts

    m.ServerHello.decode(sh(b"\x00\x2b\x00\x02\x03\x04"))  # exactly 6
    with pytest.raises(AlertError) as exc:
        m.ServerHello.decode(sh(b"\x00\x2b\x00\x01\x03"))  # well-formed, 5
    assert exc.value.alert is Alert.decode_error


def test_record_end_is_required_before_a_key_change() -> None:
    reader = m.HandshakeReader()
    msgs = reader.feed(SH + EE)  # EE smuggled into ServerHello's plaintext record
    with pytest.raises(AlertError) as exc:
        reader.require_record_end(msgs, 0)
    assert exc.value.alert is Alert.unexpected_message
    reader = m.HandshakeReader()
    msgs = reader.feed(SH)
    reader.require_record_end(msgs, 0)
    reader = m.HandshakeReader()
    msgs = reader.feed(SH + EE[:5])
    with pytest.raises(AlertError):
        reader.require_record_end(msgs, 0)  # complete SH, but a partial message follows


def test_reader_rejects_oversized_and_unknown_headers_immediately() -> None:
    with pytest.raises(AlertError) as exc:
        m.HandshakeReader().feed(bytes([11]) + (m.DEFAULT_MAX_MESSAGE + 1).to_bytes(3, "big"))
    assert exc.value.alert is Alert.illegal_parameter
    reader = m.HandshakeReader(max_message=100)
    assert reader.feed(bytes([11, 0, 0, 100])) == [] and reader.pending()
    with pytest.raises(AlertError) as exc:
        m.HandshakeReader().feed(bytes([99, 0xFF, 0xFF, 0xFF]))
    assert exc.value.alert is Alert.unexpected_message


def test_reader_reassembly_is_linear() -> None:
    """The largest possible message, fed as 16 KiB records, must not cost quadratic copying.

    Measured locally: about 0.02 s linear against 2.5 s with per-record buffer
    copies, so the bound below leaves a wide margin on slower CI machines.
    """
    import time

    size = (1 << 24) - 1
    raw = bytes([11]) + size.to_bytes(3, "big") + bytes(size)
    reader = m.HandshakeReader(max_message=size)
    start = time.perf_counter()
    msgs = [x for i in range(0, len(raw), 1 << 14) for x in reader.feed(raw[i : i + (1 << 14)])]
    elapsed = time.perf_counter() - start
    assert len(msgs) == 1 and len(msgs[0].body) == size
    assert elapsed < 0.5, elapsed


def test_server_name_sender_rules() -> None:
    for bad in ("qtls.test.", "192.0.2.1", "::1", "a\x00b", "é.test", "a b"):
        with pytest.raises(CodecUsageError):
            m.encode_server_name(bad, C)
    assert m.decode_server_name(m.encode_server_name("qtls.test", C), C) == "qtls.test"


def test_server_name_receiver_rules() -> None:
    non_ascii = b"\x00\x05\x00\x00\x02\xc3\xa9"
    with pytest.raises(AlertError) as exc:
        m.decode_server_name(non_ascii, C)
    assert exc.value.alert is Alert.illegal_parameter
    empty_host = b"\x00\x03\x00\x00\x00"
    with pytest.raises(AlertError) as exc:
        m.decode_server_name(empty_host, C)
    assert exc.value.alert is Alert.decode_error


@pytest.mark.parametrize("extra", [1, 2, 3])
def test_trailing_bytes_inside_client_shares(extra: int) -> None:
    entry = m.KeyShareEntry(X25519, CLIENT_X25519_PUBLIC).encode() + bytes(extra)
    with pytest.raises(AlertError) as exc:
        m.decode_key_share(len(entry).to_bytes(2, "big") + entry, C)
    assert exc.value.alert is Alert.decode_error


def test_empty_certificate_verify_signature_decodes() -> None:
    assert m.CertificateVerify.decode(b"\x08\x04\x00\x00") == m.CertificateVerify(0x0804, b"")


def test_codecs_refuse_contexts_they_dont_define() -> None:
    entry = m.KeyShareEntry(X25519, b"k")
    calls = [
        lambda: m.encode_supported_versions(TLS13, C),
        lambda: m.encode_supported_versions([TLS13], S),
        lambda: m.encode_supported_versions(TLS13, E),
        lambda: m.encode_key_share(entry, C),
        lambda: m.encode_key_share([entry], S),
        lambda: m.encode_key_share(entry, E),
        lambda: m.encode_server_name(None, S),
        lambda: m.decode_supported_versions(b"\x03\x04", E),
        lambda: m.decode_key_share(b"\x00\x1d\x00\x01k", m.Context.certificate_entry),
        lambda: m.decode_server_name(b"", S),
    ]
    for call in calls:
        with pytest.raises(CodecUsageError):
            call()


def test_alert_encoding_levels() -> None:
    assert m.encode_alert(Alert.close_notify) == b"\x01\x00"
    assert m.encode_alert(Alert.user_canceled) == b"\x01\x5a"
    assert m.encode_alert(Alert.decode_error) == b"\x02\x32"
    rfc_close = h(event("client", "send alert record")["payload"])
    assert m.encode_alert(Alert.close_notify) == rfc_close


def test_peer_input_only_ever_raises_alert_errors() -> None:
    """Fuzz every decoder with mutations of the RFC 8448 messages (seeded, deterministic)."""
    import random

    rng = random.Random(8448)
    seeds = [CH, SH, EE, CERT, CV, SFIN, NST]
    decoders = [
        lambda b: [m.decode_message(x) for x in m.HandshakeReader().feed(b)],
        lambda b: m.ClientHello.decode(b[4:]),
        lambda b: m.ServerHello.decode(b[4:]),
        lambda b: m.EncryptedExtensions.decode(b[4:]),
        lambda b: m.Certificate.decode(b[4:]),
        lambda b: m.decode_key_share(b[4:], C),
        lambda b: m.decode_server_name(b[4:], C),
        lambda b: m.decode_supported_groups(b[4:]),
        lambda b: m.decode_supported_versions(b[4:], C),
        lambda b: m.decode_alert(b[:2]),
    ]
    for _ in range(3000):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 4)):
            op = rng.randrange(3)
            i = rng.randrange(len(data)) if data else 0
            if op == 0 and data:
                data[i] ^= 1 << rng.randrange(8)
            elif op == 1:
                del data[i : i + rng.randint(1, 8)]
            else:
                data[i:i] = rng.randbytes(rng.randint(1, 8))
        for decode in decoders:
            try:
                decode(bytes(data))
            except AlertError:
                pass


def test_require_record_end_rejects_a_bad_index_as_local_misuse() -> None:
    reader = m.HandshakeReader()
    msgs = reader.feed(SFIN)
    for bad in (-1, 1, 5):
        with pytest.raises(CodecUsageError):
            reader.require_record_end(msgs, bad)


def test_default_message_limit_is_d23s_128_kib() -> None:
    assert m.DEFAULT_MAX_MESSAGE == 128 * 1024
    size = m.DEFAULT_MAX_MESSAGE
    raw = bytes([11]) + size.to_bytes(3, "big") + bytes(size)
    [msg] = m.HandshakeReader().feed(raw)  # exactly the limit is accepted
    assert len(msg.body) == size


def test_server_hello_field_bounds() -> None:
    entry = m.KeyShareEntry(X25519, SERVER_X25519_PUBLIC).encode()
    with pytest.raises(AlertError) as exc:
        m.decode_key_share(entry + b"\x00", S)
    assert exc.value.alert is Alert.decode_error
    exts = b"\x00\x2b\x00\x02\x03\x04"
    long_echo = b"\x03\x03" + SH[6:38] + b"\x21" + bytes(33) + b"\x13\x01\x00" + len(exts).to_bytes(2, "big") + exts
    with pytest.raises(AlertError) as exc:
        m.ServerHello.decode(long_echo)
    assert exc.value.alert is Alert.decode_error


def test_encoder_lower_bounds() -> None:
    with pytest.raises(CodecUsageError):
        m.ServerHello(SH[6:38], b"", 0x1301, ()).encode()  # extensions below 6
    with pytest.raises(CodecUsageError):
        m.Certificate(b"", (m.CertificateEntry(b"", ()),)).encode()  # empty cert_data
    assert m.CertificateVerify(0x0804, b"").encode() == b"\x08\x04\x00\x00"
    with pytest.raises(CodecUsageError):
        m.encode_server_name("a\x7fb", C)


def test_peer_alert_fields() -> None:
    from qtls.alerts import PeerAlert

    alert = PeerAlert(2, 50)
    assert (alert.level, alert.description) == (2, 50)
    assert "decode_error" in str(alert)


def test_typed_extension_decoders_only_raise_alert_errors() -> None:
    """Fuzz each typed codec on its own RFC 8448 extension body, plus seeded duplicates and HRR."""
    import random

    rng = random.Random(9846)
    hello = m.ClientHello.decode(body(CH))
    server = m.ServerHello.decode(body(SH))
    cases = [
        (m.find_extension(hello.extensions, 0), lambda d: m.decode_server_name(d, C)),
        (m.find_extension(hello.extensions, 10), m.decode_supported_groups),
        (m.find_extension(hello.extensions, 13), m.decode_signature_algorithms),
        (m.find_extension(hello.extensions, 43), lambda d: m.decode_supported_versions(d, C)),
        (m.find_extension(hello.extensions, 51), lambda d: m.decode_key_share(d, C)),
        (m.find_extension(server.extensions, 43), lambda d: m.decode_supported_versions(d, S)),
        (m.find_extension(server.extensions, 51), lambda d: m.decode_key_share(d, S)),
    ]
    for _ in range(4000):
        seed, decode = rng.choice(cases)
        data = bytearray(seed)
        for _ in range(rng.randint(1, 3)):
            i = rng.randrange(len(data) + 1)
            op = rng.randrange(3)
            if op == 0 and data:
                data[min(i, len(data) - 1)] ^= 1 << rng.randrange(8)
            elif op == 1:
                del data[i : i + rng.randint(1, 4)]
            else:
                data[i:i] = rng.choice([b"\x80", b"\xff", b"\x00", rng.randbytes(2)])
        try:
            decode(bytes(data))
        except AlertError:
            pass
    # Seeded structures random mutation rarely reaches.
    hrr = m.ServerHello(m.HRR_RANDOM, b"", 0x1301, (ext(43, b"\x03\x04"),)).encode()
    dup = m.encode_extensions((ext(43, b"\x03\x04"),)) * 2
    for raw, decode in (
        (hrr, m.ServerHello.decode),
        (len(dup).to_bytes(2, "big") + dup, m.EncryptedExtensions.decode),
        (b"\x00\x00\x00\x05\x00\x00\x00\x00\x00", m.Certificate.decode),
        (b"\x00\x05\x00\x00\x02\xc3\xa9", lambda d: m.decode_server_name(d, C)),
    ):
        with pytest.raises(AlertError):
            decode(raw)
