"""The strict DER codec (specs.md D20). Hand-written bytes are the oracle."""

from __future__ import annotations

import datetime as dt
import random

import pytest

from qtls import der
from qtls.alerts import AlertError, CodecUsageError
from rfc8448_trace import CERT

UTC = dt.timezone.utc


def rfc_certificate() -> bytes:
    n = int.from_bytes(CERT[8:11], "big")
    return CERT[11 : 11 + n]


# --------------------------------------------------------------------------- #
# INTEGER
# --------------------------------------------------------------------------- #

INTEGERS = {
    0: "020100", 1: "020101", 127: "02017f", 128: "02020080", 255: "020200ff", 256: "02020100",
    -1: "0201ff", -128: "020180", -129: "0202ff7f",
    2**159: "02150080" + "00" * 19, 2**160: "021501" + "00" * 20,
}  # fmt: skip


@pytest.mark.parametrize("value", INTEGERS, ids=str)
def test_integer_both_ways(value: int) -> None:
    assert der.integer(value).hex() == INTEGERS[value]
    assert der.parse(bytes.fromhex(INTEGERS[value])).as_int() == value


@pytest.mark.parametrize("raw", ["0200", "02020000", "0202007f", "0202ff80", "0202ffff"])
def test_non_minimal_integers_are_rejected(raw: str) -> None:
    with pytest.raises(der.DerError):
        der.parse(bytes.fromhex(raw)).as_int()


# --------------------------------------------------------------------------- #
# Lengths
# --------------------------------------------------------------------------- #

LENGTHS = {0: "00", 127: "7f", 128: "8180", 255: "81ff", 256: "820100", 65535: "82ffff", 65536: "83010000"}


@pytest.mark.parametrize("n", LENGTHS, ids=str)
def test_length_both_ways(n: int) -> None:
    encoded = der.octet_string(bytes(n))
    assert encoded[1 : 1 + len(LENGTHS[n]) // 2].hex() == LENGTHS[n]
    assert der.parse(encoded).as_octets() == bytes(n)


@pytest.mark.parametrize(
    "raw",
    ["04817f" + "00" * 127, "04820080" + "00" * 128, "048000", "0485000000000100", "04030000", "04"],
    ids=["long-where-short-fits", "leading-zero", "indefinite", "five-length-bytes", "overrun", "no-length"],
)
def test_bad_lengths_are_rejected(raw: str) -> None:
    with pytest.raises(der.DerError):
        der.parse(bytes.fromhex(raw))


def test_indefinite_length_alone_is_rejected() -> None:
    with pytest.raises(der.DerError, match="indefinite"):
        der.parse(bytes.fromhex("3080"))


def test_huge_declared_length_is_rejected_quickly() -> None:
    with pytest.raises(der.DerError):
        der.parse(bytes.fromhex("3084ffffffff") + bytes(10))


# --------------------------------------------------------------------------- #
# OBJECT IDENTIFIER
# --------------------------------------------------------------------------- #

OIDS = {
    "1.2.840.10045.4.3.2": "06082a8648ce3d040302",
    "1.2.840.10045.2.1": "06072a8648ce3d0201",
    "1.2.840.10045.3.1.7": "06082a8648ce3d030107",
    "2.16.840.1.101.3.4.3.17": "060960864801650304031" + "1",
    "2.16.840.1.101.3.4.3.18": "06096086480165030403" + "12",
    "2.16.840.1.101.3.4.4.1": "06096086480165030404" + "01",
    "2.16.840.1.101.3.4.4.2": "06096086480165030404" + "02",
    "1.3.6.1.4.1.32473.1.1": "060a2b0601040181fd590101",
    "2.5.29.19": "0603551d13",
    "2.999": "06028837",
}


@pytest.mark.parametrize("dotted", OIDS)
def test_oid_both_ways(dotted: str) -> None:
    assert der.oid(dotted).hex() == OIDS[dotted]
    assert der.parse(bytes.fromhex(OIDS[dotted])).as_oid() == dotted


def test_large_oid_arcs_round_trip() -> None:
    for dotted in ("1.2.4294967296", "2.4294967295.1", "1.3.18446744073709551616"):
        assert der.parse(der.oid(dotted)).as_oid() == dotted


@pytest.mark.parametrize("raw", ["0600", "0602802a", "06022a86", "060180"], ids=["empty", "0x80-lead", "truncated", "lone-0x80"])
def test_bad_oids_are_rejected(raw: str) -> None:
    with pytest.raises(der.DerError):
        der.parse(bytes.fromhex(raw)).as_oid()


def test_invalid_oids_cannot_be_encoded() -> None:
    for bad in ("1", "3.1", "1.40", "0.40"):
        with pytest.raises(CodecUsageError):
            der.oid(bad)


# --------------------------------------------------------------------------- #
# BIT STRING, BOOLEAN, NULL, strings
# --------------------------------------------------------------------------- #


def test_bit_strings() -> None:
    assert der.parse(bytes.fromhex("030300abcd")).as_bit_string() == b"\xab\xcd"
    for raw in ("0300", "030108", "030201ff", "030101", "030207ff"):
        with pytest.raises(der.DerError):
            der.parse(bytes.fromhex(raw)).as_bit_string()


@pytest.mark.parametrize(
    ("bits", "raw"),
    [({0}, "03020780"), ({5, 6}, "03020106"), ({2}, "03020520"), ({0, 2}, "030205a0"), ({0, 8}, "0303078080"), (set(), "030100")],
)
def test_named_bits(bits: set[int], raw: str) -> None:
    assert der.named_bits(bits).hex() == raw
    assert der.parse(bytes.fromhex(raw)).as_named_bits() == bits


def test_named_bits_must_be_trimmed() -> None:
    for raw in ("03020680", "0303000000", "03020781"):  # trailing zero bits, zero byte, nonzero padding
        with pytest.raises(der.DerError):
            der.parse(bytes.fromhex(raw)).as_named_bits()


def test_boolean_and_null() -> None:
    assert der.boolean(True).hex() == "0101ff" and der.boolean(False).hex() == "010100"
    assert der.parse(bytes.fromhex("0101ff")).as_bool() is True
    for raw in ("010101", "0101fe", "0100", "01020000"):
        with pytest.raises(der.DerError):
            der.parse(bytes.fromhex(raw)).as_bool()
    der.parse(bytes.fromhex("0500")).as_null()
    with pytest.raises(der.DerError):
        der.parse(bytes.fromhex("050100")).as_null()


def test_strings() -> None:
    assert der.parse(der.utf8_string("qTLS é")).as_str() == "qTLS é"
    assert der.parse(bytes.fromhex("130361627a")).as_str() == "abz"
    for raw in ("0c01ff", "130140", "160180"):  # bad UTF-8, '@' not printable, IA5 > 0x7f
        with pytest.raises(der.DerError):
            der.parse(bytes.fromhex(raw)).as_str()


# --------------------------------------------------------------------------- #
# Times (RFC 5280 §4.1.2.5)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("when", "raw"),
    [
        (dt.datetime(1950, 1, 1, tzinfo=UTC), "170d3530303130313030303030305a"),
        (dt.datetime(2049, 12, 31, 23, 59, 59, tzinfo=UTC), "170d3439313233313233353935395a"),
        (dt.datetime(2050, 1, 1, tzinfo=UTC), "180f32303530303130313030303030305a"),
        (dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC), "180f39393939313233313233353935395a"),
    ],
    ids=["1950", "2049", "2050", "9999"],
)
def test_times_both_ways(when: dt.datetime, raw: str) -> None:
    assert der.time(when).hex() == raw
    assert der.parse(bytes.fromhex(raw)).as_time() == when


@pytest.mark.parametrize(
    "text",
    [
        b"\x17\x0f" + b"260101000000.5Z",  # fraction
        b"\x17\x0b" + b"2601010000Z",  # no seconds
        b"\x17\x11" + b"260101000000+0100",  # offset
        b"\x17\x0d" + b"260230000000Z",  # 30 February
        b"\x17\x0d" + b"260101240000Z",  # hour 24
        b"\x17\x0d" + b"260101000060Z",  # second 60
        b"\x18\x0f" + b"20260101000000Z",  # GeneralizedTime before 2050
    ],
    ids=["fraction", "no-seconds", "offset", "feb-30", "hour-24", "second-60", "gt-before-2050"],
)
def test_bad_times_are_rejected(text: bytes) -> None:
    with pytest.raises(der.DerError):
        der.parse(text).as_time()


def test_naive_or_fractional_times_cannot_be_encoded() -> None:
    with pytest.raises(CodecUsageError):
        der.time(dt.datetime(2026, 1, 1))
    with pytest.raises(CodecUsageError):
        der.time(dt.datetime(2026, 1, 1, microsecond=1, tzinfo=UTC))


# --------------------------------------------------------------------------- #
# Structure
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw",
    ["1f2200", "2200", "2300", "2100", "2600", "2c00", "1000", "1100", "300102", "3003020100" + "00"],
    ids=["high-tag", "constructed-integer", "constructed-bitstring", "constructed-boolean", "constructed-oid",
         "constructed-utf8", "primitive-sequence", "primitive-set", "truncated-child", "trailing-top"],
)  # fmt: skip
def test_structural_rejections(raw: str) -> None:
    with pytest.raises(der.DerError):
        der.parse(bytes.fromhex(raw)).children()


@pytest.mark.parametrize("raw", ["1000", "1100"], ids=["primitive-sequence", "primitive-set"])
def test_primitive_form_of_a_constructed_type_fails_at_parse(raw: str) -> None:
    with pytest.raises(der.DerError):
        der.parse(bytes.fromhex(raw))


def test_utc_time_with_a_non_ascii_digit_is_rejected() -> None:
    text = b"2601010000" + "\u0660".encode() + b"Z"  # ARABIC-INDIC DIGIT ZERO; strptime would accept it
    assert len(text) == 13
    with pytest.raises(der.DerError, match="RFC 5280 form"):
        der.parse(b"\x17\x0d" + text).as_time()


def test_trailing_bytes_inside_children() -> None:
    with pytest.raises(der.DerError):
        der.parse(bytes.fromhex("3004020100" + "05")).children()


def test_set_of_is_sorted() -> None:
    a, b, c = der.integer(1), der.integer(2), der.octet_string(b"\x00")
    assert der.set_of(b, c, a) == der.tlv(der.SET, a + b + c)
    assert [n.raw for n in der.parse(der.set_of(c, b, a)).children()] == [a, b, c]
    with pytest.raises(der.DerError):
        der.parse(der.tlv(der.SET, b + a)).children()


# --------------------------------------------------------------------------- #
# A real certificate
# --------------------------------------------------------------------------- #


def test_rfc8448_certificate_round_trips() -> None:
    cert = rfc_certificate()
    assert der.reencode(der.parse(cert)) == cert


def test_mutated_certificates_only_raise_der_or_alert_errors() -> None:
    """Every truncation, plus 10k random flips: nothing but DerError / bad_certificate escapes."""
    from qtls import x509

    cert = rfc_certificate()
    rng = random.Random(5280)
    inputs = [cert[:n] for n in range(len(cert))]
    for _ in range(10_000):
        data = bytearray(cert)
        for _ in range(rng.randint(1, 3)):
            i = rng.randrange(len(data))
            data[i] = rng.randrange(256) if rng.random() < 0.5 else data[i] ^ (1 << rng.randrange(8))
        inputs.append(bytes(data))
    for data in inputs:
        try:
            x509.parse(data)
        except AlertError as exc:
            assert exc.reason is not None
        try:
            der.reencode(der.parse(data))
        except der.DerError:
            pass


def test_deep_nesting_does_not_crash() -> None:
    data = b""
    for _ in range(10_000):
        data = der.seq(data)
    node = der.parse(data)
    for _ in range(100):
        (node,) = node.children()


# --------------------------------------------------------------------------- #
# Added after the Phase 2c review
# --------------------------------------------------------------------------- #


def test_single_defect_negatives() -> None:
    with pytest.raises(der.DerError, match="high tag"):
        der.parse(bytes.fromhex("1f0100"))
    with pytest.raises(der.DerError, match="oversized"):
        der.parse(bytes.fromhex("04850100000000"))
    with pytest.raises(der.DerError):
        der.parse(bytes.fromhex("03020780")).as_bit_string()  # unused bits, zero padding


def test_huge_oid_arcs_are_cheap_and_rejected() -> None:
    import time

    hostile = der.tlv(der.OID, b"\x2a" + b"\x81" * 120_000 + b"\x01")
    start = time.perf_counter()
    with pytest.raises(der.DerError, match="too long"):
        der.parse(hostile).as_oid()
    assert time.perf_counter() - start < 0.05
    assert der.parse(der.oid("1.2.18446744073709551615")).as_oid() == "1.2.18446744073709551615"  # 2^64-1 fits


def test_pre_1950_and_non_utc_times() -> None:
    t = dt.datetime(1949, 12, 31, 23, 59, 59, tzinfo=UTC)
    assert der.time(t).hex() == "180f31393439313233313233353935395a"
    assert der.parse(der.time(t)).as_time() == t
    plus_one = dt.datetime(2026, 1, 1, 1, 0, 0, tzinfo=dt.timezone(dt.timedelta(hours=1)))
    assert der.time(plus_one) == der.time(dt.datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC))


def test_encoder_misuse() -> None:
    with pytest.raises(CodecUsageError):
        der.oid("1.2.-1")
    with pytest.raises(CodecUsageError):
        der.explicit(31, b"")
    assert der.parse(bytes.fromhex("16017f")).as_str() == "\x7f"  # DEL is valid IA5


def test_x509_certificates_fuzz_only_raise_alert_errors() -> None:
    """Truncations and flips of qTLS's own certificate (EC SPKI, extensions), not just RFC 8448's."""
    from qtls import chains, x509

    chain = chains.build_chain(leaf_alg="ECDSA-P256-SHA256", issuer_alg="ECDSA-P256-SHA256", scts=2,
                               not_before=dt.datetime(2026, 11, 12, tzinfo=UTC))  # fmt: skip
    cert = chain.cert_data[0]
    rng = random.Random(6962)
    inputs = [cert[:n] for n in range(0, len(cert), 3)]
    for _ in range(3000):
        data = bytearray(cert)
        data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        inputs.append(bytes(data))
    for data in inputs:
        try:
            x509.parse(data)
        except AlertError as exc:
            assert exc.reason is not None
