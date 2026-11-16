"""Trust anchor IDs and patterns (draft-ietf-tls-trust-anchor-ids-07; specs.md D32).

Oracles: the draft's Appendix B and B.1 vectors (vendored, tests/vectors/
trust-anchor-ids/SOURCE), the worked examples of §4 and §5.3.1, and the MTC -08
§5.1 / §8.2 / §8.2.1 examples for the IDs MTC derives from a CA ID.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qtls import der
from qtls.alerts import CodecUsageError
from qtls.trust_anchor_ids import Pattern, TrustAnchorID, pattern_contains

APPENDIX_B = json.loads((Path(__file__).parent / "vectors" / "trust-anchor-ids" / "appendix_b.json").read_text())

CASES = [(g["pattern"], i, g["contained"]) for g in APPENDIX_B["groups"] for i in g["ids"]]


def tai(text: str) -> TrustAnchorID:
    return TrustAnchorID.from_ascii(text)


# --------------------------------------------------------------------------- #
# Representations (§4, §4.1)
# --------------------------------------------------------------------------- #


def test_section_4_example_representations() -> None:
    t = tai("32473.1")
    assert t.raw == bytes([0x81, 0xFD, 0x59, 0x01])  # binary representation
    assert t.der == bytes([0x0D, 0x04, 0x81, 0xFD, 0x59, 0x01])  # ASN.1 (DER) representation
    assert t.ascii == str(t) == "32473.1"
    assert t.full_oid == "1.3.6.1.4.1.32473.1"
    assert der.parse(t.der).as_relative_oid() == t.raw
    assert TrustAnchorID(t.raw) == t


def test_full_oid_agrees_with_the_oid_codec() -> None:
    """The full OID's DER contents end with the binary representation (the prefix is fixed)."""
    for text in ("32473.1", "32473.100.1.8.42", "0", "4294967295.18446744073709551616"):
        t = tai(text)
        assert der.oid(t.full_oid)[2:] == der.oid("1.3.6.1.4.1")[2:] + t.raw


@pytest.mark.parametrize("text", ["0", "127", "128", "32473.1", "32473.100.2.8.42", "18446744073709551616.3"])
def test_ascii_round_trips(text: str) -> None:
    t = tai(text)
    assert t.ascii == text
    assert TrustAnchorID(t.raw).components == tuple(int(p) for p in text.split("."))


@pytest.mark.parametrize("text", ["", ".", "1.", ".1", "1..2", "01", "1.02", "-1", "+1", " 1", "1 ", "1.a", "١", "1e3"])
def test_ascii_must_be_canonical_dotted_decimal(text: str) -> None:
    with pytest.raises(CodecUsageError):
        tai(text)


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        ("", "empty"),
        ("80", "non-minimal first component"),
        ("8001", "non-minimal first component"),
        ("0180", "truncated last component"),
        ("01808001", "non-minimal second component"),
        ("81", "truncated"),
        ("81ff", "truncated"),
        ("01" * 33, "33 bytes"),
    ],
    ids=lambda v: v if len(v) < 20 else "33-bytes",
)
def test_invalid_binary_representations_are_refused_as_configuration(raw: str, why: str) -> None:
    with pytest.raises(CodecUsageError):
        TrustAnchorID(bytes.fromhex(raw))


def test_length_bound_is_32_bytes() -> None:
    assert len(TrustAnchorID(b"\x01" * 32).raw) == 32
    with pytest.raises(CodecUsageError):
        TrustAnchorID(b"\x01" * 33)
    with pytest.raises(CodecUsageError):
        TrustAnchorID.from_components([1] * 33)


def test_ca_id_length_budget_for_mtc_arcs() -> None:
    """MTC -08 §5.1/§5.2/§6.4.3: log numbers <= 65535 and landmarks <= 2^48 − 1 add up to 11 bytes,
    so a CA ID of 21 bytes is the longest whose every landmark ID fits in 32 (and 28 for log IDs)."""
    ca21 = TrustAnchorID(b"\x01" * 21)
    assert len(ca21.child(1, 65535, 2**48 - 1).raw) == 32
    with pytest.raises(CodecUsageError):
        TrustAnchorID(b"\x01" * 22).child(1, 65535, 2**48 - 1)
    assert len(TrustAnchorID(b"\x01" * 28).child(0, 65535).raw) == 32
    with pytest.raises(CodecUsageError):
        TrustAnchorID(b"\x01" * 29).child(0, 65535)


@pytest.mark.parametrize(
    "peer",
    ["", "80", "8001", "0180", "81", "01" * 33, "01" * 255, "81fd5901ff", "81fd590100"],
    ids=lambda v: v[:12] or "empty",
)
def test_peer_ids_are_only_compared_never_rejected(peer: str) -> None:
    """MTC -08 §7.2 step 12 / §6.2 GREASE, TAI §8 and App. B.1: an unknown or malformed peer ID
    matches nothing; it never raises."""
    raw = bytes.fromhex(peer)
    ca = tai("32473.1")
    assert ca.matches(raw) is False
    assert pattern_contains(Pattern.from_text("32473.{0-}").raw, raw) is False
    assert ca.matches(bytes.fromhex("81fd5901")) is True


def test_arbitrarily_large_components_are_accepted() -> None:
    """§8: TLS implementations MUST accept IDs with arbitrarily large OID components."""
    big = TrustAnchorID(bytes.fromhex("81fd5982808080808080808003"))
    assert big.components == (32473, 2**64 + 3)
    huge = TrustAnchorID(b"\xff" * 31 + b"\x7f")  # one 217-bit component
    assert huge.components == (2**224 - 1,)


def test_only_bytes_are_ids() -> None:
    with pytest.raises(CodecUsageError):
        TrustAnchorID("32473.1")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Patterns (§5.3.1, Appendix B)
# --------------------------------------------------------------------------- #


def test_section_5_3_1_example_pattern() -> None:
    p = Pattern.from_text("32473.{123-456}.{789-}")
    assert p.raw == bytes([0x81, 0xFD, 0x59, 0x81, 0xFD, 0x59, 0x7B, 0x83, 0x48, 0x86, 0x15, 0x80])
    assert p.text == "32473.{123-456}.{789-}"
    for yes in ("32473.123.789", "32473.300.900", "32473.456.99999"):
        assert p.contains(tai(yes))
    for no in ("32473.123", "32473.123.789.0", "32474.123.789", "32473.500.789", "32473.123.700"):
        assert not p.contains(tai(no))


@pytest.mark.parametrize(("pattern", "ident", "contained"), CASES, ids=lambda v: v if isinstance(v, str) else str(v))
def test_appendix_b(pattern: str, ident: str, contained: bool) -> None:
    assert pattern_contains(bytes.fromhex(pattern), bytes.fromhex(ident)) is contained


@pytest.mark.parametrize("case", APPENDIX_B["invalid"], ids=lambda c: f"{c['id']}-in-{c['pattern']}")
def test_appendix_b1_invalid_ids_or_patterns(case: dict) -> None:
    assert pattern_contains(bytes.fromhex(case["pattern"]), bytes.fromhex(case["id"])) is False


def test_appendix_b_vectors_were_all_extracted() -> None:
    """Guards the extraction script: App. B has 5 + 7 + 3 + 3 cases and B.1 has 4."""
    assert [len(g["ids"]) for g in APPENDIX_B["groups"]] == [5, 7, 3, 3]
    assert len(APPENDIX_B["invalid"]) == 4


def test_appendix_b_patterns_round_trip_through_text() -> None:
    texts = {g["pattern"]: g["pattern_text"] for g in APPENDIX_B["groups"]}
    assert Pattern.from_text("32473.{123-456}.{789-}").raw.hex() in texts
    big = Pattern(((32473, 32473), (2**64 + 1, 2**64 + 3)))
    assert big.raw.hex() == "81fd5981fd598280808080808080800182808080808080808003"
    assert Pattern.from_text(big.text) == big


def test_empty_pattern_contains_only_the_empty_id() -> None:
    """§5.3.1 on raw bytes: zero components on both sides succeed; any mismatch fails."""
    assert pattern_contains(b"", b"")
    assert not pattern_contains(b"", b"\x01")
    assert not pattern_contains(b"\x01\x01", b"")


def test_pattern_contains_never_raises_on_garbage() -> None:
    import random

    rng = random.Random(20261115)
    for _ in range(20000):
        pattern = rng.randbytes(rng.randrange(0, 12))
        ident = rng.randbytes(rng.randrange(0, 8))
        assert pattern_contains(pattern, ident) in (True, False)


def test_pattern_matching_agrees_with_integer_comparison() -> None:
    """The byte procedure must equal comparing the decoded integers, on every valid input."""
    import random

    rng = random.Random(7)
    values = [0, 1, 127, 128, 129, 255, 16383, 16384, 32473, 2**32 - 1, 2**64, 2**64 + 1]
    for _ in range(3000):
        n = rng.randrange(1, 3)  # up to three components of <= 10 bytes: under the 32-byte bound
        pairs = []
        for _ in range(n):
            lo = rng.choice(values)
            hi = rng.choice([None, *[v for v in values if v >= lo]])
            pairs.append((lo, hi))
        p = Pattern(tuple(pairs))
        comps = [rng.choice(values) for _ in range(rng.choice([n, n, n - 1, n + 1]) or 1)]
        expected = len(comps) == n and all(lo <= c and (hi is None or c <= hi) for c, (lo, hi) in zip(comps, pairs))
        assert p.contains(TrustAnchorID.from_components(comps)) is expected, (p.text, comps)


@pytest.mark.parametrize("text", ["", "1.", "{-1}", "{2-1}", "{01-2}", "{1-2", "1-2", "{1--}", "a"])
def test_bad_pattern_text_is_a_usage_error(text: str) -> None:
    with pytest.raises(CodecUsageError):
        Pattern.from_text(text)


def test_pattern_text_forms() -> None:
    assert Pattern(((5, 5), (1, 9), (3, None))).text == "5.{1-9}.{3-}"
    assert Pattern.from_text("5.{1-9}.{3-}").pairs == ((5, 5), (1, 9), (3, None))
    assert Pattern.from_text("{4-4}").text == "4"


# --------------------------------------------------------------------------- #
# MTC's use of trust anchor IDs (MTC -08 §5.1, §8.2, §8.2.1)
# --------------------------------------------------------------------------- #


def test_mtc_landmark_id_example() -> None:
    """§8.2: landmark 42 of CA 32473.100, log 8, is 32473.100.1.8.42."""
    assert tai("32473.100").child(1, 8, 42) == tai("32473.100.1.8.42")


def test_mtc_landmark_group_example() -> None:
    """§8.2.1: a relying party up to date as of landmark 42 of log 8 sends 32473.100.2.8.42."""
    group = tai("32473.100").child(2, 8, 42)
    standalone = Pattern.from_text("32473.100.2.{0-}.{0-}")
    landmark_42 = Pattern.from_text("32473.100.2.8.{42-}")
    assert standalone.contains(group) and landmark_42.contains(group)
    assert landmark_42.contains(tai("32473.100.2.8.43"))  # a newer group still covers landmark 42
    assert not landmark_42.contains(tai("32473.100.2.8.41"))  # an older one doesn't
    assert not landmark_42.contains(tai("32473.100.2.9.42"))  # another log
    assert not landmark_42.contains(tai("32473.101.2.8.42"))  # another CA
    assert not standalone.contains(tai("32473.100"))  # the bare CA ID isn't a group ID


def test_non_minimal_values_never_match() -> None:
    """§5.3.1 "If the first byte of in is 0x80, fail": App. B's non-minimal case is out of range
    anyway, so these are the inputs where only that check gives the answer."""
    assert pattern_contains(bytes.fromhex("0080"), bytes.fromhex("8001")) is False  # 0.{0-}: non-minimal ID
    assert pattern_contains(bytes.fromhex("80018200"), bytes.fromhex("8101")) is False  # non-minimal min


def test_infinity_in_a_middle_pair() -> None:
    """MTC -08 §8.2.1's standalone pattern has two unbounded pairs, not just a last one."""
    assert Pattern.from_text("32473.100.2.{0-}.{0-}").raw.hex() == "81fd5981fd59646402020080" + "0080"
    assert pattern_contains(Pattern.from_text("32473.{0-}.1").raw, tai("32473.7.1").raw)
    assert not pattern_contains(Pattern.from_text("32473.{0-}.1").raw, tai("32473.7.2").raw)


def test_dn_form_of_section_4_1() -> None:
    """§4.1: the trust anchor ID as a one-attribute PKIX name, 1.3.6.1.5.5.7.25.3=#0d0481fd5901."""
    t = tai("32473.1")
    name = der.seq(der.set_of(der.seq(der.oid("1.3.6.1.5.5.7.25.3"), t.der)))
    (rdn,) = der.parse(name).children()
    oid, value = rdn.children()[0].children()
    assert oid.as_oid() == "1.3.6.1.5.5.7.25.3"
    assert value.raw.hex() == "0d0481fd5901" and value.as_relative_oid() == t.raw


def test_a_31_byte_component_round_trips() -> None:
    """§8: arbitrarily large components; 32 bytes caps one at 217 bits, so no other bound is needed."""
    t = TrustAnchorID(b"\x81" + b"\xff" * 29 + b"\x7f" + b"\x01")
    assert len(t.raw) == 32 and t.components[0].bit_length() == 211
    assert TrustAnchorID.from_ascii(t.ascii) == t


@pytest.mark.timeout(10)
@pytest.mark.parametrize(
    "call",
    [
        lambda: TrustAnchorID.from_components([-1]),
        lambda: tai("32473").child(-1),
        lambda: Pattern(((-1, None),)),
        lambda: Pattern(()),
        lambda: TrustAnchorID.from_components([]),
        lambda: tai("1" * 5000),
        lambda: Pattern.from_text("{1-" + "9" * 5000 + "}"),
        lambda: tai("32473.1").matches(1),  # bytes(1) would be b"\\x00": never a silent match
        lambda: tai("32473.1").matches("81fd5901"),
        lambda: pattern_contains(0, 0),
    ],
    ids=["neg-component", "neg-child", "neg-pattern", "empty-pattern", "no-components", "huge-decimal",
         "huge-pattern-decimal", "int-peer", "str-peer", "int-pattern"],  # fmt: skip
)
def test_local_misuse_is_a_usage_error_and_never_hangs(call) -> None:  # noqa: ANN001
    with pytest.raises(CodecUsageError):
        call()


def test_peer_bytes_may_be_any_bytes_like() -> None:
    raw = tai("32473.1").raw
    assert tai("32473.1").matches(bytearray(raw)) and tai("32473.1").matches(memoryview(raw))
