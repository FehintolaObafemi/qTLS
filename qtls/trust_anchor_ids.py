"""Trust anchor IDs and ID patterns (draft-ietf-tls-trust-anchor-ids-07; specs.md D32).

A trust anchor ID is a relative OID under 1.3.6.1.4.1. It's held in its
**binary representation** (the contents octets of the RELATIVE-OID's DER, §4),
which is what TLS carries and what §8 recommends keeping: equality and
pattern matching work on these bytes, so OID components of any size are
handled without converting them (§8 MUST).

MTC (Phase 3) uses trust anchor IDs for CA IDs, log IDs, landmarks and landmark
groups (MTC -08 §5.1, §8.2); 3c's ``trust_anchors`` extension carries them.

A :class:`TrustAnchorID` is **local configuration** (a CA ID, a cosigner ID,
the landmark group a client advertises), validated when it's built; a bad one
is ``CodecUsageError``. IDs from a **peer** (a ClientHello list, an MTCProof
``cosigner_id``) are never validated or rejected here: they stay raw bytes,
framed only by the structure that carries them, and are compared with
configured IDs (:meth:`TrustAnchorID.matches`) or patterns
(:func:`pattern_contains`). An unknown, oversized or malformed one simply
matches nothing, as MTC -08 §7.2 step 12 ("Unrecognized cosigners MUST be
ignored"), its GREASE IDs (§6.2) and trust-anchor-ids App. B.1 need.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from qtls import der
from qtls.alerts import CodecUsageError

MAX_LEN = 32  # §4: the binary representation MUST NOT exceed 32 bytes
PEN_PREFIX = "1.3.6.1.4.1"  # §4: trust anchor IDs are relative to this arc
INFINITY = None  # a pattern pair's max that has no bound


def _encode_component(value: int) -> bytes:
    """X.690 §8.19.2 base-128, minimal (also the §5.3.1 pattern integer encoding)."""
    if value < 0:
        raise CodecUsageError("OID components are non-negative")
    out = [value & 0x7F]
    value >>= 7
    while value:
        out.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(out))


def _decode_components(raw: bytes) -> tuple[int, ...]:
    out, value = [], 0
    for byte in raw:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            out.append(value)
            value = 0
    return tuple(out)


_DECIMAL = re.compile(r"0|[1-9][0-9]{0,99}")  # 100 digits: far past 32 bytes' 224 bits


def _parse_decimal(text: str) -> int:
    if not _DECIMAL.fullmatch(text):
        raise CodecUsageError(f"{text[:20]!r} isn't a canonical decimal OID component of at most 100 digits")
    return int(text)


def _peer_bytes(value: object, what: str) -> bytes:
    """A peer value as bytes; anything else is our bug, never a silent match (``bytes(1)`` is ``b"\\x00"``)."""
    if not isinstance(value, bytes | bytearray | memoryview):
        raise CodecUsageError(f"{what} must be bytes, not {type(value).__name__}")
    return bytes(value)


@dataclass(frozen=True, order=False)
class TrustAnchorID:
    """A valid trust anchor ID, by its binary representation (§4)."""

    raw: bytes

    def __post_init__(self) -> None:
        raw = self.raw
        if not isinstance(raw, bytes):
            raise CodecUsageError("a trust anchor ID is bytes")
        if len(raw) > MAX_LEN:
            raise CodecUsageError(f"trust anchor ID is {len(raw)} bytes; at most {MAX_LEN} (§4)")
        der.check_relative_oid(raw, CodecUsageError)

    @classmethod
    def from_components(cls, components: Iterable[int]) -> TrustAnchorID:
        parts = list(components)
        if not parts:
            raise CodecUsageError("a trust anchor ID has at least one component")
        return cls(b"".join(_encode_component(c) for c in parts))

    @classmethod
    def from_ascii(cls, text: str) -> TrustAnchorID:
        """Strict dotted decimal, e.g. ``"32473.1"`` (§4's ASCII representation)."""
        return cls.from_components(_parse_decimal(p) for p in text.split("."))

    @property
    def components(self) -> tuple[int, ...]:
        return _decode_components(self.raw)

    @property
    def ascii(self) -> str:
        return ".".join(map(str, self.components))

    @property
    def full_oid(self) -> str:
        """The OID in dotted decimal, under 1.3.6.1.4.1 (§4)."""
        return f"{PEN_PREFIX}.{self.ascii}"

    @property
    def der(self) -> bytes:
        """The RELATIVE-OID's DER encoding (§4's ASN.1 representation)."""
        return der.relative_oid(self.raw)

    def matches(self, peer_id: bytes) -> bool:
        """Whether a peer's ID (any bytes, unvalidated) is this ID: byte equality (§8)."""
        return _peer_bytes(peer_id, "a peer trust anchor ID") == self.raw

    def child(self, *components: int) -> TrustAnchorID:
        """This ID with ``components`` appended (MTC -08 §5.1 arcs: logs, landmarks, groups).

        Past 32 bytes it's ``CodecUsageError``: a CA ID of more than 21 bytes
        can't name landmark 2^48 − 1 of log 65535 (D32's budget).
        """
        return TrustAnchorID.from_components((*self.components, *components))

    def __str__(self) -> str:
        return self.ascii


# --------------------------------------------------------------------------- #
# Patterns (§5.3.1)
# --------------------------------------------------------------------------- #


def _remove_integer(data: bytes) -> tuple[bytes, bytes] | None:
    """§5.3.1 "remove an encoded base-128 integer": (value, rest), or None on failure."""
    if not data or data[0] == 0x80:  # empty, or not minimally encoded
        return None
    for i, byte in enumerate(data):
        if not byte & 0x80:
            return data[: i + 1], data[i + 1 :]
    return None  # truncated


def _compare(a: bytes, b: bytes) -> int:
    """§5.3.1: by length, then lexicographically (order-preserving for minimal encodings)."""
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    return (a > b) - (a < b)


def pattern_contains(pattern: bytes, trust_anchor_id: bytes) -> bool:
    """Whether ``pattern`` contains ``trust_anchor_id``, both as bytes (§5.3.1, verbatim)."""
    pattern, ident = _peer_bytes(pattern, "a pattern"), _peer_bytes(trust_anchor_id, "a trust anchor ID")
    while ident:
        taken = _remove_integer(ident)
        if taken is None:
            return False
        v, ident = taken
        taken = _remove_integer(pattern)
        if taken is None:
            return False
        lo, pattern = taken
        if _compare(v, lo) < 0:
            return False
        if pattern and pattern[0] == 0x80:  # max is infinity
            pattern = pattern[1:]
            continue
        taken = _remove_integer(pattern)
        if taken is None:
            return False
        hi, pattern = taken
        if _compare(hi, v) < 0:
            return False
    return not pattern


_PAIR = re.compile(r"\{([0-9]+)-([0-9]*)\}|([0-9]+)")


@dataclass(frozen=True)
class Pattern:
    """A trust anchor ID pattern: one (min, max) pair per component; max None is infinity."""

    pairs: tuple[tuple[int, int | None], ...]

    def __post_init__(self) -> None:
        if not self.pairs:
            raise CodecUsageError("a pattern has at least one pair")
        for lo, hi in self.pairs:
            if lo < 0 or (hi is not None and hi < lo):
                raise CodecUsageError(f"bad pattern pair ({lo}, {hi})")

    @classmethod
    def from_text(cls, text: str) -> Pattern:
        """``"32473.{123-456}.{789-}"`` (§5.3.1's text representation)."""
        pairs: list[tuple[int, int | None]] = []
        for part in text.split("."):
            m = _PAIR.fullmatch(part)
            if not m:
                raise CodecUsageError(f"{part!r} isn't a pattern component")
            if m.group(3) is not None:
                v = _parse_decimal(m.group(3))
                pairs.append((v, v))
            else:
                lo = _parse_decimal(m.group(1))
                hi = _parse_decimal(m.group(2)) if m.group(2) else INFINITY
                pairs.append((lo, hi))
        return cls(tuple(pairs))

    @property
    def raw(self) -> bytes:
        out = b""
        for lo, hi in self.pairs:
            out += _encode_component(lo) + (b"\x80" if hi is None else _encode_component(hi))
        return out

    @property
    def text(self) -> str:
        parts = []
        for lo, hi in self.pairs:
            if hi == lo:
                parts.append(str(lo))
            elif hi is None:
                parts.append(f"{{{lo}-}}")
            else:
                parts.append(f"{{{lo}-{hi}}}")
        return ".".join(parts)

    def contains(self, trust_anchor_id: TrustAnchorID) -> bool:
        return pattern_contains(self.raw, trust_anchor_id.raw)

    def __str__(self) -> str:
        return self.text
