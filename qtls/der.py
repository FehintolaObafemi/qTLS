"""A strict DER codec (X.690 §10, specs.md D20), for X.509 now and MTC in Phase 3.

Decoding accepts only canonical DER: definite, minimal lengths; low tag
numbers; minimal INTEGERs and OID arcs; BOOLEAN 0x00/0xFF; zero BIT STRING
padding; RFC 5280 time formats; sorted SET OF; nothing trailing. Anything else
raises :class:`DerError`, which certificate code turns into ``bad_certificate``.
Every node keeps its exact bytes (``raw``) so signed data is never re-encoded.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from qtls.alerts import CodecUsageError

# Universal tags (X.680 §8.6)
BOOLEAN, INTEGER, BIT_STRING, OCTET_STRING, NULL, OID = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
UTF8_STRING, SEQUENCE, SET, PRINTABLE_STRING, IA5_STRING = 0x0C, 0x30, 0x31, 0x13, 0x16
UTC_TIME, GENERALIZED_TIME = 0x17, 0x18

_UNIVERSAL_PRIMITIVE = {BOOLEAN, INTEGER, BIT_STRING, OCTET_STRING, NULL, OID,
                        UTF8_STRING, PRINTABLE_STRING, IA5_STRING, UTC_TIME, GENERALIZED_TIME}  # fmt: skip
_UNIVERSAL_CONSTRUCTED = {SEQUENCE, SET}
MAX_ARC_BYTES = 10  # 70 bits: every real OID arc fits
_PRIMITIVE_NUMBERS = {t & 0x1F for t in _UNIVERSAL_PRIMITIVE}
_CONSTRUCTED_NUMBERS = {t & 0x1F for t in _UNIVERSAL_CONSTRUCTED}
_PRINTABLE = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?")


class DerError(Exception):
    """Input that isn't canonical DER (or isn't the expected structure)."""


# --------------------------------------------------------------------------- #
# Decoding
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Node:
    """One TLV. ``tag`` is the full identifier octet; ``raw`` is the whole TLV."""

    tag: int
    contents: bytes
    raw: bytes

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> list[Node]:
        if not self.constructed:
            raise DerError(f"tag 0x{self.tag:02x} is primitive; it has no children")
        out, pos = [], 0
        while pos < len(self.contents):
            node, pos = _read(self.contents, pos)
            out.append(node)
        if self.tag == SET:
            _check_set_order(out)
        return out

    def expect(self, tag: int) -> Node:
        if self.tag != tag:
            raise DerError(f"expected tag 0x{tag:02x}, found 0x{self.tag:02x}")
        return self

    # Typed accessors -------------------------------------------------------

    def as_int(self) -> int:
        c = self.expect(INTEGER).contents
        if not c:
            raise DerError("empty INTEGER")
        if len(c) > 1 and ((c[0] == 0x00 and c[1] < 0x80) or (c[0] == 0xFF and c[1] >= 0x80)):
            raise DerError("non-minimal INTEGER")
        return int.from_bytes(c, "big", signed=True)

    def as_bool(self) -> bool:
        c = self.expect(BOOLEAN).contents
        if c not in (b"\x00", b"\xff"):
            raise DerError("BOOLEAN must be 0x00 or 0xFF")
        return c == b"\xff"

    def as_null(self) -> None:
        if self.expect(NULL).contents:
            raise DerError("NULL with contents")

    def as_oid(self) -> str:
        c = self.expect(OID).contents
        if not c or c[-1] & 0x80:
            raise DerError("truncated OBJECT IDENTIFIER")
        arcs, value, start, width = [], 0, True, 0
        for byte in c:
            if start and byte == 0x80:
                raise DerError("non-minimal OBJECT IDENTIFIER arc")
            width += 1
            if width > MAX_ARC_BYTES:  # bounds the work a hostile OID can cause
                raise DerError("OBJECT IDENTIFIER arc too long")
            value = (value << 7) | (byte & 0x7F)
            start = not byte & 0x80
            if start:
                arcs.append(value)
                value, width = 0, 0
        first = arcs[0]
        head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
        return ".".join(map(str, head + arcs[1:]))

    def as_bit_string(self) -> bytes:
        c = self.expect(BIT_STRING).contents
        if not c:
            raise DerError("empty BIT STRING")
        unused, data = c[0], c[1:]
        if unused:  # keys and signatures are whole bytes; named bits use as_named_bits
            raise DerError("qTLS only uses whole-byte BIT STRINGs here")
        return data

    def as_named_bits(self) -> set[int]:
        """A named-bit BIT STRING (e.g. keyUsage): DER trims trailing zero bits (X.690 §11.2.2)."""
        c = self.expect(BIT_STRING).contents
        if not c:
            raise DerError("empty BIT STRING")
        unused, data = c[0], c[1:]
        if unused > 7 or (unused and not data):
            raise DerError("bad BIT STRING padding count")
        if data and data[-1] & ((1 << unused) - 1):
            raise DerError("BIT STRING padding bits must be zero")
        if data and not data[-1] & (1 << unused):
            raise DerError("named-bit BIT STRING has trailing zero bits")
        return {i for i in range(len(data) * 8 - unused) if data[i // 8] & (0x80 >> (i % 8))}

    def as_octets(self) -> bytes:
        return self.expect(OCTET_STRING).contents

    def as_str(self) -> str:
        if self.tag == UTF8_STRING:
            try:
                return self.contents.decode("utf-8")
            except UnicodeDecodeError:
                raise DerError("invalid UTF8String") from None
        if self.tag == PRINTABLE_STRING:
            if not set(self.contents) <= _PRINTABLE:
                raise DerError("invalid PrintableString")
            return self.contents.decode("ascii")
        if self.tag == IA5_STRING:
            if any(b > 0x7F for b in self.contents):
                raise DerError("invalid IA5String")
            return self.contents.decode("ascii")
        raise DerError(f"tag 0x{self.tag:02x} is not a supported string type")

    def as_time(self) -> dt.datetime:
        """RFC 5280 §4.1.2.5: UTCTime YYMMDDHHMMSSZ, GeneralizedTime YYYYMMDDHHMMSSZ."""
        c = self.contents
        if self.tag == UTC_TIME:
            text, fmt, size = c, "%y%m%d%H%M%SZ", 13
        elif self.tag == GENERALIZED_TIME:
            text, fmt, size = c, "%Y%m%d%H%M%SZ", 15
        else:
            raise DerError("expected a time")
        if len(text) != size or not text[:-1].isdigit() or not text.endswith(b"Z"):
            raise DerError("time not in the RFC 5280 form")
        try:
            value = dt.datetime.strptime(text.decode(), fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            raise DerError("invalid time") from None
        if self.tag == UTC_TIME and value.year >= 2050:
            value = value.replace(year=value.year - 100)  # YY >= 50 means 19YY
        if self.tag == GENERALIZED_TIME and 1950 <= value.year < 2050:
            raise DerError("GeneralizedTime for 1950-2049 must be UTCTime (RFC 5280)")
        return value


def _read(data: bytes, pos: int) -> tuple[Node, int]:
    start = pos
    if pos >= len(data):
        raise DerError("truncated: missing tag")
    tag = data[pos]
    pos += 1
    if tag & 0x1F == 0x1F:
        raise DerError("high tag numbers are not used")
    if pos >= len(data):
        raise DerError("truncated: missing length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DerError("indefinite length")
    else:
        n = first & 0x7F
        if n > 4 or pos + n > len(data):
            raise DerError("truncated or oversized length")
        length_bytes = data[pos : pos + n]
        pos += n
        if length_bytes[0] == 0:
            raise DerError("non-minimal length (leading zero)")
        length = int.from_bytes(length_bytes, "big")
        if length < 0x80:
            raise DerError("long-form length where short form fits")
    if pos + length > len(data):
        raise DerError("truncated contents")
    if tag & 0xC0 == 0:  # universal class: check primitive/constructed form
        number = tag & 0x1F
        if (tag & 0x20 and number in _PRIMITIVE_NUMBERS) or (not tag & 0x20 and number in _CONSTRUCTED_NUMBERS):
            raise DerError(f"wrong primitive/constructed form for tag 0x{tag:02x}")
    node = Node(tag, data[pos : pos + length], data[start : pos + length])
    return node, pos + length


def _check_set_order(items: list[Node]) -> None:
    raws = [n.raw for n in items]
    if raws != sorted(raws):
        raise DerError("SET OF elements not in DER order")


def parse(data: bytes) -> Node:
    """Parse exactly one TLV that spans all of ``data``."""
    node, pos = _read(bytes(data), 0)
    if pos != len(data):
        raise DerError(f"{len(data) - pos} trailing bytes")
    return node


# --------------------------------------------------------------------------- #
# Encoding
# --------------------------------------------------------------------------- #


def tlv(tag: int, contents: bytes) -> bytes:
    n = len(contents)
    if n < 0x80:
        length = bytes([n])
    else:
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(body)]) + body
    return bytes([tag]) + length + contents


def seq(*parts: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    return tlv(SET, b"".join(sorted(parts)))


def integer(n: int) -> bytes:
    size = max(1, (n + (n < 0)).bit_length() // 8 + 1)
    return tlv(INTEGER, n.to_bytes(size, "big", signed=True))


def boolean(value: bool) -> bytes:
    return tlv(BOOLEAN, b"\xff" if value else b"\x00")


def null() -> bytes:
    return tlv(NULL, b"")


def oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] >= 40) or min(arcs) < 0:
        raise CodecUsageError(f"invalid OID {dotted}")
    out = b""
    for arc in [40 * arcs[0] + arcs[1], *arcs[2:]]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(chunk))
    return tlv(OID, out)


def bit_string(data: bytes) -> bytes:
    return tlv(BIT_STRING, b"\x00" + data)


def named_bits(bits: set[int]) -> bytes:
    """Encode a named-bit BIT STRING with trailing zero bits trimmed (X.690 §11.2.2)."""
    if not bits:
        return tlv(BIT_STRING, b"\x00")
    length = max(bits) + 1
    data = bytearray((length + 7) // 8)
    for i in bits:
        data[i // 8] |= 0x80 >> (i % 8)
    return tlv(BIT_STRING, bytes([len(data) * 8 - length]) + bytes(data))


def octet_string(data: bytes) -> bytes:
    return tlv(OCTET_STRING, data)


def utf8_string(text: str) -> bytes:
    return tlv(UTF8_STRING, text.encode("utf-8"))


def ia5_string(text: str) -> bytes:
    data = text.encode("ascii")
    return tlv(IA5_STRING, data)


def time(value: dt.datetime) -> bytes:
    """UTCTime through 2049, GeneralizedTime from 2050 (RFC 5280 §4.1.2.5)."""
    if value.tzinfo is None:
        raise CodecUsageError("certificate times must be timezone-aware")
    value = value.astimezone(dt.timezone.utc)
    if value.microsecond:
        raise CodecUsageError("certificate times have whole seconds")
    if 1950 <= value.year < 2050:
        return tlv(UTC_TIME, value.strftime("%y%m%d%H%M%SZ").encode())
    return tlv(GENERALIZED_TIME, f"{value.year:04d}".encode() + value.strftime("%m%d%H%M%SZ").encode())


def explicit(number: int, inner: bytes) -> bytes:
    """A constructed context-specific tag ``[number] EXPLICIT``."""
    if not 0 <= number < 31:
        raise CodecUsageError("context tag number out of range")
    return tlv(0xA0 | number, inner)


def reencode(node: Node) -> bytes:
    """Rebuild a parsed tree from its parts (a test oracle for the codec)."""
    if node.constructed:
        return tlv(node.tag, b"".join(reencode(c) for c in node.children()))
    return tlv(node.tag, node.contents)
