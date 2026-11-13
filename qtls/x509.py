"""The X.509 profile qTLS builds and accepts, and certificate-path validation (specs.md D24).

* One algorithm table maps OID ↔ crypto name ↔ TLS codepoint(s) ↔ kind.
* Parsing is algorithm-agnostic (an MTC's ``id-alg-mtcProof`` parses too) and
  keeps the exact bytes of every field: the signed TBS, the SPKI (which MTC and
  D12 hash), names, extensions. Nothing is ever re-encoded to be verified.
* Validation runs in a fixed order so the same chain always gets the same
  alert (D24), raises :class:`AlertError` with a ``reason`` tag, and never
  reads the clock: ``now`` is an input.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from qtls import crypto, der
from qtls.alerts import Alert, AlertError, CodecUsageError

# --------------------------------------------------------------------------- #
# Algorithms
# --------------------------------------------------------------------------- #

Kind = Literal["sig", "kem"]


EC_PUBLIC_KEY = "1.2.840.10045.2.1"
PRIME256V1 = "1.2.840.10045.3.1.7"
MTC_PROOF = "1.3.6.1.5.5.7.6.67"  # Phase 3; listed so its parameters are checked too


@dataclass(frozen=True)
class Algorithm:
    name: str  # qtls.crypto name
    oid: str  # signature algorithm OID (for KEMs: the key OID; KEMs never sign)
    spki_oid: str  # the key's AlgorithmIdentifier OID in a SubjectPublicKeyInfo
    kind: Kind
    codepoints: tuple[int, ...]  # TLS SignatureScheme(s); AuthKEM variants for KEMs


ALGORITHMS: tuple[Algorithm, ...] = (
    Algorithm("ECDSA-P256-SHA256", "1.2.840.10045.4.3.2", EC_PUBLIC_KEY, "sig", (0x0403,)),
    Algorithm("ML-DSA-44", "2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.17", "sig", (0x0904,)),
    Algorithm("ML-DSA-65", "2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.18", "sig", (0x0905,)),
    Algorithm("Falcon-512", "1.3.6.1.4.1.32473.1.1", "1.3.6.1.4.1.32473.1.1", "sig", (0xFE50,)),
    Algorithm("ML-KEM-512", "2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.1", "kem", (0xFE40, 0xFE42)),
    Algorithm("ML-KEM-768", "2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.2", "kem", (0xFE41, 0xFE43)),
)
BY_NAME = {a.name: a for a in ALGORITHMS}
BY_OID = {a.oid: a for a in ALGORITHMS if a.kind == "sig"}  # signature algorithm OIDs
BY_SPKI_OID = {a.spki_oid: a for a in ALGORITHMS}  # key OIDs
SIGNATURE_CODEPOINTS = frozenset(cp for a in ALGORITHMS if a.kind == "sig" for cp in a.codepoints)
_PARAMS_ABSENT = {a.oid for a in ALGORITHMS} | {MTC_PROOF}

# Extensions (RFC 5280 §4.2, RFC 6962 §3.3)
BASIC_CONSTRAINTS = "2.5.29.19"
KEY_USAGE = "2.5.29.15"
SUBJECT_ALT_NAME = "2.5.29.17"
SUBJECT_KEY_ID = "2.5.29.14"
AUTHORITY_KEY_ID = "2.5.29.35"
SCT_LIST = "1.3.6.1.4.1.11129.2.4.2"
_UNDERSTOOD = {BASIC_CONSTRAINTS, KEY_USAGE, SUBJECT_ALT_NAME, SUBJECT_KEY_ID, AUTHORITY_KEY_ID, SCT_LIST}

COMMON_NAME = "2.5.4.3"
DIGITAL_SIGNATURE, KEY_ENCIPHERMENT, KEY_CERT_SIGN, CRL_SIGN = 0, 2, 5, 6


def _bad(message: str, reason: str) -> AlertError:
    return AlertError(Alert.bad_certificate, message, reason)


# --------------------------------------------------------------------------- #
# Parsed certificates
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Extension:
    oid: str
    critical: bool
    value: bytes  # extnValue contents (the inner DER)
    raw: bytes


@dataclass(frozen=True)
class Profile:
    """The extensions qTLS interprets, parsed once."""

    ca: bool
    path_len: int | None
    basic_constraints_critical: bool
    key_usage: frozenset[int] | None
    dns_names: tuple[str, ...]


@dataclass(frozen=True)
class Certificate:
    """A parsed certificate. Every ``*_raw`` field is a slice of ``raw``.

    The spans cover everything MTC's TBSCertificateLogEntry is built from
    (Phase 3): version, issuer, validity, subject, the SPKI algorithm, the
    SPKI itself (hashed), and the extensions wrapper.
    """

    raw: bytes
    tbs_raw: bytes
    version_raw: bytes
    validity_raw: bytes
    spki_alg_raw: bytes
    extensions_raw: bytes  # the whole [3] wrapper
    profile: Profile
    serial: int
    signature_oid: str  # from the outer signatureAlgorithm (equal to the TBS one)
    signature_params: bytes | None  # raw DER of the parameters, None if absent
    issuer_raw: bytes
    subject_raw: bytes
    not_before: dt.datetime
    not_after: dt.datetime
    spki_raw: bytes
    spki_oid: str
    spki_params: bytes | None
    public_key: bytes
    extensions: tuple[Extension, ...]
    signature: bytes

    def extension(self, oid: str) -> Extension | None:
        return next((e for e in self.extensions if e.oid == oid), None)

    @property
    def subject_cn(self) -> str | None:
        return _common_name(self.subject_raw)

    def sizes(self) -> dict[str, int]:
        """Where the bytes go: key, signature, SCTs, and DER/structure overhead."""
        sct = self.extension(SCT_LIST)
        sct_len = len(sct.raw) if sct else 0
        parts = {"public_key": len(self.public_key), "signature": len(self.signature), "scts": sct_len}
        parts["overhead"] = len(self.raw) - sum(parts.values())
        return parts


def _alg_id(node: der.Node, what: str) -> tuple[str, bytes | None]:
    parts = node.expect(der.SEQUENCE).children()
    if not 1 <= len(parts) <= 2:
        raise der.DerError(f"{what}: bad AlgorithmIdentifier")
    return parts[0].as_oid(), parts[1].raw if len(parts) == 2 else None


def _common_name(name_raw: bytes) -> str | None:
    for rdn in der.parse(name_raw).children():
        for attr in rdn.expect(der.SET).children():
            oid, value = attr.expect(der.SEQUENCE).children()
            if oid.as_oid() == COMMON_NAME:
                return value.as_str()
    return None


def _check_name(name_raw: bytes) -> None:
    rdns = der.parse(name_raw).expect(der.SEQUENCE).children()
    if not rdns:
        raise _bad("empty Name", "name-empty")
    for rdn in rdns:
        attrs = rdn.expect(der.SET).children()
        if not attrs:
            raise _bad("empty RDN", "name-empty")
        for attr in attrs:
            parts = attr.expect(der.SEQUENCE).children()
            if len(parts) != 2:
                raise der.DerError("bad AttributeTypeAndValue")
            parts[0].as_oid()
            parts[1].as_str()


def _parse_spki(spki: der.Node) -> tuple[str, bytes | None, bytes, bytes]:
    parts = spki.expect(der.SEQUENCE).children()
    if len(parts) != 2:
        raise der.DerError("bad SubjectPublicKeyInfo")
    oid, params = _alg_id(parts[0], "SubjectPublicKeyInfo")
    key = parts[1].as_bit_string()
    # Known algorithms must be exactly right (D24); unknown ones are kept for verify to refuse.
    if oid == EC_PUBLIC_KEY:
        if params is None or der.parse(params).as_oid() != PRIME256V1:
            raise _bad("EC key not on prime256v1", "ec-curve")
        if not crypto.ec_point_valid(key):
            raise _bad("EC key must be an uncompressed point on P-256", "ec-point")
    elif oid in BY_SPKI_OID:
        alg = BY_SPKI_OID[oid]
        expected = (crypto.SIGNATURES[alg.name].public_key_len if alg.kind == "sig"
                    else crypto.KEMS[alg.name].public_key_len)  # fmt: skip
        if params is not None:
            raise _bad(f"{alg.name} key parameters must be absent", "spki-params")
        if len(key) != expected:
            raise _bad(f"{alg.name} key is {len(key)} bytes, expected {expected}", "key-length")
    return oid, params, key, parts[0].raw


def parse(data: bytes) -> Certificate:
    """Parse one certificate strictly. Malformed input → ``bad_certificate``."""
    try:
        return _parse(bytes(data))
    except (der.DerError, ValueError, IndexError) as exc:
        # ValueError/IndexError: a well-formed TLV with the wrong number of parts.
        raise _bad(f"malformed certificate: {exc}", "der") from None


def _parse(data: bytes) -> Certificate:
    cert = der.parse(data).expect(der.SEQUENCE)
    parts = cert.children()
    if len(parts) != 3:
        raise der.DerError("Certificate must have three parts")
    tbs, outer_alg, sig_bits = parts
    signature_oid, signature_params = _alg_id(outer_alg, "signatureAlgorithm")
    if signature_oid in _PARAMS_ABSENT and signature_params is not None:
        raise _bad("signature algorithm parameters must be absent", "alg-params")
    signature = sig_bits.as_bit_string()

    fields = tbs.expect(der.SEQUENCE).children()
    if not fields or fields[0].tag != 0xA0:
        raise _bad("version must be present and v3", "version")
    (version_node,) = fields[0].children()
    if version_node.as_int() != 2:
        raise _bad("only X.509 v3 is accepted", "version")
    if len(fields) != 8:  # v3 with extensions, no unique IDs (D24)
        raise _bad("TBSCertificate must have exactly the qTLS profile's fields", "tbs-shape")
    _, serial_node, inner_alg, issuer, validity, subject, spki, ext_wrapper = fields
    serial = serial_node.as_int()
    if serial <= 0 or len(serial_node.contents) > 20:
        raise _bad("serial must be positive and at most 20 octets", "serial")
    if inner_alg.raw != outer_alg.raw:
        raise _bad("inner and outer signature algorithms differ", "alg-mismatch")
    _check_name(issuer.raw)
    _check_name(subject.raw)
    times = validity.expect(der.SEQUENCE).children()
    if len(times) != 2:
        raise der.DerError("Validity must have two times")
    not_before, not_after = (t.as_time() for t in times)
    spki_oid, spki_params, public_key, spki_alg_raw = _parse_spki(spki)

    if ext_wrapper.tag != 0xA3:
        raise _bad("extensions must be present", "tbs-shape")
    (ext_seq,) = ext_wrapper.children()
    ext_nodes = ext_seq.expect(der.SEQUENCE).children()
    if not ext_nodes:
        raise _bad("extensions must not be empty (RFC 5280)", "extensions-empty")
    extensions, seen = [], set()
    for node in ext_nodes:
        items = node.expect(der.SEQUENCE).children()
        oid = items[0].as_oid()
        critical = False
        if len(items) == 3:
            critical = items[1].as_bool()
            if not critical:
                raise _bad("critical FALSE must be omitted (DER DEFAULT)", "default-encoded")
        elif len(items) != 2:
            raise der.DerError("bad Extension")
        if oid in seen:
            raise _bad(f"duplicate extension {oid}", "duplicate-extension")
        seen.add(oid)
        if critical and oid not in _UNDERSTOOD:
            raise _bad(f"unrecognised critical extension {oid}", "unknown-critical")
        extensions.append(Extension(oid, critical, items[-1].as_octets(), node.raw))
    exts = tuple(extensions)
    profile = _parse_profile(exts)
    return Certificate(
        data, tbs.raw, fields[0].raw, validity.raw, spki_alg_raw, ext_wrapper.raw, profile,
        serial, signature_oid, signature_params, issuer.raw, subject.raw,
        not_before, not_after, spki.raw, spki_oid, spki_params, public_key, exts, signature,
    )  # fmt: skip


def _parse_profile(extensions: tuple[Extension, ...]) -> Profile:
    def get(oid: str) -> Extension | None:
        return next((e for e in extensions if e.oid == oid), None)

    ca, path_len = False, None
    bc = get(BASIC_CONSTRAINTS)
    if bc:
        items = der.parse(bc.value).expect(der.SEQUENCE).children()
        if items and items[0].tag == der.BOOLEAN:
            ca = items[0].as_bool()
            if not ca:
                raise _bad("cA FALSE must be omitted (DER DEFAULT)", "default-encoded")
            items = items[1:]
        if items:
            path_len = items[0].as_int()
            if path_len < 0 or not ca or len(items) > 1:
                raise _bad("bad basicConstraints", "basic-constraints")
        if ca and not bc.critical:  # RFC 5280 §4.2.1.9: MUST be critical in CA certificates
            raise _bad("a CA's basicConstraints must be critical", "basic-constraints")
    key_usage = None
    ku = get(KEY_USAGE)
    if ku:
        key_usage = frozenset(der.parse(ku.value).as_named_bits())
    dns = []
    san = get(SUBJECT_ALT_NAME)
    if san:
        names = der.parse(san.value).expect(der.SEQUENCE).children()
        if not names:
            raise _bad("empty subjectAltName", "san")
        for gn in names:
            if gn.tag == 0x82:  # [2] IMPLICIT IA5String dNSName
                if not gn.contents or any(b > 0x7F for b in gn.contents):
                    raise _bad("dNSName must be non-empty IA5", "san")
                dns.append(gn.contents.decode("ascii"))
    skid = get(SUBJECT_KEY_ID)
    if skid:
        der.parse(skid.value).as_octets()
    akid = get(AUTHORITY_KEY_ID)
    if akid:
        if akid.critical:  # RFC 5280 §4.2.1.1: MUST be non-critical
            raise _bad("authorityKeyIdentifier must not be critical", "akid-critical")
        for item in der.parse(akid.value).expect(der.SEQUENCE).children():
            if item.tag not in (0x80, 0xA1, 0x82):
                raise der.DerError("bad AuthorityKeyIdentifier")
    sct = get(SCT_LIST)
    if sct:
        _parse_sct_list(der.parse(sct.value).as_octets())
    return Profile(ca, path_len, bc.critical if bc else False, key_usage, tuple(dns))


# --------------------------------------------------------------------------- #
# Building
# --------------------------------------------------------------------------- #


def name(common_name: str) -> bytes:
    """A Name with a single CN (UTF8String) RDN."""
    return der.seq(der.set_of(der.seq(der.oid(COMMON_NAME), der.utf8_string(common_name))))


def _alg_identifier(oid: str) -> bytes:
    return der.seq(der.oid(oid))  # parameters absent for every qTLS algorithm (D24)


def spki(alg_name: str, public_key: bytes) -> bytes:
    algorithm = BY_NAME[alg_name]
    if algorithm.spki_oid == EC_PUBLIC_KEY:
        alg = der.seq(der.oid(EC_PUBLIC_KEY), der.oid(PRIME256V1))
    else:
        alg = _alg_identifier(algorithm.spki_oid)
    return der.seq(alg, der.bit_string(public_key))


def key_id(spki_der: bytes) -> bytes:
    """RFC 7093 §2 method 1: the leftmost 160 bits of SHA-256(subjectPublicKey)."""
    key = der.parse(spki_der).children()[1].as_bit_string()
    return crypto.sha256(key).digest()[:20]


def _ext(oid: str, value: bytes, critical: bool = False) -> bytes:
    return der.seq(der.oid(oid), *([der.boolean(True)] if critical else []), der.octet_string(value))


@dataclass(frozen=True)
class SctSpec:
    """An SCT, signed by a stand-in log key of the issuer's algorithm (size realism only)."""

    log_key: crypto.SigPrivateKey
    timestamp_ms: int
    signing_seed: bytes


def _sct(spec: SctSpec, leaf_spki: bytes) -> bytes:
    log_id = crypto.sha256(spki(spec.log_key.alg, spec.log_key.public_key)).digest()  # RFC 6962 §3.2
    ts = spec.timestamp_ms.to_bytes(8, "big")
    # The signed message (D24): version ‖ type ‖ timestamp ‖ leaf SPKI. CT validation is out of scope.
    message = b"\x00\x00" + ts + leaf_spki
    signature = spec.log_key.sign(message, seed=spec.signing_seed)
    scheme = BY_NAME[spec.log_key.alg].codepoints[0]
    return (b"\x00" + log_id + ts + b"\x00\x00" + scheme.to_bytes(2, "big")
            + len(signature).to_bytes(2, "big") + signature)  # fmt: skip


def _sct_list(scts: Sequence[bytes]) -> bytes:
    body = b"".join(len(s).to_bytes(2, "big") + s for s in scts)
    return len(body).to_bytes(2, "big") + body


def _parse_sct_list(data: bytes) -> list[bytes]:
    if len(data) < 2 or int.from_bytes(data[:2], "big") != len(data) - 2 or len(data) == 2:
        raise der.DerError("bad SCT list")
    out, pos = [], 2
    while pos < len(data):
        if pos + 2 > len(data):
            raise der.DerError("truncated SCT")
        n = int.from_bytes(data[pos : pos + 2], "big")
        if n == 0 or pos + 2 + n > len(data):
            raise der.DerError("bad SCT length")
        out.append(data[pos + 2 : pos + 2 + n])
        pos += 2 + n
    return out


def issue(
    *,
    subject_cn: str,
    subject_spki: bytes,
    issuer_cn: str,
    issuer_key: crypto.SigPrivateKey,
    issuer_spki: bytes,
    serial: int,
    not_before: dt.datetime,
    not_after: dt.datetime,
    signing_seed: bytes,
    ca: bool = False,
    path_len: int | None = None,
    key_usage: set[int] | None = None,
    dns_names: Sequence[str] = (),
    scts: Sequence[SctSpec] = (),
) -> bytes:
    """Build and sign one certificate in the qTLS profile (D24)."""
    if serial <= 0 or (serial.bit_length() + 8) // 8 > 20:
        raise CodecUsageError("serial must be positive and fit in 20 octets")
    sig_alg = _alg_identifier(BY_NAME[issuer_key.alg].oid)
    exts = []
    bc = ([der.boolean(True)] if ca else []) + ([der.integer(path_len)] if path_len is not None else [])
    exts.append(_ext(BASIC_CONSTRAINTS, der.seq(*bc), critical=True))
    usage = key_usage if key_usage is not None else ({KEY_CERT_SIGN, CRL_SIGN} if ca else set())
    if usage:
        exts.append(_ext(KEY_USAGE, der.named_bits(usage), critical=True))
    exts.append(_ext(SUBJECT_KEY_ID, der.octet_string(key_id(subject_spki))))
    if issuer_spki != subject_spki:
        exts.append(_ext(AUTHORITY_KEY_ID, der.seq(der.tlv(0x80, key_id(issuer_spki)))))
    if dns_names:
        exts.append(_ext(SUBJECT_ALT_NAME, der.seq(*(der.tlv(0x82, n.encode("ascii")) for n in dns_names))))
    if scts:
        exts.append(_ext(SCT_LIST, der.octet_string(_sct_list([_sct(s, subject_spki) for s in scts]))))
    tbs = der.seq(
        der.explicit(0, der.integer(2)),
        der.integer(serial),
        sig_alg,
        name(issuer_cn),
        der.seq(der.time(not_before), der.time(not_after)),
        name(subject_cn),
        subject_spki,
        der.explicit(3, der.seq(*exts)),
    )
    signature = issuer_key.sign(tbs, seed=signing_seed)
    return der.seq(tbs, sig_alg, der.bit_string(signature))


# --------------------------------------------------------------------------- #
# Path validation
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TrustAnchor:
    """A trust anchor: a name and a key (D24). Its validity isn't checked.

    Anchors are local configuration, so a malformed one is a local error
    (``CodecUsageError``) when it's created, never blamed on the peer.
    """

    name_raw: bytes
    spki_raw: bytes
    spki_oid: str = field(init=False, repr=False)
    public_key: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        try:
            _check_name(self.name_raw)
            oid, key = parse_spki(self.spki_raw)
        except AlertError as exc:
            raise CodecUsageError(f"malformed trust anchor: {exc}") from None
        object.__setattr__(self, "spki_oid", oid)
        object.__setattr__(self, "public_key", key)

    @classmethod
    def from_certificate(cls, cert_der: bytes) -> TrustAnchor:
        cert = parse(cert_der)
        return cls(cert.subject_raw, cert.spki_raw)


@dataclass(frozen=True)
class VerifiedLeaf:
    kind: Kind
    alg: str
    public_key: bytes
    spki_raw: bytes
    certificate: Certificate = field(repr=False)


DEFAULT_BACKENDS: Mapping[str, crypto.Backend] = {
    "ECDSA-P256-SHA256": "openssl",
    "ML-DSA-44": "openssl",
    "ML-DSA-65": "openssl",
    "Falcon-512": "liboqs",
}


def verify_chain(
    cert_data: Sequence[bytes],
    anchors: Sequence[TrustAnchor],
    *,
    server_name: str,
    now: dt.datetime,
    accepted: set[int] | frozenset[int],
    expected_kind: Kind | None = None,
    backends: Mapping[str, crypto.Backend] = DEFAULT_BACKENDS,
) -> VerifiedLeaf:
    """Validate a TLS certificate_list (leaf first) in D24's fixed order.

    ``expected_kind`` is the key kind the handshake's authentication mode
    needs: ``"sig"`` for CertificateVerify, ``"kem"`` for AuthKEM. A leaf of
    the other kind is ``unsupported_certificate`` (P8: no KEM leaf under
    signature authentication, and vice versa).

    ``accepted`` holds the SignatureScheme codepoints allowed for certificate
    signatures (``signature_algorithms_cert`` semantics). The chain must be in
    order, leaf first (D24).
    """
    if now.tzinfo is None:
        raise CodecUsageError("now must be timezone-aware")
    if not cert_data:
        raise _bad("empty certificate chain", "empty-chain")
    # 1. Parse every certificate.
    certs = [parse(c) for c in cert_data]

    # A sent root that is itself a trust anchor is ignored (RFC 8446 §4.4.2 allows sending it).
    last = certs[-1]
    if len(certs) > 1 and any(a.name_raw == last.subject_raw and a.spki_raw == last.spki_raw for a in anchors):
        certs = certs[:-1]

    # 2. The top certificate must be issued by a trust anchor (several may share a name).
    top = certs[-1]
    candidates = [a for a in anchors if a.name_raw == top.issuer_raw]
    if not candidates:
        raise AlertError(Alert.unknown_ca, "no trust anchor for the chain", "unknown-anchor")

    # 3. Every signature algorithm must be one the peer accepts.
    for cert in certs:
        alg = BY_OID.get(cert.signature_oid)
        if alg is None or not set(alg.codepoints) & accepted:
            raise AlertError(Alert.unsupported_certificate,
                             f"signature algorithm {cert.signature_oid} not accepted", "algorithm")  # fmt: skip

    # 4. Each link: issuer name, issuer key type, signature. The top link may try every candidate.
    for i, cert in enumerate(certs):
        if i + 1 < len(certs):
            issuer = certs[i + 1]
            issuer_keys = [(issuer.subject_raw, issuer.spki_oid, issuer.public_key)]
        else:
            issuer_keys = [(a.name_raw, a.spki_oid, a.public_key) for a in candidates]
        _verify_link(cert, issuer_keys, backends)

    # 5. CA constraints on every issuer in the chain.
    for depth, cert in enumerate(certs[1:]):
        profile = cert.profile
        if not profile.ca:
            raise _bad("issuer is not a CA", "not-a-ca")
        if profile.key_usage is not None and KEY_CERT_SIGN not in profile.key_usage:
            raise _bad("issuer lacks keyCertSign", "key-usage")
        if profile.path_len is not None and depth > profile.path_len:
            raise _bad("path length constraint exceeded", "path-len")

    # 6. Validity, for every certificate in the chain.
    for cert in certs:
        if not cert.not_before <= now <= cert.not_after:
            raise AlertError(Alert.certificate_expired, "certificate not valid at this time", "validity")

    # 7. The leaf: not a CA, key usage that fits its key kind, and the server name.
    leaf = certs[0]
    if leaf.profile.ca:
        raise _bad("leaf is a CA", "leaf-is-ca")
    leaf_alg = BY_SPKI_OID.get(leaf.spki_oid)
    if leaf_alg is None:
        raise AlertError(Alert.unsupported_certificate, f"leaf key {leaf.spki_oid} not supported", "leaf-key")
    if expected_kind is not None and leaf_alg.kind != expected_kind:
        raise AlertError(Alert.unsupported_certificate,
                         f"a {leaf_alg.kind} leaf can't be used for {expected_kind} authentication", "leaf-kind")  # fmt: skip
    usage = leaf.profile.key_usage
    if leaf_alg.kind == "sig":
        # RFC 8446 §4.4.2.2: digitalSignature must be set *if* keyUsage is present.
        if usage is not None and DIGITAL_SIGNATURE not in usage:
            raise _bad("leaf key usage doesn't allow signing", "leaf-key-usage")
    elif usage is None or KEY_ENCIPHERMENT not in usage:  # KEM leaves must say so (D24)
        raise _bad("KEM leaf must have keyEncipherment", "leaf-key-usage")
    if not any(_dns_match(n, server_name) for n in leaf.profile.dns_names):
        raise _bad("certificate is not for this server name", "name")
    return VerifiedLeaf(leaf_alg.kind, leaf_alg.name, leaf.public_key, leaf.spki_raw, leaf)


def _verify_link(
    cert: Certificate, issuer_keys: list[tuple[bytes, str, bytes]], backends: Mapping[str, crypto.Backend]
) -> None:
    alg = BY_OID[cert.signature_oid]
    backend = backends.get(alg.name)
    if backend is None:
        raise CodecUsageError(f"no backend configured for {alg.name}")
    named = [(oid, key) for name, oid, key in issuer_keys if name == cert.issuer_raw]
    if not named:
        raise _bad("issuer name doesn't match", "issuer-name")
    typed = [key for oid, key in named if oid == alg.spki_oid]
    if not typed:
        raise _bad("issuer key doesn't match the signature algorithm", "issuer-key-type")
    for key in typed:
        try:
            crypto.sig_verify(alg.name, key, cert.tbs_raw, cert.signature, backend)
            return
        except crypto.InvalidSignature:
            continue
    raise _bad("certificate signature doesn't verify", "signature")


def parse_spki(spki_raw: bytes) -> tuple[str, bytes]:
    """(key algorithm OID, key bytes) of a raw SubjectPublicKeyInfo."""
    try:
        oid, _params, key, _alg = _parse_spki(der.parse(spki_raw))
    except (der.DerError, ValueError, IndexError) as exc:
        raise _bad(f"malformed SubjectPublicKeyInfo: {exc}", "der") from None
    return oid, key


def _dns_match(presented: str, server_name: str) -> bool:
    """Exact, ASCII case-insensitive; no wildcards, no trailing dots, no CN fallback (D24)."""
    if "*" in presented or presented.endswith(".") or server_name.endswith("."):
        return False
    try:
        a, b = presented.encode("ascii"), server_name.encode("ascii")
    except UnicodeEncodeError:
        return False
    return a.lower() == b.lower()
