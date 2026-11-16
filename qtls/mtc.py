"""Merkle Tree Certificates: codecs, issuance and relying-party verification (MTC -08; specs.md D33, D34).

Wire structures use the TLS presentation language (MTC -08 §5.2.1, §5.3.1, §6.2)
and are decoded strictly: lengths in bounds, nothing trailing, list orders as
the draft requires. A peer's malformed input is an :class:`AlertError` with a
reason; misuse of the builders is a :class:`CodecUsageError`.

Trust anchor IDs (CA, log and cosigner IDs) that qTLS configures are
:class:`TrustAnchorID`. Those a peer sends (a ``cosigner_id``, a certificate's
issuer) stay bytes and are only compared with configured ones (D32).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol

from qtls import crypto, der, merkle, x509
from qtls import messages as m
from qtls.alerts import Alert, AlertError, CodecUsageError
from qtls.trust_anchor_ids import TrustAnchorID

HASH_SIZE = 32
UINT48_MAX = (1 << 48) - 1
MAX_LOG_NUMBER = 0xFFFF  # MTC -08 §5.2: logs 1 to 65535
MAX_CA_ID_LEN = 21  # D32: the longest CA ID whose every landmark ID fits in 32 bytes
SUBTREE_LABEL = b"subtree/v1\n\x00"  # MTC -08 §5.3.1
NULL_ENTRY, TBS_CERT_ENTRY = 0, 1  # MTCLogEntryType (§5.2.1)
MAX_ENTRY = 0xFFFF  # §5.2.1: an MTCLogEntry is at most 65535 bytes
UINT64_MAX = (1 << 64) - 1
MTC_PROOF_ALGORITHM = der.seq(der.oid(x509.MTC_PROOF))  # parameters omitted (§6.2)


def _bad(message: str, reason: str) -> AlertError:
    return AlertError(Alert.bad_certificate, message, reason)


# --------------------------------------------------------------------------- #
# Identifiers (§5.1, §5.2, §5.3.1, §8.2)
# --------------------------------------------------------------------------- #


def check_ca_id(ca_id: TrustAnchorID) -> TrustAnchorID:
    """A CA ID that leaves room for every log, landmark and group ID under it (D32)."""
    if len(ca_id.raw) > MAX_CA_ID_LEN:
        raise CodecUsageError(f"an MTC CA ID is at most {MAX_CA_ID_LEN} bytes (D32)")
    return ca_id


def _check_log_number(log_number: int) -> None:
    if not 1 <= log_number <= MAX_LOG_NUMBER:
        raise CodecUsageError(f"log numbers run from 1 to {MAX_LOG_NUMBER} (§5.2)")


def log_id(ca_id: TrustAnchorID, log_number: int) -> TrustAnchorID:
    """{caID logs(0) N} (§5.2)."""
    _check_log_number(log_number)
    return check_ca_id(ca_id).child(0, log_number)


def landmark_id(ca_id: TrustAnchorID, log_number: int, landmark: int) -> TrustAnchorID:
    """{caID landmarks(1) N L} (§5.1, §8.2)."""
    _check_log_number(log_number)
    return check_ca_id(ca_id).child(1, log_number, landmark)


def landmark_group_id(ca_id: TrustAnchorID, log_number: int, landmark: int) -> TrustAnchorID:
    """{caID landmarkGroups(2) N L} (§5.1, §8.2.1)."""
    _check_log_number(log_number)
    return check_ca_id(ca_id).child(2, log_number, landmark)


def origin(ident: TrustAnchorID) -> bytes:
    """cosigner_name / log_origin: "oid/1.3.6.1.4.1." + the ID's ASCII form (§5.3.1)."""
    return f"oid/{ident.full_oid}".encode("ascii")


# --------------------------------------------------------------------------- #
# Codecs
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EntryExtension:
    """MTCLogEntryExtension (§5.2.1)."""

    ext_type: int
    data: bytes


def _encode_extensions(exts: Sequence[EntryExtension]) -> bytes:
    types = [e.ext_type for e in exts]
    if types != sorted(set(types)):
        raise CodecUsageError("log entry extensions must be strictly ascending by type (§5.2.1)")
    body = b"".join(m.uint(e.ext_type, 2) + m.vector(e.data, 2, 0, 0xFFFF, "extension_data") for e in exts)
    return m.vector(body, 2, 0, 0xFFFF, "extensions")


def _decode_extensions(r: m.Reader) -> tuple[EntryExtension, ...]:
    inner = m.Reader(r.vector(2, 0, 0xFFFF, "extensions"), "MTC extensions")
    out: list[EntryExtension] = []
    while inner.remaining():
        ext_type = inner.uint(2)
        if out and ext_type <= out[-1].ext_type:
            raise AlertError(Alert.decode_error, "MTC extensions not strictly ascending (§5.2.1)", "decode")
        out.append(EntryExtension(ext_type, inner.vector(2, 0, 0xFFFF, "extension_data")))
    return tuple(out)


@dataclass(frozen=True)
class LogEntry:
    """MTCLogEntry (§5.2.1). ``tbs`` is the TBSCertificateLogEntry contents octets, or None for null_entry."""

    tbs: bytes | None
    extensions: tuple[EntryExtension, ...] = ()

    def encode(self) -> bytes:
        body = _encode_extensions(self.extensions)
        body += m.uint(NULL_ENTRY if self.tbs is None else TBS_CERT_ENTRY, 2) + (self.tbs or b"")
        if len(body) > MAX_ENTRY:
            raise CodecUsageError(f"an MTCLogEntry is at most {MAX_ENTRY} bytes (§5.2.1)")
        return body

    @staticmethod
    def decode(data: bytes) -> LogEntry:
        if len(data) > MAX_ENTRY:
            raise AlertError(Alert.decode_error, "MTCLogEntry over 65535 bytes", "decode")
        r = m.Reader(data, "MTCLogEntry")
        exts = _decode_extensions(r)
        entry_type = r.uint(2)
        if entry_type == NULL_ENTRY:
            r.done()
            return LogEntry(None, exts)
        if entry_type == TBS_CERT_ENTRY:
            return LogEntry(r.take(r.remaining()), exts)
        raise AlertError(Alert.decode_error, f"unknown MTCLogEntryType {entry_type}", "decode")


NULL_LOG_ENTRY = LogEntry(None).encode()  # 00 00 00 00: the sparse tree's filler (D31)


def _cosigner_order(raw: bytes) -> tuple[int, bytes]:
    """§6.2: shorter IDs first, then lexicographic."""
    return len(raw), raw


@dataclass(frozen=True)
class Cosignature:
    cosigner_id: bytes  # binary representation; a peer's, so never validated (D32)
    signature: bytes


@dataclass(frozen=True)
class MTCProof:
    """MTCProof (§6.2), the signatureValue of a Merkle Tree certificate."""

    start: int
    end: int
    inclusion_proof: bytes
    signatures: tuple[Cosignature, ...] = ()
    extensions: tuple[EntryExtension, ...] = ()

    @property
    def extensions_raw(self) -> bytes:
        """The length-prefixed ``extensions`` field, as it's hashed into the log entry (§7.2 step 8.2)."""
        return _encode_extensions(self.extensions)

    def encode(self) -> bytes:
        if not (0 <= self.start <= UINT48_MAX and 0 <= self.end <= UINT48_MAX):
            raise CodecUsageError("start and end are uint48")
        ids = [s.cosigner_id for s in self.signatures]
        if ids != sorted(set(ids), key=_cosigner_order):
            raise CodecUsageError("cosignatures must be unique and ordered by cosigner_id (§6.2)")
        sigs = b"".join(
            m.vector(s.cosigner_id, 1, 1, 0xFF, "cosigner_id") + m.vector(s.signature, 2, 0, 0xFFFF, "signature")
            for s in self.signatures
        )
        return (_encode_extensions(self.extensions) + m.uint(self.start, 6) + m.uint(self.end, 6)
                + m.vector(self.inclusion_proof, 2, 0, 0xFFFF, "inclusion_proof")
                + m.vector(sigs, 3, 0, (1 << 24) - 1, "signatures"))  # fmt: skip

    @staticmethod
    def decode(data: bytes) -> MTCProof:
        """Strict decode (§6.2, §7.2 step 2). Any failure is a decode_error the caller re-labels."""
        r = m.Reader(data, "MTCProof")
        exts = _decode_extensions(r)
        start, end = r.uint(6), r.uint(6)
        proof = r.vector(2, 0, 0xFFFF, "inclusion_proof")
        inner = m.Reader(r.vector(3, 0, (1 << 24) - 1, "signatures"), "MTCProof signatures")
        r.done()
        sigs: list[Cosignature] = []
        while inner.remaining():
            cid = inner.vector(1, 1, 0xFF, "cosigner_id")
            if sigs and _cosigner_order(cid) <= _cosigner_order(sigs[-1].cosigner_id):
                raise AlertError(Alert.decode_error, "cosigner IDs duplicated or out of order (§6.2)", "decode")
            sigs.append(Cosignature(cid, inner.vector(2, 0, 0xFFFF, "signature")))
        return MTCProof(start, end, proof, tuple(sigs), exts)


def cosigned_subtree(cosigner: TrustAnchorID, log: TrustAnchorID, start: int, end: int, subtree_hash: bytes) -> bytes:
    """The message a cosigner signs for a subtree: CosignedSubtree with timestamp 0 (§5.3.1, §6.2)."""
    if len(subtree_hash) != HASH_SIZE:
        raise CodecUsageError("subtree_hash is 32 bytes")
    return (SUBTREE_LABEL + m.vector(origin(cosigner), 1, 1, 0xFF, "cosigner_name") + m.uint(0, 8)
            + m.vector(origin(log), 1, 1, 0xFF, "log_origin") + m.uint(start, 8) + m.uint(end, 8)
            + subtree_hash)  # fmt: skip


# --------------------------------------------------------------------------- #
# Certificates below the D24 profile (§7.2 works on any DER TBSCertificate)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TBSFields:
    """The exact bytes of a TBSCertificate's fields that a log entry is made of (§5.2.1, §7.2 step 7)."""

    version_raw: bytes  # empty when absent (DEFAULT v1)
    serial: int
    signature_raw: bytes  # the inner AlgorithmIdentifier
    issuer_raw: bytes
    validity_raw: bytes
    subject_raw: bytes
    spki_raw: bytes
    spki_alg_raw: bytes
    rest_raw: bytes  # issuerUniqueID, subjectUniqueID, extensions: everything after the SPKI


@dataclass(frozen=True)
class SplitCertificate:
    tbs: TBSFields
    outer_alg_raw: bytes
    signature_value: der.Node  # the BIT STRING node, unchecked


def split_certificate(cert_der: bytes) -> SplitCertificate:
    """Canonical DER, X.509's shape, and no profile: what §7.2 needs from any certificate.

    Malformed DER is ``bad_certificate`` (``der``), as in :func:`qtls.x509.parse`.
    """
    try:
        cert = der.parse(cert_der).expect(der.SEQUENCE).children()
        if len(cert) != 3:
            raise der.DerError("Certificate must have three parts")
        tbs, outer, sig = cert
        outer.expect(der.SEQUENCE)
        sig.expect(der.BIT_STRING)
        return SplitCertificate(_tbs_fields(tbs), outer.raw, sig)
    except (der.DerError, ValueError, IndexError) as exc:
        raise _bad(f"malformed certificate: {exc}", "der") from None


def tbs_fields(tbs_der: bytes) -> TBSFields:
    """:class:`TBSFields` of a DER TBSCertificate (malformed: ``bad_certificate``, ``der``)."""
    try:
        return _tbs_fields(der.parse(tbs_der))
    except (der.DerError, ValueError, IndexError) as exc:
        raise _bad(f"malformed TBSCertificate: {exc}", "der") from None


def _tbs_fields(tbs: der.Node) -> TBSFields:
    fields = tbs.expect(der.SEQUENCE).children()
    version = fields.pop(0).raw if fields and fields[0].tag == 0xA0 else b""
    if len(fields) < 6:
        raise der.DerError("TBSCertificate is too short")
    serial, inner, issuer, validity, subject, spki = fields[:6]
    spki_parts = spki.expect(der.SEQUENCE).children()
    if len(spki_parts) != 2:
        raise der.DerError("bad SubjectPublicKeyInfo")
    spki_parts[0].expect(der.SEQUENCE)
    for node in (inner, issuer, validity, subject):
        node.expect(der.SEQUENCE)
    return TBSFields(version, serial.as_int(), inner.raw, issuer.raw, validity.raw, subject.raw,
                     spki.raw, spki_parts[0].raw, b"".join(f.raw for f in fields[6:]))  # fmt: skip


def _spki_hash_field(spki_raw: bytes) -> bytes:
    """subjectPublicKeyInfoHash: OCTET STRING of SHA-256 over the DER SPKI (§5.2.1; D13)."""
    return der.octet_string(merkle.digest(spki_raw))


def tbs_log_entry(tbs: TBSFields) -> bytes:
    """TBSCertificateLogEntry contents octets (§5.2.1) for a TBSCertificate."""
    return (tbs.version_raw + tbs.issuer_raw + tbs.validity_raw + tbs.subject_raw + tbs.spki_alg_raw
            + _spki_hash_field(tbs.spki_raw) + tbs.rest_raw)  # fmt: skip


def entry_hash(tbs: TBSFields, extensions_raw: bytes) -> bytes:
    """MTH({entry}) for the certificate's log entry, single pass (§7.2 steps 7–9 and the list after them).

    Never raises on size: a relying party hashes whatever the peer sent (D33).
    """
    return merkle.leaf_hash(extensions_raw + m.uint(TBS_CERT_ENTRY, 2) + tbs_log_entry(tbs))


# --------------------------------------------------------------------------- #
# Relying-party configuration (§7.1); refused when built, never during a handshake
# --------------------------------------------------------------------------- #

COSIGNER_ALGORITHMS = ("ML-DSA-44", "ML-DSA-65", "ECDSA-P256-SHA256")  # D33; others are unrecognized


@dataclass(frozen=True)
class CosignerKey:
    alg: str
    public_key: bytes

    def __post_init__(self) -> None:
        if self.alg not in COSIGNER_ALGORITHMS:
            raise CodecUsageError(f"{self.alg} isn't a cosigner algorithm qTLS verifies (D33)")
        if len(self.public_key) != crypto.SIGNATURES[self.alg].public_key_len:
            raise CodecUsageError(f"{self.alg} public key has the wrong length")
        if self.alg == "ECDSA-P256-SHA256" and not crypto.ec_point_valid(self.public_key):
            raise CodecUsageError("the ECDSA cosigner key isn't a point on P-256")


class CosignerPolicy(Protocol):
    """Which sets of valid cosignatures a relying party accepts (§7.3).

    Only the cosigners it names (and the CA's own, always required) are verified, so the
    verification work and the counts Phase 5 reports depend on the policy, not on how many
    cosignatures a certificate carries (D33).
    """

    def cosigners(self) -> frozenset[TrustAnchorID]: ...

    def unsatisfied(self, valid: frozenset[bytes]) -> tuple[str, ...]:
        """Descriptions of the requirements ``valid`` (cosigner ID bytes) doesn't meet; empty means
        accepted. Text only, so a failure can never become a local error (D33)."""
        ...


@dataclass(frozen=True)
class RequireAll:
    """Every listed cosigner must have a valid signature (3b1's only policy; quorums are 3b2)."""

    required: frozenset[TrustAnchorID]

    def __post_init__(self) -> None:
        if not self.required:
            raise CodecUsageError("a cosigner policy requires at least one cosigner (D33)")

    def cosigners(self) -> frozenset[TrustAnchorID]:
        return self.required

    def unsatisfied(self, valid: frozenset[bytes]) -> tuple[str, ...]:
        return tuple(sorted(str(c) for c in self.required if c.raw not in valid))


@dataclass(frozen=True)
class TrustedSubtree:
    """A subtree known to be consistent with the relying party's cosigner requirements (§7.4)."""

    log_number: int
    start: int
    end: int
    subtree_hash: bytes
    landmark: int | None = None  # which landmark it belongs to ({caID 1 N L}), for selection in 3c

    def __post_init__(self) -> None:
        _check_log_number(self.log_number)
        if not merkle.valid_subtree(self.start, self.end) or self.end > UINT48_MAX:
            raise CodecUsageError(f"[{self.start}, {self.end}) isn't a subtree an MTCProof can name")
        if len(self.subtree_hash) != HASH_SIZE:
            raise CodecUsageError("subtree_hash is 32 bytes")


@dataclass(frozen=True)
class RevokedRange:
    """Revoked serial numbers [lo, hi) (§7.5; half-open, as §7.1 writes them)."""

    lo: int
    hi: int

    def __post_init__(self) -> None:
        if not 0 <= self.lo < self.hi <= 1 << 64:
            raise CodecUsageError(f"revoked range [{self.lo}, {self.hi}) isn't inside [0, 2^64)")


@dataclass(frozen=True)
class CAPolicy:
    """One Merkle Tree CA as a relying party trusts it (§7.1)."""

    ca_id: TrustAnchorID
    policy: CosignerPolicy
    trusted_subtrees: tuple[TrustedSubtree, ...] = ()
    revoked: tuple[RevokedRange, ...] = ()

    def __post_init__(self) -> None:
        check_ca_id(self.ca_id)
        if self.ca_id not in self.policy.cosigners():
            raise CodecUsageError("the CA's own cosigner must be in the policy (§7.3; D33)")
        if not self.policy.unsatisfied(frozenset()):
            raise CodecUsageError("a policy must refuse a certificate with no valid cosignatures (D33)")
        keys = [(t.log_number, t.start, t.end) for t in self.trusted_subtrees]
        if len(keys) != len(set(keys)):
            raise CodecUsageError("two trusted subtrees name the same (log, start, end)")

    def trusted(self, log_number: int, start: int, end: int) -> TrustedSubtree | None:
        return next((t for t in self.trusted_subtrees if (t.log_number, t.start, t.end) == (log_number, start, end)), None)


@dataclass(frozen=True)
class MTCTrustStore:
    """Every Merkle Tree CA a relying party trusts, and the cosigners it knows (§7.1, §7.3).

    Cosigners are shared across CAs (§7.3 allows it); each CA's policy names the ones it needs.
    """

    cosigners: Mapping[TrustAnchorID, CosignerKey]
    cas: tuple[CAPolicy, ...]
    backends: Mapping[str, crypto.Backend] = field(default_factory=lambda: {a: "openssl" for a in COSIGNER_ALGORITHMS})
    _by_ca: Mapping[bytes, CAPolicy] = field(init=False, repr=False, compare=False)
    _keys: Mapping[bytes, tuple[TrustAnchorID, CosignerKey]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Frozen copies: configuration can't change after it's been checked.
        object.__setattr__(self, "cosigners", MappingProxyType(dict(self.cosigners)))
        object.__setattr__(self, "cas", tuple(self.cas))
        object.__setattr__(self, "backends", MappingProxyType(dict(self.backends)))
        by_ca = {c.ca_id.raw: c for c in self.cas}
        if len(by_ca) != len(self.cas):
            raise CodecUsageError("two CAs share an ID")
        for ca in self.cas:
            missing = ca.policy.cosigners() - set(self.cosigners)
            if missing:
                raise CodecUsageError(f"{ca.ca_id} requires unknown cosigner(s) {sorted(map(str, missing))}")
        for key in self.cosigners.values():
            if key.alg not in self.backends:
                raise CodecUsageError(f"no backend configured for cosigner algorithm {key.alg}")
            if self.backends[key.alg] not in crypto.BACKENDS:
                raise CodecUsageError(f"unknown backend {self.backends[key.alg]}")
            if key.alg not in crypto.supported(self.backends[key.alg])[1]:
                raise CodecUsageError(f"backend {self.backends[key.alg]} can't verify {key.alg}")
        object.__setattr__(self, "_by_ca", MappingProxyType(by_ca))
        object.__setattr__(self, "_keys", MappingProxyType({cid.raw: (cid, k) for cid, k in self.cosigners.items()}))

    def ca_for(self, issuer_id: bytes | None) -> CAPolicy | None:
        """Bytewise match of a peer's issuer ID (D32)."""
        return self._by_ca.get(issuer_id) if issuer_id is not None else None

    def cosigner(self, peer_id: bytes) -> tuple[TrustAnchorID, CosignerKey] | None:
        """The configured cosigner a peer's ``cosigner_id`` names, by a dict lookup (D33: no per-entry scan)."""
        return self._keys.get(peer_id)


# --------------------------------------------------------------------------- #
# §7.2: verifying an MTC certificate's signature
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VerifiedProof:
    ca_id: TrustAnchorID
    log_number: int
    index: int
    start: int
    end: int
    subtree_hash: bytes
    trusted_subtree: TrustedSubtree | None  # set when step 11 decided
    valid_cosigners: frozenset[bytes]  # when step 12 decided: the CA and policy cosigners whose signatures verified


def _issuer_trust_anchor_id(issuer_raw: bytes) -> bytes | None:
    """A TAI name's ID bytes, or None for anything else, however malformed (TAI §4.1)."""
    try:
        return x509.trust_anchor_id_of(issuer_raw)
    except der.DerError:
        return None


def verify_proof(cert_der: bytes, store: MTCTrustStore) -> VerifiedProof:
    """MTC -08 §7.2 for one certificate, in D33's order: the CA first, then steps 1–12."""
    cert = split_certificate(cert_der)
    tbs = cert.tbs
    # 0. §7.2 applies to certificates whose issuer is a Merkle Tree CA, and §7.5's ranges are per CA.
    ca = store.ca_for(_issuer_trust_anchor_id(tbs.issuer_raw))
    if ca is None:
        raise AlertError(Alert.unknown_ca, "issuer isn't a configured Merkle Tree CA", "mtc-unknown-ca")
    # 1. id-alg-mtcProof, parameters omitted, in both places (the outer one must equal it too).
    if tbs.signature_raw != MTC_PROOF_ALGORITHM or cert.outer_alg_raw != MTC_PROOF_ALGORITHM:
        raise _bad("signature algorithm isn't id-alg-mtcProof without parameters", "mtc-alg")
    # 2. Decode the MTCProof: whole bytes, nothing after it.
    value = cert.signature_value.contents
    if not value or value[0] != 0:
        raise _bad("signatureValue isn't a whole number of bytes", "mtc-proof")
    try:
        proof = MTCProof.decode(value[1:])
    except AlertError as exc:
        raise _bad(f"MTCProof doesn't decode: {exc}", "mtc-proof") from None
    # 3.
    serial = tbs.serial
    if not 0 <= serial <= UINT64_MAX:
        raise _bad("serial number outside [0, 2^64 - 1]", "mtc-serial")
    # 4.
    if any(r.lo <= serial < r.hi for r in ca.revoked):
        raise AlertError(Alert.certificate_revoked, f"serial {serial:#x} is in a revoked range", "mtc-revoked")
    # 5.
    index, log_number = serial & UINT48_MAX, serial >> 48
    if log_number == 0:
        raise _bad("log number zero", "mtc-log-number")
    # 6. From the configured CA ID, never the peer's bytes (D32).
    log = log_id(ca.ca_id, log_number)
    # 7.–9.
    leaf = entry_hash(tbs, proof.extensions_raw)
    # 10.
    try:
        subtree_hash = merkle.evaluate_inclusion_proof(
            start=proof.start, end=proof.end, index=index, entry_hash=leaf, proof=proof.inclusion_proof
        )
    except merkle.MerkleError as exc:
        raise _bad(f"inclusion proof: {exc}", f"mtc-{exc.reason}") from None
    # 11. A trusted subtree decides on its own.
    trusted = ca.trusted(log_number, proof.start, proof.end)
    if trusted is not None:
        if trusted.subtree_hash != subtree_hash:
            raise _bad("the proof doesn't lead to the trusted subtree's hash", "mtc-trusted-subtree")
        return VerifiedProof(ca.ca_id, log_number, index, proof.start, proof.end, subtree_hash, trusted, frozenset())
    # 12. The CA's and the policy's cosigners are checked; others (and GREASE) are ignored, and an
    # invalid signature doesn't count (D33). The CA's signature is required whatever the policy (§7.3).
    wanted = {c.raw for c in ca.policy.cosigners()} | {ca.ca_id.raw}
    valid: set[bytes] = set()
    errors: list[str] = []
    for sig in proof.signatures:
        found = store.cosigner(sig.cosigner_id) if sig.cosigner_id in wanted else None
        if found is None:
            continue
        signer, key = found
        message = cosigned_subtree(signer, log, proof.start, proof.end, subtree_hash)
        try:
            crypto.sig_verify(key.alg, key.public_key, message, sig.signature, store.backends[key.alg])
            valid.add(signer.raw)
        except crypto.InvalidSignature:
            errors.append(str(signer))
    unmet = ca.policy.unsatisfied(frozenset(valid))
    if ca.ca_id.raw not in valid:
        unmet = (f"{ca.ca_id} (the CA)", *unmet)
    if unmet:
        raise _bad(f"cosigner requirements not met: {list(unmet)}; invalid signatures from {errors}", "mtc-cosigners")
    return VerifiedProof(ca.ca_id, log_number, index, proof.start, proof.end, subtree_hash, None, frozenset(valid))


@dataclass(frozen=True)
class VerifiedCertificate:
    leaf: x509.VerifiedLeaf
    proof: VerifiedProof  # standalone or landmark-relative, which cosigners counted (3c selection, Phase 5 rows)


def verify_certificate(
    cert_data: Sequence[bytes],
    store: MTCTrustStore,
    *,
    server_name: str,
    now: dt.datetime,
    expected_kind: x509.Kind | None,
) -> VerifiedCertificate:
    """A TLS certificate_list holding one MTC certificate: the D24 profile parse, §7.2, then the rest
    of path validation unchanged (§7.2's last paragraph; D33). The profile parse comes first, so a
    certificate that breaks D24 gets D24's alert even from an unknown CA."""
    if now.tzinfo is None:
        raise CodecUsageError("now must be timezone-aware")
    if len(cert_data) != 1:
        raise _bad("an MTC certificate is sent alone (D33)", "mtc-chain")
    leaf = x509.parse(cert_data[0])
    proof = verify_proof(cert_data[0], store)
    x509.check_validity(leaf, now)
    return VerifiedCertificate(x509.check_leaf(leaf, server_name=server_name, expected_kind=expected_kind), proof)


# --------------------------------------------------------------------------- #
# Issuance (a CA's side; deterministic fixtures, D34)
# --------------------------------------------------------------------------- #

def trust_anchor_name(ident: TrustAnchorID) -> bytes:
    """The ID as a PKIX name: one RDN, one id-rdna-trustAnchorID attribute (TAI §4.1)."""
    return der.seq(der.set_of(der.seq(der.oid(x509.TRUST_ANCHOR_ID_ATTRIBUTE), ident.der)))


@dataclass(frozen=True)
class Cosigner:
    """A cosigner's key (§5.3). ``signing_seed`` makes its signatures deterministic (fixtures)."""

    cosigner_id: TrustAnchorID
    key: crypto.SigPrivateKey
    signing_seed: bytes | None = None

    @property
    def public(self) -> CosignerKey:
        return CosignerKey(self.key.alg, self.key.public_key)

    def sign(self, log: TrustAnchorID, start: int, end: int, subtree_hash: bytes) -> Cosignature:
        message = cosigned_subtree(self.cosigner_id, log, start, end, subtree_hash)
        return Cosignature(self.cosigner_id.raw, self.key.sign(message, seed=self.signing_seed))


def fixture_cosigner(cosigner_id: TrustAnchorID, alg: str, role: str, fixture_seed: bytes = b"qtls fixture v1") -> Cosigner:
    """A deterministic cosigner: seeded key, seeded signatures (liboqs ML-DSA; RFC 6979 ECDSA)."""
    from qtls import chains  # chains imports x509 and crypto only; imported here to keep mtc's import light

    if alg not in COSIGNER_ALGORITHMS:
        raise CodecUsageError(f"{alg} isn't a cosigner algorithm (D33)")
    key = chains.signing_key(alg, fixture_seed, role)
    return Cosigner(cosigner_id, key, chains.signing_seed(alg, fixture_seed, role))


class IssuanceLog:
    """One issuance log of a CA (§5.2): entries, checkpoints and landmarks, and the certificates
    they make (§6.3, §6.4). Unset indices hold null_entry, so a log can be large and sparse (D31)."""

    def __init__(self, ca_id: TrustAnchorID, log_number: int) -> None:
        self.ca_id = check_ca_id(ca_id)
        self.log_number = log_number
        self.log_id = log_id(ca_id, log_number)
        self.size = 0
        self._entries: dict[int, bytes] = {}  # index → MTCLogEntry, for the non-null ones
        self._tbs: dict[int, bytes] = {}
        self.checkpoints: list[int] = [0]
        self.landmarks: list[int] = [0]  # landmark 0 has tree size 0 (§6.4.1)
        self._tree: merkle.Tree | None = None

    def append_null(self, count: int = 1) -> None:
        if count < 0 or self.size + count > UINT48_MAX:
            raise CodecUsageError("an issuance log holds at most 2^48 - 1 entries (§5.2)")
        self.size += count
        self._tree = None

    def add_certificate(
        self,
        *,
        subject_cn: str,
        subject_spki: bytes,
        not_before: dt.datetime,
        not_after: dt.datetime,
        key_usage: set[int],
        dns_names: Sequence[str],
        extensions: tuple[EntryExtension, ...] = (),
    ) -> int:
        """Log a TBSCertificateLogEntry for a qTLS-profile certificate (D24); returns its index."""
        index = self.size
        if index + 1 > UINT48_MAX:
            raise CodecUsageError("an issuance log holds at most 2^48 - 1 entries (§5.2)")
        tbs = x509.build_tbs(
            subject_name=x509.name(subject_cn), subject_spki=subject_spki, issuer_name=trust_anchor_name(self.ca_id),
            signature_algorithm=MTC_PROOF_ALGORITHM, serial=(self.log_number << 48) | index,
            not_before=not_before, not_after=not_after, authority_key_id=None, key_usage=key_usage,
            dns_names=dns_names,
        )  # fmt: skip
        entry = LogEntry(tbs_log_entry(tbs_fields(tbs)), extensions).encode()
        self.append_null()  # only once everything above succeeded: a refused input leaves the log as it was
        self._entries[index] = entry
        self._tbs[index] = tbs
        return index

    def checkpoint(self) -> int:
        if self.size <= self.checkpoints[-1]:
            raise CodecUsageError("a checkpoint needs new entries")
        self.checkpoints.append(self.size)
        return self.size

    def add_landmark(self) -> int:
        """Allocate the next landmark at the current size (§6.4.1); returns its number."""
        if self.size <= self.landmarks[-1]:
            raise CodecUsageError("landmark tree sizes strictly increase (§6.4.1)")
        self.landmarks.append(self.size)
        return len(self.landmarks) - 1

    def tree(self) -> merkle.Tree:
        if self._tree is None:
            leaves = {i: merkle.leaf_hash(e) for i, e in self._entries.items()}
            self._tree = merkle.Tree(self.size, leaves, merkle.leaf_hash(NULL_LOG_ENTRY))
        return self._tree

    def landmark_subtrees(self, landmark: int) -> tuple[tuple[int, int], tuple[int, int]]:
        """§6.4.1: the two subtrees covering [size(L-1), size(L))."""
        if not 0 <= landmark < len(self.landmarks):
            raise CodecUsageError(f"no landmark {landmark}")
        if landmark == 0:
            return (0, 0), (0, 0)
        return merkle.find_subtrees(self.landmarks[landmark - 1], self.landmarks[landmark])

    def trusted_subtrees(self) -> tuple[TrustedSubtree, ...]:
        """Every non-empty landmark subtree, for a relying party's configuration (§7.4)."""
        tree, out = self.tree(), []
        for landmark in range(1, len(self.landmarks)):
            for start, end in self.landmark_subtrees(landmark):
                if start < end:
                    out.append(TrustedSubtree(self.log_number, start, end, tree.hash(start, end), landmark))
        return tuple(out)

    def _certificate(self, index: int, start: int, end: int, signatures: Sequence[Cosignature]) -> bytes:
        if index not in self._tbs:
            raise CodecUsageError(f"entry {index} isn't a certificate")
        proof = MTCProof(start, end, self.tree().inclusion_proof(start, end, index),
                         tuple(sorted(signatures, key=lambda c: _cosigner_order(c.cosigner_id))),
                         LogEntry.decode(self._entries[index]).extensions)  # fmt: skip
        return der.seq(self._tbs[index], MTC_PROOF_ALGORITHM, der.bit_string(proof.encode()))

    def standalone(self, index: int, cosigners: Sequence[Cosigner]) -> bytes:
        """§6.3: the subtree of the checkpoint interval holding ``index``, cosigned."""
        prev = max((c for c in self.checkpoints if c <= index), default=None)
        cur = min((c for c in self.checkpoints if c > index), default=None)
        if prev is None or cur is None:
            raise CodecUsageError(f"entry {index} isn't covered by a checkpoint yet")
        start, end = next(s for s in merkle.find_subtrees(prev, cur) if s[0] <= index < s[1])
        subtree_hash = self.tree().hash(start, end)
        return self._certificate(index, start, end, [c.sign(self.log_id, start, end, subtree_hash) for c in cosigners])

    def landmark_relative(self, index: int) -> bytes:
        """§6.4.4: the subtree of the lowest landmark past ``index``, with no signatures."""
        landmark = next((n for n, size in enumerate(self.landmarks) if size > index), None)
        if landmark is None:
            raise CodecUsageError(f"no landmark covers entry {index} yet")
        start, end = next(s for s in self.landmark_subtrees(landmark) if s[0] <= index < s[1])
        return self._certificate(index, start, end, [])
