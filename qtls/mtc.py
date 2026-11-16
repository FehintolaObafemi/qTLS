"""Merkle Tree Certificates: codecs, issuance, relying-party configuration and verification (MTC -08; specs.md D33–D36).

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
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
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


def cosigned_subtree(
    cosigner: TrustAnchorID, log: TrustAnchorID, start: int, end: int, subtree_hash: bytes, *, timestamp: int = 0
) -> bytes:
    """The message a cosigner signs: CosignedSubtree (§5.3.1). A certificate's cosignatures have
    timestamp 0 (§6.2); a checkpoint cosignature is timestamped and covers [0, size) (§5.3.1, §7.4)."""
    if len(subtree_hash) != HASH_SIZE:
        raise CodecUsageError("subtree_hash is 32 bytes")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or not 0 <= timestamp <= UINT64_MAX:
        raise CodecUsageError("timestamp is a uint64")
    if timestamp and start:
        raise CodecUsageError("only a checkpoint cosignature, with start 0, has a timestamp (§5.3.1)")
    return (SUBTREE_LABEL + m.vector(origin(cosigner), 1, 1, 0xFF, "cosigner_name") + m.uint(timestamp, 8)
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


QUORUM_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")  # starts with a letter: never a TAI, '#' or space (D35)
MAX_QUORUM_DEPTH = 8  # a quorum of cosigners only has depth 1


@dataclass(frozen=True)
class Quorum:
    """At least ``threshold`` of ``members`` (§7.3; D35): a member counts when it's a cosigner with a
    valid signature or a satisfied nested quorum, at most once. Quorums form a DAG: an equal
    sub-quorum may be shared under several parents (the WG demo's ``group``), but two unequal
    quorums may not share a name, since messages and the demo's policy text name them."""

    name: str
    threshold: int
    members: tuple[TrustAnchorID | Quorum, ...]
    _cosigners: frozenset[TrustAnchorID] = field(init=False, repr=False, compare=False)
    _named: Mapping[str, Quorum] = field(init=False, repr=False, compare=False)
    _depth: int = field(init=False, repr=False, compare=False)
    _hash: int = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not QUORUM_NAME.fullmatch(self.name):
            raise CodecUsageError(f"quorum name {self.name!r} isn't [A-Za-z][A-Za-z0-9_.-]{{0,63}} (D35)")
        if not isinstance(self.members, tuple | list):
            raise CodecUsageError("quorum members are a tuple")
        members = tuple(self.members)
        object.__setattr__(self, "members", members)
        if not all(isinstance(x, TrustAnchorID | Quorum) for x in members):
            raise CodecUsageError("a quorum member is a TrustAnchorID or a Quorum")
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, int):
            raise CodecUsageError("a quorum threshold is an int")
        if not 1 <= self.threshold <= len(members):
            raise CodecUsageError(f"quorum {self.name}: threshold {self.threshold} outside 1..{len(members)}")
        if len(set(members)) != len(members):
            raise CodecUsageError(f"quorum {self.name} lists a member twice")
        subs = [x for x in members if isinstance(x, Quorum)]
        depth = 1 + max((q._depth for q in subs), default=0)
        if depth > MAX_QUORUM_DEPTH:
            raise CodecUsageError(f"quorum {self.name} is nested {depth} deep; at most {MAX_QUORUM_DEPTH}")
        named: dict[str, Quorum] = {self.name: self}
        for q in subs:
            for name, node in q._named.items():
                if named.setdefault(name, node) is not node and named[name] != node:
                    raise CodecUsageError(f"two different quorums are named {name}")
        cosigners = frozenset(x for x in members if isinstance(x, TrustAnchorID)).union(*(q._cosigners for q in subs))
        object.__setattr__(self, "_cosigners", cosigners)
        object.__setattr__(self, "_named", MappingProxyType(named))
        object.__setattr__(self, "_depth", depth)
        object.__setattr__(self, "_hash", hash((self.name, self.threshold, members)))

    def __hash__(self) -> int:
        return self._hash

    def cosigners(self) -> frozenset[TrustAnchorID]:
        return self._cosigners

    def quorums(self) -> Mapping[str, Quorum]:
        """Every quorum in the DAG, by name (this one included)."""
        return self._named

    def _count(self, valid: frozenset[bytes], memo: dict[int, bool]) -> int:
        """How many members are met. Called once per node per evaluation (the memo is by identity)."""
        return sum(1 for x in self.members if _member_met(x, valid, memo))

    def satisfied(self, valid: frozenset[bytes]) -> frozenset[str]:
        """The names of every quorum in the DAG that ``valid`` meets (the demo's "groups satisfied")."""
        memo: dict[int, bool] = {}
        return frozenset(name for name, q in self._named.items() if _member_met(q, valid, memo))

    def unsatisfied(self, valid: frozenset[bytes]) -> tuple[str, ...]:
        """Empty if met; otherwise this quorum's name, then its unmet members' names (text only, D33)."""
        memo: dict[int, bool] = {}
        if _member_met(self, valid, memo):
            return ()
        return (self.name, *(str(x) if isinstance(x, TrustAnchorID) else x.name
                             for x in self.members if not _member_met(x, valid, memo)))  # fmt: skip


def _member_met(member: TrustAnchorID | Quorum, valid: frozenset[bytes], memo: dict[int, bool]) -> bool:
    if isinstance(member, TrustAnchorID):
        return member.raw in valid
    key = id(member)  # a shared node is evaluated once per call, so evaluation is linear in the DAG
    if key not in memo:
        memo[key] = member._count(valid, memo) >= member.threshold
    return memo[key]


@dataclass(frozen=True)
class TrustedSubtree:
    """A subtree known to be consistent with the relying party's cosigner requirements (§7.4)."""

    log_number: int
    start: int
    end: int
    subtree_hash: bytes
    landmark: int | None = None  # which landmark it belongs to ({caID 1 N L}), for selection in 3c
    expiry: int | None = None  # the landmark's expiry (POSIX seconds) when derived (§7.4); None when hand-typed

    def __post_init__(self) -> None:
        _check_log_number(self.log_number)
        if self.expiry is not None and (isinstance(self.expiry, bool) or not isinstance(self.expiry, int)
                                        or not 0 <= self.expiry <= UINT64_MAX):  # fmt: skip
            raise CodecUsageError("a landmark expiry is a uint64 of POSIX seconds")
        if self.landmark is not None and (isinstance(self.landmark, bool) or not isinstance(self.landmark, int)
                                          or not 1 <= self.landmark <= UINT48_MAX):  # fmt: skip
            raise CodecUsageError("a trusted subtree's landmark is 1 to 2^48 - 1 (landmark 0 has no subtrees)")
        if self.expiry is not None and self.landmark is None:
            raise CodecUsageError("a derived subtree (with an expiry) names its landmark")
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
    ca_key: CosignerKey | None = None  # from the CA certificate (§5.5); the store adds it to its cosigners
    reference_sizes: tuple[tuple[int, int], ...] = ()  # (log, reference checkpoint size) of derived subtrees (§7.4)

    def __post_init__(self) -> None:
        object.__setattr__(self, "trusted_subtrees", tuple(self.trusted_subtrees))
        object.__setattr__(self, "revoked", tuple(self.revoked))
        object.__setattr__(self, "reference_sizes", tuple(tuple(x) for x in self.reference_sizes))
        check_ca_id(self.ca_id)
        for log, size in self.reference_sizes:
            _check_log_number(log)
            if isinstance(log, bool) or isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= UINT48_MAX:
                raise CodecUsageError(f"reference size {size!r} for log {log!r} isn't 1 to 2^48 - 1")
        if len({log for log, _ in self.reference_sizes}) != len(self.reference_sizes):
            raise CodecUsageError("one reference size per log")
        if self.ca_id not in self.policy.cosigners():
            raise CodecUsageError("the CA's own cosigner must be in the policy (§7.3; D33)")
        if not self.policy.unsatisfied(frozenset()):
            raise CodecUsageError("a policy must refuse a certificate with no valid cosignatures (D33)")
        keys = [(t.log_number, t.start, t.end) for t in self.trusted_subtrees]
        if len(keys) != len(set(keys)):
            raise CodecUsageError("two trusted subtrees name the same (log, start, end)")

    def trusted(self, log_number: int, start: int, end: int) -> TrustedSubtree | None:
        return next((t for t in self.trusted_subtrees if (t.log_number, t.start, t.end) == (log_number, start, end)), None)

    @classmethod
    def from_ca_certificate(
        cls,
        ca: CACertificate,
        policy: CosignerPolicy,
        trusted_subtrees: Sequence[TrustedSubtree] = (),
        revoked: Sequence[RevokedRange] = (),
    ) -> CAPolicy:
        """§7.1 from a CA certificate (§5.5): its ID, its cosigner key, and its serial bounds as revoked
        ranges, plus any out-of-band ranges and subtrees."""
        return cls(ca.ca_id, policy, tuple(trusted_subtrees), (*ca.revoked(), *revoked), ca.key)


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
        cosigners = dict(self.cosigners)
        for ca in self.cas:  # a CA certificate's key is the CA's cosigner (§7.1); a different one is a conflict
            if ca.ca_key is not None and cosigners.setdefault(ca.ca_id, ca.ca_key) != ca.ca_key:
                raise CodecUsageError(f"{ca.ca_id}: the CA certificate's key differs from the configured cosigner key")
        object.__setattr__(self, "cosigners", MappingProxyType(cosigners))
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

    def with_ca(self, ca: CAPolicy, *, replacing: CAPolicy) -> MTCTrustStore:
        """A new store with ``ca`` in place of ``replacing``, by compare-and-swap: refused unless this
        store's CA with that ID is still exactly ``replacing``, so a change made from a stale store (a
        revocation, or derived subtrees) never overwrites a newer one. Its policy and key must be the
        ones it replaces, so subtrees derived under one policy can't serve another (D36); changing who
        must sign means building a new store. Derived subtrees go through :meth:`with_derived`."""
        old = self.ca_for(ca.ca_id.raw)
        if old is None:
            raise CodecUsageError(f"no CA {ca.ca_id} to replace")
        if old != replacing:
            raise CodecUsageError(f"{ca.ca_id}: the CA changed since it was read (a derivation or `replacing`); start again")
        if ca.policy != old.policy or ca.ca_key != old.ca_key:
            raise CodecUsageError(f"{ca.ca_id}: with_ca keeps the CA's policy and key")
        return replace(self, cas=tuple(ca if c is old else c for c in self.cas))

    def with_derived(self, derived: DerivedLandmarks) -> MTCTrustStore:
        """Install a derivation (§7.4) by compare-and-swap: only if this store's CA is still exactly the
        one it was derived from and the CA's and policy's cosigner keys are unchanged, so a revocation
        or key change installed in between is never lost or bypassed (D36)."""
        if any(self.cosigners.get(c) != k for c, k in derived.keys.items()):
            raise CodecUsageError(f"{derived.base.ca_id}: a cosigner key changed since the derivation; derive again")
        return self.with_ca(derived.ca, replacing=derived.base)


# --------------------------------------------------------------------------- #
# §5.5: the CA certificate (configuration input, so every refusal is CodecUsageError; D35)
# --------------------------------------------------------------------------- #

MTC_CA_EXTENSION = "1.3.6.1.5.5.7.1.38"  # id-pe-mtcCertificationAuthority-SHA256 (§5.5)
ALG_UNSIGNED = "1.3.6.1.5.5.7.6.36"  # id-alg-unsigned (RFC 9925)
RDNA_UNSIGNED = "1.3.6.1.5.5.7.25.1"  # id-rdna-unsigned (RFC 9925)
MIN_SERIAL, MAX_SERIAL = 1 << 48, UINT64_MAX  # mtcMinSerial, mtcMaxSerial (§5.5)
# The CA cosigner's sigAlg, mapped explicitly to the SPKI algorithm it needs (D35).
_CA_SIG_ALGS = {x509.BY_NAME[a].oid: x509.BY_NAME[a] for a in COSIGNER_ALGORITHMS}
_CA_UNDERSTOOD = {MTC_CA_EXTENSION, x509.KEY_USAGE, x509.BASIC_CONSTRAINTS}


@dataclass(frozen=True)
class CACertificate:
    """What a relying party takes from a Merkle Tree CA certificate (§5.5, §7.1)."""

    ca_id: TrustAnchorID
    key: CosignerKey
    min_serial: int
    max_serial: int

    def revoked(self) -> tuple[RevokedRange, ...]:
        """[0, minSerial) and [maxSerial + 1, 2^64), empty ones dropped (§7.1)."""
        ranges = (RevokedRange(0, self.min_serial) if self.min_serial else None,
                  RevokedRange(self.max_serial + 1, 1 << 64) if self.max_serial < UINT64_MAX else None)  # fmt: skip
        return tuple(r for r in ranges if r is not None)


def _check_serial_bounds(min_serial: int, max_serial: int) -> None:
    for value in (min_serial, max_serial):
        if isinstance(value, bool) or not isinstance(value, int) or not MIN_SERIAL <= value <= MAX_SERIAL:
            raise CodecUsageError(f"minSerial and maxSerial are in [2^48, 2^64 - 1] (§5.5), not {value!r}")
    if min_serial > max_serial:  # the demo accepts this and revokes everything; qTLS refuses it (D35)
        raise CodecUsageError("minSerial is greater than maxSerial")


def parse_ca_certificate(cert_der: bytes) -> CACertificate:
    """A Merkle Tree CA certificate (§5.5), strictly. Its signature and validity aren't checked: it's
    a trust anchor, trusted by configuration (RFC 5280 §6.1.1(d); RFC 9925 makes it unsigned)."""
    try:
        return _parse_ca_certificate(bytes(cert_der))
    except (der.DerError, AlertError, ValueError, IndexError, TypeError) as exc:
        raise CodecUsageError(f"malformed MTC CA certificate: {exc}") from None


def _parse_ca_certificate(data: bytes) -> CACertificate:
    parts = der.parse(data).expect(der.SEQUENCE).children()
    if len(parts) != 3:
        raise CodecUsageError("a certificate has three parts")
    tbs, outer, sig = parts
    sig.expect(der.BIT_STRING)
    fields = tbs.expect(der.SEQUENCE).children()
    if len(fields) < 8 or fields[0].tag != 0xA0 or fields[-1].tag != 0xA3:
        raise CodecUsageError("not a v3 TBSCertificate with extensions")
    (version,) = fields[0].children()
    if version.as_int() != 2:
        raise CodecUsageError("a CA certificate is X.509 v3")
    serial, inner, _issuer, validity, subject, spki = fields[1:7]
    if [f.tag for f in fields[7:-1]] not in ([], [0x81], [0x82], [0x81, 0x82]):  # issuer/subjectUniqueID
        raise CodecUsageError("unexpected TBSCertificate fields")
    serial.as_int()
    if inner.expect(der.SEQUENCE).raw != outer.expect(der.SEQUENCE).raw:
        raise CodecUsageError("inner and outer signature algorithms differ (RFC 5280 §4.1.1.2)")
    for t in validity.expect(der.SEQUENCE).children():
        t.as_time()
    raw_id = x509.trust_anchor_id_of(subject.raw)
    if raw_id is None:
        raise CodecUsageError("the subject isn't a trust anchor ID name (§5.5, TAI §4.1)")
    ca_id = check_ca_id(TrustAnchorID(raw_id))
    spki_oid, public_key = x509.parse_spki(spki.raw)

    (ext_seq,) = fields[-1].children()
    exts: dict[str, tuple[bool, bytes]] = {}
    for node in ext_seq.expect(der.SEQUENCE).children():
        items = node.expect(der.SEQUENCE).children()
        if len(items) not in (2, 3):
            raise CodecUsageError("bad Extension")
        oid, critical = items[0].as_oid(), len(items) == 3 and items[1].as_bool()
        if len(items) == 3 and not critical:
            raise CodecUsageError("critical FALSE must be omitted (DER DEFAULT)")
        if oid in exts:
            raise CodecUsageError(f"extension {oid} appears twice")
        if critical and oid not in _CA_UNDERSTOOD:
            raise CodecUsageError(f"unrecognised critical extension {oid}")
        exts[oid] = (critical, items[-1].as_octets())
    if not exts:
        raise CodecUsageError("extensions must not be empty (RFC 5280)")

    if MTC_CA_EXTENSION not in exts:
        raise CodecUsageError("no Merkle Tree CA extension (§5.5)")
    critical, value = exts[MTC_CA_EXTENSION]
    if not critical:
        raise CodecUsageError("the Merkle Tree CA extension must be critical (§5.5)")
    body = der.parse(value).expect(der.SEQUENCE).children()
    if len(body) != 3:
        raise CodecUsageError("MTCCertificationAuthority is SEQUENCE {sigAlg, minSerial, maxSerial}")
    alg_parts = body[0].expect(der.SEQUENCE).children()
    alg = _CA_SIG_ALGS.get(alg_parts[0].as_oid()) if len(alg_parts) == 1 else None
    if alg is None:
        raise CodecUsageError("sigAlg isn't a cosigner algorithm qTLS verifies, with parameters absent (D33)")
    if spki_oid != alg.spki_oid:
        raise CodecUsageError(f"sigAlg {alg.name} doesn't match the subject public key")
    min_serial, max_serial = body[1].as_int(), body[2].as_int()
    _check_serial_bounds(min_serial, max_serial)

    if x509.KEY_USAGE not in exts or x509.KEY_CERT_SIGN not in der.parse(exts[x509.KEY_USAGE][1]).as_named_bits():
        raise CodecUsageError("key usage must be present and assert keyCertSign (§5.5)")
    bc = der.parse(exts[x509.BASIC_CONSTRAINTS][1]).expect(der.SEQUENCE).children() if x509.BASIC_CONSTRAINTS in exts else []
    if not bc or not bc[0].as_bool():
        raise CodecUsageError("basic constraints must be present with cA TRUE (§5.5)")
    return CACertificate(ca_id, CosignerKey(alg.name, public_key), min_serial, max_serial)


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


def _wanted_cosigner(store: MTCTrustStore, ca: CAPolicy, peer_id: bytes) -> tuple[TrustAnchorID, CosignerKey] | None:
    """The configured key for ``peer_id`` if it's the CA or one of its policy's cosigners, else None:
    only those are ever verified (D33), in step 12 and for checkpoints (§7.4)."""
    found = store.cosigner(peer_id)
    if found is None or (found[0] != ca.ca_id and found[0] not in ca.policy.cosigners()):
        return None
    return found


def unmet_requirements(ca: CAPolicy, valid: frozenset[bytes]) -> tuple[str, ...]:
    """What ``valid`` (the cosigner IDs whose signatures verified) lacks under ``ca``: the CA's own
    signature, always required (§7.3), then the policy. Empty means accepted. The one evaluation
    behind §7.2 step 12 and §7.4's checkpoint sufficiency (D35, D36)."""
    unmet = ca.policy.unsatisfied(valid)
    if ca.ca_id.raw not in valid:
        unmet = (f"{ca.ca_id} (the CA)", *unmet)
    return unmet


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
    valid: set[bytes] = set()
    errors: list[str] = []
    for sig in proof.signatures:
        found = _wanted_cosigner(store, ca, sig.cosigner_id)
        if found is None:
            continue
        signer, key = found
        message = cosigned_subtree(signer, log, proof.start, proof.end, subtree_hash)
        try:
            crypto.sig_verify(key.alg, key.public_key, message, sig.signature, store.backends[key.alg])
            valid.add(signer.raw)
        except crypto.InvalidSignature:
            errors.append(str(signer))
    unmet = unmet_requirements(ca, frozenset(valid))
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
# §6.4: landmarks and their published form (configuration input: CodecUsageError; D36)
# --------------------------------------------------------------------------- #

EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
MAX_LANDMARK_DOCUMENT = 1 << 20  # bytes; 2^48 lines can't be meant
_DOC_NUMBER = rb"(0|[1-9][0-9]{0,19})"  # ASCII digits, no sign or leading zero, at most 20 of them
_DOC_HEADER = re.compile(_DOC_NUMBER)
_DOC_LINE = re.compile(_DOC_NUMBER + rb" " + _DOC_NUMBER)


@dataclass(frozen=True)
class Landmark:
    """A landmark (§6.4.1): its number, the log's size when it was allocated, and its expiry (POSIX seconds)."""

    number: int
    tree_size: int
    expiry: int

    def __post_init__(self) -> None:
        for value in (self.number, self.tree_size, self.expiry):
            if isinstance(value, bool) or not isinstance(value, int):
                raise CodecUsageError("landmark fields are ints")
        if not (0 <= self.number <= self.tree_size <= UINT48_MAX and 0 <= self.expiry <= UINT64_MAX):
            raise CodecUsageError(f"{self} is out of range (§6.4.1)")
        if self.number == 0 and (self.tree_size, self.expiry) != (0, 0):
            raise CodecUsageError("landmark 0 has tree size 0 and expiry 0 (§6.4.1)")

    def active(self, now: dt.datetime) -> bool:
        """Not yet expired: ``now`` <= expiry, inclusive like a notAfter (D24), and a landmark's expiry
        is at least its entries' notAfter (§6.4.1). Landmark 0 is never active."""
        return self.number != 0 and _seconds(now) <= (self.expiry, 0)


def _seconds(now: dt.datetime) -> tuple[int, int]:
    """(whole seconds, microseconds) since the Epoch, exact (no float, no timedelta overflow)."""
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise CodecUsageError("now must be a timezone-aware datetime")
    delta = now - EPOCH
    return delta.days * 86400 + delta.seconds, delta.microseconds


def _check_sequence(landmarks: Sequence[Landmark]) -> None:
    if not landmarks or landmarks[0] != Landmark(0, 0, 0):
        raise CodecUsageError("a landmark sequence starts at landmark 0 (§6.4.1)")
    for prev, cur in zip(landmarks, landmarks[1:]):
        if cur.number != prev.number + 1 or cur.tree_size <= prev.tree_size or cur.expiry < prev.expiry:
            raise CodecUsageError(f"landmark {cur.number} doesn't follow {prev.number} (§6.4.1)")


def encode_landmarks(landmarks: Sequence[Landmark], now: dt.datetime) -> bytes:
    """§6.4.3 for a whole landmark sequence: the latest number, then the active landmarks and the
    newest expired one (landmark 0 if no other has expired), newest first."""
    _seconds(now)
    landmarks = tuple(landmarks)
    _check_sequence(landmarks)
    oldest = max(lm.number for lm in landmarks if not lm.active(now))
    lines = [f"{lm.tree_size} {lm.expiry}\n" for lm in reversed(landmarks[oldest:])]
    return (f"{landmarks[-1].number}\n" + "".join(lines)).encode("ascii")


@dataclass(frozen=True)
class LandmarkDocument:
    """A decoded §6.4.3 document at ``now``: the active landmarks, oldest first, and the newest
    expired one (``boundary``), which gives the oldest active landmark's previous tree size."""

    latest: int
    active: tuple[Landmark, ...]
    boundary: Landmark

    def landmark(self, number: int) -> Landmark:
        found = next((lm for lm in self.active if lm.number == number), None)
        if found is None:
            raise CodecUsageError(f"landmark {number} isn't active in this document")
        return found

    def subtrees(self, number: int) -> tuple[tuple[int, int], ...]:
        """Landmark ``number``'s non-empty landmark subtrees (§6.4.1)."""
        lm = self.landmark(number)
        prev = self.boundary if number - 1 == self.boundary.number else self.landmark(number - 1)
        return tuple(st for st in merkle.find_subtrees(prev.tree_size, lm.tree_size) if st[0] < st[1])


def decode_landmarks(data: bytes, now: dt.datetime) -> LandmarkDocument:
    """§6.4.3, strictly: every line is checked for syntax and order, then lines after the first
    expired one are ignored (a decoder may stop there). Every refusal is ``CodecUsageError``."""
    if not isinstance(data, bytes | bytearray | memoryview):
        raise CodecUsageError("a landmark document is bytes")
    data = bytes(data)
    _seconds(now)
    if len(data) > MAX_LANDMARK_DOCUMENT:
        raise CodecUsageError(f"a landmark document over {MAX_LANDMARK_DOCUMENT} bytes")
    if not data.endswith(b"\n"):
        raise CodecUsageError("every line of a landmark document ends in a newline (§6.4.3)")
    header, *body = data[:-1].split(b"\n")
    if not _DOC_HEADER.fullmatch(header):
        raise CodecUsageError(f"bad header line {header[:40]!r}")
    latest = int(header)
    if latest > UINT48_MAX:
        raise CodecUsageError("latest_landmark is at most 2^48 - 1 (§6.4.3)")
    if not 1 <= len(body) <= latest + 1:
        raise CodecUsageError(f"{len(body)} landmark lines for latest landmark {latest} (§6.4.3)")
    parsed: list[Landmark] = []
    for i, line in enumerate(body):
        match = _DOC_LINE.fullmatch(line)
        if not match:
            raise CodecUsageError(f"bad landmark line {line[:60]!r}")
        size, expiry = int(match[1]), int(match[2])
        if size > UINT48_MAX or expiry > UINT64_MAX:
            raise CodecUsageError(f"landmark line {line[:60]!r} is out of range (§6.4.3)")
        if parsed and not (size < parsed[-1].tree_size and expiry <= parsed[-1].expiry):
            raise CodecUsageError("tree sizes must strictly decrease and expiries not increase (§6.4.3)")
        parsed.append(Landmark(latest - i, size, expiry))  # refuses size < number and a landmark 0 other than "0 0"
    first_expired = next((i for i, lm in enumerate(parsed) if not lm.active(now)), None)
    if first_expired is None:
        raise CodecUsageError("a landmark document needs an expired landmark (§6.4.3)")
    return LandmarkDocument(latest, tuple(reversed(parsed[:first_expired])), parsed[first_expired])


# --------------------------------------------------------------------------- #
# §7.4: trusted subtrees from a cosigned reference checkpoint and consistency proofs (D36)
# --------------------------------------------------------------------------- #


def _check_hash(value: object, what: str) -> None:
    if not isinstance(value, bytes) or len(value) != HASH_SIZE:
        raise CodecUsageError(f"{what} is {HASH_SIZE} bytes")


@dataclass(frozen=True)
class CheckpointSignature:
    """A timestamped cosignature on a checkpoint: CosignedSubtree(timestamp, 0, size, root) (§5.3.1).
    The timestamp is bound into the message; qTLS doesn't judge its freshness."""

    cosigner_id: bytes  # the peer's bytes, matched bytewise (D32)
    timestamp: int
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.cosigner_id, bytes) or not isinstance(self.signature, bytes):
            raise CodecUsageError("cosigner_id and signature are bytes")
        if isinstance(self.timestamp, bool) or not isinstance(self.timestamp, int) or not 0 <= self.timestamp <= UINT64_MAX:
            raise CodecUsageError("a checkpoint timestamp is a uint64")


@dataclass(frozen=True)
class LargerCheckpoint:
    """A cosigned checkpoint containing the reference one, with the consistency proof between them
    (§7.4's second option). A plain record: anything wrong in it means its signers don't count."""

    size: int
    root_hash: bytes
    cosignatures: tuple[CheckpointSignature, ...]
    consistency_proof: bytes


@dataclass(frozen=True)
class ReferenceCheckpoint:
    """A log's reference checkpoint (§7.4): its size, root, the cosignatures on it, and larger
    checkpoints that vouch for it."""

    size: int
    root_hash: bytes
    cosignatures: tuple[CheckpointSignature, ...] = ()
    larger: tuple[LargerCheckpoint, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.size, bool) or not isinstance(self.size, int) or not 1 <= self.size <= UINT48_MAX:
            raise CodecUsageError("a reference checkpoint has 1 to 2^48 - 1 entries")
        _check_hash(self.root_hash, "root_hash")
        object.__setattr__(self, "cosignatures", tuple(self.cosignatures))
        object.__setattr__(self, "larger", tuple(self.larger))
        if not all(isinstance(c, CheckpointSignature) for c in self.cosignatures):
            raise CodecUsageError("cosignatures are CheckpointSignatures")
        if not all(isinstance(c, LargerCheckpoint) for c in self.larger):
            raise CodecUsageError("larger checkpoints are LargerCheckpoints")


@dataclass(frozen=True)
class SubtreeProof:
    """A CA's published subtree consistency proof against the reference checkpoint (§4.4, §7.4).
    A plain record of peer bytes: looked up by the (start, end) the document gives, never trusted."""

    start: int
    end: int
    subtree_hash: bytes
    proof: bytes


@dataclass(frozen=True)
class LogLandmarks:
    """One log's update: its landmark document, reference checkpoint and subtree proofs."""

    log_number: int
    document: LandmarkDocument
    checkpoint: ReferenceCheckpoint
    proofs: tuple[SubtreeProof, ...] = ()

    def __post_init__(self) -> None:
        _check_log_number(self.log_number)
        object.__setattr__(self, "proofs", tuple(self.proofs))
        if not isinstance(self.document, LandmarkDocument) or not isinstance(self.checkpoint, ReferenceCheckpoint):
            raise CodecUsageError("a log update is a LandmarkDocument and a ReferenceCheckpoint")
        if not all(isinstance(p, SubtreeProof) for p in self.proofs):
            raise CodecUsageError("proofs are SubtreeProofs")


DISCARD_REASONS = frozenset({
    "checkpoint-cosigners", "beyond-checkpoint", "subtree-proof-missing", "subtree-proof-duplicate",
    "subtree-proof-malformed", "subtree-consistency", "subtree-conflict", "newer-than-discarded", "reference-regressed",
    "over-bound",
})  # fmt: skip


@dataclass(frozen=True)
class DiscardedLandmark:
    log_number: int
    landmark: Landmark
    reason: str


@dataclass(frozen=True)
class DerivedLandmarks:
    """The CA's own policy with its derived subtrees; every landmark this call rejected, with why (a
    rejected attempt at a landmark validated earlier leaves that one held; ``over-bound`` ones are gone);
    and what it was derived from: the CA as it was (``base``) and the keys of the CA's and policy's
    cosigners. Install it with :meth:`MTCTrustStore.with_derived`, which checks both are unchanged."""

    ca: CAPolicy
    discarded: tuple[DiscardedLandmark, ...]
    base: CAPolicy
    keys: Mapping[TrustAnchorID, CosignerKey]
    # Per updated log: "ok", "checkpoint-cosigners" or "reference-regressed", so a failed or replayed
    # refresh is visible even when every landmark it offered was already held.
    log_status: Mapping[int, str]


def checkpoint_cosigners(store: MTCTrustStore, ca: CAPolicy, log_number: int, checkpoint: ReferenceCheckpoint) -> frozenset[bytes]:
    """The CA and policy cosigners whose checkpoint signatures vouch for ``checkpoint`` (§7.4): on it,
    or on a larger checkpoint with a valid consistency proof to it. Never raises on peer bytes."""
    log = log_id(ca.ca_id, log_number)
    valid: set[bytes] = set()

    def count(sigs: Sequence[CheckpointSignature], size: int, root: bytes) -> None:
        for sig in sigs:
            found = None if sig.cosigner_id in valid else _wanted_cosigner(store, ca, sig.cosigner_id)
            if found is None:
                continue
            signer, key = found
            message = cosigned_subtree(signer, log, 0, size, root, timestamp=sig.timestamp)
            try:
                crypto.sig_verify(key.alg, key.public_key, message, sig.signature, store.backends[key.alg])
                valid.add(signer.raw)
            except crypto.InvalidSignature:
                pass

    count(checkpoint.cosignatures, checkpoint.size, checkpoint.root_hash)
    for larger in checkpoint.larger:
        if _consistent(checkpoint, larger):
            count(larger.cosignatures, larger.size, larger.root_hash)
    return frozenset(valid)


def _consistent(ref: ReferenceCheckpoint, larger: LargerCheckpoint) -> bool:
    if (isinstance(larger.size, bool) or not isinstance(larger.size, int) or not ref.size <= larger.size <= UINT48_MAX
            or not isinstance(larger.root_hash, bytes) or len(larger.root_hash) != HASH_SIZE
            or not isinstance(larger.consistency_proof, bytes)
            or not all(isinstance(c, CheckpointSignature) for c in larger.cosignatures)):  # fmt: skip
        return False
    try:
        merkle.verify_consistency(n=larger.size, start=0, end=ref.size, proof=larger.consistency_proof,
                                  subtree_hash=ref.root_hash, root_hash=larger.root_hash)  # fmt: skip
    except merkle.MerkleError:
        return False
    return True


def derive_landmarks(
    store: MTCTrustStore, ca_id: TrustAnchorID, updates: Sequence[LogLandmarks], *, max_active_landmarks: int,
    now: dt.datetime,
) -> DerivedLandmarks:
    """§7.4 for one CA across its logs, merged onto what earlier derivations validated (D36).

    ``now`` is authoritative: only landmarks active at ``now`` are held, whether held from before or
    offered by an update (a document's decode time only governed its grammar). Per updated log,
    oldest first: the checkpoint's signers must meet the CA's own requirements (the step-12
    evaluation) and its size must not be below the one recorded before; a landmark already held is
    kept as it is (no proof needed), and one re-published differently conflicts; a new landmark must
    fit in the checkpoint, each of its subtrees needs a valid consistency proof, and none may repeat a
    subtree known under another landmark or with another hash. The first landmark that fails is
    discarded with every newer one in its log. Then the per-CA bound over everything held: the newest
    by expiry go. Hand-typed subtrees are kept and not counted. Nothing in a document, proof or
    checkpoint raises; only arguments do."""
    _seconds(now)
    ca = store.ca_for(ca_id.raw)
    if ca is None:
        raise CodecUsageError(f"no CA {ca_id} in the store")
    if isinstance(max_active_landmarks, bool) or not isinstance(max_active_landmarks, int) or max_active_landmarks < 0:
        raise CodecUsageError("max_active_landmarks is a non-negative int")
    updates = tuple(updates)
    if not all(isinstance(u, LogLandmarks) for u in updates):
        raise CodecUsageError("updates are LogLandmarks")
    if len({u.log_number for u in updates}) != len(updates):
        raise CodecUsageError("one update per log, so a log's landmarks are judged against one checkpoint")
    hand = tuple(t for t in ca.trusted_subtrees if t.expiry is None)
    # Earlier derived landmarks still active: (log, number) -> (landmark, its subtrees by start).
    held: dict[tuple[int, int], tuple[Landmark, tuple[TrustedSubtree, ...]]] = {}
    for t in ca.trusted_subtrees:
        if t.expiry is not None:
            key = (t.log_number, t.landmark)
            lm, ts = held.get(key, (Landmark(t.landmark, t.end, t.expiry), ()))  # type: ignore[arg-type]
            held[key] = (replace(lm, tree_size=max(lm.tree_size, t.end)), tuple(sorted((*ts, t), key=lambda x: x.start)))  # type: ignore[index]
    held = {k: v for k, v in held.items() if v[0].active(now)}
    # Every subtree already trusted: (log, start, end) -> (its landmark, None if hand-typed; its hash).
    known = {(t.log_number, t.start, t.end): (None, t.subtree_hash) for t in hand}
    known |= {(t.log_number, t.start, t.end): (t.landmark, t.subtree_hash) for _, ts in held.values() for t in ts}
    sizes = dict(ca.reference_sizes)
    discarded: list[DiscardedLandmark] = []
    status: dict[int, str] = {}
    for update in updates:
        ref, log = update.checkpoint, update.log_number
        offered = [lm for lm in update.document.active if lm.active(now)]  # expired at now: as if absent
        problem = None
        if unmet_requirements(ca, checkpoint_cosigners(store, ca, log, ref)):
            problem = "checkpoint-cosigners"
        elif ref.size < sizes.get(log, 0):
            problem = "reference-regressed"
        status[log] = problem or "ok"
        if problem is not None:  # the log keeps what it had, recorded size included
            discarded += (DiscardedLandmark(log, lm, problem) for lm in offered if (log, lm.number) not in held)
            continue
        sizes[log] = ref.size
        proofs: dict[object, SubtreeProof | None] = {}
        for p in update.proofs:  # a (start, end) given twice is ambiguous: None
            if not (isinstance(p.start, int) and isinstance(p.end, int)):
                continue  # names no subtree the document asks for: ignored, like any unexpected proof
            key = (p.start, p.end)
            proofs[key] = None if key in proofs else p
        failed = False
        for lm in offered:  # oldest first
            ranges = update.document.subtrees(lm.number)
            mine = held.get((log, lm.number))
            subtrees: list[TrustedSubtree] = []
            reason: str | None = None
            if mine is not None:  # validated before: kept as it is, unless re-published differently
                if tuple((t.start, t.end) for t in mine[1]) == ranges:  # the same ranges: the same tree size
                    continue
                reason = "subtree-conflict"
            elif lm.tree_size > ref.size:
                reason = "beyond-checkpoint"
            elif failed:
                reason = "newer-than-discarded"
            for start, end in ranges if reason is None else ():
                reason = _subtree_problem(proofs, start, end, ref)
                if reason is None and known.get((log, start, end), (lm.number, proofs[(start, end)].subtree_hash)) != (  # type: ignore[union-attr]
                        lm.number, proofs[(start, end)].subtree_hash):  # type: ignore[union-attr]  # fmt: skip
                    reason = "subtree-conflict"  # already trusted under another landmark or with another hash
                if reason is not None:
                    break
                subtrees.append(TrustedSubtree(log, start, end, proofs[(start, end)].subtree_hash,  # type: ignore[union-attr]
                                               lm.number, lm.expiry))  # fmt: skip
            if reason is not None:
                failed = True
                discarded.append(DiscardedLandmark(log, lm, reason))
                continue
            held[(log, lm.number)] = (lm, tuple(subtrees))  # disjoint from every other offered landmark's ranges
    # The per-CA bound over everything held: drop the newest by expiry (ties: higher log, then higher
    # number). Expiry never decreases within a log, so each log keeps a contiguous oldest prefix.
    order = sorted(held, key=lambda k: (held[k][0].expiry, k[0], k[1]))
    discarded += (DiscardedLandmark(k[0], held[k][0], "over-bound") for k in order[max_active_landmarks:])
    # Output order: hand-typed as configured, then derived by (log, landmark, start).
    trusted = hand + tuple(t for k in sorted(order[:max_active_landmarks]) for t in held[k][1])
    derived = replace(ca, trusted_subtrees=trusted, reference_sizes=tuple(sorted(sizes.items())))
    keys = {c: store.cosigners[c] for c in ca.policy.cosigners() | {ca.ca_id}}
    return DerivedLandmarks(derived, tuple(discarded), ca, MappingProxyType(keys), MappingProxyType(status))


def _subtree_problem(proofs: Mapping[object, SubtreeProof | None], start: int, end: int, ref: ReferenceCheckpoint) -> str | None:
    if (start, end) not in proofs:
        return "subtree-proof-missing"
    p = proofs[(start, end)]
    if p is None:
        return "subtree-proof-duplicate"
    if (not isinstance(p.subtree_hash, bytes) or len(p.subtree_hash) != HASH_SIZE
            or not isinstance(p.proof, bytes) or len(p.proof) % HASH_SIZE):  # fmt: skip
        return "subtree-proof-malformed"
    try:
        merkle.verify_consistency(n=ref.size, start=start, end=end, proof=p.proof, subtree_hash=p.subtree_hash,
                                  root_hash=ref.root_hash)  # fmt: skip
    except merkle.MerkleError:
        return "subtree-consistency"
    return None


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

    def sign_checkpoint(self, log: TrustAnchorID, size: int, root_hash: bytes, timestamp: int) -> CheckpointSignature:
        """A timestamped checkpoint cosignature over [0, size) (§5.3.1)."""
        message = cosigned_subtree(self.cosigner_id, log, 0, size, root_hash, timestamp=timestamp)
        return CheckpointSignature(self.cosigner_id.raw, timestamp, self.key.sign(message, seed=self.signing_seed))


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
        self.landmark_expiries: list[int] = [0]  # and expiry 0; POSIX seconds
        self._max_not_after = 0  # the latest notAfter logged, POSIX seconds (§6.4.1's expiry floor)
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
        self._max_not_after = max(self._max_not_after, _seconds(not_after)[0])
        return index

    def checkpoint(self) -> int:
        if self.size <= self.checkpoints[-1]:
            raise CodecUsageError("a checkpoint needs new entries")
        self.checkpoints.append(self.size)
        return self.size

    def add_landmark(self, expiry: int | None = None) -> int:
        """Allocate the next landmark at the current size (§6.4.1); returns its number. Its expiry
        (POSIX seconds) is at least the previous one's and every logged notAfter (§6.4.1 MUSTs);
        None picks the smallest such value."""
        if self.size <= self.landmarks[-1]:
            raise CodecUsageError("landmark tree sizes strictly increase (§6.4.1)")
        floor = max(self.landmark_expiries[-1], self._max_not_after)
        if expiry is None:
            expiry = floor
        if isinstance(expiry, bool) or not isinstance(expiry, int) or not 0 <= expiry <= UINT64_MAX:
            raise CodecUsageError("a landmark expiry is a uint64 of POSIX seconds")
        if expiry < self.landmark_expiries[-1]:
            raise CodecUsageError("landmark expiries never decrease (§6.4.1)")
        if expiry < self._max_not_after:
            raise CodecUsageError("a landmark expires no earlier than every certificate below it (§6.4.1)")
        self.landmarks.append(self.size)
        self.landmark_expiries.append(expiry)
        return len(self.landmarks) - 1

    def landmark_sequence(self) -> tuple[Landmark, ...]:
        """Every landmark so far, from landmark 0 (§6.4.1): the input to :func:`encode_landmarks`."""
        return tuple(Landmark(n, size, exp) for n, (size, exp) in enumerate(zip(self.landmarks, self.landmark_expiries)))

    def reference_checkpoint(self, cosigners: Sequence[Cosigner], timestamp: int, size: int | None = None) -> ReferenceCheckpoint:
        """The checkpoint of the first ``size`` entries (default: all), cosigned with ``timestamp`` (§7.4)."""
        size = self.size if size is None else size
        if not 0 < size <= self.size:
            raise CodecUsageError(f"no checkpoint of size {size} in a log of {self.size}")
        root = self.tree().hash(0, size)
        return ReferenceCheckpoint(size, root, tuple(c.sign_checkpoint(self.log_id, size, root, timestamp) for c in cosigners))

    def larger_checkpoint(self, reference_size: int, cosigners: Sequence[Cosigner], timestamp: int,
                          size: int | None = None) -> LargerCheckpoint:  # fmt: skip
        """A later checkpoint (default: all entries), cosigned, with its consistency proof to an earlier one (§7.4)."""
        ref = self.reference_checkpoint([], 0, reference_size)
        cur = self.reference_checkpoint(cosigners, timestamp, size)
        return LargerCheckpoint(cur.size, cur.root_hash, cur.cosignatures, self.tree().consistency_proof(0, ref.size, cur.size))

    def landmark_proofs(self, reference_size: int) -> tuple[SubtreeProof, ...]:
        """What a CA publishes for §7.4: each non-empty subtree of every landmark that fits in the
        reference checkpoint, with its consistency proof to it."""
        if not 0 < reference_size <= self.size:
            raise CodecUsageError(f"no checkpoint of size {reference_size} in a log of {self.size}")
        tree = self.tree()
        return tuple(SubtreeProof(s, e, tree.hash(s, e), tree.consistency_proof(s, e, reference_size))
                     for n in range(1, len(self.landmarks)) if self.landmarks[n] <= reference_size
                     for s, e in self.landmark_subtrees(n) if s < e)  # fmt: skip

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
        """Every non-empty landmark subtree, for a relying party's configuration (§7.4's "trusted
        update service" route: typed in, so ``expiry`` stays None)."""
        tree, out = self.tree(), []
        for landmark in range(1, len(self.landmarks)):
            for start, end in self.landmark_subtrees(landmark):
                if start < end:
                    out.append(TrustedSubtree(self.log_number, start, end, tree.hash(start, end), landmark))
        return tuple(out)

    def ca_certificate(self, cosigner: Cosigner, *, min_serial: int, max_serial: int, not_before: dt.datetime,
                       not_after: dt.datetime) -> bytes:  # fmt: skip
        """The CA's certificate (§5.5) in RFC 9925's unsigned form, as the WG demo builds it: serial 1,
        issuer id-rdna-unsigned, id-alg-unsigned, then key usage keyCertSign, basic constraints cA
        and the Merkle Tree CA extension, all critical."""
        if cosigner.cosigner_id != self.ca_id:
            raise CodecUsageError("the CA certificate's key is the CA cosigner's (§5.4, §5.5)")
        _check_serial_bounds(min_serial, max_serial)
        alg = x509.BY_NAME[cosigner.key.alg]
        unsigned = der.seq(der.oid(ALG_UNSIGNED))

        def ext(oid: str, value: bytes) -> bytes:
            return der.seq(der.oid(oid), der.boolean(True), der.octet_string(value))

        tbs = der.seq(
            der.explicit(0, der.integer(2)), der.integer(1), unsigned,
            der.seq(der.set_of(der.seq(der.oid(RDNA_UNSIGNED), der.utf8_string("")))),
            der.seq(der.time(not_before), der.time(not_after)),
            trust_anchor_name(self.ca_id), x509.spki(alg.name, cosigner.key.public_key),
            der.explicit(3, der.seq(
                ext(x509.KEY_USAGE, der.named_bits({x509.KEY_CERT_SIGN})),
                ext(x509.BASIC_CONSTRAINTS, der.seq(der.boolean(True))),
                ext(MTC_CA_EXTENSION, der.seq(der.seq(der.oid(alg.oid)), der.integer(min_serial), der.integer(max_serial))),
            )),
        )  # fmt: skip
        return der.seq(tbs, unsigned, der.bit_string(b""))

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
