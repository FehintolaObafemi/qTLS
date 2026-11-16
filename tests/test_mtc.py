"""Merkle Tree certificates: codecs, issuance and §7.2 verification (MTC -08; specs.md D33, D34, D13, D14).

Independent oracles:

* tests/vectors/mtc-demo/: the MTC WG's Go demo at the -08 tag generated two
  corpora (its own config, with deliberate malformations, and one in qTLS's
  profile) and verified each certificate alone under each policy. qTLS must
  reach the same verdict, for a reason that names the same failure.
* The demo's checkpoint: qTLS's tree over the corpus' log entries must hash to
  the root the demo published.
* The WG's TBSCertificate → MTCLogEntry known answers (demo/encode_test.go).
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import random
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from qtls import crypto, der, merkle, mtc, x509
from qtls.alerts import Alert, AlertError, CodecUsageError
from qtls.trust_anchor_ids import TrustAnchorID

UTC = dt.timezone.utc
VECTORS = Path(__file__).parent / "vectors" / "mtc-demo"
NOT_BEFORE, NOT_AFTER = dt.datetime(2026, 1, 1, tzinfo=UTC), dt.datetime(2026, 4, 1, tzinfo=UTC)
NOW = dt.datetime(2026, 2, 1, tzinfo=UTC)


def tai(text: str) -> TrustAnchorID:
    return TrustAnchorID.from_ascii(text)


CA = tai("32473.9")
C1, C2, C3 = CA.child(1), CA.child(2), CA.child(3)


def reason_of(call: Callable[[], object]) -> tuple[Alert, str]:
    with pytest.raises(AlertError) as info:
        call()
    return info.value.alert, info.value.reason


# --------------------------------------------------------------------------- #
# A. Identifiers and configuration
# --------------------------------------------------------------------------- #


def test_mtc_identifiers() -> None:
    """MTC -08 §5.1, §5.2, §8.2 and §8.2.1's example (CA 32473.100, log 8, landmark 42)."""
    ca = tai("32473.100")
    assert mtc.log_id(ca, 8) == tai("32473.100.0.8")
    assert mtc.landmark_id(ca, 8, 42) == tai("32473.100.1.8.42")
    assert mtc.landmark_group_id(ca, 8, 42) == tai("32473.100.2.8.42")
    assert mtc.log_id(ca, 65535).raw == ca.raw + bytes.fromhex("0083ff7f")
    assert mtc.landmark_id(ca, 1, 2**48 - 1) == ca.child(1, 1, 2**48 - 1)
    for bad in (0, 65536):
        with pytest.raises(CodecUsageError):
            mtc.log_id(ca, bad)


def test_ca_id_budget_is_enforced_where_ids_are_derived() -> None:
    mtc.landmark_id(TrustAnchorID(b"\x01" * 21), 65535, 2**48 - 1)
    with pytest.raises(CodecUsageError):
        mtc.log_id(TrustAnchorID(b"\x01" * 22), 1)


def test_origin_strings() -> None:
    """§5.3.1's example, and the demo checkpoint's origin line for its log."""
    assert mtc.origin(tai("32473.1")) == b"oid/1.3.6.1.4.1.32473.1"
    first_line = (VECTORS / "qtls" / "checkpoint").read_text().splitlines()[0]
    assert first_line == mtc.origin(mtc.log_id(CA, 3)).decode()


KEY44 = mtc.CosignerKey("ML-DSA-44", b"\x00" * crypto.SIGNATURES["ML-DSA-44"].public_key_len)


@pytest.mark.parametrize(
    "build",
    [
        lambda: mtc.RequireAll(frozenset()),  # an empty policy would accept forged one-leaf subtrees
        lambda: mtc.CAPolicy(CA, mtc.RequireAll(frozenset({C1}))),  # the CA's own cosigner isn't required
        lambda: mtc.CAPolicy(TrustAnchorID(b"\x01" * 22), mtc.RequireAll(frozenset({TrustAnchorID(b"\x01" * 22)}))),
        lambda: mtc.MTCTrustStore({CA: KEY44}, (mtc.CAPolicy(CA, mtc.RequireAll(frozenset({CA, C1}))),)),
        lambda: mtc.MTCTrustStore({CA: KEY44}, (mtc.CAPolicy(CA, mtc.RequireAll(frozenset({CA}))),) * 2),
        lambda: mtc.CosignerKey("Falcon-512", b"\x00" * 897),
        lambda: mtc.CosignerKey("ML-DSA-44", b"\x00" * 10),
        lambda: mtc.TrustedSubtree(1, 1, 3, b"\x00" * 32),
        lambda: mtc.TrustedSubtree(0, 0, 4, b"\x00" * 32),
        lambda: mtc.TrustedSubtree(65536, 0, 4, b"\x00" * 32),
        lambda: mtc.TrustedSubtree(1, 0, 2**48, b"\x00" * 32),
        lambda: mtc.TrustedSubtree(1, 0, 4, b"\x00" * 31),
        lambda: mtc.CAPolicy(CA, mtc.RequireAll(frozenset({CA})), (mtc.TrustedSubtree(1, 0, 4, b"\x00" * 32),
                                                                   mtc.TrustedSubtree(1, 0, 4, b"\x01" * 32))),
        lambda: mtc.RevokedRange(5, 5),
        lambda: mtc.RevokedRange(-1, 5),
        lambda: mtc.RevokedRange(0, 2**64 + 1),
    ],
    ids=["empty-policy", "ca-not-required", "long-ca-id", "unknown-required", "duplicate-ca", "falcon-cosigner",
         "short-key", "not-subtree", "log-0", "log-65536", "end-beyond-uint48", "short-hash", "duplicate-subtree",
         "empty-range", "negative-range", "range-past-2^64"],
)
def test_bad_configuration_is_refused_when_built(build: Callable[[], object]) -> None:
    with pytest.raises(CodecUsageError):
        build()


# --------------------------------------------------------------------------- #
# B. Codecs
# --------------------------------------------------------------------------- #


def test_null_entry_is_four_zero_bytes() -> None:
    assert mtc.NULL_LOG_ENTRY == b"\x00\x00\x00\x00"
    assert mtc.LogEntry.decode(b"\x00\x00\x00\x00") == mtc.LogEntry(None)


def test_log_entry_codec() -> None:
    exts = (mtc.EntryExtension(0, b""), mtc.EntryExtension(0xFFFF, b"\x01\x02"))
    entry = mtc.LogEntry(b"tbs", exts)
    assert mtc.LogEntry.decode(entry.encode()) == entry
    assert entry.encode() == bytes.fromhex("000a" "00000000" "ffff00020102" "0001") + b"tbs"
    for raw in ("0000" "0002", "0000", "0008" "00010000" "00010000" "0000", "0008" "00020000" "00010000" "0000"):
        assert reason_of(lambda: mtc.LogEntry.decode(bytes.fromhex(raw))) == (Alert.decode_error, "decode")
    with pytest.raises(AlertError):
        mtc.LogEntry.decode(b"\x00\x00\x00\x00\x00")  # a null entry has no body
    big = mtc.LogEntry(b"\x00" * (0xFFFF - 4))
    assert len(big.encode()) == 0xFFFF
    with pytest.raises(CodecUsageError):
        mtc.LogEntry(b"\x00" * (0xFFFF - 3)).encode()
    with pytest.raises(CodecUsageError):
        mtc.LogEntry(None, (mtc.EntryExtension(2, b""), mtc.EntryExtension(1, b""))).encode()


def test_mtc_proof_wire_format() -> None:
    """§6.2 by hand: extensions, uint48 start and end, inclusion_proof<0..2^16-1>, signatures<0..2^24-1>."""
    proof = mtc.MTCProof(0x010203040506, 0x0708090A0B0C, b"\xaa" * 32,
                         (mtc.Cosignature(b"\x7f", b""), mtc.Cosignature(b"\x81\x01", b"\x55")))  # fmt: skip
    raw = proof.encode()
    assert raw == bytes.fromhex("0000" "010203040506" "0708090a0b0c" "0020" + "aa" * 32
                                + "00000a" "017f" "0000" "028101" "0001" "55")  # fmt: skip
    assert mtc.MTCProof.decode(raw) == proof


@pytest.mark.parametrize(
    "raw",
    [
        "0000" "000000000000" "000000000001" "0000" "000000" "00",  # trailing byte
        "0000" "000000000000" "000000000001" "0000" "000003" "00" "0000",  # empty cosigner_id
        "0000" "000000000000" "000000000001" "0000" "000008" "0181" "0000" "0181" "0000",  # duplicate
        "0000" "000000000000" "000000000001" "0000" "000009" "028101" "0000" "0181" "0000",  # longer first
        "0000" "000000000000" "000000000001" "0000" "000008" "0182" "0000" "0181" "0000",  # same length, out of order
        "0000" "000000000000" "000000000001" "0000" "000005" "0181" "0005" "00",  # signature overruns
    ],
    ids=["trailing", "empty-id", "duplicate", "longer-first", "lexicographic-out-of-order", "overrun"],
)
def test_mtc_proof_rejections(raw: str) -> None:
    assert reason_of(lambda: mtc.MTCProof.decode(bytes.fromhex(raw))) == (Alert.decode_error, "decode")


def test_mtc_proof_cosigner_order_is_shortlex() -> None:
    """§6.2: a 2-byte ID sorts before a 4-byte one even when it's lexicographically larger."""
    ok = mtc.MTCProof(0, 1, b"", (mtc.Cosignature(b"\xff\x7f", b""), mtc.Cosignature(b"\x81\xfd\x59\x01", b"")))
    assert mtc.MTCProof.decode(ok.encode()) == ok
    with pytest.raises(CodecUsageError):
        mtc.MTCProof(0, 1, b"", tuple(reversed(ok.signatures))).encode()
    long_id = mtc.Cosignature(b"\x01" * 255, b"")
    assert mtc.MTCProof.decode(mtc.MTCProof(0, 1, b"", (long_id,)).encode()).signatures == (long_id,)


def test_mtc_proof_truncation_at_every_offset_is_rejected() -> None:
    raw = mtc.MTCProof(3, 4, b"\x11" * 64, (mtc.Cosignature(b"\x01", b"sig"),),
                       (mtc.EntryExtension(1, b"x"),)).encode()  # fmt: skip
    for n in range(len(raw)):
        with pytest.raises(AlertError):
            mtc.MTCProof.decode(raw[:n])


def test_uint48_bounds_on_encode() -> None:
    mtc.MTCProof(2**48 - 1, 2**48 - 1, b"").encode()
    with pytest.raises(CodecUsageError):
        mtc.MTCProof(0, 2**48, b"").encode()


def test_cosigned_subtree_bytes() -> None:
    """§5.3.1 by hand: label, u8 names, uint64 timestamp 0, uint64 start and end, the hash."""
    h = bytes(range(32))
    msg = mtc.cosigned_subtree(tai("32473.1"), tai("32473.1.0.1"), 0x0102, 0x0304, h)
    name, origin = b"oid/1.3.6.1.4.1.32473.1", b"oid/1.3.6.1.4.1.32473.1.0.1"
    assert msg == (b"subtree/v1\n\x00" + bytes([len(name)]) + name + b"\x00" * 8 + bytes([len(origin)]) + origin
                   + (0x0102).to_bytes(8, "big") + (0x0304).to_bytes(8, "big") + h)  # fmt: skip


# --------------------------------------------------------------------------- #
# C. Log entries
# --------------------------------------------------------------------------- #

WG_KAT = json.loads((VECTORS / "wg_kat.json").read_text())


@pytest.mark.parametrize("case", WG_KAT, ids=["no-extensions", "extensions"])
def test_wg_log_entry_known_answers(case: dict) -> None:
    """demo/encode_test.go: TBSCertificate → MTCLogEntry, -08 wire format."""
    expected = bytes.fromhex(case["log_entry"])
    exts_len = int.from_bytes(expected[:2], "big")
    extensions_raw = expected[: 2 + exts_len]
    fields = mtc.tbs_fields(bytes.fromhex(case["tbs"]))
    assert extensions_raw + b"\x00\x01" + mtc.tbs_log_entry(fields) == expected
    assert mtc.entry_hash(fields, extensions_raw) == merkle.leaf_hash(expected)


def test_wg_known_answers_were_all_extracted() -> None:
    assert len(WG_KAT) == 2 and WG_KAT[1]["log_entry"].startswith("000400010000")


def _tbs(**changes: object) -> bytes:
    base = dict(subject_name=x509.name("qtls.test"), subject_spki=x509.spki("ECDSA-P256-SHA256", _EC),
                issuer_name=mtc.trust_anchor_name(CA), signature_algorithm=mtc.MTC_PROOF_ALGORITHM,
                serial=(3 << 48) | 5, not_before=NOT_BEFORE, not_after=NOT_AFTER, authority_key_id=None,
                key_usage={x509.DIGITAL_SIGNATURE}, dns_names=["qtls.test"])  # fmt: skip
    base.update(changes)
    return x509.build_tbs(**base)  # type: ignore[arg-type]


_EC = bytes.fromhex("04" + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")  # fmt: skip
_EC2 = bytes.fromhex("04" + "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
                     "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")  # fmt: skip


def test_entry_hash_depends_on_exactly_the_logged_fields() -> None:
    """§5.2.1/§12.6: version, issuer, validity, subject, SPKI algorithm and SPKI hash, extensions are
    bound; serial and the signature algorithm are not (they're authenticated another way)."""
    base = mtc.entry_hash(mtc.tbs_fields(_tbs()), b"\x00\x00")
    changed = {
        "issuer": _tbs(issuer_name=mtc.trust_anchor_name(tai("32473.8"))),
        "validity": _tbs(not_after=NOT_AFTER + dt.timedelta(seconds=1)),
        "subject": _tbs(subject_name=x509.name("other.test")),
        "spki-key": _tbs(subject_spki=x509.spki("ECDSA-P256-SHA256", _EC2)),
        "extensions": _tbs(dns_names=["other.test"]),
    }
    for what, tbs in changed.items():
        assert mtc.entry_hash(mtc.tbs_fields(tbs), b"\x00\x00") != base, what
    assert mtc.entry_hash(mtc.tbs_fields(_tbs()), b"\x00\x04\x00\x01\x00\x00") != base  # entry extensions
    same = {"serial": _tbs(serial=7), "signature-alg": _tbs(signature_algorithm=der.seq(der.oid(x509.BY_NAME["ML-DSA-44"].oid)))}
    for what, tbs in same.items():
        assert mtc.entry_hash(mtc.tbs_fields(tbs), b"\x00\x00") == base, what


def test_spki_hash_is_over_the_der_spki() -> None:
    """D13: subjectPublicKeyInfoHash = SHA-256(DER SPKI), never the raw key."""
    fields = mtc.tbs_fields(_tbs())
    entry = mtc.tbs_log_entry(fields)
    assert der.octet_string(crypto.merkle_sha256(fields.spki_raw)) in entry
    assert der.octet_string(crypto.merkle_sha256(_EC)) not in entry
    assert fields.spki_alg_raw == der.seq(der.oid(x509.EC_PUBLIC_KEY), der.oid(x509.PRIME256V1))


# --------------------------------------------------------------------------- #
# Fixtures for §7.2 (qTLS-issued, deterministic; liboqs signs ML-DSA from a seed)
# --------------------------------------------------------------------------- #


class Issued:
    def __init__(self) -> None:
        from qtls import chains

        self.log = mtc.IssuanceLog(CA, 3)
        self.log.append_null(5)
        self.leaf44 = x509.spki("ML-DSA-44", chains.signing_key("ML-DSA-44", b"qtls fixture v1", "leaf").public_key)
        self.index = self.log.add_certificate(**self.leaf_args(self.leaf44))
        self.log.append_null(10)
        self.log.checkpoint()  # [0, 16): the subtree is [0, 16)'s cover
        self.log.append_null(3)
        self.later = self.log.add_certificate(**self.leaf_args(self.leaf44))
        self.log.append_null(12)
        self.log.checkpoint()
        self.landmark = self.log.add_landmark()
        self.cs = {c.cosigner_id: c for c in (
            mtc.fixture_cosigner(CA, "ML-DSA-44", "mtc-ca"), mtc.fixture_cosigner(C1, "ML-DSA-65", "mtc-cosigner-1"),
            mtc.fixture_cosigner(C2, "ECDSA-P256-SHA256", "mtc-cosigner-2"),
        )}  # fmt: skip
        self.standalone = self.log.standalone(self.later, [self.cs[CA], self.cs[C1]])
        self.landmark_cert = self.log.landmark_relative(self.later)

    @staticmethod
    def leaf_args(spki: bytes, **changes: object) -> dict:
        args = dict(subject_cn="qtls.test", subject_spki=spki, not_before=NOT_BEFORE, not_after=NOT_AFTER,
                    key_usage={x509.DIGITAL_SIGNATURE}, dns_names=["qtls.test"])  # fmt: skip
        args.update(changes)
        return args

    def store(self, required: frozenset[TrustAnchorID] = frozenset({CA}), trusted: bool = False,
              revoked: tuple[mtc.RevokedRange, ...] = ()) -> mtc.MTCTrustStore:  # fmt: skip
        subtrees = self.log.trusted_subtrees() if trusted else ()
        return mtc.MTCTrustStore({cid: c.public for cid, c in self.cs.items()},
                                 (mtc.CAPolicy(CA, mtc.RequireAll(required), subtrees, revoked),))  # fmt: skip


@pytest.fixture(scope="module")
def issued(require_liboqs: None) -> Issued:
    return Issued()


def verify(cert: bytes, store: mtc.MTCTrustStore) -> mtc.VerifiedProof:
    return mtc.verify_proof(cert, store)


def resign(issued: Issued, cert: bytes, *, tbs: bytes | None = None, proof: mtc.MTCProof | None = None,
           outer: bytes | None = None, value: bytes | None = None) -> bytes:  # fmt: skip
    """The certificate with parts replaced (the signature value as raw BIT STRING contents)."""
    t, o, sig = der.parse(cert).children()
    if value is None:
        value = b"\x00" + (proof.encode() if proof is not None else sig.contents[1:])
    return der.seq(tbs if tbs is not None else t.raw, outer if outer is not None else o.raw, der.tlv(der.BIT_STRING, value))


def proof_of(cert: bytes) -> mtc.MTCProof:
    return mtc.MTCProof.decode(der.parse(cert).children()[2].contents[1:])


def rebuild_tbs(cert: bytes, *, serial: int | None = None, issuer: bytes | None = None, alg: bytes | None = None) -> bytes:
    f = mtc.tbs_fields(der.parse(cert).children()[0].raw)
    return der.seq(f.version_raw, der.integer(f.serial if serial is None else serial), alg or f.signature_raw,
                   issuer or f.issuer_raw, f.validity_raw, f.subject_raw, f.spki_raw, f.rest_raw)  # fmt: skip


# --------------------------------------------------------------------------- #
# D. §7.2, one check at a time (D33)
# --------------------------------------------------------------------------- #


def test_issued_certificates_verify(issued: Issued) -> None:
    v = verify(issued.standalone, issued.store(frozenset({CA, C1})))
    assert (v.log_number, v.index, v.trusted_subtree) == (3, issued.later, None)
    assert v.valid_cosigners == {CA.raw, C1.raw}
    lm = verify(issued.landmark_cert, issued.store(trusted=True))
    assert lm.trusted_subtree is not None and lm.trusted_subtree.landmark == issued.landmark
    assert proof_of(issued.landmark_cert).signatures == ()


def test_full_path_validation(issued: Issued) -> None:
    for cert, store in ((issued.standalone, issued.store()), (issued.landmark_cert, issued.store(trusted=True))):
        result = mtc.verify_certificate([cert], store, server_name="qtls.test", now=NOW, expected_kind="sig")
        assert result.leaf.alg == "ML-DSA-44" and result.leaf.spki_raw == issued.leaf44
        assert (result.proof.trusted_subtree is None) == (cert == issued.standalone)


@pytest.mark.parametrize(
    "issuer",
    [x509.name("qTLS root"), "other-tai", "log-id", "ca-id-prefix"],
    ids=["cn-name", "other-ca", "log-id", "longer-id"],
)
def test_step_0_unknown_issuer_comes_first(issued: Issued, issuer: object) -> None:
    """Before any §7.2 step: even a revoked serial and a broken proof are unknown_ca (D33)."""
    names = {"other-tai": mtc.trust_anchor_name(tai("32473.8")),
             "log-id": mtc.trust_anchor_name(mtc.log_id(CA, 3)),
             "ca-id-prefix": mtc.trust_anchor_name(CA.child(9))}  # fmt: skip
    name = names.get(issuer, issuer)  # type: ignore[call-overload]
    cert = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, issuer=name), value=b"\x01junk")
    store = issued.store(revoked=(mtc.RevokedRange(0, 2**64),))
    assert reason_of(lambda: verify(cert, store)) == (Alert.unknown_ca, "mtc-unknown-ca")


def test_step_1_signature_algorithm(issued: Issued) -> None:
    other = der.seq(der.oid(x509.BY_NAME["ML-DSA-44"].oid))
    for cert in (resign(issued, issued.standalone, outer=other),
                 resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, alg=other)),
                 resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, alg=der.seq(der.oid(x509.MTC_PROOF), der.null())),
                        outer=der.seq(der.oid(x509.MTC_PROOF), der.null()))):  # fmt: skip
        assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, "mtc-alg")


@pytest.mark.parametrize("damage", ["unused-bit", "empty", "trailing", "truncated", "unsorted"])
def test_step_2_proof_decoding(issued: Issued, damage: str) -> None:
    raw = der.parse(issued.standalone).children()[2].contents[1:]
    p = proof_of(issued.standalone)
    value = {
        "unused-bit": b"\x01" + raw,
        "empty": b"",
        "trailing": b"\x00" + raw + b"\x00",
        "truncated": b"\x00" + raw[:-1],
        "unsorted": b"\x00" + _unsorted(p),
    }[damage]
    cert = resign(issued, issued.standalone, value=value)
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, "mtc-proof")


def _unsorted(p: mtc.MTCProof) -> bytes:
    """The signatures in reverse (longer ID first), framed by hand: the encoder refuses it."""
    sigs = b"".join(bytes([len(s.cosigner_id)]) + s.cosigner_id + len(s.signature).to_bytes(2, "big") + s.signature
                    for s in reversed(p.signatures))  # fmt: skip
    return (p.extensions_raw + p.start.to_bytes(6, "big") + p.end.to_bytes(6, "big")
            + len(p.inclusion_proof).to_bytes(2, "big") + p.inclusion_proof + len(sigs).to_bytes(3, "big") + sigs)  # fmt: skip


@pytest.mark.parametrize("serial", [-1, -(2**48), 2**64, 2**64 + 2**48 * 3 + 21], ids=["-1", "negative", "2^64", "2^64+real"])
def test_step_3_serial_range(issued: Issued, serial: int) -> None:
    cert = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, serial=serial))
    store = issued.store(revoked=(mtc.RevokedRange(0, 2**64),))  # step 3 comes before revocation
    assert reason_of(lambda: verify(cert, store)) == (Alert.bad_certificate, "mtc-serial")


def test_step_3_largest_serial_passes_and_fails_later(issued: Issued) -> None:
    cert = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, serial=2**64 - 1))
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, "mtc-index-range")


def test_step_4_revoked_ranges_are_half_open(issued: Issued) -> None:
    serial = (3 << 48) | issued.later
    for lo, hi, revoked in ((serial, serial + 1, True), (0, serial + 1, True), (serial + 1, serial + 2, False),
                            (serial - 1, serial, False), (0, serial, False), (serial, 2**64, True)):  # fmt: skip
        store = issued.store(frozenset({CA, C1}), revoked=(mtc.RevokedRange(lo, hi),))
        if revoked:
            assert reason_of(lambda: verify(issued.standalone, store)) == (Alert.certificate_revoked, "mtc-revoked")
        else:
            verify(issued.standalone, store)


def test_step_4_comes_before_the_proof(issued: Issued) -> None:
    cert = resign(issued, issued.standalone, value=b"\x00" + proof_of(issued.standalone).encode()[:-1] + b"\x00\x00")
    store = issued.store(revoked=(mtc.RevokedRange(0, 2**64),))
    assert reason_of(lambda: verify(cert, store)) == (Alert.bad_certificate, "mtc-proof")  # step 2 is earlier still
    cert = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, serial=(3 << 48) | 2**40))
    assert reason_of(lambda: verify(cert, store)) == (Alert.certificate_revoked, "mtc-revoked")


def test_step_5_log_zero(issued: Issued) -> None:
    cert = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, serial=issued.later))
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, "mtc-log-number")
    with_min_serial = issued.store(revoked=(mtc.RevokedRange(0, 1 << 48),))  # what a CA's minSerial implies (3b2)
    assert reason_of(lambda: verify(cert, with_min_serial)) == (Alert.certificate_revoked, "mtc-revoked")


def test_steps_5_6_another_log_number(issued: Issued) -> None:
    """The cosignatures name log 3; the same entry claimed in log 4 isn't what they signed."""
    cert = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, serial=(4 << 48) | issued.later))
    assert reason_of(lambda: verify(cert, issued.store(frozenset({CA, C1})))) == (Alert.bad_certificate, "mtc-cosigners")


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("index-outside", "mtc-index-range"),
        ("not-subtree", "mtc-not-subtree"),
        ("ragged", "mtc-ragged"),
        ("too-long", "mtc-too-long"),
        ("too-short", "mtc-too-short"),
    ],
)
def test_step_10_inclusion_proof(issued: Issued, change: str, reason: str) -> None:
    p = proof_of(issued.standalone)
    tbs = None
    if change == "index-outside":
        tbs = rebuild_tbs(issued.standalone, serial=(3 << 48) | p.end)
    proofs = {
        "not-subtree": replace(p, start=p.start + 1),
        "ragged": replace(p, inclusion_proof=p.inclusion_proof + b"\x00"),
        "too-long": replace(p, inclusion_proof=p.inclusion_proof + b"\x00" * 32),
        "too-short": replace(p, inclusion_proof=p.inclusion_proof[:-32]),
    }
    cert = resign(issued, issued.standalone, tbs=tbs, proof=proofs.get(change))
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, reason)


def test_step_11_a_trusted_subtree_decides(issued: Issued) -> None:
    store = issued.store(trusted=True)
    v = verify(issued.landmark_cert, store)
    assert v.valid_cosigners == frozenset()  # no signatures needed or checked
    # A matching (log, start, end) with the wrong hash fails even with valid cosignatures (no fall-through).
    t = store.cas[0].trusted_subtrees
    wrong = tuple(replace(s, subtree_hash=bytes(32)) for s in t)
    bad_store = mtc.MTCTrustStore(store.cosigners, (replace(store.cas[0], trusted_subtrees=wrong),))
    p = proof_of(issued.landmark_cert)
    signed = resign(issued, issued.landmark_cert, proof=replace(p, signatures=tuple(
        issued.cs[c].sign(issued.log.log_id, p.start, p.end, issued.log.tree().hash(p.start, p.end)) for c in (CA,))))
    verify(signed, issued.store())  # the cosignature itself is good
    assert reason_of(lambda: verify(signed, bad_store)) == (Alert.bad_certificate, "mtc-trusted-subtree")


def test_step_11_trusted_subtrees_of_another_log_or_ca_do_not_apply(issued: Issued) -> None:
    store = issued.store(trusted=True)
    other_log = tuple(replace(s, log_number=4) for s in store.cas[0].trusted_subtrees)
    s1 = mtc.MTCTrustStore(store.cosigners, (replace(store.cas[0], trusted_subtrees=other_log),))
    assert reason_of(lambda: verify(issued.landmark_cert, s1)) == (Alert.bad_certificate, "mtc-cosigners")
    other_ca = mtc.CAPolicy(tai("32473.8"), mtc.RequireAll(frozenset({tai("32473.8")})), store.cas[0].trusted_subtrees)
    s2 = mtc.MTCTrustStore({**store.cosigners, tai("32473.8"): KEY44}, (replace(store.cas[0], trusted_subtrees=()), other_ca))
    assert reason_of(lambda: verify(issued.landmark_cert, s2)) == (Alert.bad_certificate, "mtc-cosigners")


def test_step_12_cosigner_policy(issued: Issued) -> None:
    p = proof_of(issued.standalone)
    assert reason_of(lambda: verify(issued.standalone, issued.store(frozenset({CA, C2})))) == (Alert.bad_certificate, "mtc-cosigners")
    # An invalid signature from a required cosigner doesn't count.
    bad = tuple(mtc.Cosignature(s.cosigner_id, s.signature[:-1] + bytes([s.signature[-1] ^ 1])) if s.cosigner_id == C1.raw else s
                for s in p.signatures)  # fmt: skip
    cert = resign(issued, issued.standalone, proof=replace(p, signatures=bad))
    assert reason_of(lambda: verify(cert, issued.store(frozenset({CA, C1})))) == (Alert.bad_certificate, "mtc-cosigners")
    verify(cert, issued.store())  # ...and from a recognized cosigner that isn't required, it's simply not counted
    # Swapping two cosigners' signatures makes both invalid.
    swapped = (replace(p.signatures[0], signature=p.signatures[1].signature), replace(p.signatures[1], signature=p.signatures[0].signature))
    cert = resign(issued, issued.standalone, proof=replace(p, signatures=swapped))
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, "mtc-cosigners")


@pytest.mark.parametrize("junk", [b"", b"\x01", b"\x30\x00", b"\x00" * 2420, b"\xff" * 3309, b"\x30\x06\x02\x01\x01\x02\x01\x01"])
def test_step_12_junk_signatures_are_just_invalid(issued: Issued, junk: bytes) -> None:
    """Never an exception other than the policy failure, on either cosigner algorithm family."""
    p = proof_of(issued.standalone)
    sigs = tuple(replace(s, signature=junk) for s in p.signatures)
    cert = resign(issued, issued.standalone, proof=replace(p, signatures=sigs))
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, "mtc-cosigners")
    ec = mtc.Cosignature(C2.raw, junk)
    cert = resign(issued, issued.standalone, proof=replace(p, signatures=(*p.signatures, ec)))
    verify(cert, issued.store())  # recognized ECDSA cosigner, junk, not required: ignored


def test_step_12_grease_and_unknown_cosigners_are_ignored(issued: Issued) -> None:
    p = proof_of(issued.standalone)
    extra = (mtc.Cosignature(b"\x01" * 255, b"junk"), mtc.Cosignature(b"\x7f", b""), mtc.Cosignature(C3.raw, b"x" * 2420))
    sigs = tuple(sorted((*p.signatures, *extra), key=lambda c: (len(c.cosigner_id), c.cosigner_id)))
    cert = resign(issued, issued.standalone, proof=replace(p, signatures=sigs))
    verify(cert, issued.store(frozenset({CA, C1})))


def test_step_12_cosignature_bound_to_its_log(issued: Issued) -> None:
    """A cosignature over the same subtree of another log (another log_origin) doesn't verify here."""
    p = proof_of(issued.standalone)
    h = issued.log.tree().hash(p.start, p.end)
    other = mtc.log_id(CA, 4)
    sigs = tuple(issued.cs[CA].sign(other, p.start, p.end, h) for _ in (0,))
    cert = resign(issued, issued.standalone, proof=replace(p, signatures=sigs))
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, "mtc-cosigners")


def test_a_one_leaf_subtree_needs_signatures_too(issued: Issued) -> None:
    """[i, i+1) with an empty proof evaluates to the entry hash itself, so anyone can make it: only
    step 11 or 12 authenticates it, which is why a policy can't be empty (D33)."""
    i = issued.later
    cert = resign(issued, issued.standalone, proof=mtc.MTCProof(i, i + 1, b""))
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, "mtc-cosigners")


def test_key_binding(issued: Issued) -> None:
    """A valid proof can't carry another key: the SPKI hash is in the entry (§7.2 step 7.3; D13)."""
    from qtls import chains

    f = mtc.tbs_fields(der.parse(issued.standalone).children()[0].raw)
    for alg, role in (("ML-DSA-44", "other"), ("ML-DSA-65", "leaf")):
        spki = x509.spki(alg, chains.signing_key(alg, b"qtls fixture v1", role).public_key)
        tbs = der.seq(f.version_raw, der.integer(f.serial), f.signature_raw, f.issuer_raw, f.validity_raw, f.subject_raw,
                      spki, f.rest_raw)  # fmt: skip
        cert = resign(issued, issued.standalone, tbs=tbs)
        assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, "mtc-cosigners")
        cert = resign(issued, issued.landmark_cert, tbs=tbs)
        assert reason_of(lambda: verify(cert, issued.store(trusted=True))) == (Alert.bad_certificate, "mtc-trusted-subtree")


def test_an_oversized_log_entry_is_a_certificate_failure_not_a_local_error(issued: Issued) -> None:
    """A peer's TBSCertificateLogEntry may exceed 65535 bytes; the relying party hashes it anyway (D33)."""
    f = mtc.tbs_fields(der.parse(issued.standalone).children()[0].raw)
    big_ext = der.seq(der.oid("1.3.6.1.4.1.32473.99"), der.octet_string(b"\x00" * 70000))
    exts = der.parse(f.rest_raw).children()[0].children()
    rest = der.explicit(3, der.seq(*(e.raw for e in exts), big_ext))
    tbs = der.seq(f.version_raw, der.integer(f.serial), f.signature_raw, f.issuer_raw, f.validity_raw,
                  f.subject_raw, f.spki_raw, rest)  # fmt: skip
    cert = resign(issued, issued.standalone, tbs=tbs)
    assert len(mtc.tbs_log_entry(mtc.tbs_fields(tbs))) > 0xFFFF
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, "mtc-cosigners")


def test_after_7_2_the_rest_of_path_validation(issued: Issued) -> None:
    store = issued.store()

    def full(cert_data: list[bytes], **kw: object) -> object:
        args = dict(server_name="qtls.test", now=NOW, expected_kind="sig")
        args.update(kw)
        return mtc.verify_certificate(cert_data, store, **args)  # type: ignore[arg-type]

    assert reason_of(lambda: full([issued.standalone], now=NOT_AFTER + dt.timedelta(days=1))) == (Alert.certificate_expired, "validity")
    assert reason_of(lambda: full([issued.standalone], server_name="other.test")) == (Alert.bad_certificate, "name")
    assert reason_of(lambda: full([issued.standalone], expected_kind="kem")) == (Alert.unsupported_certificate, "leaf-kind")
    assert reason_of(lambda: full([issued.standalone, issued.standalone])) == (Alert.bad_certificate, "mtc-chain")
    assert reason_of(lambda: full([])) == (Alert.bad_certificate, "mtc-chain")
    # §7.2 comes first: a broken proof on an expired certificate is the proof's failure.
    broken = resign(issued, issued.standalone, proof=replace(proof_of(issued.standalone), signatures=()))
    assert reason_of(lambda: full([broken], now=NOT_AFTER + dt.timedelta(days=1))) == (Alert.bad_certificate, "mtc-cosigners")


def test_x509_chains_do_not_accept_mtc_certificates(issued: Issued) -> None:
    """verify_chain stays X.509-only (D30): an MTC leaf under no X.509 anchor is unknown_ca."""
    from qtls import chains

    chain = chains.build_chain(leaf_alg="ML-DSA-44", issuer_alg="ML-DSA-44", not_before=NOT_BEFORE)
    assert reason_of(lambda: x509.verify_chain([issued.standalone], [chain.anchor], server_name="qtls.test", now=NOW,
                                               accepted={0x0904}, expected_kind="sig")) == (Alert.unknown_ca, "unknown-anchor")  # fmt: skip


def test_missing_backend_is_refused_when_the_store_is_built(issued: Issued) -> None:
    keys = {cid: c.public for cid, c in issued.cs.items()}
    policy = (mtc.CAPolicy(CA, mtc.RequireAll(frozenset({CA}))),)
    with pytest.raises(CodecUsageError):
        mtc.MTCTrustStore(keys, policy, {"ML-DSA-44": "openssl", "ML-DSA-65": "openssl"})
    with pytest.raises(CodecUsageError):
        mtc.MTCTrustStore(keys, policy, {a: "nope" for a in mtc.COSIGNER_ALGORITHMS})  # type: ignore[misc]
    with pytest.raises(CodecUsageError):  # liboqs has no ECDSA: refused now, not during a handshake
        mtc.MTCTrustStore(keys, policy, {"ML-DSA-44": "openssl", "ML-DSA-65": "openssl", "ECDSA-P256-SHA256": "liboqs"})


# --------------------------------------------------------------------------- #
# E. The Go demo's verdicts
# --------------------------------------------------------------------------- #


def _demo_store(corpus: str, policy: str) -> tuple[mtc.MTCTrustStore, dict[str, str]]:
    base = VECTORS / corpus
    config = json.loads((base / "config.json").read_text())
    ca_id = tai(config["ID"])
    split = mtc.split_certificate((base / "ca_cert.der").read_bytes())
    oid, key = x509.parse_spki(split.tbs.spki_raw)
    cosigners = {ca_id: mtc.CosignerKey(x509.BY_SPKI_OID[oid].name, key)}
    required = {ca_id}
    for line in (base / f"policy-{policy}.txt").read_text().splitlines():
        parts = line.split()
        if parts and parts[0] == "cosigner":
            o, k = x509.parse_spki(base64.b64decode(parts[3]))
            cosigners[tai(parts[1])] = mtc.CosignerKey(x509.BY_SPKI_OID[o].name, k)
        elif parts and parts[0] == "require-cosigners":
            required.add(tai(parts[2]))
    lo = (config["CACert"]["MinSerial"]["Log"] << 48) | config["CACert"]["MinSerial"]["Index"]
    hi = ((config["CACert"]["MaxSerial"]["Log"] << 48) | config["CACert"]["MaxSerial"]["Index"]) + 1
    revoked = tuple(r for r in (mtc.RevokedRange(0, lo) if lo else None, mtc.RevokedRange(hi, 2**64) if hi < 2**64 else None) if r)
    trusted: tuple[mtc.TrustedSubtree, ...] = ()
    if policy == "landmarks":
        marks = json.loads((base / "landmarks.json").read_text())
        trusted = tuple(mtc.TrustedSubtree(config["LogNumber"], s["start"], s["end"], base64.b64decode(s["hash"]), m["landmark"])
                        for m in marks for s in m["subtrees"])  # fmt: skip
    store = mtc.MTCTrustStore(cosigners, (mtc.CAPolicy(ca_id, mtc.RequireAll(frozenset(required)), trusted, revoked),))
    return store, json.loads((base / "verdicts.json").read_text())


DEMO_CASES = [(c, p, name) for c in ("wg", "qtls") for name, by in json.loads((VECTORS / c / "verdicts.json").read_text()).items()
              for p in by]  # fmt: skip

# How each demo verdict reads as a D33 reason (§7.2 level).
DEMO_REASONS = {
    "signature was not a whole number of bytes": "mtc-proof",
    "malformed MTCProof": "mtc-proof",
    "cosigners not in canonical order or duplicate": "mtc-proof",
    "cosigner policy not satisfied": "mtc-cosigners",
    "trusted subtree hash mismatch": "mtc-trusted-subtree",
    "unparsable: x509: inner and outer signature algorithm identifiers don't match": "mtc-alg",
}


@pytest.mark.parametrize(("corpus", "policy", "name"), DEMO_CASES, ids=[f"{c}-{p}-{n}" for c, p, n in DEMO_CASES])
def test_same_verdict_as_the_go_demo(corpus: str, policy: str, name: str) -> None:
    store, verdicts = _demo_store(corpus, policy)
    demo = verdicts[name][policy]
    cert = (VECTORS / corpus / "certs" / f"{name}.der").read_bytes()
    if demo == "OK":
        mtc.verify_proof(cert, store)
        return
    expected = next(r for prefix, r in DEMO_REASONS.items() if demo.startswith(prefix))
    assert reason_of(lambda: mtc.verify_proof(cert, store))[1] == expected


def test_demo_corpora_cover_what_they_should() -> None:
    """Guards the vendored corpora: every demo verdict kind, accepts and rejects in each."""
    seen = {next((p for p in DEMO_REASONS if v.startswith(p)), v)
            for c in ("wg", "qtls") for by in json.loads((VECTORS / c / "verdicts.json").read_text()).values() for v in by.values()}
    assert seen == {"OK", *DEMO_REASONS}
    assert len(DEMO_CASES) == 28 * 2 + 24 * 4


@pytest.mark.parametrize("name", sorted(json.loads((VECTORS / "qtls" / "verdicts.json").read_text())))
def test_qtls_corpus_end_to_end(name: str) -> None:
    """The qTLS-profile corpus through the whole of verify_certificate: D24 parse, §7.2, leaf checks."""
    store, verdicts = _demo_store("qtls", "ca-only")
    cert = (VECTORS / "qtls" / "certs" / f"{name}.der").read_bytes()
    kind = "kem" if b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x04" in cert else "sig"
    call = lambda: mtc.verify_certificate([cert], store, server_name="qtls.test", now=NOW, expected_kind=kind)  # noqa: E731
    if verdicts[name]["ca-only"] == "OK":
        assert call().leaf.kind == kind
        return
    # The TLS path parses D24 first, so a malformed signatureValue or algorithm pair gets D24's reason (D33).
    demo = verdicts[name]["ca-only"]
    expected = {"signature was not a whole number of bytes": "der",
                "unparsable: x509: inner and outer signature algorithm identifiers don't match": "alg-mismatch"}.get(
        demo, next(r for prefix, r in DEMO_REASONS.items() if demo.startswith(prefix)))  # fmt: skip
    assert reason_of(call)[1] == expected


def test_our_tree_matches_the_demo_checkpoint() -> None:
    """qTLS's Merkle tree over the corpus' log entries (from each certificate, null elsewhere) has
    the size and root the demo's checkpoint publishes: entry construction checked end to end."""
    lines = (VECTORS / "qtls" / "checkpoint").read_text().splitlines()
    size, root = int(lines[1]), base64.b64decode(lines[2])
    leaves = {}
    for path in (VECTORS / "qtls" / "certs").glob("*.der"):
        cert = path.read_bytes()
        split = mtc.split_certificate(cert)
        value = split.signature_value.contents[1:]
        extensions_raw = value[: 2 + int.from_bytes(value[:2], "big")]
        leaves[split.tbs.serial & mtc.UINT48_MAX] = mtc.entry_hash(split.tbs, extensions_raw)
    tree = merkle.Tree(size, leaves, merkle.leaf_hash(mtc.NULL_LOG_ENTRY))
    assert tree.hash(0, size) == root
    marks = json.loads((VECTORS / "qtls" / "landmarks.json").read_text())
    for m in marks:
        for s in m["subtrees"]:
            assert tree.hash(s["start"], s["end"]) == base64.b64decode(s["hash"])


# --------------------------------------------------------------------------- #
# F. Issuance and sizes (D14, D34)
# --------------------------------------------------------------------------- #


def test_serial_and_issuer_of_issued_certificates(issued: Issued) -> None:
    leaf = x509.parse(issued.standalone)
    assert leaf.serial == (3 << 48) | issued.later
    assert x509.trust_anchor_id_of(leaf.issuer_raw) == CA.raw
    assert leaf.signature_oid == x509.MTC_PROOF and leaf.extension(x509.AUTHORITY_KEY_ID) is None


def test_landmarks_and_checkpoints(issued: Issued) -> None:
    log = issued.log
    assert log.landmarks[0] == 0 and log.landmark_subtrees(0) == ((0, 0), (0, 0))
    with pytest.raises(CodecUsageError):
        log.add_landmark()  # no new entries since the last one
    with pytest.raises(CodecUsageError):
        log.checkpoint()
    fresh = mtc.IssuanceLog(CA, 1)
    fresh.append_null(3)
    with pytest.raises(CodecUsageError):
        fresh.standalone(0, [])  # no checkpoint covers it yet
    with pytest.raises(CodecUsageError):
        fresh.landmark_relative(0)
    with pytest.raises(CodecUsageError):
        fresh.append_null(2**48)


def _depth_certificate(depth: int, cosigners: list[mtc.Cosigner], leaf: bytes) -> tuple[bytes, bytes]:
    """D14's fixture: the entry at index 0 of a log of 2^depth + 1 entries, so its subtree is [0, 2^depth)."""
    log = mtc.IssuanceLog(CA, 1)
    index = log.add_certificate(**Issued.leaf_args(leaf))
    log.append_null(2**depth)
    log.checkpoint()
    log.add_landmark()
    return log.standalone(index, cosigners), log.landmark_relative(index)


def test_d14_proof_sizes_and_monotone_certificate_size(issued: Issued) -> None:
    sizes = {}
    for depth in (12, 23):
        for n in (1, 2, 3):
            cs = [issued.cs[c] for c in (CA, C1, C2)[:n]]
            standalone, landmark = _depth_certificate(depth, cs, issued.leaf44)
            assert len(proof_of(standalone).inclusion_proof) == len(proof_of(landmark).inclusion_proof) == 32 * depth
            assert len(proof_of(standalone).signatures) == n and proof_of(landmark).signatures == ()
            sizes[(depth, n)] = len(standalone)
            sizes[(depth, 0)] = len(landmark)
    assert 32 * 12 == 384 and 32 * 23 == 736  # MTC -08 §6.5
    for depth in (12, 23):
        assert sizes[(depth, 0)] < sizes[(depth, 1)] < sizes[(depth, 2)] < sizes[(depth, 3)]
    for n in (0, 1, 2, 3):
        assert sizes[(12, n)] + 11 * 32 == sizes[(23, n)]


def test_kem_leaves_in_mtc(issued: Issued) -> None:
    """D13: an ML-KEM leaf is certified like any other key, and comes back as a KEM leaf."""
    log = mtc.IssuanceLog(CA, 2)
    for alg in ("ML-KEM-512", "ML-KEM-768"):
        key = crypto.kem_generate(alg, "liboqs", seed=bytes(64))
        index = log.add_certificate(**Issued.leaf_args(x509.spki(alg, key.public_key), key_usage={x509.KEY_ENCIPHERMENT}))
        log.checkpoint()
        cert = log.standalone(index, [issued.cs[CA]])
        leaf = mtc.verify_certificate([cert], issued.store(), server_name="qtls.test", now=NOW, expected_kind="kem").leaf
        assert (leaf.kind, leaf.alg, leaf.public_key) == ("kem", alg, key.public_key)


# --------------------------------------------------------------------------- #
# G. Robustness
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("which", ["standalone", "landmark"])
def test_every_single_byte_change_is_an_alert_or_harmless(issued: Issued, which: str) -> None:
    """XOR 0x01 at every byte: an AlertError, or an accept only inside the one cosignature element the
    policy doesn't require (D33: unrecognized or invalid cosignatures are ignored)."""
    cert = issued.standalone if which == "standalone" else issued.landmark_cert
    store = issued.store(trusted=which == "landmark")
    rng = random.Random(3)
    positions = range(len(cert)) if len(cert) < 2000 else sorted(rng.sample(range(len(cert)), 1000))
    c1 = next(s for s in proof_of(issued.standalone).signatures if s.cosigner_id == C1.raw)
    element = bytes([len(c1.cosigner_id)]) + c1.cosigner_id + len(c1.signature).to_bytes(2, "big") + c1.signature
    c1_at = cert.find(element) if which == "standalone" else -1
    for i in positions:
        damaged = cert[:i] + bytes([cert[i] ^ 1]) + cert[i + 1 :]
        try:
            verify(damaged, store)
        except AlertError:
            continue
        assert c1_at <= i < c1_at + len(element), f"byte {i} changed and still verified"


def test_every_truncation_is_an_alert(issued: Issued) -> None:
    for n in range(0, len(issued.landmark_cert)):
        with pytest.raises(AlertError):
            verify(issued.landmark_cert[:n], issued.store(trusted=True))


# --------------------------------------------------------------------------- #
# H. Review round: ordering, bit widths, policies, configuration, issuance
# --------------------------------------------------------------------------- #


def test_unknown_issuer_beats_a_wrong_algorithm(issued: Issued) -> None:
    other = der.seq(der.oid(x509.BY_NAME["ML-DSA-44"].oid))
    tbs = rebuild_tbs(issued.standalone, issuer=mtc.trust_anchor_name(tai("32473.8")), alg=other)
    cert = resign(issued, issued.standalone, tbs=tbs, outer=other)
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.unknown_ca, "mtc-unknown-ca")


def test_tls_path_parses_d24_before_the_proof(issued: Issued) -> None:
    """D33: on the TLS path an inner/outer algorithm mismatch is D24's alg-mismatch, not mtc-alg, and a
    profile violation beats an unknown CA."""
    other = der.seq(der.oid(x509.BY_NAME["ML-DSA-44"].oid))
    full = lambda c: mtc.verify_certificate([c], issued.store(), server_name="qtls.test", now=NOW, expected_kind="sig")  # noqa: E731
    assert reason_of(lambda: full(resign(issued, issued.standalone, outer=other))) == (Alert.bad_certificate, "alg-mismatch")
    unknown = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, issuer=mtc.trust_anchor_name(tai("32473.8"))),
                     outer=other)  # fmt: skip
    assert reason_of(lambda: full(unknown)) == (Alert.bad_certificate, "alg-mismatch")


def test_index_uses_all_48_bits(issued: Issued) -> None:
    log = mtc.IssuanceLog(CA, 3)
    log.append_null(2**47 + 5)
    i = log.add_certificate(**Issued.leaf_args(issued.leaf44))
    log.append_null(2)
    log.checkpoint()
    assert verify(log.standalone(i, [issued.cs[CA]]), issued.store()).index == 2**47 + 5


def test_log_number_uses_all_16_bits(issued: Issued) -> None:
    cert = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, serial=((3 + 256) << 48) | issued.later))
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.bad_certificate, "mtc-cosigners")


def test_ecdsa_cosignature_counts(issued: Issued) -> None:
    p = proof_of(issued.standalone)
    h = issued.log.tree().hash(p.start, p.end)
    sigs = (issued.cs[CA].sign(issued.log.log_id, p.start, p.end, h), issued.cs[C2].sign(issued.log.log_id, p.start, p.end, h))
    cert = resign(issued, issued.standalone, proof=replace(p, signatures=sigs))
    assert verify(cert, issued.store(frozenset({CA, C2}))).valid_cosigners == {CA.raw, C2.raw}


def test_revoked_ranges_are_per_ca(issued: Issued) -> None:
    base = issued.store()
    other = mtc.CAPolicy(tai("32473.8"), mtc.RequireAll(frozenset({tai("32473.8")})), (), (mtc.RevokedRange(0, 2**64),))
    store = mtc.MTCTrustStore({**base.cosigners, tai("32473.8"): base.cosigners[CA]}, (base.cas[0], other))
    verify(issued.standalone, store)


MALFORMED_ISSUERS = {
    "three-parts": der.seq(der.set_of(der.seq(der.oid(x509.TRUST_ANCHOR_ID_ATTRIBUTE), CA.der, der.null()))),
    "attr-not-seq": der.seq(der.tlv(0x31, der.integer(1))),
    "rdn-primitive": der.seq(der.integer(1)),
    "rdn-is-a-sequence": der.seq(der.seq(der.seq(der.oid(x509.TRUST_ANCHOR_ID_ATTRIBUTE), CA.der))),
    "attr-is-a-set": der.seq(der.set_of(der.tlv(0x31, der.oid(x509.TRUST_ANCHOR_ID_ATTRIBUTE) + CA.der))),
    "non-minimal": der.seq(der.set_of(der.seq(der.oid(x509.TRUST_ANCHOR_ID_ATTRIBUTE), der.tlv(der.RELATIVE_OID, b"\x80\x01")))),
    "second-rdn": der.seq(der.set_of(der.seq(der.oid(x509.TRUST_ANCHOR_ID_ATTRIBUTE), CA.der)),
                          der.set_of(der.seq(der.oid(x509.COMMON_NAME), der.utf8_string("x")))),
    "other-attribute": der.seq(der.set_of(der.seq(der.oid(x509.COMMON_NAME), CA.der))),
}  # fmt: skip


@pytest.mark.parametrize("issuer", MALFORMED_ISSUERS.values(), ids=MALFORMED_ISSUERS.keys())
def test_malformed_issuer_names_match_no_ca(issued: Issued, issuer: bytes) -> None:
    """Only a well-formed TAI name can name a CA (TAI §4.1): anything else is unknown_ca."""
    cert = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, issuer=issuer))
    assert reason_of(lambda: verify(cert, issued.store())) == (Alert.unknown_ca, "mtc-unknown-ca")


def test_issuance_carries_entry_extensions(issued: Issued) -> None:
    log = mtc.IssuanceLog(CA, 3)
    i = log.add_certificate(**Issued.leaf_args(issued.leaf44), extensions=(mtc.EntryExtension(7, b"x"),))
    log.checkpoint()
    cert = log.standalone(i, [issued.cs[CA]])
    assert proof_of(cert).extensions == (mtc.EntryExtension(7, b"x"),)
    verify(cert, issued.store())


def test_issuance_picks_the_spec_subtrees(issued: Issued) -> None:
    """§6.3: the checkpoint interval's subtree; §6.4.4: the lowest landmark past the index."""
    log = issued.log
    assert log.checkpoints == [0, 16, 32] and log.landmarks == [0, 32]
    p = proof_of(issued.standalone)
    assert (p.start, p.end) == (16, 24)  # find_subtrees(16, 32) holding index 19
    p0 = proof_of(log.standalone(issued.index, [issued.cs[CA]]))
    assert (p0.start, p0.end) == (0, 8)
    two = mtc.IssuanceLog(CA, 3)
    two.append_null(5)
    i = two.add_certificate(**Issued.leaf_args(issued.leaf44))
    two.append_null(10)
    two.add_landmark()
    two.append_null(16)
    two.add_landmark()
    lm = proof_of(two.landmark_relative(i))
    assert (lm.start, lm.end) == (0, 8)


@pytest.mark.parametrize("corpus", ["qtls", "wg"])
def test_landmark_subtrees_match_the_demo(corpus: str) -> None:
    """§6.4.1 against the demo: the same landmark sizes give the same two subtrees each."""
    marks = json.loads((VECTORS / corpus / "landmarks.json").read_text())
    log = mtc.IssuanceLog(CA, 3)
    for mk in marks:
        log.append_null(mk["tree_size"] - log.size)
        assert log.add_landmark() == mk["landmark"]
        assert [list(s) for s in log.landmark_subtrees(mk["landmark"])] == [[s["start"], s["end"]] for s in mk["subtrees"]]


def test_codec_and_log_bounds() -> None:
    with pytest.raises(CodecUsageError):
        mtc.LogEntry(None, (mtc.EntryExtension(1, b""), mtc.EntryExtension(1, b""))).encode()
    with pytest.raises(AlertError):
        mtc.LogEntry.decode(b"\x00\x00\x00\x01" + b"\x00" * 0xFFFC)
    mtc.LogEntry.decode(b"\x00\x00\x00\x01" + b"\x00" * 0xFFFB)
    log = mtc.IssuanceLog(CA, 1)
    log.append_null(2**48 - 1)
    with pytest.raises(CodecUsageError):
        log.append_null(1)
    with pytest.raises(CodecUsageError):
        mtc.IssuanceLog(CA, 1).append_null(-1)


def test_signatures_are_sorted_whatever_order_they_are_given(issued: Issued) -> None:
    cert = issued.log.standalone(issued.later, [issued.cs[C1], issued.cs[CA]])
    assert [s.cosigner_id for s in proof_of(cert).signatures] == [CA.raw, C1.raw]


def test_a_failed_add_certificate_leaves_the_log_unchanged(issued: Issued) -> None:
    log = mtc.IssuanceLog(CA, 1)
    for bad in (dict(not_before=dt.datetime(2026, 1, 1)), dict(dns_names=["ünï.test"]),
                dict(extensions=(mtc.EntryExtension(2, b""), mtc.EntryExtension(1, b"")))):  # fmt: skip
        with pytest.raises((CodecUsageError, UnicodeEncodeError)):
            log.add_certificate(**Issued.leaf_args(issued.leaf44, **bad))
    assert log.size == 0
    assert log.add_certificate(**Issued.leaf_args(issued.leaf44)) == 0


class _QuorumWithoutCA:
    """2 of {CA, C1, C2}: a 3b2-style policy that alone would accept a certificate the CA never signed."""

    def cosigners(self) -> frozenset[TrustAnchorID]:
        return frozenset({CA, C1, C2})

    def unsatisfied(self, valid: frozenset[bytes]) -> tuple[str, ...]:
        n = len(valid & {CA.raw, C1.raw, C2.raw})
        return () if n >= 2 else ("group two-of-three",)  # a group, not a cosigner ID


def test_the_ca_signature_is_required_whatever_the_policy(issued: Issued) -> None:
    """§7.3 authenticity (and the demo): a policy satisfied without the CA still fails, and its
    non-ID descriptions never become a local error (D33)."""
    p = proof_of(issued.standalone)
    h = issued.log.tree().hash(p.start, p.end)
    sigs = tuple(issued.cs[c].sign(issued.log.log_id, p.start, p.end, h) for c in (C1, C2))
    cert = resign(issued, issued.standalone, proof=replace(p, signatures=sigs))
    store = mtc.MTCTrustStore({cid: c.public for cid, c in issued.cs.items()}, (mtc.CAPolicy(CA, _QuorumWithoutCA()),))
    with pytest.raises(AlertError) as info:
        verify(cert, store)
    assert info.value.reason == "mtc-cosigners" and "32473.9 (the CA)" in str(info.value)
    unsigned = resign(issued, issued.standalone, proof=replace(p, signatures=()))
    with pytest.raises(AlertError) as info:
        verify(unsigned, store)
    assert "group two-of-three" in str(info.value)
    verify(issued.standalone, store)  # CA and C1: both requirements met


def test_a_policy_that_accepts_nothing_signed_is_refused() -> None:
    class Empty:
        def cosigners(self) -> frozenset[TrustAnchorID]:
            return frozenset({CA})

        def unsatisfied(self, valid: frozenset[bytes]) -> tuple[str, ...]:
            return ()

    with pytest.raises(CodecUsageError):
        mtc.CAPolicy(CA, Empty())


def test_only_the_policys_cosigners_are_verified(issued: Issued) -> None:
    """D33: verification work follows the policy, not the certificate (Phase 5 counts)."""
    p = proof_of(issued.standalone)
    h = issued.log.tree().hash(p.start, p.end)
    sigs = tuple(issued.cs[c].sign(issued.log.log_id, p.start, p.end, h) for c in (CA, C1, C2))
    cert = resign(issued, issued.standalone, proof=replace(p, signatures=sigs))
    with crypto.count_ops() as ops:
        v = verify(cert, issued.store())
    assert v.valid_cosigners == {CA.raw}
    assert sum(n for (b, a, op), n in ops.items() if op == "verify") == 1


def test_mtc_cosigners_message_names_unmet_and_invalid(issued: Issued) -> None:
    p = proof_of(issued.standalone)
    bad = tuple(replace(s, signature=b"\x00" * len(s.signature)) if s.cosigner_id == C1.raw else s for s in p.signatures)
    cert = resign(issued, issued.standalone, proof=replace(p, signatures=bad))
    with pytest.raises(AlertError) as info:
        verify(cert, issued.store(frozenset({CA, C1, C2})))
    assert "32473.9.1" in str(info.value) and "32473.9.2" in str(info.value) and "invalid signatures from ['32473.9.1']" in str(info.value)


def test_configuration_is_frozen_when_built(issued: Issued) -> None:
    keys = {cid: c.public for cid, c in issued.cs.items()}
    store = mtc.MTCTrustStore(keys, (mtc.CAPolicy(CA, mtc.RequireAll(frozenset({CA, C1}))),))
    keys.pop(C1)
    verify(issued.standalone, store)
    with pytest.raises(TypeError):
        store.cosigners[C1] = keys[CA]  # type: ignore[index]


def test_a_malformed_ecdsa_cosigner_key_is_refused() -> None:
    with pytest.raises(CodecUsageError):
        mtc.CosignerKey("ECDSA-P256-SHA256", b"\x04" + b"\x00" * 64)


def test_many_unrecognized_cosignatures_cost_linear_time(issued: Issued) -> None:
    """~1 MB of GREASE cosignatures: decoded and skipped by dict lookup in well under a few seconds (D33);
    3c caps the Certificate message size."""
    import time

    p = proof_of(issued.standalone)
    grease = [mtc.Cosignature(i.to_bytes(3, "big"), b"") for i in range(0x010000, 0x010000 + 170_000)]
    sigs = tuple(sorted((*p.signatures, *grease), key=lambda c: (len(c.cosigner_id), c.cosigner_id)))
    cert = resign(issued, issued.standalone, proof=replace(p, signatures=sigs))
    start = time.perf_counter()
    verify(cert, issued.store())
    assert time.perf_counter() - start < 10


def test_naive_now_is_a_usage_error(issued: Issued) -> None:
    with pytest.raises(CodecUsageError):
        mtc.verify_certificate([issued.standalone], issued.store(), server_name="qtls.test", now=dt.datetime(2026, 2, 1),
                               expected_kind="sig")  # fmt: skip


def test_seeded_structural_fuzz_only_raises_alerts() -> None:
    """Random replace/insert/delete on the Go corpus: an AlertError with a reason, or an accept."""
    store, _ = _demo_store("qtls", "ca-only")
    certs = [p.read_bytes() for p in sorted((VECTORS / "qtls" / "certs").glob("*.der"))]
    rng = random.Random(33)
    for _ in range(500):
        cert = bytearray(rng.choice(certs))
        for _ in range(rng.randrange(1, 4)):
            i = rng.randrange(len(cert))
            op = rng.randrange(3)
            if op == 0:
                cert[i] = rng.randrange(256)
            elif op == 1:
                cert[i:i] = bytes([rng.randrange(256)])
            else:
                del cert[i]
        try:
            mtc.verify_proof(bytes(cert), store)
        except AlertError as exc:
            assert exc.reason


def test_fixture_issuance_is_byte_for_byte_reproducible(issued: Issued) -> None:
    """D34: two independent fixture runs give identical certificates (ML-DSA seeded, ECDSA RFC 6979)."""
    again = Issued()
    assert again.standalone == issued.standalone and again.landmark_cert == issued.landmark_cert
    cs = [mtc.fixture_cosigner(c, a, r) for c, a, r in ((CA, "ML-DSA-44", "mtc-ca"), (C1, "ML-DSA-65", "mtc-cosigner-1"),
                                                        (C2, "ECDSA-P256-SHA256", "mtc-cosigner-2"))]  # fmt: skip
    log = issued.log
    assert log.standalone(issued.later, cs) == log.standalone(issued.later, [issued.cs[c] for c in (CA, C1, C2)])


def test_backends_are_frozen_too(issued: Issued) -> None:
    backends = {a: "openssl" for a in mtc.COSIGNER_ALGORITHMS}
    store = mtc.MTCTrustStore({cid: c.public for cid, c in issued.cs.items()},
                              (mtc.CAPolicy(CA, mtc.RequireAll(frozenset({CA}))),), backends)  # fmt: skip
    backends.clear()
    verify(issued.standalone, store)
