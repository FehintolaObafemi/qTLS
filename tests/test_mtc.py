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
import importlib.util
import itertools
import json
import random
import re
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from qtls import crypto, der, merkle, mtc, x509
from qtls.alerts import Alert, AlertError, CodecUsageError
from qtls.trust_anchor_ids import TrustAnchorID

UTC = dt.timezone.utc
VECTORS = Path(__file__).parent / "vectors" / "mtc-demo"


def _load_demo():  # noqa: ANN202
    """scripts/mtc_demo.py: the policy renderer and parser, Go's verdict classes, the comparison."""
    spec = importlib.util.spec_from_file_location("mtc_demo", Path(__file__).parent.parent / "scripts" / "mtc_demo.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["mtc_demo"] = module
    spec.loader.exec_module(module)
    return module


DEMO = _load_demo()
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
    """The vendored policy, read by the same parser the live differential uses, over the CA's
    certificate parsed by qTLS (§7.1): its key, ID and serial bounds."""
    base = VECTORS / corpus
    store = DEMO.demo_store((base / "ca_cert.der").read_bytes(), (base / f"policy-{policy}.txt").read_text())
    return store, json.loads((base / "verdicts.json").read_text())


def _details(corpus: str) -> dict[str, dict[str, dict]]:
    return json.loads((VECTORS / corpus / "details.json").read_text())


DEMO_CASES = [(c, p, name) for c in ("wg", "qtls") for name, by in json.loads((VECTORS / c / "verdicts.json").read_text()).items()
              for p in by]  # fmt: skip


@pytest.mark.parametrize(("corpus", "policy", "name"), DEMO_CASES, ids=[f"{c}-{p}-{n}" for c, p, n in DEMO_CASES])
def test_same_verdict_as_the_go_demo(corpus: str, policy: str, name: str) -> None:
    """The same accept/reject for a reason in Go's verdict class, the same quorums met by the
    cosigners Go found, and on a step-12 accept the same cosigners counted (D33, D35)."""
    store, verdicts = _demo_store(corpus, policy)
    go = DEMO.GoResult.from_json(_details(corpus)[name][policy])
    assert go.verdict == verdicts[name][policy]
    cert = (VECTORS / corpus / "certs" / f"{name}.der").read_bytes()
    assert DEMO.compare_one(cert, store, go) is None
    # And the exact reason, from a table kept apart from the script's classes.
    if go.verdict == "OK":
        mtc.verify_proof(cert, store)
    else:
        expected = next(r for prefix, r in DEMO_REASONS.items() if go.verdict.startswith(prefix))
        assert reason_of(lambda: mtc.verify_proof(cert, store))[1] == expected


# How each vendored demo verdict reads as a D33 reason (§7.2 level).
DEMO_REASONS = {
    "signature was not a whole number of bytes": "mtc-proof",
    "malformed MTCProof": "mtc-proof",
    "cosigners not in canonical order or duplicate": "mtc-proof",
    "cosigner policy not satisfied": "mtc-cosigners",
    "trusted subtree hash mismatch": "mtc-trusted-subtree",
    "unparsable: x509: inner and outer signature algorithm identifiers don't match": "mtc-alg",
    "certificate serial ": "mtc-revoked",
}


def test_demo_corpora_cover_what_they_should() -> None:
    """Guards the vendored corpora without hard-coded totals: every verdict has a class; each class
    the corpora are meant to exercise appears; every policy and certificate is verified under every
    policy; each quorum policy has an accept at exactly k and a reject at k - 1 (D35)."""
    seen = set()
    for c in ("wg", "qtls"):
        verdicts = json.loads((VECTORS / c / "verdicts.json").read_text())
        policies = {p.stem.removeprefix("policy-") for p in (VECTORS / c).glob("policy-*.txt")}
        assert {n for n in verdicts} == {p.stem for p in (VECTORS / c / "certs").glob("*.der")}
        assert all(set(by) == policies for by in verdicts.values()), c
        assert set(_details(c)) == set(verdicts)
        seen |= {r for by in verdicts.values() for v in by.values() for r in DEMO.go_class(v)}
    assert seen >= {"OK", "mtc-proof", "mtc-alg", "mtc-cosigners", "mtc-trusted-subtree", "mtc-revoked"}
    assert {p.stem.removeprefix("policy-") for p in (VECTORS / "qtls").glob("policy-*.txt")} >= {
        "ca-only", "ca-and-1", "ca-and-2", "landmarks", "quorum-2-of-3", "nested", "revoked", "landmarks-derived"}
    assert {p.stem.removeprefix("policy-") for p in (VECTORS / "wg").glob("policy-*.txt")} >= {"wg-sample", "landmarks-derived"}
    verdicts = json.loads((VECTORS / "qtls" / "verdicts.json").read_text())
    for policy, k, accept, reject in (("quorum-2-of-3", 2, {CA, C1, C2}, {CA, C1}), ("nested", 2, {CA, C2, C3}, {CA, C2})):
        store, _ = _demo_store("qtls", policy)
        root = store.cas[0].policy
        assert isinstance(root, mtc.Quorum) and root.threshold == k
        for signers, ok in ((accept, True), (reject, False)):
            name = f"cert_{DEMO.SUBSETS_ENTRY}_{_mask(signers)}"
            assert (verdicts[name][policy] == "OK") is ok, (policy, name)
            assert (root.unsatisfied(frozenset(c.raw for c in signers)) == ()) is ok


def _mask(signers: set[TrustAnchorID]) -> int:
    return sum(bit for c, bit in ((CA, 8), (C1, 1), (C2, 2), (C3, 4)) if c in signers)


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
    expected = {"signature was not a whole number of bytes": {"der"},
                "unparsable: x509: inner and outer signature algorithm identifiers don't match": {"alg-mismatch"}}.get(
        demo, DEMO.go_class(demo))  # fmt: skip
    assert reason_of(call)[1] in expected


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


# --------------------------------------------------------------------------- #
# I. Cosigner quorums (§7.3; D35)
# --------------------------------------------------------------------------- #

Q = mtc.Quorum


def _chain(depth: int) -> mtc.Quorum:
    q = Q("d1", 1, (C1,))
    for d in range(2, depth + 1):
        q = Q(f"d{d}", 1, (q,))
    return q


@pytest.mark.parametrize(
    "build",
    [
        lambda: Q("q", 0, (C1, C2)), lambda: Q("q", 3, (C1, C2)), lambda: Q("q", -1, (C1,)), lambda: Q("q", True, (C1,)),
        lambda: Q("q", 1, ()), lambda: Q("q", 1, (C1, C1)), lambda: Q("q", 1, (Q("a", 1, (C1,)), Q("a", 1, (C1,)))),
        lambda: Q("", 1, (C1,)), lambda: Q(" q", 1, (C1,)), lambda: Q("a b", 1, (C1,)), lambda: Q("a#b", 1, (C1,)),
        lambda: Q("ä", 1, (C1,)), lambda: Q("32473.1", 1, (C1,)), lambda: Q("1abc", 1, (C1,)), lambda: Q("a" * 65, 1, (C1,)),
        lambda: Q("q\n", 1, (C1,)), lambda: Q(b"q", 1, (C1,)),  # type: ignore[arg-type]
        lambda: Q("q", 2, (Q("a", 1, (C1,)), Q("b", 1, (Q("a", 1, (C2,)),)))),  # two different "a" in one DAG
        lambda: Q("q", 1, (Q("q", 1, (C1,)),)),  # a child named like its parent
        lambda: Q("q", 1, ("32473.9.1",)), lambda: Q("q", 1, (C1.raw,)), lambda: Q("q", 1, (1,)),  # type: ignore[arg-type]
        lambda: Q("q", 1, C1), lambda: _chain(9),  # type: ignore[arg-type]
    ],
    ids=["k=0", "k=n+1", "k<0", "k-bool", "no-members", "duplicate-id", "duplicate-quorum", "empty-name", "leading-space",
         "space", "hash", "non-ascii", "dotted-decimal", "digit-first", "65-chars", "newline", "bytes-name", "name-clash",
         "parent-name-clash", "str-member", "bytes-member", "int-member", "not-a-sequence", "depth-9"],
)
def test_quorum_construction_refusals(build: Callable[[], object]) -> None:
    with pytest.raises(CodecUsageError):
        build()


def test_quorum_construction_accepts() -> None:
    assert Q("q", 1, (C1, C2)).threshold == 1 and Q("q", 2, (C1, C2)).threshold == 2
    assert _chain(8).cosigners() == {C1}
    shared = Q("operator-A", 1, (C1,))
    dag = Q("root", 2, (Q("x", 1, (shared, C2)), Q("y", 1, (shared, C3))))  # the WG sample's shape
    assert set(dag.quorums()) == {"root", "x", "y", "operator-A"}
    copy = Q("root", 2, (Q("x", 1, (shared, C2)), Q("y", 1, (Q("operator-A", 1, (C1,)), C3))))  # equal, not identical
    assert copy == dag and hash(copy) == hash(dag)
    listed = Q("q", 1, [C1, C2])  # type: ignore[arg-type]
    assert listed.members == (C1, C2) and isinstance(listed.members, tuple)
    Q("a" * 64, 1, (C1,))
    Q("Z9_.-", 1, (C1,))


@pytest.mark.parametrize("k", [1, 2, 3])
def test_quorum_counts_every_subset(k: int) -> None:
    q = Q("q", k, (C1, C2, C3))
    for n in range(4):
        for subset in itertools.combinations((C1, C2, C3), n):
            valid = frozenset(c.raw for c in subset) | {CA.raw, b"\x7f"}  # non-members don't count
            assert (q.unsatisfied(valid) == ()) is (n >= k), subset


def test_a_nested_quorum_counts_once_and_only_when_met() -> None:
    inner = Q("inner", 2, (C2, C3))
    q = Q("outer", 2, (C1, inner))
    assert q.unsatisfied(frozenset({C2.raw, C3.raw})) == ("outer", "32473.9.1")  # inner met: one member, not two
    assert q.unsatisfied(frozenset({C1.raw, C2.raw})) == ("outer", "inner")
    assert q.unsatisfied(frozenset({C1.raw, C2.raw, C3.raw})) == ()
    only_through_child = Q("top", 1, (Q("mid", 1, (Q("leaf", 2, (C2, C3)),)),))
    assert only_through_child.unsatisfied(frozenset({C2.raw})) == ("top", "mid")
    assert only_through_child.unsatisfied(frozenset({C2.raw, C3.raw})) == ()
    assert only_through_child.satisfied(frozenset({C2.raw, C3.raw})) == {"top", "mid", "leaf"}
    assert only_through_child.satisfied(frozenset({C2.raw})) == frozenset()


def test_quorum_messages_are_names_only() -> None:
    q = Q("ca-and-two", 2, (CA, Q("two-of-three", 2, (C1, C2, C3))))
    unmet = q.unsatisfied(frozenset({C1.raw, b"\xff" * 40}))
    assert unmet == ("ca-and-two", "32473.9", "two-of-three")
    assert all(type(x) is str for x in unmet)
    assert q.unsatisfied(frozenset({CA.raw, C1.raw, C3.raw})) == ()


def test_a_shared_quorum_is_evaluated_once_per_call(monkeypatch: pytest.MonkeyPatch) -> None:
    shared = Q("shared", 1, (C1, C2))
    root = Q("root", 3, (Q("a", 1, (shared,)), Q("b", 1, (shared, C3)), shared))
    calls: list[str] = []
    real = mtc.Quorum._count

    def counting(self: mtc.Quorum, valid: frozenset[bytes], memo: dict) -> int:
        calls.append(self.name)
        return real(self, valid, memo)

    monkeypatch.setattr(mtc.Quorum, "_count", counting)
    assert root.unsatisfied(frozenset({C1.raw})) == ()
    assert sorted(calls) == ["a", "b", "root", "shared"]
    calls.clear()
    root.satisfied(frozenset({C3.raw}))
    assert sorted(calls) == ["a", "b", "root", "shared"]


def test_require_all_is_quorum_n_of_n() -> None:
    req, quorum = mtc.RequireAll(frozenset({C1, C2, C3})), Q("all", 3, (C1, C2, C3))
    assert req.cosigners() == quorum.cosigners()
    for n in range(4):
        for subset in itertools.combinations((C1, C2, C3), n):
            valid = frozenset(c.raw for c in subset)
            assert (req.unsatisfied(valid) == ()) is (quorum.unsatisfied(valid) == ())


def test_quorum_configuration_rules() -> None:
    dag = Q("root", 2, (CA, Q("x", 1, (C1, Q("y", 1, (C2,))))))
    assert dag.cosigners() == {CA, C1, C2}
    with pytest.raises(CodecUsageError):
        mtc.CAPolicy(CA, Q("no-ca", 1, (C1, C2)))  # the CA must be in the union (§7.3; D33)
    with pytest.raises(CodecUsageError):
        mtc.MTCTrustStore({CA: KEY44, C1: KEY44}, (mtc.CAPolicy(CA, dag),))  # C2 has no key
    mtc.MTCTrustStore({CA: KEY44, C1: KEY44, C2: KEY44}, (mtc.CAPolicy(CA, dag),))


class Quorums:
    """Certificates from the 3b1 fixture log, cosigned by every subset of {CA, C1, C2, C3}."""

    def __init__(self, issued: Issued) -> None:
        self.issued = issued
        self.cs = {**issued.cs, C3: mtc.fixture_cosigner(C3, "ML-DSA-44", "mtc-cosigner-3")}
        p = proof_of(issued.standalone)
        h = issued.log.tree().hash(p.start, p.end)
        self.certs = {}
        for n in range(5):
            for subset in itertools.combinations((CA, C1, C2, C3), n):
                sigs = tuple(sorted((self.cs[c].sign(issued.log.log_id, p.start, p.end, h) for c in subset),
                                    key=lambda c: (len(c.cosigner_id), c.cosigner_id)))  # fmt: skip
                self.certs[frozenset(subset)] = resign(issued, issued.standalone, proof=replace(p, signatures=sigs))

    def store(self, policy: mtc.CosignerPolicy) -> mtc.MTCTrustStore:
        return mtc.MTCTrustStore({c: k.public for c, k in self.cs.items()}, (mtc.CAPolicy(CA, policy),))


@pytest.fixture(scope="module")
def quorums(issued: Issued) -> Quorums:
    return Quorums(issued)


NESTED = Q("nested", 2, (CA, Q("inner", 1, (C1, Q("deep", 2, (C2, C3))))))


def test_step_12_under_quorums(quorums: Quorums) -> None:
    """Every subset of {CA, C1, C2, C3} under 2-of-{CA, C1, C2}, a nested policy and the 3b1 RequireAll:
    accepted exactly when the quorum is met and the CA signed (§7.3: the CA is always required)."""
    policies = {
        "two-of": (Q("two-of", 2, (CA, C1, C2)), lambda s: CA in s and len(s & {CA, C1, C2}) >= 2),
        "nested": (NESTED, lambda s: CA in s and (C1 in s or {C2, C3} <= s)),
        "require-all": (mtc.RequireAll(frozenset({CA, C2})), lambda s: {CA, C2} <= s),
    }
    for name, (policy, expected) in policies.items():
        store = quorums.store(policy)
        for subset, cert in quorums.certs.items():
            if expected(subset):
                v = verify(cert, store)
                assert v.valid_cosigners == {c.raw for c in subset & (policy.cosigners() | {CA})}, (name, subset)
            else:
                assert reason_of(lambda: verify(cert, store)) == (Alert.bad_certificate, "mtc-cosigners"), (name, subset)


def test_the_ca_counts_toward_a_quorum_and_is_still_required(quorums: Quorums) -> None:
    store = quorums.store(Q("two-of", 2, (CA, C1, C2)))
    with pytest.raises(AlertError) as info:
        verify(quorums.certs[frozenset({C1, C2})], store)  # the quorum is met without the CA
    assert info.value.reason == "mtc-cosigners" and "32473.9 (the CA)" in str(info.value)
    assert verify(quorums.certs[frozenset({CA, C1})], store).valid_cosigners == {CA.raw, C1.raw}


def test_invalid_unknown_and_grease_signatures_never_count_toward_a_quorum(quorums: Quorums) -> None:
    store = quorums.store(Q("two-of", 2, (CA, C1, C2)))
    p = proof_of(quorums.certs[frozenset({CA, C1})])
    flipped = tuple(replace(s, signature=s.signature[:-1] + bytes([s.signature[-1] ^ 1])) if s.cosigner_id == C1.raw else s
                    for s in p.signatures)  # fmt: skip
    extra = (mtc.Cosignature(b"\x01" * 255, b"junk"), mtc.Cosignature(b"\x7f", b""), mtc.Cosignature(CA.child(200).raw, b"g"))
    for sigs in (flipped, tuple(sorted((*flipped, *extra), key=lambda c: (len(c.cosigner_id), c.cosigner_id)))):
        cert = resign(quorums.issued, quorums.issued.standalone, proof=replace(p, signatures=sigs))
        assert reason_of(lambda: verify(cert, store)) == (Alert.bad_certificate, "mtc-cosigners")


def test_only_the_ca_and_quorum_cosigners_are_verified_once_each(quorums: Quorums, monkeypatch: pytest.MonkeyPatch) -> None:
    """D33: verification work follows the policy, not the certificate, under any quorum."""
    calls: list[bytes] = []
    real = crypto.sig_verify

    def spy(alg: str, key: bytes, message: bytes, signature: bytes, backend: crypto.Backend) -> None:
        calls.append(message)
        real(alg, key, message, signature, backend)

    monkeypatch.setattr(crypto, "sig_verify", spy)
    p = proof_of(quorums.certs[frozenset({CA, C1, C2, C3})])
    grease = [mtc.Cosignature(i.to_bytes(3, "big"), b"") for i in range(0x010000, 0x010000 + 50)]
    sigs = tuple(sorted((*p.signatures, *grease), key=lambda c: (len(c.cosigner_id), c.cosigner_id)))
    cert = resign(quorums.issued, quorums.issued.standalone, proof=replace(p, signatures=sigs))
    v = verify(cert, quorums.store(Q("q", 2, (CA, Q("one", 1, (C1,))))))
    assert v.valid_cosigners == {CA.raw, C1.raw} and len(calls) == 2
    assert {m[13:13 + m[12]] for m in calls} == {mtc.origin(CA), mtc.origin(C1)}


def test_robustness_under_a_nested_quorum_store(quorums: Quorums) -> None:
    """3b1's single-byte, truncation and structural fuzz, re-run against a nested-quorum store: only
    AlertError, never a local error (D33)."""
    store = quorums.store(NESTED)
    cert = quorums.certs[frozenset({CA, C1, C2, C3})]
    verify(cert, store)
    rng = random.Random(35)
    for i in sorted(rng.sample(range(len(cert)), 600)):
        try:
            verify(cert[:i] + bytes([cert[i] ^ 1]) + cert[i + 1 :], store)
        except AlertError as exc:
            assert exc.reason
    for n in range(0, len(cert), 7):
        with pytest.raises(AlertError):
            verify(cert[:n], store)
    for _ in range(300):
        damaged = bytearray(cert)
        for _ in range(rng.randrange(1, 4)):
            i = rng.randrange(len(damaged))
            op = rng.randrange(3)
            if op == 0:
                damaged[i] = rng.randrange(256)
            elif op == 1:
                damaged[i:i] = bytes([rng.randrange(256)])
            else:
                del damaged[i]
        try:
            verify(bytes(damaged), store)
        except AlertError as exc:
            assert exc.reason


# --------------------------------------------------------------------------- #
# J. The CA certificate (§5.5, §7.1; D35)
# --------------------------------------------------------------------------- #

UNSIGNED = der.seq(der.oid(mtc.ALG_UNSIGNED))
ML44_OID, ML65_OID, EC_SIG_OID = (x509.BY_NAME[a].oid for a in ("ML-DSA-44", "ML-DSA-65", "ECDSA-P256-SHA256"))
MIN3, MAX3 = 3 << 48, (3 << 48) | (2**48 - 1)


def _ext(oid: str, value: bytes, critical: bool = True) -> bytes:
    return der.seq(der.oid(oid), *([der.boolean(True)] if critical else []), der.octet_string(value))


def _mtc_value(alg: bytes | None = None, lo: bytes | None = None, hi: bytes | None = None, extra: bytes = b"") -> bytes:
    return der.seq(alg if alg is not None else der.seq(der.oid(ML44_OID)), lo if lo is not None else der.integer(MIN3),
                   hi if hi is not None else der.integer(MAX3), extra)  # fmt: skip


KU = _ext(x509.KEY_USAGE, der.named_bits({x509.KEY_CERT_SIGN}))
BC = _ext(x509.BASIC_CONSTRAINTS, der.seq(der.boolean(True)))


def _mtc_ext(value: bytes | None = None, critical: bool = True, oid: str = mtc.MTC_CA_EXTENSION) -> bytes:
    return _ext(oid, value if value is not None else _mtc_value(), critical)


def _ca(keys: dict[str, bytes], *, exts: list[bytes] | None = None, version: bytes | None = der.explicit(0, der.integer(2)),
        subject: bytes | None = None, spki: bytes | None = None, inner: bytes = UNSIGNED, outer: bytes = UNSIGNED,
        validity: tuple[dt.datetime, dt.datetime] = (NOT_BEFORE, NOT_AFTER), signature: bytes = der.bit_string(b""),
        extra_fields: bytes = b"") -> bytes:  # fmt: skip
    """A CA certificate from parts; by default exactly what IssuanceLog.ca_certificate builds for 32473.9."""
    tbs = der.seq(version or b"", der.integer(1), inner,
                  der.seq(der.set_of(der.seq(der.oid(mtc.RDNA_UNSIGNED), der.utf8_string("")))),
                  der.seq(der.time(validity[0]), der.time(validity[1])), subject if subject is not None else mtc.trust_anchor_name(CA),
                  spki if spki is not None else x509.spki("ML-DSA-44", keys["ML-DSA-44"]), extra_fields,
                  der.explicit(3, der.seq(*(exts if exts is not None else [KU, BC, _mtc_ext()]))))  # fmt: skip
    return der.seq(tbs, outer, signature)


@pytest.fixture(scope="module")
def ca_keys(require_liboqs: None) -> dict[str, bytes]:
    from qtls import chains

    return {alg: chains.signing_key(alg, b"qtls fixture v1", role).public_key
            for alg, role in (("ML-DSA-44", "mtc-ca"), ("ML-DSA-65", "mtc-cosigner-1"), ("ECDSA-P256-SHA256", "mtc-cosigner-2"))}


def test_vendored_ca_certificates_parse() -> None:
    """Go-built CA certificates (RFC 9925 unsigned) as qTLS reads them."""
    from qtls import chains

    wg = mtc.parse_ca_certificate((VECTORS / "wg" / "ca_cert.der").read_bytes())
    assert (wg.ca_id, wg.key.alg, wg.min_serial, wg.max_serial) == (tai("32473.1"), "ML-DSA-44", 1 << 48, (5 << 48) | (2**48 - 1))
    q = mtc.parse_ca_certificate((VECTORS / "qtls" / "ca_cert.der").read_bytes())
    assert (q.ca_id, q.min_serial, q.max_serial) == (CA, MIN3, MAX3)
    assert q.key == mtc.CosignerKey("ML-DSA-44", chains.signing_key("ML-DSA-44", b"qtls fixture v1", "mtc-ca").public_key)
    assert q.revoked() == (mtc.RevokedRange(0, MIN3), mtc.RevokedRange(MAX3 + 1, 1 << 64))


@pytest.mark.parametrize("corpus", ["wg", "qtls"])
def test_ca_certificate_ranges_match_the_demo_config(corpus: str) -> None:
    """What 3b1 derived from config.json by hand, qTLS now reads from the certificate (§7.1)."""
    config = json.loads((VECTORS / corpus / "config.json").read_text())
    lo = (config["CACert"]["MinSerial"]["Log"] << 48) | config["CACert"]["MinSerial"]["Index"]
    hi = ((config["CACert"]["MaxSerial"]["Log"] << 48) | config["CACert"]["MaxSerial"]["Index"]) + 1
    ca = mtc.parse_ca_certificate((VECTORS / corpus / "ca_cert.der").read_bytes())
    assert ca.revoked() == (mtc.RevokedRange(0, lo), mtc.RevokedRange(hi, 2**64))


def test_issued_ca_certificate_is_the_demos_byte_for_byte(ca_keys: dict[str, bytes]) -> None:
    """IssuanceLog.ca_certificate against the Go-built certificate for the same CA (a known answer)."""
    log = mtc.IssuanceLog(CA, 3)
    cert = log.ca_certificate(mtc.fixture_cosigner(CA, "ML-DSA-44", "mtc-ca"), min_serial=MIN3, max_serial=MAX3,
                              not_before=NOT_BEFORE, not_after=NOT_AFTER)  # fmt: skip
    assert cert == (VECTORS / "qtls" / "ca_cert.der").read_bytes() == _ca(ca_keys)
    with pytest.raises(CodecUsageError):
        log.ca_certificate(mtc.fixture_cosigner(C1, "ML-DSA-65", "mtc-cosigner-1"), min_serial=MIN3, max_serial=MAX3,
                           not_before=NOT_BEFORE, not_after=NOT_AFTER)  # fmt: skip
    for lo, hi in ((MIN3 + 1, MIN3), (2**48 - 1, MAX3), (MIN3, 2**64)):
        with pytest.raises(CodecUsageError):
            log.ca_certificate(mtc.fixture_cosigner(CA, "ML-DSA-44", "mtc-ca"), min_serial=lo, max_serial=hi,
                               not_before=NOT_BEFORE, not_after=NOT_AFTER)  # fmt: skip


@pytest.mark.parametrize(("alg", "role"), [("ML-DSA-44", "mtc-ca"), ("ML-DSA-65", "mtc-cosigner-1"), ("ECDSA-P256-SHA256", "mtc-cosigner-2")])
def test_ca_certificate_round_trip(require_liboqs: None, alg: str, role: str) -> None:
    ca_id = tai("32473.77")
    cosigner = mtc.fixture_cosigner(ca_id, alg, role)
    cert = mtc.IssuanceLog(ca_id, 1).ca_certificate(cosigner, min_serial=2**48, max_serial=2**64 - 1,
                                                    not_before=NOT_BEFORE, not_after=NOT_AFTER)  # fmt: skip
    parsed = mtc.parse_ca_certificate(cert)
    assert (parsed.ca_id, parsed.key, parsed.min_serial, parsed.max_serial) == (ca_id, cosigner.public, 2**48, 2**64 - 1)


@pytest.mark.parametrize(
    ("lo", "hi", "revoked"),
    [
        (2**48, 2**64 - 1, [(0, 2**48)]),
        (2**48, 2**64 - 2, [(0, 2**48), (2**64 - 1, 2**64)]),
        (MIN3, MIN3, [(0, MIN3), (MIN3 + 1, 2**64)]),
        (2**64 - 1, 2**64 - 1, [(0, 2**64 - 1)]),
    ],
    ids=["widest", "max-2^64-2", "min=max", "only-the-last-serial"],
)
def test_ca_certificate_serial_boundaries(ca_keys: dict[str, bytes], lo: int, hi: int, revoked: list) -> None:
    cert = _ca(ca_keys, exts=[KU, BC, _mtc_ext(_mtc_value(lo=der.integer(lo), hi=der.integer(hi)))])
    assert [(r.lo, r.hi) for r in mtc.parse_ca_certificate(cert).revoked()] == revoked


def _ca_mutants(k: dict[str, bytes]) -> dict[str, bytes]:
    good = _ca(k)
    off_curve = bytes.fromhex("04") + b"\x00" * 63 + b"\x01"
    ec_spki = x509.spki("ECDSA-P256-SHA256", k["ECDSA-P256-SHA256"])
    alg = lambda oid, *params: _mtc_ext(_mtc_value(alg=der.seq(der.oid(oid), *params)))  # noqa: E731
    sub = lambda *rdns: der.seq(*rdns)  # noqa: E731
    attr = lambda oid, value: der.seq(der.oid(oid), value)  # noqa: E731
    return {
        "non-canonical-boolean": _ca(k, exts=[KU, der.seq(der.oid(x509.BASIC_CONSTRAINTS), der.tlv(der.BOOLEAN, b"\x01"),
                                                          der.octet_string(der.seq(der.boolean(True)))), _mtc_ext()]),
        "non-minimal-length": der.seq(der.parse(good).children()[0].raw, UNSIGNED, b"\x03\x81\x01\x00"),
        "v1": _ca(k, version=None), "v2": _ca(k, version=der.explicit(0, der.integer(1))),
        "trailing-bytes": good + b"\x00",
        "unique-ids-out-of-order": _ca(k, extra_fields=der.tlv(0x82, b"\x00") + der.tlv(0x81, b"\x00")),
        "subject-cn": _ca(k, subject=x509.name("32473.9")),
        "subject-two-attributes": _ca(k, subject=sub(der.set_of(attr(x509.TRUST_ANCHOR_ID_ATTRIBUTE, CA.der),
                                                                attr(x509.COMMON_NAME, der.utf8_string("x"))))),
        "subject-two-rdns": _ca(k, subject=sub(der.set_of(attr(x509.TRUST_ANCHOR_ID_ATTRIBUTE, CA.der)),
                                               der.set_of(attr(x509.COMMON_NAME, der.utf8_string("x"))))),
        "subject-non-minimal-id": _ca(k, subject=sub(der.set_of(attr(x509.TRUST_ANCHOR_ID_ATTRIBUTE, der.tlv(der.RELATIVE_OID, b"\x80\x01"))))),
        "subject-empty-id": _ca(k, subject=sub(der.set_of(attr(x509.TRUST_ANCHOR_ID_ATTRIBUTE, der.tlv(der.RELATIVE_OID, b""))))),
        "subject-22-byte-id": _ca(k, subject=mtc.trust_anchor_name(TrustAnchorID(b"\x01" * 22))),
        "mtc-absent": _ca(k, exts=[KU, BC]),
        "mtc-twice": _ca(k, exts=[KU, BC, _mtc_ext(), _mtc_ext()]),
        "mtc-not-critical": _ca(k, exts=[KU, BC, _mtc_ext(critical=False)]),
        "mtc-wrong-oid": _ca(k, exts=[KU, BC, _mtc_ext(oid="1.3.6.1.5.5.7.1.39", critical=False)]),
        "mtc-trailing": _ca(k, exts=[KU, BC, _mtc_ext(_mtc_value() + b"\x00")]),
        "mtc-extra-field": _ca(k, exts=[KU, BC, _mtc_ext(_mtc_value(extra=der.integer(0)))]),
        "mtc-non-minimal-integer": _ca(k, exts=[KU, BC, _mtc_ext(_mtc_value(lo=der.tlv(der.INTEGER, b"\x00" + MIN3.to_bytes(7, "big"))))]),
        "mtc-negative": _ca(k, exts=[KU, BC, _mtc_ext(_mtc_value(lo=der.integer(-1)))]),
        "mtc-not-a-sequence": _ca(k, exts=[KU, BC, _mtc_ext(der.integer(1))]),
        "min-below-2^48": _ca(k, exts=[KU, BC, _mtc_ext(_mtc_value(lo=der.integer(2**48 - 1)))]),
        "max-2^64": _ca(k, exts=[KU, BC, _mtc_ext(_mtc_value(hi=der.integer(2**64)))]),
        "min>max": _ca(k, exts=[KU, BC, _mtc_ext(_mtc_value(lo=der.integer(MIN3 + 10), hi=der.integer(MIN3 + 5)))]),
        "sigalg-ml-dsa-87": _ca(k, exts=[KU, BC, alg("2.16.840.1.101.3.4.3.19")]),
        "sigalg-ed25519": _ca(k, exts=[KU, BC, alg("1.3.101.112")]),
        "sigalg-p384": _ca(k, exts=[KU, BC, alg("1.2.840.10045.4.3.3")]),
        "sigalg-falcon": _ca(k, exts=[KU, BC, alg(x509.BY_NAME["Falcon-512"].oid)]),
        "sigalg-null-params": _ca(k, exts=[KU, BC, alg(ML44_OID, der.null())]),
        "sigalg-empty": _ca(k, exts=[KU, BC, _mtc_ext(_mtc_value(alg=der.seq()))]),
        "ml-dsa-44-sigalg-ml-dsa-65-key": _ca(k, spki=x509.spki("ML-DSA-65", k["ML-DSA-65"])),
        "ml-dsa-65-sigalg-ml-dsa-44-key": _ca(k, exts=[KU, BC, alg(ML65_OID)]),
        "ecdsa-sigalg-ml-dsa-key": _ca(k, exts=[KU, BC, alg(EC_SIG_OID)]),
        "ml-dsa-sigalg-ec-key": _ca(k, spki=ec_spki),
        "ec-key-off-curve": _ca(k, spki=x509.spki("ECDSA-P256-SHA256", off_curve), exts=[KU, BC, alg(EC_SIG_OID)]),
        "ec-key-p384-curve": _ca(k, spki=der.seq(der.seq(der.oid(x509.EC_PUBLIC_KEY), der.oid("1.3.132.0.34")),
                                                 der.bit_string(k["ECDSA-P256-SHA256"])), exts=[KU, BC, alg(EC_SIG_OID)]),
        "ku-absent": _ca(k, exts=[BC, _mtc_ext()]),
        "ku-without-keycertsign": _ca(k, exts=[_ext(x509.KEY_USAGE, der.named_bits({x509.DIGITAL_SIGNATURE})), BC, _mtc_ext()]),
        "bc-absent": _ca(k, exts=[KU, _mtc_ext()]),
        "bc-ca-false": _ca(k, exts=[KU, _ext(x509.BASIC_CONSTRAINTS, der.seq()), _mtc_ext()]),
        "bc-path-len-only": _ca(k, exts=[KU, _ext(x509.BASIC_CONSTRAINTS, der.seq(der.integer(0))), _mtc_ext()]),
        "unknown-critical": _ca(k, exts=[KU, BC, _mtc_ext(), _ext("1.2.3.4", der.null())]),
        "critical-ski": _ca(k, exts=[KU, BC, _mtc_ext(), _ext(x509.SUBJECT_KEY_ID, der.octet_string(CA.raw))]),
        "duplicate-ku": _ca(k, exts=[KU, KU, BC, _mtc_ext()]),
        "no-extensions": _ca(k, exts=[]),
        "inner-outer-mismatch": _ca(k, outer=der.seq(der.oid(ML44_OID))),
        "outer-params": _ca(k, outer=der.seq(der.oid(mtc.ALG_UNSIGNED), der.null())),
        "two-parts": der.seq(der.parse(good).children()[0].raw, UNSIGNED),
        "signature-not-a-bit-string": der.seq(der.parse(good).children()[0].raw, UNSIGNED, der.octet_string(b"")),
        "not-der": b"\x30\x80\x00\x00",
        "empty": b"",
    }


CA_MUTANTS = sorted(_ca_mutants({"ML-DSA-44": b"\x00" * 1312, "ML-DSA-65": b"\x00" * 1952,
                                 "ECDSA-P256-SHA256": _EC}))  # names only; the bytes are rebuilt with real keys


@pytest.mark.parametrize("mutant", CA_MUTANTS)
def test_every_ca_certificate_rule_is_refused_as_configuration(ca_keys: dict[str, bytes], mutant: str) -> None:
    """One mutant per §5.5 / RFC 5280 rule: CodecUsageError, never AlertError or DerError (it's local
    configuration, D35); the unmutated certificate parses."""
    mtc.parse_ca_certificate(_ca(ca_keys))
    with pytest.raises(CodecUsageError):
        mtc.parse_ca_certificate(_ca_mutants(ca_keys)[mutant])


def test_what_the_ca_certificate_parser_does_not_check(ca_keys: dict[str, bytes]) -> None:
    """A trust anchor: no signature or validity check (RFC 5280 §6.1.1(d), RFC 9925); a subject key
    identifier that isn't the CA ID is only a SHOULD (§5.5) and Go accepts it, so qTLS does too."""
    expired = _ca(ca_keys, validity=(dt.datetime(2000, 1, 1, tzinfo=UTC), dt.datetime(2001, 1, 1, tzinfo=UTC)))
    garbage = _ca(ca_keys, inner=der.seq(der.oid(ML44_OID)), outer=der.seq(der.oid(ML44_OID)), signature=der.bit_string(b"\x01" * 2420))
    ski = _ca(ca_keys, exts=[KU, BC, _mtc_ext(), _ext(x509.SUBJECT_KEY_ID, der.octet_string(b"\x01\x02"), critical=False)])
    noncritical_unknown = _ca(ca_keys, exts=[KU, BC, _mtc_ext(), _ext("1.2.3.4", der.null(), critical=False)])
    unique_ids = _ca(ca_keys, extra_fields=der.tlv(0x81, b"\x00") + der.tlv(0x82, b"\x00"))
    path_len = _ca(ca_keys, exts=[KU, _ext(x509.BASIC_CONSTRAINTS, der.seq(der.boolean(True), der.integer(0))), _mtc_ext()])
    for cert in (expired, garbage, ski, noncritical_unknown, unique_ids, path_len):
        assert mtc.parse_ca_certificate(cert).ca_id == CA


def test_ca_certificate_parse_never_raises_a_peer_error(ca_keys: dict[str, bytes]) -> None:
    """Seeded byte changes and truncations of a CA certificate: parsed, or CodecUsageError (D35)."""
    good = _ca(ca_keys)
    rng = random.Random(55)
    for i in sorted(rng.sample(range(len(good)), 400)) + list(range(0, 200)):
        for damaged in (good[:i] + bytes([good[i] ^ rng.randrange(1, 256)]) + good[i + 1 :], good[:i]):
            try:
                mtc.parse_ca_certificate(damaged)
            except CodecUsageError:
                pass


def test_ecdsa_ca_certificate(require_liboqs: None) -> None:
    cosigner = mtc.fixture_cosigner(CA, "ECDSA-P256-SHA256", "mtc-cosigner-2")
    cert = mtc.IssuanceLog(CA, 3).ca_certificate(cosigner, min_serial=MIN3, max_serial=MAX3, not_before=NOT_BEFORE,
                                                 not_after=NOT_AFTER)  # fmt: skip
    ca = mtc.parse_ca_certificate(cert)
    assert ca.key == cosigner.public
    log = mtc.IssuanceLog(CA, 3)
    log.append_null(3)
    i = log.add_certificate(**Issued.leaf_args(x509.spki("ECDSA-P256-SHA256", _EC)))
    log.checkpoint()
    store = mtc.MTCTrustStore({}, (mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({CA}))),))
    assert verify(log.standalone(i, [cosigner]), store).valid_cosigners == {CA.raw}


def test_ca_certificate_in_the_store(issued: Issued, ca_keys: dict[str, bytes]) -> None:
    ca = mtc.parse_ca_certificate(_ca(ca_keys))
    extra = (mtc.RevokedRange(MIN3 + 5, MIN3 + 7), mtc.RevokedRange(0, 10))  # overlapping the certificate's own range
    policy = mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({CA, C1})), (), extra)
    assert policy.revoked == (*ca.revoked(), *extra) and policy.ca_key == ca.key
    store = mtc.MTCTrustStore({C1: issued.cs[C1].public}, (policy,))  # the CA's key comes from its certificate
    assert store.cosigners[CA] == ca.key
    verify(issued.standalone, store)
    assert mtc.MTCTrustStore({CA: ca.key, C1: issued.cs[C1].public}, (policy,)).cosigners[CA] == ca.key
    with pytest.raises(CodecUsageError):  # a different key configured for the CA's ID
        mtc.MTCTrustStore({CA: issued.cs[C1].public, C1: issued.cs[C1].public}, (policy,))
    serial = (3 << 48) | issued.later
    narrowed = mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({CA})), (), (mtc.RevokedRange(serial, serial + 1),))
    assert reason_of(lambda: verify(issued.standalone, mtc.MTCTrustStore({}, (narrowed,)))) == (Alert.certificate_revoked, "mtc-revoked")


def test_log_zero_is_revoked_once_ranges_come_from_the_ca_certificate(issued: Issued, ca_keys: dict[str, bytes]) -> None:
    """D33 step 4: with [0, minSerial) from the CA certificate, a log-0 serial is mtc-revoked, not mtc-log-number."""
    store = mtc.MTCTrustStore({}, (mtc.CAPolicy.from_ca_certificate(mtc.parse_ca_certificate(_ca(ca_keys)), mtc.RequireAll(frozenset({CA}))),))
    cert = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, serial=issued.later))
    assert reason_of(lambda: verify(cert, store)) == (Alert.certificate_revoked, "mtc-revoked")
    for log in (2, 4):
        cert = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, serial=(log << 48) | issued.later))
        assert reason_of(lambda: verify(cert, store)) == (Alert.certificate_revoked, "mtc-revoked")
    for serial in (MIN3, MAX3):  # the edges of [minSerial, maxSerial] are accepted ranges
        cert = resign(issued, issued.standalone, tbs=rebuild_tbs(issued.standalone, serial=serial))
        assert reason_of(lambda: verify(cert, store))[0] != Alert.certificate_revoked


# --------------------------------------------------------------------------- #
# K. Landmarks: issuance, the §6.4.3 document, activity (D36)
# --------------------------------------------------------------------------- #

NOT_AFTER_S = int(NOT_AFTER.timestamp())


def test_landmark_expiry_on_issuance(issued: Issued) -> None:
    """§6.4.1: landmark 0 is (0, 0, 0); expiries never decrease and cover every logged notAfter."""
    log = mtc.IssuanceLog(CA, 1)
    assert log.landmark_sequence() == (mtc.Landmark(0, 0, 0),)
    log.append_null(4)
    assert log.add_landmark() == 1 and log.landmark_expiries == [0, 0]  # only null entries: expiry 0 is allowed
    log.add_certificate(**Issued.leaf_args(issued.leaf44))
    with pytest.raises(CodecUsageError):
        log.add_landmark(NOT_AFTER_S - 1)  # below the certificate's notAfter
    assert log.landmark_sequence() == (mtc.Landmark(0, 0, 0), mtc.Landmark(1, 4, 0)) and log.landmarks == [0, 4]
    assert log.add_landmark(NOT_AFTER_S) == 2  # exactly its notAfter
    log.append_null(1)
    for bad in (NOT_AFTER_S - 1, -1, 2**64, True, 1.5, "1"):
        with pytest.raises(CodecUsageError):
            log.add_landmark(bad)  # type: ignore[arg-type]
    assert log.landmarks == [0, 4, 5] and log.landmark_expiries == [0, 0, NOT_AFTER_S]  # refusals change nothing
    assert log.add_landmark(NOT_AFTER_S) == 3  # equal to the previous one
    log.append_null(1)
    assert log.add_landmark() == 4 and log.landmark_expiries[-1] == NOT_AFTER_S  # None: the floor
    log.append_null(1)
    log.add_landmark(2**64 - 1)
    log.append_null(1)
    assert log.add_landmark() == 6 and log.landmark_expiries[-1] == 2**64 - 1


def test_no_argument_landmarks_keep_issuance_byte_identical(issued: Issued) -> None:
    """3b1's callers pass no expiry: same landmarks, same certificates (the 3b1 fixture is reproduced)."""
    again = Issued()
    assert again.landmark_cert == issued.landmark_cert and again.log.landmarks == [0, 32]
    assert again.log.landmark_expiries == [0, NOT_AFTER_S]


def _doc(*lines: str) -> bytes:
    return "".join(line + "\n" for line in lines).encode()


GOOD_DOC = _doc("3", "300 2000", "200 1500", "100 1000", "0 0")
DOC_NOW = mtc.EPOCH + dt.timedelta(seconds=1200)  # landmarks 2 and 3 active, 1 expired


@pytest.mark.parametrize(
    "data",
    [
        b"", b"\n", _doc("3"), GOOD_DOC[:-1], GOOD_DOC + b"\n", GOOD_DOC.replace(b"\n", b"\r\n"),
        GOOD_DOC.replace(b"300 2000", b"300\t2000"), GOOD_DOC.replace(b"300 2000", b"300  2000"),
        GOOD_DOC.replace(b"300 2000", b" 300 2000"), GOOD_DOC.replace(b"300 2000", b"300 2000 "),
        GOOD_DOC.replace(b"3\n", b"+3\n", 1), GOOD_DOC.replace(b"300 2000", b"-0 2000"), GOOD_DOC.replace(b"300 2000", b"0300 2000"),
        GOOD_DOC.replace(b"0 0\n", b"00 0\n"), GOOD_DOC.replace(b"300 2000", b"3_00 2000"),
        GOOD_DOC.replace(b"3\n", "٣\n".encode(), 1), GOOD_DOC.replace(b"3\n", "³\n".encode(), 1),
        b"\xef\xbb\xbf" + GOOD_DOC, GOOD_DOC.replace(b"300 2000", b"300 2000\xff"), GOOD_DOC.replace(b"300 2000", b"300 2000x"),
        GOOD_DOC.replace(b"3\n", b"3" * 5000 + b"\n", 1), GOOD_DOC.replace(b"2000", b"9" * 21),
        _doc(str(2**48), "0 0"), _doc("1", f"{2**48} 0", "0 0"), _doc("1", f"5 {2**64}", "0 0"),
        _doc("1", "200 2000", "100 1000", "0 0"),  # latest + 2 lines
        _doc("3", "300 2000", "300 1500", "100 1000", "0 0"), _doc("3", "300 2000", "400 1500", "100 1000", "0 0"),  # sizes equal, increasing
        _doc("3", "300 1500", "200 2000", "0 0"),  # expiry increasing
        _doc("2", "300 2000", "200 1500"),  # no expired line
        _doc("1", "100 1000", "0 5"), _doc("1", "100 1000", "1 0"),  # landmark 0 isn't "0 0"
        _doc("3", "2 2000", "1 1500", "0 0"),  # landmark 3 at tree size 2 (sizes strictly increase from 0)
        b"1\n100 1000\n0 0\n" * 2, GOOD_DOC + b"x",
    ],
    ids=["empty", "newline-only", "header-only", "no-final-newline", "blank-line", "crlf", "tab", "double-space",
         "leading-space", "trailing-space", "plus", "minus-zero", "leading-zero", "double-zero", "underscore",
         "arabic-digit", "superscript", "bom", "non-ascii-byte", "trailing-garbage", "5000-digits", "21-digits",
         "header-2^48", "size-2^48", "expiry-2^64", "latest+2-lines", "equal-sizes", "increasing-sizes",
         "increasing-expiry", "no-expired-line", "landmark-0-expiry", "landmark-0-size", "size-below-number",
         "two-documents", "text-after-last-newline"],
)
def test_landmark_document_grammar(data: bytes) -> None:
    """§6.4.3 strictly, every refusal CodecUsageError (never ValueError from int())."""
    mtc.decode_landmarks(GOOD_DOC, DOC_NOW)
    with pytest.raises(CodecUsageError):
        mtc.decode_landmarks(data, DOC_NOW)


def test_landmark_document_line_count_is_checked_first() -> None:
    """§6.4.3's "greater than latest_landmark + 1 such lines" is refused as such, before any line is read
    (a later line would also name a negative landmark)."""
    for data in (_doc("1", "200 2000", "100 1000", "0 0"), _doc("0", "0 0", "0 0"), _doc("0") + b"x\n" * 3):
        with pytest.raises(CodecUsageError, match="landmark lines for latest landmark"):
            mtc.decode_landmarks(data, DOC_NOW)


def test_landmark_document_limits_and_inputs() -> None:
    top = 2**48 - 1
    doc = mtc.decode_landmarks(_doc(str(top), f"{top} {2**64 - 1}", f"{top - 1} 0"), DOC_NOW)
    assert doc.latest == top and doc.active == (mtc.Landmark(top, top, 2**64 - 1),)
    assert mtc.decode_landmarks(_doc("1", "200 2000", "0 0"), DOC_NOW).active == (mtc.Landmark(1, 200, 2000),)  # latest + 1 lines
    assert mtc.decode_landmarks(_doc("2", "300 2000", "200 2000", "0 0"), DOC_NOW).active[0].expiry == 2000  # equal expiries
    assert mtc.decode_landmarks(bytearray(GOOD_DOC), DOC_NOW) == mtc.decode_landmarks(memoryview(GOOD_DOC), DOC_NOW)
    for bad in (GOOD_DOC.decode(), None, 3):
        with pytest.raises(CodecUsageError):
            mtc.decode_landmarks(bad, DOC_NOW)  # type: ignore[arg-type]
    with pytest.raises(CodecUsageError):
        mtc.decode_landmarks(GOOD_DOC, dt.datetime(2026, 2, 1))  # naive now
    with pytest.raises(CodecUsageError):
        mtc.decode_landmarks(b"1\n" + b"1 1\n" * (mtc.MAX_LANDMARK_DOCUMENT // 4), DOC_NOW)  # over the byte cap
    big = _doc(str(70000), *(f"{70000 - i} {70000 - i}" for i in range(70000)), "0 0")
    assert len(big) < mtc.MAX_LANDMARK_DOCUMENT and len(mtc.decode_landmarks(big, DOC_NOW).active) == 70000 - 1200 + 1  # expiry 1200 = now is active


def test_landmark_activity_is_inclusive_like_not_after(issued: Issued) -> None:
    """Active iff now <= expiry, the same comparison as a certificate's notAfter (D24): expiry - 1 s and
    expiry are active, expiry + 1 µs isn't. Landmark 0 is never active, not even at the Epoch."""
    expiry = NOT_AFTER_S
    lm = mtc.Landmark(1, 10, expiry)
    leaf = x509.parse(issued.standalone)
    assert leaf.not_after == NOT_AFTER
    for delta, active in ((dt.timedelta(seconds=-1), True), (dt.timedelta(0), True), (dt.timedelta(microseconds=1), False)):
        now = NOT_AFTER + delta
        assert lm.active(now) is active
        try:
            x509.check_validity(leaf, now)
            valid = True
        except AlertError:
            valid = False
        assert valid is active
        doc = mtc.decode_landmarks(_doc("1", f"10 {expiry}", "0 0"), now)
        assert doc.active == ((lm,) if active else ()) and doc.boundary == (mtc.Landmark(0, 0, 0) if active else lm)
    assert not mtc.Landmark(0, 0, 0).active(mtc.EPOCH)
    assert mtc.decode_landmarks(_doc("1", "10 0", "0 0"), mtc.EPOCH).active == (mtc.Landmark(1, 10, 0),)


def test_landmark_document_prefix_processing() -> None:
    """Several expired lines are fine; lines after the first expired one are checked, then ignored."""
    doc = mtc.decode_landmarks(GOOD_DOC, DOC_NOW)
    assert doc.latest == 3 and [lm.number for lm in doc.active] == [2, 3] and doc.boundary == mtc.Landmark(1, 100, 1000)
    with pytest.raises(CodecUsageError):
        mtc.decode_landmarks(_doc("3", "300 2000", "200 1500", "100 1000", "0 7"), DOC_NOW)  # after the boundary, still checked
    with pytest.raises(CodecUsageError):
        mtc.decode_landmarks(_doc("3", "300 2000", "200 1500", "100 1000", "150 0"), DOC_NOW)
    assert mtc.decode_landmarks(_doc("4", "400 2000", "300 1500", "200 1000", "150 900", "0 0"), DOC_NOW).boundary.number == 2
    for line in ("250 900", "150 1100"):  # order broken only after the boundary: still refused
        with pytest.raises(CodecUsageError, match="strictly decrease"):
            mtc.decode_landmarks(_doc("4", "400 2000", "300 1500", "200 1000", line, "0 0"), DOC_NOW)


def test_landmark_document_subtrees() -> None:
    doc = mtc.decode_landmarks(GOOD_DOC, DOC_NOW)
    assert doc.subtrees(2) == tuple(s for s in merkle.find_subtrees(100, 200) if s[0] < s[1])
    assert doc.subtrees(3) == tuple(s for s in merkle.find_subtrees(200, 300) if s[0] < s[1])
    one = mtc.decode_landmarks(_doc("5", "65 2000", "64 9"), DOC_NOW)
    assert one.subtrees(5) == ((64, 65),)  # the empty second subtree is dropped
    for n in (0, 1, 4):
        with pytest.raises(CodecUsageError):
            doc.subtrees(n)


def test_encode_landmarks_round_trips(issued: Issued) -> None:
    log = mtc.IssuanceLog(CA, 1)
    for n, expiry in enumerate((100, 200, 200, 300), 1):
        log.append_null(10 * n)
        log.add_landmark(expiry)
    seq = log.landmark_sequence()
    for now_s, active in ((50, [1, 2, 3, 4]), (150, [2, 3, 4]), (250, [4]), (350, [])):
        now = mtc.EPOCH + dt.timedelta(seconds=now_s)
        data = mtc.encode_landmarks(seq, now)
        assert data.startswith(b"4\n")  # the header is the newest landmark, active or not
        doc = mtc.decode_landmarks(data, now)
        assert [lm.number for lm in doc.active] == active and doc.active == tuple(seq[n] for n in active)
        assert doc.boundary == seq[(active[0] if active else 5) - 1]  # the newest expired: landmark 0 if no other
        assert data.count(b"\n") == len(active) + 2
    for bad in ((), (mtc.Landmark(1, 1, 0),), (seq[0], seq[2]), (seq[0], mtc.Landmark(1, 0 + 10, 5), mtc.Landmark(2, 10, 5)),
                (seq[0], mtc.Landmark(1, 10, 5), mtc.Landmark(2, 20, 4))):  # fmt: skip
        with pytest.raises(CodecUsageError):
            mtc.encode_landmarks(bad, DOC_NOW)
    with pytest.raises(CodecUsageError):
        mtc.encode_landmarks(seq[:1], dt.datetime(2026, 1, 1))


@pytest.mark.parametrize("corpus", ["qtls", "wg"])
def test_document_subtrees_match_the_demos_printed_landmarks(corpus: str) -> None:
    """§6.4.1 through the §6.4.3 document against the demo's output (wg's landmark 3 starts at 2032 < 2036)."""
    marks = json.loads((VECTORS / corpus / "landmarks.json").read_text())
    doc = mtc.decode_landmarks(DEMO.landmark_document(marks, NOT_AFTER_S, NOW), NOW)
    assert [lm.number for lm in doc.active] == [m["landmark"] for m in marks]
    for m in marks:
        assert doc.subtrees(m["landmark"]) == tuple((s["start"], s["end"]) for s in m["subtrees"] if s["start"] < s["end"])
    if corpus == "wg":
        assert doc.subtrees(3) == ((2032, 2048), (2048, 2122))


@pytest.mark.parametrize("build", [lambda: mtc.Landmark(-1, 0, 0), lambda: mtc.Landmark(0, 1, 0), lambda: mtc.Landmark(0, 0, 1),
                                   lambda: mtc.Landmark(5, 4, 0), lambda: mtc.Landmark(1, 2**48, 0), lambda: mtc.Landmark(1, 1, 2**64),
                                   lambda: mtc.Landmark(1, 1, -1), lambda: mtc.Landmark(True, 1, 0)])
def test_landmark_fields_are_checked(build: Callable[[], object]) -> None:
    with pytest.raises(CodecUsageError):
        build()


# --------------------------------------------------------------------------- #
# L. §7.4: trusted subtrees from a cosigned reference checkpoint (D36)
# --------------------------------------------------------------------------- #

TS = int(dt.datetime(2026, 1, 15, tzinfo=UTC).timestamp())
EXPIRIES = {n: NOT_AFTER_S + 3600 * n for n in range(1, 5)}


class Landmarked:
    """Log 3 of CA 32473.9 with the draft's §7.4 example landmarks (sizes 200, 300, 400, 500), a
    certificate under each, and entries up to 700 for larger checkpoints. Another ``cn`` gives a fork:
    the same sizes and expiries over different entries."""

    def __init__(self, issued: Issued, cn: str = "qtls.test") -> None:
        self.cs = {**issued.cs, C3: mtc.fixture_cosigner(C3, "ML-DSA-44", "mtc-cosigner-3")}
        self.log = mtc.IssuanceLog(CA, 3)
        self.index = {}
        for n, size in enumerate((200, 300, 400, 500), 1):
            self.log.append_null(size - 10 - self.log.size)
            self.index[n] = self.log.add_certificate(**Issued.leaf_args(issued.leaf44, subject_cn=cn))
            self.log.append_null(size - self.log.size)
            assert self.log.add_landmark(EXPIRIES[n]) == n
        self.log.append_null(700 - self.log.size)
        self.doc = mtc.decode_landmarks(mtc.encode_landmarks(self.log.landmark_sequence(), NOW), NOW)
        self.keys = {c: k.public for c, k in self.cs.items()}
        self.certs = {n: self.log.landmark_relative(i) for n, i in self.index.items()}

    def update(self, signers: tuple[TrustAnchorID, ...] = (CA,), size: int = 520, *, proofs: object = None,
               larger: tuple[mtc.LargerCheckpoint, ...] = (), log_number: int = 3, ts: int = TS) -> mtc.LogLandmarks:  # fmt: skip
        ref = self.log.reference_checkpoint([self.cs[c] for c in signers], ts, size)
        return mtc.LogLandmarks(log_number, self.doc, replace(ref, larger=larger),
                                self.log.landmark_proofs(size) if proofs is None else proofs)  # type: ignore[arg-type]

    def store(self, policy: mtc.CosignerPolicy = mtc.RequireAll(frozenset({CA})), subtrees: tuple = ()) -> mtc.MTCTrustStore:
        return mtc.MTCTrustStore(self.keys, (mtc.CAPolicy(CA, policy, subtrees),))

    def derive(self, *updates: mtc.LogLandmarks, policy: mtc.CosignerPolicy = mtc.RequireAll(frozenset({CA})),
               bound: int = 10) -> mtc.DerivedLandmarks:  # fmt: skip
        return mtc.derive_landmarks(self.store(policy), CA, updates, max_active_landmarks=bound, now=NOW)

    def expected(self, *landmarks: int) -> tuple[mtc.TrustedSubtree, ...]:
        return tuple(replace(t, expiry=EXPIRIES[t.landmark]) for t in self.log.trusted_subtrees() if t.landmark in landmarks)

    def proofs_for(self, landmark: int, size: int = 520) -> list[mtc.SubtreeProof]:
        ranges = set(self.doc.subtrees(landmark))
        return [p for p in self.log.landmark_proofs(size) if (p.start, p.end) in ranges]


@pytest.fixture(scope="module")
def lm(issued: Issued) -> Landmarked:
    return Landmarked(issued)


def _kept(d: mtc.DerivedLandmarks) -> set[int]:
    return {t.landmark for t in d.ca.trusted_subtrees}  # type: ignore[misc]


def _reasons(d: mtc.DerivedLandmarks) -> dict[tuple[int, int], str]:
    return {(x.log_number, x.landmark.number): x.reason for x in d.discarded}


def test_derived_subtrees_are_the_landmark_subtrees_and_verify_end_to_end(lm: Landmarked) -> None:
    d = lm.derive(lm.update())
    assert d.discarded == () and d.ca.trusted_subtrees == lm.expected(1, 2, 3, 4)
    assert d.ca.reference_sizes == ((3, 520),) and all(t.expiry is not None for t in d.ca.trusted_subtrees)
    store = lm.store().with_derived(d)
    for n, cert in lm.certs.items():
        v = mtc.verify_certificate([cert], store, server_name="qtls.test", now=NOW, expected_kind="sig")
        assert v.proof.trusted_subtree is not None and v.proof.trusted_subtree.landmark == n
        assert v.proof.trusted_subtree.expiry == EXPIRIES[n]
    hand = lm.store(subtrees=lm.log.trusted_subtrees())  # §7.4's trusted-update-service route: the same subtrees, typed in
    assert [verify(c, hand).subtree_hash for c in lm.certs.values()] == [verify(c, store).subtree_hash for c in lm.certs.values()]


def test_the_drafts_example_reference_checkpoint_of_350(lm: Landmarked) -> None:
    """§7.4: landmarks at 200, 300, 400, 500 and a reference checkpoint of 350: the first two."""
    d = lm.derive(lm.update(size=350))
    assert _kept(d) == {1, 2} and _reasons(d) == {(3, 3): "beyond-checkpoint", (3, 4): "beyond-checkpoint"}
    d = lm.derive(lm.update(size=150))
    assert _kept(d) == set() and set(_reasons(d).values()) == {"beyond-checkpoint"} and len(d.discarded) == 4
    assert _kept(lm.derive(lm.update(size=500))) == {1, 2, 3, 4}  # the reference may equal the latest landmark


def _flip(p: mtc.SubtreeProof, field: str = "proof") -> mtc.SubtreeProof:
    value = getattr(p, field)
    return replace(p, **{field: value[:-1] + bytes([value[-1] ^ 1])})


def test_a_failing_landmark_is_discarded_with_every_newer_one(lm: Landmarked) -> None:
    proofs = lm.log.landmark_proofs(520)
    first2, second3 = lm.proofs_for(2)[0], lm.proofs_for(3)[1]
    for bad, failing in ((first2, 2), (second3, 3)):  # the first or the second subtree of a landmark
        for field in ("proof", "subtree_hash"):
            d = lm.derive(lm.update(proofs=[_flip(p, field) if p == bad else p for p in proofs]))
            assert _kept(d) == set(range(1, failing))
            assert _reasons(d) == {(3, failing): "subtree-consistency",
                                   **{(3, n): "newer-than-discarded" for n in range(failing + 1, 5)}}  # fmt: skip


@pytest.mark.parametrize(
    ("damage", "reason"),
    [
        ("ragged", "subtree-proof-malformed"), ("short-hash", "subtree-proof-malformed"), ("str-hash", "subtree-proof-malformed"),
        ("list-proof", "subtree-proof-malformed"), ("missing", "subtree-proof-missing"), ("duplicate", "subtree-proof-duplicate"),
        ("wrong-landmark", "subtree-consistency"), ("truncated", "subtree-consistency"), ("extended", "subtree-consistency"),
    ],
)
def test_per_landmark_proof_problems_are_discards_never_errors(lm: Landmarked, damage: str, reason: str) -> None:
    """Looked up by the (start, end) the document gives, never trusted for its own range (D36)."""
    proofs = list(lm.log.landmark_proofs(520))
    target = lm.proofs_for(2)[0]
    i = proofs.index(target)
    other = lm.proofs_for(1)[0]
    proofs[i:i + 1] = {
        "ragged": [replace(target, proof=target.proof + b"\x00")],
        "short-hash": [replace(target, subtree_hash=target.subtree_hash[:31])],
        "str-hash": [replace(target, subtree_hash=target.subtree_hash.hex())],
        "list-proof": [replace(target, proof=list(target.proof))],
        "missing": [],
        "duplicate": [target, target],
        "wrong-landmark": [replace(other, start=target.start, end=target.end)],
        "truncated": [replace(target, proof=target.proof[:-32])],
        "extended": [replace(target, proof=target.proof + bytes(32))],
    }[damage]
    d = lm.derive(lm.update(proofs=proofs))
    assert _reasons(d) == {(3, 2): reason, (3, 3): "newer-than-discarded", (3, 4): "newer-than-discarded"}
    assert _kept(d) == {1}


def test_unexpected_proofs_are_ignored(lm: Landmarked) -> None:
    junk = [mtc.SubtreeProof(0, 1, bytes(32), b""), mtc.SubtreeProof("0", "128", b"", b""), mtc.SubtreeProof(0, 2**60, b"x", b"y"),
            mtc.SubtreeProof(0, 200, bytes(32), bytes(64))]  # fmt: skip
    d = lm.derive(lm.update(proofs=[*junk, *lm.log.landmark_proofs(520)]))
    assert d.discarded == () and _kept(d) == {1, 2, 3, 4}


def test_the_per_ca_bound_discards_the_newest(lm: Landmarked) -> None:
    assert _kept(lm.derive(lm.update(), bound=4)) == {1, 2, 3, 4}
    d = lm.derive(lm.update(), bound=3)
    assert _kept(d) == {1, 2, 3} and _reasons(d) == {(3, 4): "over-bound"}
    d = lm.derive(lm.update(), bound=0)
    assert _kept(d) == set() and set(_reasons(d).values()) == {"over-bound"}
    for bad in (-1, True, 1.5, "3", None):
        with pytest.raises(CodecUsageError):
            lm.derive(lm.update(), bound=bad)  # type: ignore[arg-type]


def test_validation_discards_come_before_the_bound(lm: Landmarked) -> None:
    proofs = [_flip(p) if p == lm.proofs_for(2)[0] else p for p in lm.log.landmark_proofs(520)]
    d = lm.derive(lm.update(proofs=proofs), bound=3)
    assert _kept(d) == {1} and _reasons(d) == {(3, 2): "subtree-consistency", (3, 3): "newer-than-discarded",
                                               (3, 4): "newer-than-discarded"}  # fmt: skip
    d = lm.derive(lm.update(proofs=proofs), bound=0)
    assert _reasons(d) == {(3, 1): "over-bound", (3, 2): "subtree-consistency", (3, 3): "newer-than-discarded",
                           (3, 4): "newer-than-discarded"}  # fmt: skip


def test_the_bound_is_per_ca_across_logs(lm: Landmarked, issued: Issued) -> None:
    """Over the bound, drop the newest by expiry (ties: higher log, then higher number): each log
    keeps a contiguous oldest prefix (§7.4: "per CA")."""
    log4 = mtc.IssuanceLog(CA, 4)
    for size, expiry in ((50, EXPIRIES[1]), (90, EXPIRIES[1] + 1800), (130, EXPIRIES[3] + 1800)):
        log4.add_certificate(**Issued.leaf_args(issued.leaf44))
        log4.append_null(size - log4.size)
        log4.add_landmark(expiry)
    doc4 = mtc.decode_landmarks(mtc.encode_landmarks(log4.landmark_sequence(), NOW), NOW)
    u4 = mtc.LogLandmarks(4, doc4, log4.reference_checkpoint([lm.cs[CA]], TS), log4.landmark_proofs(130))
    order = [(3, 1), (4, 1), (4, 2), (3, 2), (3, 3), (4, 3), (3, 4)]  # by (expiry, log, number)
    for bound in range(0, 8):
        d = lm.derive(lm.update(), u4, bound=bound)
        kept = {(t.log_number, t.landmark) for t in d.ca.trusted_subtrees}
        assert kept == set(order[:bound]) and _reasons(d) == dict.fromkeys(order[bound:], "over-bound")
        for log in (3, 4):
            numbers = sorted(n for g, n in kept if g == log)
            assert numbers == list(range(1, len(numbers) + 1))  # a contiguous oldest prefix
    assert lm.derive(lm.update(), u4).ca.reference_sizes == ((3, 520), (4, 130))
    with pytest.raises(CodecUsageError):
        lm.derive(lm.update(), lm.update())  # one update per log


# Checkpoint cosignatures --------------------------------------------------- #


def test_checkpoint_cosigners_must_meet_the_cas_own_requirements(lm: Landmarked) -> None:
    """The step-12 evaluation (CA required, then the policy) on the checkpoint's valid signers (D36)."""
    policy = Q("q", 2, (CA, Q("two", 2, (C1, C2, C3))))
    assert _kept(lm.derive(lm.update((CA, C1, C3)), policy=policy)) == {1, 2, 3, 4}
    for signers in ((CA, C1), (C1, C2, C3), (CA,), ()):
        d = lm.derive(lm.update(signers), policy=policy)
        assert _kept(d) == set() and set(_reasons(d).values()) == {"checkpoint-cosigners"} and len(d.discarded) == 4
    either = Q("either", 1, (CA, C1))  # met by C1 alone, but the CA's checkpoint signature is still required
    assert set(_reasons(lm.derive(lm.update((C1,)), policy=either)).values()) == {"checkpoint-cosigners"}
    assert _kept(lm.derive(lm.update((CA,)), policy=either)) == {1, 2, 3, 4}


def test_junk_unknown_and_grease_checkpoint_signatures_do_not_count(lm: Landmarked) -> None:
    policy = mtc.RequireAll(frozenset({CA, C1}))
    good = lm.update((CA, C1))
    sigs = good.checkpoint.cosignatures
    c1 = next(s for s in sigs if s.cosigner_id == C1.raw)
    for junk in (b"", b"\x01", c1.signature[:-1], c1.signature + b"\x00", b"\x00" * len(c1.signature)):
        others = tuple(s for s in sigs if s.cosigner_id != C1.raw)
        extra = (mtc.CheckpointSignature(C1.raw, TS, junk), mtc.CheckpointSignature(b"\x01" * 40, TS, b"x"),
                 mtc.CheckpointSignature(CA.child(200).raw, TS, b"g"), mtc.CheckpointSignature(b"", 0, b""))  # fmt: skip
        u = replace(good, checkpoint=replace(good.checkpoint, cosignatures=others + extra))
        assert set(_reasons(lm.derive(u, policy=policy)).values()) == {"checkpoint-cosigners"}
    # A cosigner may sign more than once: any valid signature counts.
    u = replace(good, checkpoint=replace(good.checkpoint, cosignatures=(mtc.CheckpointSignature(C1.raw, TS, b"bad"), *sigs)))
    assert _kept(lm.derive(u, policy=policy)) == {1, 2, 3, 4}


def test_only_ca_and_policy_checkpoint_signatures_are_verified(lm: Landmarked, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bytes] = []
    real = crypto.sig_verify

    def spy(alg: str, key: bytes, message: bytes, signature: bytes, backend: crypto.Backend) -> None:
        calls.append(message)
        real(alg, key, message, signature, backend)

    u = lm.update((CA, C1, C2, C3))
    sigs = u.checkpoint.cosignatures
    u = replace(u, checkpoint=replace(u.checkpoint, cosignatures=sigs + sigs))  # each twice: verified once
    monkeypatch.setattr(crypto, "sig_verify", spy)
    assert _kept(lm.derive(u, policy=mtc.RequireAll(frozenset({CA, C2})))) == {1, 2, 3, 4}
    assert sorted(m[13:13 + m[12]] for m in calls) == sorted([mtc.origin(CA), mtc.origin(C2)])


def test_checkpoint_signatures_are_bound_to_their_log_and_timestamp(lm: Landmarked) -> None:
    good = lm.update()
    assert _kept(lm.derive(replace(good, log_number=4))) == set()  # log 3's checkpoint offered for log 4
    assert set(_reasons(lm.derive(replace(good, log_number=4))).values()) == {"checkpoint-cosigners"}
    shifted = tuple(replace(s, timestamp=s.timestamp + 1) for s in good.checkpoint.cosignatures)
    assert _kept(lm.derive(replace(good, checkpoint=replace(good.checkpoint, cosignatures=shifted)))) == set()
    zero = lm.update(ts=0)  # timestamp 0 is a valid checkpoint signature too (§5.3.1), with no freshness claim
    assert zero.checkpoint.cosignatures[0].timestamp == 0 and _kept(lm.derive(zero)) == {1, 2, 3, 4}
    top = lm.update(ts=2**64 - 1)
    assert _kept(lm.derive(top)) == {1, 2, 3, 4}


def test_a_cosigner_may_vouch_through_a_larger_checkpoint(lm: Landmarked) -> None:
    """§7.4's second option: a cosigned checkpoint containing the reference one, with a consistency proof."""
    policy = mtc.RequireAll(frozenset({CA, C1, C2}))
    l600 = lm.log.larger_checkpoint(520, [lm.cs[C1]], TS, 600)
    l700 = lm.log.larger_checkpoint(520, [lm.cs[C2]], TS + 5, 700)
    assert _kept(lm.derive(lm.update((CA,), larger=(l600, l700)), policy=policy)) == {1, 2, 3, 4}  # each its own larger one
    assert _kept(lm.derive(lm.update((CA, C2), larger=(l600,)), policy=policy)) == {1, 2, 3, 4}
    same = lm.log.larger_checkpoint(520, [lm.cs[C1]], TS, 520)
    assert same.consistency_proof == b"" and _kept(lm.derive(lm.update((CA, C2), larger=(same,)), policy=policy)) == {1, 2, 3, 4}
    root520 = lm.log.tree().hash(0, 520)
    bad = {
        "flipped-proof": replace(l600, consistency_proof=l600.consistency_proof[:-1] + bytes([l600.consistency_proof[-1] ^ 1])),
        "swapped": replace(l600, root_hash=root520),
        "same-size-non-empty-proof": replace(same, consistency_proof=bytes(32)),
        "smaller": lm.log.larger_checkpoint(300, [lm.cs[C1]], TS, 300),
        "short-root": replace(l600, root_hash=l600.root_hash[:31]),
        "str-root": replace(l600, root_hash=l600.root_hash.hex()),
        "bool-size": replace(l600, size=True),
        "huge-size": replace(l600, size=2**48),
        "list-proof": replace(l600, consistency_proof=list(l600.consistency_proof)),
        "not-signatures": replace(l600, cosignatures=(b"x",)),
        "other-log": mtc.LargerCheckpoint(l600.size, l600.root_hash, tuple(
            lm.cs[C1].sign_checkpoint(mtc.log_id(CA, 4), 600, l600.root_hash, TS) for _ in (0,)), l600.consistency_proof),
    }
    for name, larger in bad.items():
        d = lm.derive(lm.update((CA, C2), larger=(larger,)), policy=policy)
        assert set(_reasons(d).values()) == {"checkpoint-cosigners"}, name


def test_a_checkpoint_signature_never_counts_as_a_certificate_cosignature(issued: Issued) -> None:
    """The vendored Go checkpoint signatures are timestamped, so spliced into an MTCProof for [0, size)
    (step 12 verifies timestamp 0) they don't verify; a timestamp-0 signature over the same subtree does."""
    tree = DEMO.leaf_tree((VECTORS / "qtls" / "leaf_hashes.bin").read_bytes())
    store, _ = _demo_store("qtls", "ca-only")
    ref = DEMO.parse_checkpoint((VECTORS / "qtls" / "checkpoint").read_text(), mtc.log_id(CA, 3), store.cosigners)
    cert = (VECTORS / "qtls" / "certs" / "cert_92_8.der").read_bytes()  # CA-signed, entry 92
    p = proof_of(cert)
    go_sig = next(s for s in ref.cosignatures if s.cosigner_id == CA.raw)
    spliced = replace(p, start=0, end=ref.size, inclusion_proof=tree.inclusion_proof(0, ref.size, 92),
                      signatures=(mtc.Cosignature(CA.raw, go_sig.signature),))  # fmt: skip
    cert_go = der.seq(der.parse(cert).children()[0].raw, mtc.MTC_PROOF_ALGORITHM, der.bit_string(spliced.encode()))
    assert reason_of(lambda: verify(cert_go, store)) == (Alert.bad_certificate, "mtc-cosigners")
    ours = mtc.fixture_cosigner(CA, "ML-DSA-44", "mtc-ca").sign(mtc.log_id(CA, 3), 0, ref.size, ref.root_hash)
    cert_ours = der.seq(der.parse(cert).children()[0].raw, mtc.MTC_PROOF_ALGORITHM,
                        der.bit_string(replace(spliced, signatures=(ours,)).encode()))  # fmt: skip
    assert verify(cert_ours, store).valid_cosigners == {CA.raw}


def test_cosigned_subtree_timestamps() -> None:
    h = bytes(range(32))
    zero = mtc.cosigned_subtree(tai("32473.1"), tai("32473.1.0.1"), 0, 5, h)
    assert mtc.cosigned_subtree(tai("32473.1"), tai("32473.1.0.1"), 0, 5, h, timestamp=0) == zero
    stamped = mtc.cosigned_subtree(tai("32473.1"), tai("32473.1.0.1"), 0, 5, h, timestamp=0x0102030405060708)
    assert stamped == zero.replace(b"\x00" * 8 + bytes([len(b"oid/1.3.6.1.4.1.32473.1.0.1")]),
                                   bytes.fromhex("0102030405060708") + bytes([len(b"oid/1.3.6.1.4.1.32473.1.0.1")]), 1)  # fmt: skip
    for kwargs in ({"timestamp": 1, "start": 4}, {"timestamp": -1}, {"timestamp": 2**64}, {"timestamp": True}):
        start = kwargs.pop("start", 0)
        with pytest.raises(CodecUsageError):
            mtc.cosigned_subtree(tai("32473.1"), tai("32473.1.0.1"), start, 8, h, **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("corpus", ["qtls", "wg"])
def test_go_checkpoint_cosignatures_verify_offline(corpus: str) -> None:
    """Every vendored checkpoint cosignature from a cosigner qTLS knows verifies as
    CosignedSubtree(timestamp, 0, size, root) and never with timestamp 0 (an offline KAT); its note
    key ID follows the demo's rule (cosign.go)."""
    store, _ = _demo_store(corpus, "wg-sample" if corpus == "wg" else "quorum-2-of-3")
    log = mtc.log_id(store.cas[0].ca_id, json.loads((VECTORS / corpus / "config.json").read_text())["LogNumber"])
    text = (VECTORS / corpus / "checkpoint").read_text()
    ref = DEMO.parse_checkpoint(text, log, store.cosigners)
    checked = set()
    for sig in ref.cosignatures:
        found = store.cosigner(sig.cosigner_id)
        if found is None:
            continue  # the WG's ML-DSA-87 cosigner
        signer, key = found
        assert sig.timestamp > 1_700_000_000
        crypto.sig_verify(key.alg, key.public_key, mtc.cosigned_subtree(signer, log, 0, ref.size, ref.root_hash, timestamp=sig.timestamp),
                          sig.signature, "openssl")  # fmt: skip
        with pytest.raises(crypto.InvalidSignature):
            crypto.sig_verify(key.alg, key.public_key, mtc.cosigned_subtree(signer, log, 0, ref.size, ref.root_hash),
                              sig.signature, "openssl")  # fmt: skip
        checked.add(signer)
    assert checked == set(store.cosigners)
    assert mtc.checkpoint_cosigners(store, store.cas[0], log.components[-1], ref) == {c.raw for c in store.cosigners}
    line = next(x for x in text.splitlines() if x.startswith("— "))
    raw = base64.b64decode(line.split()[2])
    tampered = text.replace(line.split()[2], base64.b64encode(bytes([raw[0] ^ 1]) + raw[1:]).decode())
    with pytest.raises(ValueError, match="key ID"):
        DEMO.parse_checkpoint(tampered, log, store.cosigners)


def test_note_key_ids_follow_the_demo() -> None:
    """cosign.go: ML-DSA-44 keys hash with the tlog-cosignature scheme byte, others with a placeholder."""
    import hashlib

    key = bytes(range(32)) * 41
    assert DEMO.note_key_id("32473.9", "ML-DSA-44", key) == hashlib.sha256(b"oid/1.3.6.1.4.1.32473.9\n\x06" + key).digest()[:4]
    other = hashlib.sha256(b"oid/1.3.6.1.4.1.32473.9.1\n\xffmtc-checkpoint/v1").digest()[:4]
    assert DEMO.note_key_id("32473.9.1", "ML-DSA-65", key) == DEMO.note_key_id("32473.9.1", "ECDSA-P256-SHA256", b"") == other


@pytest.mark.parametrize("corpus", ["qtls", "wg"])
def test_derivation_against_the_go_checkpoint_offline(corpus: str) -> None:
    """§7.4 end to end without Go: the demo's signed checkpoint, qTLS's subtree proofs over the demo's
    own leaf hashes, a document of its printed landmarks. The derived subtrees are the ones the demo
    printed, and its trusted-subtree certificates verify through them."""
    base = VECTORS / corpus
    store, _ = _demo_store(corpus, "ca-only")
    ca = store.cas[0]
    log_number = json.loads((base / "config.json").read_text())["LogNumber"]
    ref = DEMO.parse_checkpoint((base / "checkpoint").read_text(), mtc.log_id(ca.ca_id, log_number), store.cosigners)
    tree = DEMO.leaf_tree((base / "leaf_hashes.bin").read_bytes())
    assert len(tree) == ref.size and tree.hash(0, ref.size) == ref.root_hash
    marks = json.loads((base / "landmarks.json").read_text())
    d = DEMO.derived_ca(store, ca.ca_id, log_number, ref, tree, marks)
    assert d.discarded == ()
    assert {(t.start, t.end, t.subtree_hash, t.landmark) for t in d.ca.trusted_subtrees} == {
        (s["start"], s["end"], base64.b64decode(s["hash"]), m["landmark"]) for m in marks for s in m["subtrees"] if s["start"] < s["end"]}
    derived = store.with_derived(d)
    details = _details(corpus)
    trusted = [n for n, by in details.items() if by["landmarks"]["trusted"]]
    assert trusted
    for name in trusted:
        cert = (base / "certs" / f"{name}.der").read_bytes()
        assert verify(cert, derived).trusted_subtree is not None, name
    assert derived.cas[0].revoked == ca.revoked  # derivation changes subtrees only


# Configuration errors and integration -------------------------------------- #


@pytest.mark.parametrize(
    "build",
    [
        lambda: mtc.ReferenceCheckpoint(0, bytes(32)), lambda: mtc.ReferenceCheckpoint(2**48, bytes(32)),
        lambda: mtc.ReferenceCheckpoint(True, bytes(32)), lambda: mtc.ReferenceCheckpoint(5, bytes(31)),
        lambda: mtc.ReferenceCheckpoint(5, "00" * 32), lambda: mtc.ReferenceCheckpoint(5, bytes(32), (b"x",)),
        lambda: mtc.ReferenceCheckpoint(5, bytes(32), (), (b"x",)),
        lambda: mtc.CheckpointSignature(CA.raw, -1, b""), lambda: mtc.CheckpointSignature(CA.raw, 2**64, b""),
        lambda: mtc.CheckpointSignature(CA.raw, True, b""), lambda: mtc.CheckpointSignature(CA, 0, b""),
        lambda: mtc.CheckpointSignature(CA.raw, 0, "sig"),
        lambda: mtc.LogLandmarks(0, mtc.decode_landmarks(GOOD_DOC, DOC_NOW), mtc.ReferenceCheckpoint(5, bytes(32))),
        lambda: mtc.LogLandmarks(1, GOOD_DOC, mtc.ReferenceCheckpoint(5, bytes(32))),
        lambda: mtc.LogLandmarks(1, mtc.decode_landmarks(GOOD_DOC, DOC_NOW), mtc.ReferenceCheckpoint(5, bytes(32)), (b"x",)),
    ],
    ids=["size-0", "size-2^48", "size-bool", "short-root", "str-root", "not-a-signature", "not-a-larger", "ts-negative",
         "ts-2^64", "ts-bool", "id-not-bytes", "sig-not-bytes", "log-0", "document-bytes", "proof-not-a-record"],
)
def test_malformed_checkpoint_structure_is_a_configuration_error(build: Callable[[], object]) -> None:
    with pytest.raises(CodecUsageError):
        build()


def test_derivation_arguments(lm: Landmarked) -> None:
    with pytest.raises(CodecUsageError):
        mtc.derive_landmarks(lm.store(), tai("32473.8"), [lm.update()], max_active_landmarks=4, now=NOW)
    with pytest.raises(CodecUsageError):
        mtc.derive_landmarks(lm.store(), CA, [lm.update().checkpoint], max_active_landmarks=4, now=NOW)  # type: ignore[list-item]
    assert mtc.derive_landmarks(lm.store(), CA, [], max_active_landmarks=4, now=NOW).ca == lm.store().cas[0]


def test_derived_and_hand_typed_subtrees_coexist_but_never_clash(lm: Landmarked) -> None:
    hand = lm.store(subtrees=lm.log.trusted_subtrees())  # typed in, landmark numbers and all
    d = mtc.derive_landmarks(hand, CA, [lm.update()], max_active_landmarks=4, now=NOW)  # a document repeating them: discards
    assert d.ca.trusted_subtrees == hand.cas[0].trusted_subtrees
    assert _reasons(d) == {(3, 1): "subtree-conflict", **{(3, n): "newer-than-discarded" for n in (2, 3, 4)}}
    other = mtc.TrustedSubtree(5, 0, 8, bytes(32))  # another log, typed in: kept
    store = lm.store(subtrees=(other,))
    d = mtc.derive_landmarks(store, CA, [lm.update(size=350)], max_active_landmarks=4, now=NOW)
    assert d.ca.trusted_subtrees == (other, *lm.expected(1, 2))
    again = mtc.derive_landmarks(store.with_derived(d), CA, [lm.update()], max_active_landmarks=4, now=NOW)  # a later update merges
    assert again.ca.trusted_subtrees == (other, *lm.expected(1, 2, 3, 4)) and again.ca.reference_sizes == ((3, 520),)
    failed = mtc.derive_landmarks(store.with_derived(d).with_derived(again), CA, [lm.update(signers=())], max_active_landmarks=4, now=NOW)
    assert failed.ca.trusted_subtrees == again.ca.trusted_subtrees and failed.ca.reference_sizes == ((3, 520),)  # kept


def test_subtrees_derived_under_one_policy_cannot_be_installed_under_another(lm: Landmarked) -> None:
    """Provenance (D36): derivation returns the CA's own policy with its subtrees, and with_ca keeps a
    CA's policy and key, so subtrees checked against P1 never serve a store that requires P2."""
    p1, p2 = mtc.RequireAll(frozenset({CA})), mtc.RequireAll(frozenset({CA, C1}))
    d = lm.derive(lm.update(), policy=p1)
    assert d.ca.policy is lm.store(p1).cas[0].policy or d.ca.policy == p1
    with pytest.raises(CodecUsageError):
        lm.store(p2).with_ca(d.ca, replacing=lm.store(p2).cas[0])
    assert lm.store(p1).with_ca(d.ca, replacing=d.base).cas[0].trusted_subtrees == lm.expected(1, 2, 3, 4)
    with pytest.raises(CodecUsageError):
        lm.store(p1).with_ca(replace(d.ca, ca_id=tai("32473.8")), replacing=d.base)
    keyed = mtc.CAPolicy(CA, p1, ca_key=lm.keys[CA])
    with pytest.raises(CodecUsageError):
        mtc.MTCTrustStore(lm.keys, (keyed,)).with_ca(replace(keyed, ca_key=None), replacing=keyed)


def test_an_expired_landmark_is_caught_by_the_certificates_not_after(lm: Landmarked) -> None:
    """Nothing at handshake time reads a landmark's expiry; §6.4.1 makes it at least every notAfter below it."""
    store = lm.store().with_derived(lm.derive(lm.update()))
    cert = lm.certs[1]
    assert verify(cert, store).trusted_subtree.expiry == EXPIRIES[1]  # type: ignore[union-attr]
    late = mtc.EPOCH + dt.timedelta(seconds=EXPIRIES[1] + 1)
    assert reason_of(lambda: mtc.verify_certificate([cert], store, server_name="qtls.test", now=late,
                                                    expected_kind="sig")) == (Alert.certificate_expired, "validity")  # fmt: skip


def test_verification_never_decodes_or_derives(lm: Landmarked, monkeypatch: pytest.MonkeyPatch) -> None:
    store = lm.store().with_derived(lm.derive(lm.update()))

    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("called during verification")

    for name in ("decode_landmarks", "encode_landmarks", "derive_landmarks", "checkpoint_cosigners", "parse_ca_certificate"):
        monkeypatch.setattr(mtc, name, boom)
    for cert in lm.certs.values():
        mtc.verify_certificate([cert], store, server_name="qtls.test", now=NOW, expected_kind="sig")


def test_seeded_derivation_fuzz(lm: Landmarked) -> None:
    """Random damage to proofs and checkpoint signatures, random reference sizes: derivation never
    raises, every discard has a known reason, and every derived hash is the log's real one (D36)."""
    rng = random.Random(36)
    tree = lm.log.tree()
    for _ in range(60):
        size = rng.choice([150, 200, 250, 350, 499, 500, 520, 700])
        u = lm.update(rng.choice([(CA,), (C1,), (CA, C1)]), size)
        proofs = list(u.proofs)
        for _ in range(rng.randrange(0, 4)):
            if not proofs:
                break
            i = rng.randrange(len(proofs))
            p = proofs[i]
            choice = rng.randrange(6)
            if choice == 0:
                proofs[i] = _flip(p, rng.choice(["proof", "subtree_hash"])) if p.proof else p
            elif choice == 1:
                proofs[i] = replace(p, proof=p.proof[: rng.randrange(len(p.proof) + 1)])
            elif choice == 2:
                proofs[i] = replace(p, start=rng.randrange(0, 600), end=rng.randrange(0, 700))
            elif choice == 3:
                proofs.append(rng.choice(proofs))
            elif choice == 4:
                del proofs[i]
            else:
                proofs[i] = replace(p, proof=p.proof + rng.randbytes(rng.randrange(1, 70)))
        sigs = tuple(replace(s, signature=s.signature[:-1] + bytes([s.signature[-1] ^ 1])) if rng.random() < 0.2 else s
                     for s in u.checkpoint.cosignatures)  # fmt: skip
        u = replace(u, proofs=tuple(proofs), checkpoint=replace(u.checkpoint, cosignatures=sigs))
        d = lm.derive(u, bound=rng.randrange(0, 6))
        assert {x.reason for x in d.discarded} <= mtc.DISCARD_REASONS
        assert len(d.discarded) + len(_kept(d)) == 4
        for t in d.ca.trusted_subtrees:
            assert t.subtree_hash == tree.hash(t.start, t.end) and t.end <= size
    for _ in range(300):
        doc = bytearray(mtc.encode_landmarks(lm.log.landmark_sequence(), NOW))
        for _ in range(rng.randrange(1, 4)):
            doc[rng.randrange(len(doc))] = rng.choice(b"0123456789 \n-x")
        try:
            mtc.decode_landmarks(bytes(doc), NOW)
        except CodecUsageError:
            pass


# --------------------------------------------------------------------------- #
# M. The demo's policy text (scripts/mtc_demo.py; D34, D35)
# --------------------------------------------------------------------------- #


def _qtls_ca() -> mtc.CACertificate:
    return mtc.parse_ca_certificate((VECTORS / "qtls" / "ca_cert.der").read_bytes())


def test_demo_policy_renders_quorums_ranges_and_subtrees(require_liboqs: None) -> None:
    ca = _qtls_ca()
    shared = Q("shared", 1, (C2, C3))
    policy = Q("root", 2, (CA, Q("left", 1, (C1, shared)), Q("right", 2, (shared, C1))))
    extra = (mtc.RevokedRange(5, 6), mtc.RevokedRange((3 << 48) | 7, 2**64))
    subtree = mtc.TrustedSubtree(3, 0, 64, bytes(range(32)), 1, 99)
    store = mtc.MTCTrustStore(DEMO.cosigner_keys(), (mtc.CAPolicy.from_ca_certificate(ca, policy, (subtree,), extra),))
    text = DEMO.demo_policy(store, CA)
    lines = text.splitlines()
    assert [x.split()[1] for x in lines if x.startswith("cosigner ")] == ["32473.9.1", "32473.9.2", "32473.9.3"]  # never the CA
    groups = [x for x in lines if x.startswith("group ")]
    assert groups == ["group shared 1 32473.9.2 32473.9.3", "group left 1 32473.9.1 shared", "group right 2 shared 32473.9.1",
                      "group root 2 32473.9 left right"]  # children first, a shared group once
    assert "require-cosigners 32473.9 root" in lines
    assert [x for x in lines if x.startswith("revoke-range ")] == [
        f"revoke-range 32473.9 0 {MIN3 - 1}", f"revoke-range 32473.9 {MAX3 + 1} max",  # the certificate's, inclusive
        "revoke-range 32473.9 5 5", f"revoke-range 32473.9 {(3 << 48) | 7} max"]
    assert lines[-1] == f"trusted-subtree 32473.9 3 0 64 {base64.b64encode(bytes(range(32))).decode()}"
    keys, parsed = DEMO.parse_demo_policy(text, ca)
    assert parsed.policy == policy and parsed.revoked == store.cas[0].revoked and parsed.ca_key == ca.key
    assert [(t.log_number, t.start, t.end, t.subtree_hash) for t in parsed.trusted_subtrees] == [(3, 0, 64, bytes(range(32)))]
    assert keys == {c: k for c, k in DEMO.cosigner_keys().items() if c != CA}
    assert DEMO.demo_policy(mtc.MTCTrustStore(keys, (parsed,)), CA).splitlines()[:-1] == lines[:-1]


def test_demo_policy_require_all_and_the_ranges_edges(require_liboqs: None) -> None:
    ca = _qtls_ca()
    keys = DEMO.cosigner_keys()
    store = mtc.MTCTrustStore(keys, (mtc.CAPolicy(CA, mtc.RequireAll(frozenset({CA, C2, C1})), (),
                                                  (mtc.RevokedRange(0, 1), mtc.RevokedRange(2**64 - 1, 2**64))),))  # fmt: skip
    text = DEMO.demo_policy(store, CA)
    assert "require-cosigners 32473.9 32473.9.1\nrequire-cosigners 32473.9 32473.9.2\n" in text
    assert "require-cosigners 32473.9 32473.9\n" not in text  # the CA is implicitly required
    assert "revoke-range 32473.9 0 0\n" in text and f"revoke-range 32473.9 {2**64 - 1} max\n" in text
    _, parsed = DEMO.parse_demo_policy(text, ca)
    assert parsed.policy == mtc.RequireAll(frozenset({CA, C1, C2}))
    assert parsed.revoked == (*ca.revoked(), mtc.RevokedRange(0, 1), mtc.RevokedRange(2**64 - 1, 2**64))


def test_demo_policy_refuses_what_the_demo_cannot_read(require_liboqs: None) -> None:
    keys = DEMO.cosigner_keys()
    big = CA.child(2**32)  # the demo reads components as uint32
    with pytest.raises(ValueError):
        DEMO.demo_policy(mtc.MTCTrustStore({**keys, big: keys[C1]}, (mtc.CAPolicy(CA, mtc.RequireAll(frozenset({CA, big}))),)), CA)
    with pytest.raises(ValueError):
        DEMO.demo_policy(mtc.MTCTrustStore(keys, (mtc.CAPolicy(CA, _QuorumWithoutCA()),)), CA)
    with pytest.raises(ValueError):
        DEMO.demo_policy(mtc.MTCTrustStore(keys, (mtc.CAPolicy(CA, mtc.RequireAll(frozenset({CA}))),)), tai("32473.8"))


def test_demo_policy_parser_adds_the_ca_and_combines_requirements(require_liboqs: None) -> None:
    ca = _qtls_ca()
    spki = lambda c: base64.b64encode(x509.spki(DEMO.cosigner_keys()[c].alg, DEMO.cosigner_keys()[c].public_key)).decode()  # noqa: E731
    head = f"cosigner 32473.9.1 mldsa65 {spki(C1)}\ncosigner 32473.9.2 ecdsa_p256_sha256 {spki(C2)}\n"
    _, p = DEMO.parse_demo_policy(head + "group g any 32473.9.1 32473.9.2  # a comment\nrequire-cosigners 32473.9 g\n", ca)
    assert p.policy == Q(DEMO.REQUIREMENTS, 2, (Q("g", 1, (C1, C2)), CA))  # the demo's implicit CA, made explicit (§7.3)
    _, p = DEMO.parse_demo_policy(head + "group g all 32473.9 32473.9.1\nrequire-cosigners all g\n"
                                  "require-cosigners 32473.8 32473.9.2\nrevoke-range 32473.8 0 max\n", ca)  # fmt: skip
    assert p.policy == Q("g", 2, (CA, C1)) and p.revoked == ca.revoked()  # another CA's lines don't apply
    _, p = DEMO.parse_demo_policy(head + "require-cosigners 32473.9 32473.9.1\nrevoke-range 32473.9 3:5 3:6\n", ca)
    assert p.policy == mtc.RequireAll(frozenset({CA, C1})) and p.revoked[-1] == mtc.RevokedRange((3 << 48) | 5, (3 << 48) | 7)
    for bad in ("cosigner 32473.9.4 mldsa87 AAAA\n", "bogus line\n", f"cosigner 32473.9.1 mldsa44 {spki(C1)}\n"):
        with pytest.raises((ValueError, CodecUsageError, AlertError)):
            DEMO.parse_demo_policy(bad, ca)


def test_the_wg_sample_policy_without_ml_dsa_87() -> None:
    """The WG's demo/policy.txt minus its ML-DSA-87 cosigner (unsupported, D33): a DAG sharing
    operator-A, with the CA's own group, revocation from 1:2100 and the printed subtrees."""
    text = (VECTORS / "wg" / "policy-wg-sample.txt").read_text()
    assert "32473.2.3" not in text.split("# Import the cosigners")[1] and "mldsa87" not in text
    store, _ = _demo_store("wg", "wg-sample")
    policy = store.cas[0].policy
    assert isinstance(policy, mtc.Quorum) and policy.name == DEMO.REQUIREMENTS and policy.threshold == 2
    assert set(policy.quorums()) == {DEMO.REQUIREMENTS, "two-independent-operators", "independent-cosigner-from-B",
                                     "operator-A", "operator-B", "operator-C", "operator-D"}  # fmt: skip
    assert policy.quorums()["two-independent-operators"].members[0] is policy.quorums()["independent-cosigner-from-B"].members[0]
    assert mtc.RevokedRange((1 << 48) + 2100, 2**64) in store.cas[0].revoked
    assert len(store.cas[0].trusted_subtrees) == 6


def test_go_verdict_classes() -> None:
    assert DEMO.go_class("OK") == {"OK"}
    assert DEMO.go_class("certificate serial 5 is revoked (range [5, 5])") == {"mtc-revoked"}
    assert DEMO.go_class("inclusion proof evaluation failed: proof too short") == {"mtc-too-short"}
    for bad in ("", "certificate serial 5 is revoked", "something new", "cosigner policy not satisfied!"):
        with pytest.raises(ValueError):
            DEMO.go_class(bad)


@pytest.mark.openssl
def test_openssl_reads_qtls_ca_certificate(require_openssl: str, tmp_path: Path) -> None:
    """An independent reading of IssuanceLog.ca_certificate's extensions (§5.5): key usage keyCertSign,
    basic constraints cA, the Merkle Tree CA extension, all critical; the RFC 9925 unsigned form."""
    import subprocess

    from openssl_tools import pem

    (tmp_path / "ca.pem").write_bytes(pem((VECTORS / "qtls" / "ca_cert.der").read_bytes()))
    text = subprocess.run([require_openssl, "x509", "-in", tmp_path / "ca.pem", "-noout", "-text"],
                          capture_output=True, text=True, check=True).stdout  # fmt: skip
    flat = re.sub(r"\s+", " ", text)
    assert "X509v3 Key Usage: critical Certificate Sign" in flat
    assert "X509v3 Basic Constraints: critical CA:TRUE" in flat
    assert "1.3.6.1.5.5.7.1.38: critical" in flat
    assert "Serial Number: 1 " in flat and "Signature Algorithm: 1.3.6.1.5.5.7.6.36" in flat
    assert "Issuer: 1.3.6.1.5.5.7.25.1" in flat


# --------------------------------------------------------------------------- #
# N. Derived state across derivations, and installing it (D36, review round 1)
# --------------------------------------------------------------------------- #


def _derive_on(store: mtc.MTCTrustStore, *updates: mtc.LogLandmarks, bound: int = 10, now: dt.datetime = NOW) -> mtc.DerivedLandmarks:
    return mtc.derive_landmarks(store, CA, updates, max_active_landmarks=bound, now=now)


def _held(store_or_d: object) -> set[tuple[int, int]]:
    ca = store_or_d.ca if isinstance(store_or_d, mtc.DerivedLandmarks) else store_or_d.cas[0]  # type: ignore[attr-defined]
    return {(t.log_number, t.landmark) for t in ca.trusted_subtrees if t.expiry is not None}


def test_a_failing_refresh_keeps_what_was_validated(lm: Landmarked) -> None:
    """Monotone state: a later checkpoint that fails its cosigners, or is smaller than the one recorded,
    leaves the log's subtrees and recorded size as they were, and only landmarks not held are listed as
    discarded; a held landmark is never re-validated (a bad re-sent proof is ignored), and a failing new
    landmark takes only itself and newer ones."""
    store = lm.store().with_derived(_derive_on(lm.store(), lm.update()))
    assert _held(store) == {(3, n) for n in range(1, 5)} and store.cas[0].reference_sizes == ((3, 520),)
    for update in (lm.update(signers=()), lm.update(size=350)):
        d = _derive_on(store, update)
        assert d.ca == store.cas[0] and d.discarded == ()  # everything offered is held already
    half = lm.store().with_derived(_derive_on(lm.store(), lm.update(size=350)))  # landmarks 1 and 2 held, size 350
    for update, reason in ((lm.update(signers=(), size=700), "checkpoint-cosigners"), (lm.update(size=340), "reference-regressed")):
        d = _derive_on(half, update)
        assert d.ca == half.cas[0] and _reasons(d) == {(3, 3): reason, (3, 4): reason}
    bad2 = [_flip(p) if p == lm.proofs_for(2, 700)[0] else p for p in lm.log.landmark_proofs(700)]
    d = _derive_on(half, lm.update(size=700, proofs=bad2))  # landmark 2 is held: its proof isn't even read
    assert d.discarded == () and _held(d) == {(3, n) for n in range(1, 5)} and d.ca.reference_sizes == ((3, 700),)
    bad3 = [_flip(p) if p == lm.proofs_for(3, 700)[0] else p for p in lm.log.landmark_proofs(700)]
    d = _derive_on(half, lm.update(size=700, proofs=bad3))
    assert _held(d) == {(3, 1), (3, 2)} and _reasons(d) == {(3, 3): "subtree-consistency", (3, 4): "newer-than-discarded"}
    assert _derive_on(half.with_derived(d), lm.update(size=520)).ca.reference_sizes == ((3, 700),)  # 520 < 700: regressed
    incremental = [p for p in lm.log.landmark_proofs(520) if p.start >= 256]  # proofs for the new landmarks only
    assert _held(_derive_on(half, lm.update(proofs=incremental))) == {(3, n) for n in range(1, 5)}


def test_a_republished_landmark_sequence_conflicts_instead_of_raising(lm: Landmarked) -> None:
    """A grammatical document renumbering what is held (landmark 2 now at 201, 3 at 300, repeating held
    ranges) is a `subtree-conflict` discard, never an exception, and later refreshes still work."""
    tree = lm.log.tree()
    proofs = lambda ranges: tuple(mtc.SubtreeProof(s, e, tree.hash(s, e), tree.consistency_proof(s, e, 520)) for s, e in ranges)  # noqa: E731
    ref = lm.log.reference_checkpoint([lm.cs[CA]], TS, 520)
    doc1 = mtc.decode_landmarks(f"2\n300 {EXPIRIES[2]}\n200 {EXPIRIES[1]}\n0 0\n".encode(), NOW)
    store = lm.store().with_derived(_derive_on(lm.store(), mtc.LogLandmarks(3, doc1, ref, proofs(doc1.subtrees(1) + doc1.subtrees(2)))))
    doc2 = mtc.decode_landmarks(f"3\n300 {EXPIRIES[3]}\n201 {EXPIRIES[2]}\n200 {EXPIRIES[1]}\n0 0\n".encode(), NOW)
    d = _derive_on(store, mtc.LogLandmarks(3, doc2, ref, proofs(doc2.subtrees(1) + doc2.subtrees(2) + doc2.subtrees(3))))
    assert d.ca == store.cas[0] and _reasons(d) == {(3, 2): "subtree-conflict", (3, 3): "newer-than-discarded"}
    assert _held(_derive_on(store.with_derived(d), lm.update())) == {(3, n) for n in range(1, 5)}


def test_a_new_landmark_repeating_a_held_range_conflicts(lm: Landmarked) -> None:
    """The known map: a new landmark whose subtree is already trusted under another landmark is refused."""
    tree = lm.log.tree()
    ref = lm.log.reference_checkpoint([lm.cs[CA]], TS, 520)
    doc1 = mtc.decode_landmarks(f"1\n200 {EXPIRIES[1]}\n0 0\n".encode(), NOW)
    mk = lambda ranges: tuple(mtc.SubtreeProof(s, e, tree.hash(s, e), tree.consistency_proof(s, e, 520)) for s, e in ranges)  # noqa: E731
    store = lm.store().with_derived(_derive_on(lm.store(), mtc.LogLandmarks(3, doc1, ref, mk(doc1.subtrees(1)))))
    doc2 = mtc.decode_landmarks(f"2\n300 {EXPIRIES[2]}\n200 {EXPIRIES[1]}\n0 0\n".encode(), NOW)
    # Expire landmark 1 so it isn't held, then offer a document whose landmark 2 repeats a range of a hand-typed subtree.
    hand = mtc.TrustedSubtree(3, 256, 300, tree.hash(256, 300))
    store2 = lm.store(subtrees=(hand,))
    d = _derive_on(store2, mtc.LogLandmarks(3, doc2, ref, mk(doc2.subtrees(1) + doc2.subtrees(2))))
    assert _reasons(d) == {(3, 2): "subtree-conflict"} and _held(d) == {(3, 1)} and hand in d.ca.trusted_subtrees
    assert _held(store) == {(3, 1)}


def test_earlier_landmarks_count_toward_the_bound_and_expire(lm: Landmarked, issued: Issued) -> None:
    """The bound is an invariant of the store, not of one call: what is held from before counts, and is
    reported over-bound when it goes. Expired held landmarks are dropped. Hand-typed subtrees never count."""
    other = mtc.TrustedSubtree(5, 0, 8, bytes(32))
    base = lm.store(subtrees=(other,))
    store = base.with_derived(_derive_on(base, lm.update(), bound=4))
    d = _derive_on(store, bound=2)
    assert _held(d) == {(3, 1), (3, 2)} and _reasons(d) == {(3, 3): "over-bound", (3, 4): "over-bound"}
    assert other in d.ca.trusted_subtrees and other in _derive_on(store, bound=0).ca.trusted_subtrees
    late = mtc.EPOCH + dt.timedelta(seconds=EXPIRIES[2] + 1)
    assert _held(_derive_on(store, now=late)) == {(3, 3), (3, 4)}  # landmarks 1 and 2 expired, silently
    log4 = mtc.IssuanceLog(CA, 4)
    for size, expiry in ((50, EXPIRIES[1]), (90, EXPIRIES[1] + 1800), (130, EXPIRIES[3] + 1800)):
        log4.add_certificate(**Issued.leaf_args(issued.leaf44))
        log4.append_null(size - log4.size)
        log4.add_landmark(expiry)
    doc4 = mtc.decode_landmarks(mtc.encode_landmarks(log4.landmark_sequence(), NOW), NOW)
    u4 = mtc.LogLandmarks(4, doc4, log4.reference_checkpoint([lm.cs[CA]], TS), log4.landmark_proofs(130))
    d = _derive_on(store, u4, bound=4)  # log 3 from before, log 4 now: one bound over both
    assert _held(d) == {(3, 1), (4, 1), (4, 2), (3, 2)}
    assert _reasons(d) == {(3, 3): "over-bound", (3, 4): "over-bound", (4, 3): "over-bound"}
    assert d.ca.reference_sizes == ((3, 520), (4, 130))
    derived = d.ca.trusted_subtrees[1:]  # by (log, landmark, start), not by expiry
    assert d.ca.trusted_subtrees[0] == other and list(derived) == sorted(derived, key=lambda t: (t.log_number, t.landmark, t.start))


def test_installing_a_derivation_is_compare_and_swap(lm: Landmarked) -> None:
    """with_derived refuses if the CA changed (a revocation installed meanwhile would be lost) or a
    cosigner key changed since the derivation; with_ca's provenance rule still holds."""
    policy = mtc.RequireAll(frozenset({CA, C1}))
    store = lm.store(policy)
    d = _derive_on(store, lm.update((CA, C1)))
    assert d.base == store.cas[0] and set(d.keys) == {CA, C1}
    assert _held(store.with_derived(d)) == {(3, n) for n in range(1, 5)}
    revoked = store.with_ca(replace(store.cas[0], revoked=(mtc.RevokedRange(0, 1 << 48),)), replacing=store.cas[0])
    with pytest.raises(CodecUsageError, match="CA changed since it was read"):
        revoked.with_derived(d)
    rekeyed = mtc.MTCTrustStore({**lm.keys, C1: lm.keys[C3]}, (mtc.CAPolicy(CA, policy),))
    with pytest.raises(CodecUsageError, match="key changed"):
        rekeyed.with_derived(d)
    with pytest.raises(CodecUsageError, match="no CA 32473.9"):
        mtc.MTCTrustStore({**lm.keys, tai("32473.8"): lm.keys[CA]},
                          (mtc.CAPolicy(tai("32473.8"), mtc.RequireAll(frozenset({tai("32473.8")}))),)).with_derived(d)
    unrelated = {**lm.keys, C2: lm.keys[C3]}  # a cosigner outside the CA and policy may change
    assert _held(mtc.MTCTrustStore(unrelated, (mtc.CAPolicy(CA, policy),)).with_derived(d)) == {(3, n) for n in range(1, 5)}


@pytest.mark.parametrize("sizes", [((0, 5),), ((65536, 5),), ((3, 0),), ((3, 2**48),), ((3, True),), ((True, 5),), ((3, 5), (3, 6)),
                                   ((3, "5"),)])
def test_reference_sizes_are_checked_when_built(sizes: tuple) -> None:
    with pytest.raises(CodecUsageError):
        mtc.CAPolicy(CA, mtc.RequireAll(frozenset({CA})), reference_sizes=sizes)
    assert mtc.CAPolicy(CA, mtc.RequireAll(frozenset({CA})), reference_sizes=((3, 2**48 - 1), (4, 1))).reference_sizes[0] == (3, 2**48 - 1)


# Review round 1: rules whose tests were vacuous or missing ------------------- #


def _document_of_length(n: int) -> bytes:
    """A valid document of exactly n bytes: landmarks latest..0, the newest with a wider expiry."""
    tail = len(" 1000000\n")

    def size(latest: int) -> int:  # header + lines latest..1 with a 7-digit expiry + "0 0"
        digits = sum(len(str(k)) for k in range(1, latest + 1))
        return len(f"{latest}\n") + digits + tail * latest + len("0 0\n")

    lo, hi = 1, n
    while lo < hi:  # the largest latest whose document fits with room to widen one expiry
        mid = (lo + hi + 1) // 2
        lo, hi = (mid, hi) if size(mid) <= n else (lo, mid - 1)
    latest = lo
    widen = n - size(latest)
    assert 0 <= widen <= 13
    lines = [f"{latest} {'9' * (7 + widen)}\n"] + [f"{k} 1000000\n" for k in range(latest - 1, 0, -1)] + ["0 0\n"]
    return (f"{latest}\n" + "".join(lines)).encode()


def test_landmark_document_byte_cap_on_a_valid_document() -> None:
    exact = _document_of_length(mtc.MAX_LANDMARK_DOCUMENT)
    assert len(exact) == mtc.MAX_LANDMARK_DOCUMENT and mtc.decode_landmarks(exact, DOC_NOW).active[-1].number > 70000
    over = _document_of_length(mtc.MAX_LANDMARK_DOCUMENT + 1)
    with pytest.raises(CodecUsageError, match="over"):
        mtc.decode_landmarks(over, DOC_NOW)
    assert len(over) == mtc.MAX_LANDMARK_DOCUMENT + 1


def test_one_update_per_log_even_when_the_updates_differ(lm: Landmarked) -> None:
    with pytest.raises(CodecUsageError, match="one update per log"):
        _derive_on(lm.store(), lm.update(size=350), lm.update(size=520, signers=(CA, C1)))


def test_issuance_previous_expiry_rule_alone(issued: Issued) -> None:
    log = mtc.IssuanceLog(CA, 1)
    log.add_certificate(**Issued.leaf_args(issued.leaf44))
    log.add_landmark(NOT_AFTER_S + 100)
    log.append_null(1)
    with pytest.raises(CodecUsageError, match="never decrease"):
        log.add_landmark(NOT_AFTER_S + 99)  # above every notAfter, below the previous expiry
    assert log.landmark_expiries == [0, NOT_AFTER_S + 100] and log.landmarks == [0, 1]
    assert log.add_landmark(NOT_AFTER_S + 100) == 2


def test_ca_certificate_extension_with_explicit_critical_false(ca_keys: dict[str, bytes]) -> None:
    explicit = der.seq(der.oid("1.2.3.4"), der.boolean(False), der.octet_string(der.null()))
    with pytest.raises(CodecUsageError, match="DEFAULT"):
        mtc.parse_ca_certificate(_ca(ca_keys, exts=[KU, BC, _mtc_ext(), explicit]))
    assert mtc.parse_ca_certificate(_ca(ca_keys, exts=[KU, BC, _mtc_ext(), _ext("1.2.3.4", der.null(), critical=False)])).ca_id == CA


def test_demo_policy_requirements_are_all_of(require_liboqs: None) -> None:
    ca = _qtls_ca()
    keys = DEMO.cosigner_keys()
    spki = lambda c: base64.b64encode(x509.spki(keys[c].alg, keys[c].public_key)).decode()  # noqa: E731
    text = "".join(f"cosigner {c} {DEMO.DEMO_ALG[keys[c].alg]} {spki(c)}\n" for c in (C1, C2, C3))
    text += "group a any 32473.9.1\ngroup b any 32473.9.2\nrequire-cosigners 32473.9 a\nrequire-cosigners all b\nrequire-cosigners 32473.9 32473.9.3\n"
    _, p = DEMO.parse_demo_policy(text, ca)
    assert p.policy == Q(DEMO.REQUIREMENTS, 4, (Q("a", 1, (C1,)), Q("b", 1, (C2,)), C3, CA))
    assert p.policy.unsatisfied(frozenset({CA.raw, C1.raw, C2.raw})) != ()


def test_trusted_subtree_expiry_range() -> None:
    for bad in (-1, 2**64, True, "1"):
        with pytest.raises(CodecUsageError):
            mtc.TrustedSubtree(1, 0, 4, bytes(32), 1, bad)  # type: ignore[arg-type]
    assert mtc.TrustedSubtree(1, 0, 4, bytes(32), 1, 2**64 - 1).expiry == 2**64 - 1


def test_odd_subtree_proof_records_are_per_landmark_discards(lm: Landmarked) -> None:
    """A record whose start or end isn't an int (or isn't even hashable) names no subtree: the landmark
    that needed the real one is discarded as missing; nothing raises."""
    target = lm.proofs_for(2)[0]
    for start, end in ((str(target.start), target.end), ([target.start], target.end), (target.start, None), (float(target.start), target.end)):
        proofs = [replace(p, start=start, end=end) if p == target else p for p in lm.log.landmark_proofs(520)]
        d = lm.derive(lm.update(proofs=proofs))
        assert _reasons(d)[(3, 2)] == "subtree-proof-missing" and _kept(d) == {1}


def test_a_refresh_at_the_same_size_is_not_a_regression_and_keeps_the_first_validation(lm: Landmarked) -> None:
    """An equal reference size is fine (only a smaller one regresses). A landmark validated before is
    kept as it was: a later document giving it another expiry doesn't rewrite it (D36)."""
    store = lm.store().with_derived(_derive_on(lm.store(), lm.update(size=520)))
    again = _derive_on(store, lm.update(size=520))
    assert again.discarded == () and again.ca == store.cas[0]
    seq = tuple(replace(x, expiry=x.expiry + 3600) if x.number else x for x in lm.log.landmark_sequence())
    later = mtc.decode_landmarks(mtc.encode_landmarks(seq, NOW), NOW)
    d = _derive_on(store, replace(lm.update(size=520), document=later))
    assert d.discarded == () and d.ca.trusted_subtrees == store.cas[0].trusted_subtrees
    assert {t.expiry for t in d.ca.trusted_subtrees} == set(EXPIRIES.values())


# Review round 2 -------------------------------------------------------------- #


def test_landmarks_expired_at_the_derivation_time_are_skipped(lm: Landmarked) -> None:
    """The derive `now` is authoritative (a document decoded earlier only had its grammar checked then):
    landmarks expired at `now` are never validated, installed or counted, held or offered, so the result
    doesn't depend on how many calls were made."""
    late = mtc.EPOCH + dt.timedelta(seconds=EXPIRIES[2] + 1)  # landmarks 1 and 2 have expired
    d = _derive_on(lm.store(), lm.update(), bound=2, now=late)
    assert _held(d) == {(3, 3), (3, 4)} and d.discarded == ()
    in_two = _derive_on(lm.store().with_derived(_derive_on(lm.store(), lm.update(), bound=2, now=NOW)), bound=2, now=late)
    assert _held(in_two) == set()  # held 1, 2 expired; 3, 4 were never held: the same as deriving at `late` with nothing
    same = _derive_on(lm.store().with_derived(d), bound=2, now=late)
    assert same.ca == d.ca and same.discarded == ()
    with pytest.raises(CodecUsageError):
        _derive_on(lm.store(), now=dt.datetime(2026, 2, 1))  # a naive now, even with nothing held


def test_derived_subtree_shape(issued: Issued) -> None:
    for bad in (dict(landmark=None, expiry=5), dict(landmark=0), dict(landmark=0, expiry=5), dict(landmark=-1),
                dict(landmark=True, expiry=5), dict(landmark=2**48)):
        with pytest.raises(CodecUsageError):
            mtc.TrustedSubtree(3, 0, 4, bytes(32), **bad)  # type: ignore[arg-type]
    mtc.TrustedSubtree(3, 0, 4, bytes(32), landmark=1, expiry=None)  # hand-typed with its landmark number


def test_hand_typed_subtrees_with_landmark_numbers_pass_through(lm: Landmarked) -> None:
    """IssuanceLog.trusted_subtrees()'s shape (landmark set, expiry None) is hand-typed: kept, never
    counted, never discarded, even with a bound of 0."""
    hand = lm.log.trusted_subtrees()
    store = lm.store(subtrees=hand)
    for bound in (0, 2, 10):
        d = _derive_on(store, bound=bound)
        assert d.ca.trusted_subtrees == hand and d.discarded == ()


def test_over_bound_reports_the_held_landmark_and_output_order_is_pinned(lm: Landmarked) -> None:
    other = mtc.TrustedSubtree(9, 0, 8, bytes(32))
    store = lm.store(subtrees=(other,)).with_derived(_derive_on(lm.store(subtrees=(other,)), lm.update()))
    d = _derive_on(store, bound=3)
    assert d.discarded == (mtc.DiscardedLandmark(3, mtc.Landmark(4, 500, EXPIRIES[4]), "over-bound"),)
    d = _derive_on(store, bound=1)
    assert d.discarded == tuple(mtc.DiscardedLandmark(3, mtc.Landmark(n, size, EXPIRIES[n]), "over-bound")
                                for n, size in ((2, 300), (3, 400), (4, 500)))  # fmt: skip
    full = store.cas[0].trusted_subtrees
    assert full[0] == other  # hand-typed first, as configured
    derived = full[1:]
    assert list(derived) == sorted(derived, key=lambda t: (t.log_number, t.landmark, t.start)) and derived == lm.expected(1, 2, 3, 4)


def test_with_ca_is_compare_and_swap(lm: Landmarked) -> None:
    """A change computed from a stale store never overwrites a newer one, either way round."""
    store = lm.store()
    stale = store.cas[0]
    d = _derive_on(store, lm.update())
    installed = store.with_derived(d)
    with pytest.raises(CodecUsageError, match="changed"):  # a revocation computed before the derivation was installed
        installed.with_ca(replace(stale, revoked=(mtc.RevokedRange(0, 1 << 48),)), replacing=stale)
    revoked = store.with_ca(replace(stale, revoked=(mtc.RevokedRange(0, 1 << 48),)), replacing=stale)
    with pytest.raises(CodecUsageError, match="changed"):
        revoked.with_ca(replace(stale, revoked=()), replacing=stale)
    current = installed.cas[0]
    both = installed.with_ca(replace(current, revoked=(mtc.RevokedRange(0, 1 << 48),)), replacing=current)
    assert _held(both) == {(3, n) for n in range(1, 5)} and both.cas[0].revoked == (mtc.RevokedRange(0, 1 << 48),)
    with pytest.raises(TypeError):
        store.with_ca(stale)  # type: ignore[call-arg]  # `replacing` is required


class TwoLogs:
    """Logs 3 and 4 of CA 32473.9 (log 3 is `Landmarked`'s, log 4 interleaves its expiries), a fork of
    log 3 with the same landmark sizes, and a hand-typed copy of log 4's landmark 4 (landmark number set,
    no expiry), for the sequence property test."""

    def __init__(self, lm: Landmarked, issued: Issued) -> None:
        self.lm = lm
        self.fork = Landmarked(issued, cn="fork.test").log
        log4 = mtc.IssuanceLog(CA, 4)
        for n, size in enumerate((60, 120, 180, 240), 1):
            log4.append_null(size - 6 - log4.size)
            log4.add_certificate(**Issued.leaf_args(issued.leaf44))
            log4.append_null(size - log4.size)
            log4.add_landmark(EXPIRIES[n] + 1800)
        log4.append_null(300 - log4.size)
        self.logs = {3: lm.log, 4: log4}
        self.trees = {3: lm.log.tree(), 4: log4.tree(), "fork": self.fork.tree()}
        self.hand = tuple(t for t in log4.trusted_subtrees() if t.landmark == 4)
        self.policy = mtc.RequireAll(frozenset({CA, C1}))

    def store(self) -> mtc.MTCTrustStore:
        return mtc.MTCTrustStore(self.lm.keys, (mtc.CAPolicy(CA, self.policy, self.hand),))

    def document(self, log: mtc.IssuanceLog, rng: random.Random) -> mtc.LandmarkDocument:
        seq = list(log.landmark_sequence())
        variant = rng.choice(["plain"] * 4 + ["renumbered", "drop-first", "resized"])
        if variant == "renumbered":  # a new first landmark: every old one moves up a number
            seq = [seq[0], mtc.Landmark(1, seq[1].tree_size // 2, seq[1].expiry)] + [replace(x, number=x.number + 1) for x in seq[1:]]
        elif variant == "drop-first":  # held ranges come back under smaller numbers
            seq = [seq[0]] + [replace(x, number=x.number - 1) for x in seq[2:]]
        elif variant == "resized":  # a held number re-published at another size
            k = rng.randrange(1, len(seq) - 1)
            seq[k] = replace(seq[k], tree_size=seq[k].tree_size - 3)
        return mtc.decode_landmarks(mtc.encode_landmarks(seq, NOW), NOW)  # decoded at NOW, derived later


def _model_order(held: dict, bound: int) -> set:
    return set(sorted(held, key=lambda k: (held[k], k[0], k[1]))[:bound])


@pytest.fixture(scope="module")
def two_logs(lm: Landmarked, issued: Issued) -> TwoLogs:
    return TwoLogs(lm, issued)


@pytest.mark.parametrize("seed", [362, 2026])
def test_seeded_sequences_of_updates_keep_the_invariants(two_logs: TwoLogs, seed: int) -> None:
    """Random well-formed and malformed updates for two logs, one after another, each installed with
    with_derived, against a model: nothing in a document, proof or checkpoint raises; held landmarks are
    active, never change, and are the oldest (by expiry) of what was held and newly validated, up to
    the bound; a held number re-published differently is a conflict; recorded sizes never decrease;
    log_status says what happened; an empty re-derive changes nothing; a stale with_ca and a changed key
    are refused. And it makes progress: landmarks get installed and every discard reason occurs."""
    rng = random.Random(seed)
    lm, tl = two_logs.lm, two_logs
    store = tl.store()
    start = now = mtc.EPOCH + dt.timedelta(seconds=EXPIRIES[1] - 5400)  # landmarks expire one by one as time moves on
    seen: set[str] = set()
    installs = 0
    keys_changed = mtc.MTCTrustStore({**lm.keys, C1: lm.keys[C3]}, store.cas)
    for step in range(110):
        if rng.random() < 0.25:
            now = now + dt.timedelta(seconds=rng.choice([900, 1800, 3600]))
        if rng.random() < 0.02 or now > mtc.EPOCH + dt.timedelta(seconds=EXPIRIES[4] + 1800):
            store, now = tl.store(), start  # a relying party starting afresh, before anything expired
        bound = rng.choice([0, 2, 3, 4, 5, 8, 8, 8])
        updates = []
        prev_sizes = dict(store.cas[0].reference_sizes)
        for log_number in rng.sample([3, 4], rng.choice([1, 1, 2])):
            src = tl.fork if log_number == 3 and rng.random() < 0.08 else tl.logs[log_number]
            tree = tl.trees["fork"] if src is tl.fork else tl.trees[log_number]
            low = prev_sizes.get(log_number, 1)
            sizes = [x for x in (50, 130, 150, 200, 250, 300, 350, 500, 520, 600, 700) if x <= src.size]
            size = rng.choice([x for x in sizes if x >= low] or sizes) if rng.random() < 0.8 else rng.choice(sizes[:4])
            doc = tl.document(src, rng)
            ranges = [r for x in doc.active for r in doc.subtrees(x.number) if r[1] <= size]
            proofs = [mtc.SubtreeProof(a, b, tree.hash(a, b), tree.consistency_proof(a, b, size)) for a, b in ranges]
            for _ in range(rng.choice([0, 0, 1, 2])):
                if proofs:
                    i = rng.randrange(len(proofs))
                    proofs[i:i + 1] = rng.choice([[_flip(proofs[i])] if proofs[i].proof else [], [proofs[i], proofs[i]], [],
                                                  [replace(proofs[i], subtree_hash=b"")], [replace(proofs[i], proof=proofs[i].proof + b"\x00")],
                                                  [replace(proofs[i], start=[0])]])  # fmt: skip
            kind = rng.choice(["good"] * 5 + ["ca-only", "junk", "empty", "grease", "larger-good", "larger-bad"])
            signers = [lm.cs[CA]] if kind.startswith(("ca-only", "larger")) else [] if kind == "empty" else [lm.cs[CA], lm.cs[C1]]
            ref = src.reference_checkpoint(signers, TS + step, size)
            if kind == "junk":
                ref = replace(ref, cosignatures=tuple(replace(c, signature=c.signature[:-1]) for c in ref.cosignatures))
            elif kind == "grease":
                ref = replace(ref, cosignatures=(mtc.CheckpointSignature(b"\x01" * 9, 1, b"g"), mtc.CheckpointSignature(C3.raw, TS, b"x"),
                                                 ref.cosignatures[0]))  # fmt: skip
            elif kind.startswith("larger"):
                larger = src.larger_checkpoint(size, [lm.cs[C1]], TS, src.size)
                if kind == "larger-bad" and larger.consistency_proof:
                    larger = replace(larger, consistency_proof=bytes(len(larger.consistency_proof)))
                ref = replace(ref, larger=(larger,))
            updates.append(mtc.LogLandmarks(log_number, doc, ref, tuple(proofs)))
        prev = store.cas[0]
        held_prev = {(t.log_number, t.landmark): t.expiry for t in prev.trusted_subtrees if t.expiry is not None and now <= mtc.EPOCH + dt.timedelta(seconds=t.expiry)}
        subtrees_prev = {(t.log_number, t.start, t.end): t for t in prev.trusted_subtrees}
        d = mtc.derive_landmarks(store, CA, updates, max_active_landmarks=bound, now=now)  # never raises on contents
        seen |= {x.reason for x in d.discarded}
        assert {x.reason for x in d.discarded} <= mtc.DISCARD_REASONS
        assert dict(d.log_status).keys() == {u.log_number for u in updates}
        held_new = {(t.log_number, t.landmark): t.expiry for t in d.ca.trusted_subtrees if t.expiry is not None}
        assert all(now <= mtc.EPOCH + dt.timedelta(seconds=e) for e in held_new.values()), step  # only active ones
        assert len(held_new) <= bound
        for x in d.discarded:  # a held landmark is listed only as another version of it, conflicting
            assert (x.log_number, x.landmark.number) not in held_new or (x.reason == "subtree-conflict" and (x.log_number, x.landmark.number) in held_prev)
        for t in d.ca.trusted_subtrees:  # held ones never change; new ones hash as in their log (or the fork's)
            k = (t.log_number, t.start, t.end)
            if (t.log_number, t.landmark) in held_prev and t.expiry is not None:
                assert subtrees_prev.get(k) == t, step
            assert t.subtree_hash in {tl.trees[t.log_number].hash(t.start, t.end), tl.trees["fork"].hash(t.start, t.end)}
        assert all(t in d.ca.trusted_subtrees for t in tl.hand)
        candidates = {**held_prev, **{k: e for k, e in held_new.items() if k not in held_prev},
                      **{(x.log_number, x.landmark.number): x.landmark.expiry for x in d.discarded if x.reason == "over-bound"}}  # fmt: skip
        assert held_new.keys() == _model_order(candidates, bound), step
        sizes = dict(d.ca.reference_sizes)
        for u in updates:
            log, status = u.log_number, d.log_status[u.log_number]
            if status == "ok":
                assert sizes[log] == u.checkpoint.size >= prev_sizes.get(log, 0)
                for x in u.document.active:  # a held number re-published differently is a conflict
                    mine = [t for t in prev.trusted_subtrees if t.expiry is not None and (t.log_number, t.landmark) == (log, x.number)]
                    if (log, x.number) in held_prev and x.active(now) and tuple((t.start, t.end) for t in mine) != u.document.subtrees(x.number):
                        assert mtc.DiscardedLandmark(log, x, "subtree-conflict") in d.discarded, step
            else:
                assert status in ("checkpoint-cosigners", "reference-regressed") and sizes.get(log) == prev_sizes.get(log)
                assert status != "reference-regressed" or u.checkpoint.size < prev_sizes[log]
        assert all(sizes.get(log, 0) >= n for log, n in prev_sizes.items())
        with pytest.raises(CodecUsageError):
            keys_changed.with_derived(d)
        installs += bool(held_new.keys() - held_prev.keys())
        store = store.with_derived(d)
        if store.cas[0] != prev:
            with pytest.raises(CodecUsageError):
                store.with_ca(replace(prev, revoked=(mtc.RevokedRange(0, 1 << 48),)), replacing=prev)  # from the stale store
        again = mtc.derive_landmarks(store, CA, [], max_active_landmarks=bound, now=now)
        assert again.ca == store.cas[0] and again.discarded == ()
    assert installs >= 8 and seen == mtc.DISCARD_REASONS, (installs, mtc.DISCARD_REASONS - seen)


def test_a_held_range_under_a_new_landmark_number_conflicts(lm: Landmarked) -> None:
    """Held subtrees are in the known map: a later document whose new landmark 3 covers exactly held
    landmark 2's ranges (2 has since expired out of the document) is a conflict, not an exception."""
    tree = lm.log.tree()
    ref = lm.log.reference_checkpoint([lm.cs[CA]], TS, 520)
    mk = lambda doc, n: tuple(mtc.SubtreeProof(s, e, tree.hash(s, e), tree.consistency_proof(s, e, 520)) for s, e in doc.subtrees(n))  # noqa: E731
    doc1 = mtc.decode_landmarks(f"2\n300 {EXPIRIES[2]}\n200 0\n".encode(), NOW)
    store = lm.store().with_derived(_derive_on(lm.store(), mtc.LogLandmarks(3, doc1, ref, mk(doc1, 2))))
    doc2 = mtc.decode_landmarks(f"3\n300 {EXPIRIES[3]}\n200 0\n".encode(), NOW)
    assert doc2.subtrees(3) == doc1.subtrees(2)
    d = _derive_on(store, mtc.LogLandmarks(3, doc2, ref, mk(doc2, 3)))
    assert _reasons(d) == {(3, 3): "subtree-conflict"} and d.ca == store.cas[0]


def test_held_subtrees_come_out_in_order_whatever_order_they_were_configured(lm: Landmarked) -> None:
    derived = tuple(reversed(lm.expected(1, 2, 3, 4)))
    d = _derive_on(lm.store(subtrees=derived))
    assert d.ca.trusted_subtrees == lm.expected(1, 2, 3, 4) and d.discarded == ()


# Review round 3 -------------------------------------------------------------- #


def test_log_status_reports_every_updated_log(lm: Landmarked) -> None:
    """A failed or replayed refresh is visible even when every landmark it offers is held already."""
    store = lm.store().with_derived(_derive_on(lm.store(), lm.update()))
    assert dict(_derive_on(lm.store(), lm.update()).log_status) == {3: "ok"}
    for update, status in ((lm.update(signers=()), "checkpoint-cosigners"), (lm.update(size=350), "reference-regressed"),
                           (lm.update(size=600), "ok")):  # fmt: skip
        d = _derive_on(store, update)
        assert dict(d.log_status) == {3: status} and d.discarded == ()
    assert dict(_derive_on(store).log_status) == {}


def test_a_fork_with_matching_landmark_sizes_is_not_detected(lm: Landmarked, issued: Issued) -> None:
    """D36's "Not detected" pinned: under a cosigned checkpoint, a fork of log 3 with the same landmark
    sizes keeps the held subtrees (never re-checked) and installs its own new ones."""
    fork = Landmarked(issued, cn="fork.test")
    assert fork.log.landmarks == lm.log.landmarks and fork.log.tree().hash(0, 200) != lm.log.tree().hash(0, 200)
    store = lm.store().with_derived(_derive_on(lm.store(), lm.update(size=350)))
    d = _derive_on(store, fork.update())
    assert d.discarded == () and dict(d.log_status) == {3: "ok"} and d.ca.reference_sizes == ((3, 520),)
    assert d.ca.trusted_subtrees == lm.expected(1, 2) + fork.expected(3, 4)


def test_failed_refresh_never_lists_landmarks_expired_at_now(lm: Landmarked) -> None:
    """The offered landmarks of a failed log are listed only if active at the derive `now` and not held."""
    late = mtc.EPOCH + dt.timedelta(seconds=EXPIRIES[1] + 1)  # landmark 1 expired; the document was decoded at NOW
    d = _derive_on(lm.store(), lm.update(signers=()), now=late)
    assert dict(d.log_status) == {3: "checkpoint-cosigners"} and _reasons(d) == {(3, n): "checkpoint-cosigners" for n in (2, 3, 4)}
    half = lm.store().with_derived(_derive_on(lm.store(), lm.update(size=350)))  # landmarks 1, 2 held
    d = _derive_on(half, lm.update(size=340), now=late)
    assert dict(d.log_status) == {3: "reference-regressed"} and _reasons(d) == {(3, 3): "reference-regressed", (3, 4): "reference-regressed"}
