"""X.509 profile, cross-checked against independent parsers, and path validation (specs.md D24, P11).

Every negative is a properly re-signed certificate that differs from a good
one only in the defect under test, and asserts the alert *and* the reason:
an unsigned edit would fail on its signature whatever else is wrong.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509 as cx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from cryptography.x509.oid import NameOID

from qtls import chains, crypto, der, x509
from qtls.alerts import Alert, AlertError
from rfc8448_trace import CERT

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 11, 13, 12, 0, 0, tzinfo=UTC)
NAME = "qtls.test"
ALL_CERT_SCHEMES = set(x509.SIGNATURE_CODEPOINTS)

MATRIX = [  # (leaf, issuer) per specs.md D19 and qtls/levels.py
    ("ECDSA-P256-SHA256", "ECDSA-P256-SHA256"),
    ("ML-DSA-44", "ML-DSA-44"),
    ("ML-DSA-44", "Falcon-512"),
    ("Falcon-512", "ML-DSA-44"),
    ("Falcon-512", "Falcon-512"),
    ("ML-DSA-65", "ML-DSA-65"),
]


def needs_liboqs(*algs: str) -> list:
    return [pytest.mark.usefixtures("require_liboqs")] if any(a not in ("ECDSA-P256-SHA256",) for a in algs) else []


def chain_for(leaf: str, issuer: str, scts: int = 0) -> chains.Chain:
    return chains.build_chain(leaf_alg=leaf, issuer_alg=issuer, scts=scts, not_before=NOW - dt.timedelta(days=1))


def verify(cert_data, anchors, **kw):  # noqa: ANN001, ANN201
    kw.setdefault("server_name", NAME)
    kw.setdefault("now", NOW)
    kw.setdefault("accepted", ALL_CERT_SCHEMES)
    return x509.verify_chain(list(cert_data), list(anchors), **kw)


def fails(alert: Alert, reason: str, call) -> None:  # noqa: ANN001
    with pytest.raises(AlertError) as exc:
        call()
    assert (exc.value.alert, exc.value.reason) == (alert, reason), exc.value


# --------------------------------------------------------------------------- #
# A small ECDSA PKI for negatives (fast, deterministic)
# --------------------------------------------------------------------------- #

ALG = "ECDSA-P256-SHA256"
ROOT_KEY = chains.signing_key(ALG, b"neg", "root")
INTER_KEY = chains.signing_key(ALG, b"neg", "intermediate")
LEAF_KEY = chains.signing_key(ALG, b"neg", "leaf")
ROOT_SPKI = x509.spki(ALG, ROOT_KEY.public_key)
INTER_SPKI = x509.spki(ALG, INTER_KEY.public_key)
LEAF_SPKI = x509.spki(ALG, LEAF_KEY.public_key)
NB, NA = NOW - dt.timedelta(days=1), NOW + dt.timedelta(days=30)


def root(**kw) -> bytes:  # noqa: ANN003
    args = dict(subject_cn="root", subject_spki=ROOT_SPKI, issuer_cn="root", issuer_key=ROOT_KEY,
                issuer_spki=ROOT_SPKI, serial=1, not_before=NB, not_after=NA, signing_seed=b"", ca=True)  # fmt: skip
    return x509.issue(**{**args, **kw})


def inter(**kw) -> bytes:  # noqa: ANN003
    args = dict(subject_cn="inter", subject_spki=INTER_SPKI, issuer_cn="root", issuer_key=ROOT_KEY,
                issuer_spki=ROOT_SPKI, serial=2, not_before=NB, not_after=NA, signing_seed=b"", ca=True)  # fmt: skip
    return x509.issue(**{**args, **kw})


def leaf(**kw) -> bytes:  # noqa: ANN003
    args = dict(subject_cn=NAME, subject_spki=LEAF_SPKI, issuer_cn="inter", issuer_key=INTER_KEY,
                issuer_spki=INTER_SPKI, serial=3, not_before=NB, not_after=NA, signing_seed=b"",
                key_usage={x509.DIGITAL_SIGNATURE}, dns_names=[NAME])  # fmt: skip
    return x509.issue(**{**args, **kw})


ANCHOR = x509.TrustAnchor.from_certificate(root())


def resign(cert_der: bytes, key: crypto.SigPrivateKey, edit) -> bytes:  # noqa: ANN001
    """Apply ``edit`` to the TBS's child encodings, then sign it again properly."""
    tbs, alg, _ = der.parse(cert_der).children()
    children = [c.raw for c in tbs.children()]
    new_tbs = der.seq(*edit(children))
    return der.seq(new_tbs, alg.raw, der.bit_string(key.sign(new_tbs, seed=b"")))


def test_the_negative_pki_is_valid() -> None:
    v = verify([leaf(), inter()], [ANCHOR])
    assert (v.kind, v.alg, v.public_key) == ("sig", ALG, LEAF_KEY.public_key)


# --------------------------------------------------------------------------- #
# Independent parsers: cryptography (and OpenSSL below)
# --------------------------------------------------------------------------- #


def cross_check(cert_der: bytes) -> None:
    """Our parse agrees with cryptography's, field by field, on bytes and values."""
    ours = x509.parse(cert_der)
    theirs = cx.load_der_x509_certificate(cert_der)
    assert theirs.version is cx.Version.v3
    assert ours.serial == theirs.serial_number
    assert ours.signature_oid == theirs.signature_algorithm_oid.dotted_string
    assert ours.issuer_raw == theirs.issuer.public_bytes()
    assert ours.subject_raw == theirs.subject.public_bytes()
    assert (ours.not_before, ours.not_after) == (theirs.not_valid_before_utc, theirs.not_valid_after_utc)
    assert ours.tbs_raw == theirs.tbs_certificate_bytes
    assert ours.signature == theirs.signature
    assert ours.spki_oid == theirs.public_key_algorithm_oid.dotted_string
    if ours.spki_oid != x509.BY_NAME["Falcon-512"].oid:  # cryptography can't load a Falcon key
        assert ours.spki_raw == theirs.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    try:
        theirs_extensions = theirs.extensions
    except ValueError as exc:
        # RFC 6962 has no codepoint for post-quantum SCT signatures (D24), so only for those
        # may cryptography refuse the SCT list; ECDSA SCTs must parse. Every other field was
        # still cross-checked above.
        sct = ours.extension(x509.SCT_LIST)
        assert sct is not None and "SCT" in str(exc), exc
        assert ours.signature_oid != x509.BY_NAME["ECDSA-P256-SHA256"].oid, exc
        assert der.parse(sct.value).as_octets()
        return
    theirs_exts = {e.oid.dotted_string: e for e in theirs_extensions}
    assert {e.oid for e in ours.extensions} == set(theirs_exts)
    for e in ours.extensions:
        assert e.critical == theirs_exts[e.oid].critical


def test_rfc8448_certificate_cross_checks() -> None:
    n = int.from_bytes(CERT[8:11], "big")
    cert = CERT[11 : 11 + n]
    cross_check(cert)
    ours = x509.parse(cert)
    assert ours.subject_cn == "rsa"
    theirs = cx.load_der_x509_certificate(cert)
    assert ours.spki_raw == theirs.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@pytest.mark.parametrize(("leaf_alg", "issuer_alg"), MATRIX, ids=lambda v: v)
@pytest.mark.parametrize("scts", [0, 2])
def test_matrix_chains_cross_check(request: pytest.FixtureRequest, leaf_alg: str, issuer_alg: str, scts: int) -> None:
    if "ECDSA" not in leaf_alg:
        request.getfixturevalue("require_liboqs")
    chain = chain_for(leaf_alg, issuer_alg, scts)
    certs = [*chain.cert_data, chain.root_der]
    for cert in certs:
        cross_check(cert)
    # Every link verifies independently: cryptography for ECDSA/ML-DSA, the raw TBS for Falcon.
    for child, parent in zip(certs, certs[1:] + [chain.root_der], strict=True):
        c, p = cx.load_der_x509_certificate(child), cx.load_der_x509_certificate(parent)
        if issuer_alg == "Falcon-512":
            parent_parsed = x509.parse(parent)
            crypto.sig_verify("Falcon-512", parent_parsed.public_key, c.tbs_certificate_bytes, c.signature, "liboqs")
        else:
            c.verify_directly_issued_by(p)
    assert cx.load_der_x509_certificate(chain.cert_data[0]).signature_algorithm_oid.dotted_string == x509.BY_NAME[issuer_alg].oid


def test_symmetric_encoding_traps_cross_check() -> None:
    """Values builder and parser could get wrong in the same way."""
    cases = [
        leaf(serial=0x80 << (8 * 18)),  # high bit set: needs a 0x00 sign byte
        leaf(serial=(1 << 159) - 1),  # exactly 20 octets
        leaf(not_after=dt.datetime(2051, 6, 1, tzinfo=UTC)),  # GeneralizedTime
        leaf(not_before=dt.datetime(1999, 1, 1, tzinfo=UTC)),  # UTCTime YY >= 50 → 19YY
        leaf(dns_names=["QTLS.Test"]),
    ]
    for cert in cases:
        cross_check(cert)
        cx.load_der_x509_certificate(cert).verify_directly_issued_by(cx.load_der_x509_certificate(inter()))
    assert verify([leaf(dns_names=["QTLS.Test"]), inter()], [ANCHOR]).alg == ALG


def test_hand_written_profile_encodings() -> None:
    cert = x509.parse(inter(path_len=0))
    get = lambda oid: cert.extension(oid)  # noqa: E731
    assert get(x509.BASIC_CONSTRAINTS).raw == bytes.fromhex("30120603551d130101ff040830060101ff020100")
    assert get(x509.BASIC_CONSTRAINTS).value == bytes.fromhex("30060101ff020100")
    assert get(x509.KEY_USAGE).value == bytes.fromhex("03020106")
    assert get(x509.BASIC_CONSTRAINTS).critical and get(x509.KEY_USAGE).critical
    leaf_cert = x509.parse(leaf())
    assert leaf_cert.extension(x509.BASIC_CONSTRAINTS).value == bytes.fromhex("3000")  # cA FALSE omitted
    assert leaf_cert.extension(x509.KEY_USAGE).value == bytes.fromhex("03020780")
    assert not leaf_cert.extension(x509.SUBJECT_KEY_ID).critical  # critical FALSE omitted
    tbs, alg, _ = der.parse(leaf()).children()
    assert alg.raw == bytes.fromhex("300a06082a8648ce3d040302")  # ecdsa-with-SHA256, parameters absent
    assert x509.spki(ALG, LEAF_KEY.public_key)[:21] == bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03")
    assert x509.spki("ML-DSA-44", bytes(1312))[:20] == bytes.fromhex("30820532300b0609608648016503040311038205")


@pytest.mark.parametrize("alg", ["ECDSA-P256-SHA256", "ML-DSA-44", "ML-DSA-65"])
def test_we_accept_chains_cryptography_built(backend: str, alg: str) -> None:
    if alg == ALG and backend == "liboqs":
        backend = "openssl"  # liboqs has no ECDSA; the case still runs once per backend parameter
    def key():  # noqa: ANN202
        return ec.generate_private_key(ec.SECP256R1()) if alg == ALG else getattr(mldsa, alg.replace("-", "").replace("MLDSA", "MLDSA") + "PrivateKey").generate()

    def build(subject, sk, issuer, ik, *, ca: bool, ku: cx.KeyUsage, san=None):  # noqa: ANN001, ANN202
        name = lambda cn: cx.Name([cx.NameAttribute(NameOID.COMMON_NAME, cn)])  # noqa: E731
        b = (cx.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer))
             .public_key(sk.public_key()).serial_number(cx.random_serial_number())
             .not_valid_before(NB).not_valid_after(NA)
             .add_extension(cx.BasicConstraints(ca=ca, path_length=None), critical=True)
             .add_extension(ku, critical=True)
             .add_extension(cx.SubjectKeyIdentifier.from_public_key(sk.public_key()), critical=False))  # fmt: skip
        if ik is not sk:
            b = b.add_extension(cx.AuthorityKeyIdentifier.from_issuer_public_key(ik.public_key()), critical=False)
        if san:
            b = b.add_extension(cx.SubjectAlternativeName([cx.DNSName(san)]), critical=False)
        return b.sign(ik, hashes.SHA256() if alg == ALG else None).public_bytes(serialization.Encoding.DER)

    ca_ku = cx.KeyUsage(False, False, False, False, False, True, True, False, False)
    ee_ku = cx.KeyUsage(True, False, False, False, False, False, False, False, False)
    rk, ik, lk = key(), key(), key()
    root_der = build("root", rk, "root", rk, ca=True, ku=ca_ku)
    inter_der = build("inter", ik, "root", rk, ca=True, ku=ca_ku)
    leaf_der = build(NAME, lk, "inter", ik, ca=False, ku=ee_ku, san=NAME)
    v = verify([leaf_der, inter_der], [x509.TrustAnchor.from_certificate(root_der)], backends={alg: backend})
    assert v.alg == alg


def _openssl() -> str | None:
    for candidate in (os.environ.get("QTLS_OPENSSL"), shutil.which("openssl"), "/opt/homebrew/opt/openssl@3/bin/openssl"):
        if candidate and Path(candidate).exists():
            out = subprocess.run([candidate, "version"], capture_output=True, text=True).stdout
            m = re.match(r"OpenSSL (\d+)\.(\d+)", out)
            if m and (int(m.group(1)), int(m.group(2))) >= (3, 5):
                return candidate
    return None


@pytest.mark.openssl
@pytest.mark.parametrize(("leaf_alg", "issuer_alg"), [m for m in MATRIX if "Falcon-512" not in m], ids=lambda v: v)
@pytest.mark.parametrize("scts", [0, 2])
def test_openssl_verifies_our_chains_strictly(require_liboqs: None, tmp_path: Path, leaf_alg: str, issuer_alg: str, scts: int) -> None:
    binary = _openssl()
    if binary is None:
        pytest.skip("OpenSSL >= 3.5 not found (set QTLS_OPENSSL)")
    chain = chain_for(leaf_alg, issuer_alg, scts)
    pem = lambda d: cx.load_der_x509_certificate(d).public_bytes(serialization.Encoding.PEM)  # noqa: E731
    (tmp_path / "root.pem").write_bytes(pem(chain.root_der))
    (tmp_path / "inter.pem").write_bytes(pem(chain.cert_data[1]))
    (tmp_path / "leaf.pem").write_bytes(pem(chain.cert_data[0]))
    result = subprocess.run(
        [binary, "verify", "-x509_strict", "-attime", str(int(NOW.timestamp())), "-verify_hostname", NAME,
         "-purpose", "sslserver", "-CAfile", str(tmp_path / "root.pem"), "-untrusted", str(tmp_path / "inter.pem"),
         str(tmp_path / "leaf.pem")],
        capture_output=True, text=True,
    )  # fmt: skip
    assert result.returncode == 0 and result.stdout.strip().endswith("OK"), result.stdout + result.stderr


# --------------------------------------------------------------------------- #
# Parse rejections (each re-signed)
# --------------------------------------------------------------------------- #


def _ext_raw(oid: str, value: bytes, critical: bool | None) -> bytes:
    crit = [der.boolean(critical)] if critical is not None else []
    return der.seq(der.oid(oid), *crit, der.octet_string(value))


def _replace_extensions(exts: list[bytes]):  # noqa: ANN202
    def edit(children: list[bytes]) -> list[bytes]:
        return children[:7] + [der.explicit(3, der.seq(*exts))]
    return edit


PARSE_REJECTIONS = {
    "v1": (lambda c: [der.explicit(0, der.integer(0))] + c[1:], "version"),
    "v2": (lambda c: [der.explicit(0, der.integer(1))] + c[1:], "version"),
    "no-version": (lambda c: c[1:], "version"),
    "serial-0": (lambda c: [c[0], der.integer(0)] + c[2:], "serial"),
    "serial-negative": (lambda c: [c[0], der.integer(-5)] + c[2:], "serial"),
    "serial-21-octets": (lambda c: [c[0], der.integer(1 << 160)] + c[2:], "serial"),
    "inner-alg-differs": (lambda c: c[:2] + [der.seq(der.oid("2.16.840.1.101.3.4.3.17"))] + c[3:], "alg-mismatch"),
    "unique-id": (lambda c: c[:7] + [der.tlv(0x81, b"\x00\x01")] + c[7:], "tbs-shape"),
    "empty-extensions": (_replace_extensions([]), "extensions-empty"),
    "duplicate-extension": (_replace_extensions([_ext_raw("2.5.29.14", der.octet_string(b"a"), None)] * 2), "duplicate-extension"),
    "unknown-critical": (_replace_extensions([_ext_raw("1.2.3.4", der.null(), True)]), "unknown-critical"),
    "critical-false-encoded": (_replace_extensions([_ext_raw("2.5.29.14", der.octet_string(b"a"), False)]), "default-encoded"),
    "ca-false-encoded": (_replace_extensions([_ext_raw("2.5.29.19", der.seq(der.boolean(False)), True)]), "default-encoded"),
}


@pytest.mark.parametrize("case", PARSE_REJECTIONS)
def test_parse_rejections(case: str) -> None:
    edit, reason = PARSE_REJECTIONS[case]
    bad = resign(leaf(), INTER_KEY, edit)
    fails(Alert.bad_certificate, reason, lambda: x509.parse(bad))
    fails(Alert.bad_certificate, reason, lambda: verify([bad, inter()], [ANCHOR]))


def test_unknown_non_critical_extension_is_accepted() -> None:
    def edit(children: list[bytes]) -> list[bytes]:
        existing = [n.raw for n in der.parse(children[7]).children()[0].children()]
        return children[:7] + [der.explicit(3, der.seq(*existing, _ext_raw("1.2.3.4", der.null(), None)))]

    cert = resign(leaf(), INTER_KEY, edit)
    assert verify([cert, inter()], [ANCHOR]).alg == ALG


def test_trailing_bytes_after_certificate_or_tbs() -> None:
    fails(Alert.bad_certificate, "der", lambda: x509.parse(leaf() + b"\x00"))
    tbs, alg, sig = der.parse(leaf()).children()
    padded = der.seq(tbs.raw + b"\x05\x00", alg.raw, sig.raw)
    fails(Alert.bad_certificate, "der", lambda: x509.parse(padded))


def test_mtc_style_certificate_parses_but_is_unsupported() -> None:
    """An id-alg-mtcProof certificate (Phase 3) goes through the same parser."""
    mtc_alg = der.seq(der.oid("1.3.6.1.5.5.7.6.67"))
    tbs, _, _ = der.parse(leaf()).children()
    children = [c.raw for c in tbs.children()]
    new_tbs = der.seq(*children[:2], mtc_alg, *children[3:])
    cert = der.seq(new_tbs, mtc_alg, der.bit_string(b"\x00" * 40))
    parsed = x509.parse(cert)
    assert parsed.signature_oid == "1.3.6.1.5.5.7.6.67"
    fails(Alert.unsupported_certificate, "algorithm", lambda: verify([cert, inter()], [ANCHOR]))


# --------------------------------------------------------------------------- #
# Path validation: positives
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("leaf_alg", "issuer_alg"), MATRIX, ids=lambda v: v)
@pytest.mark.parametrize("scts", [0, 2])
def test_matrix_chains_verify(request: pytest.FixtureRequest, leaf_alg: str, issuer_alg: str, scts: int) -> None:
    if "ECDSA" not in leaf_alg:
        request.getfixturevalue("require_liboqs")
    chain = chain_for(leaf_alg, issuer_alg, scts)
    v = verify(chain.cert_data, [chain.anchor])
    assert (v.kind, v.alg, v.public_key) == ("sig", leaf_alg, chain.leaf_signing_key.public_key)
    assert v.spki_raw == x509.spki(leaf_alg, chain.leaf_signing_key.public_key)


@pytest.mark.usefixtures("require_liboqs")
def test_kem_leaf_comes_back_as_kem() -> None:
    chain = chain_for("ML-KEM-768", "ML-DSA-65")
    v = verify(chain.cert_data, [chain.anchor])
    assert (v.kind, v.alg) == ("kem", "ML-KEM-768")
    kem_spki = x509.spki("ML-KEM-768", chain.leaf_kem_key.public_key)
    wrong_usage = x509.issue(subject_cn=NAME, subject_spki=kem_spki, issuer_cn="inter", issuer_key=INTER_KEY,
                             issuer_spki=INTER_SPKI, serial=9, not_before=NB, not_after=NA, signing_seed=b"",
                             key_usage={x509.DIGITAL_SIGNATURE}, dns_names=[NAME])  # fmt: skip
    fails(Alert.bad_certificate, "leaf-key-usage", lambda: verify([wrong_usage, inter()], [ANCHOR]))


def test_sent_root_is_ignored_and_no_intermediates_is_fine() -> None:
    assert verify([leaf(), inter(), root()], [ANCHOR]).alg == ALG
    # Ignored, not validated: an anchor's own dates don't matter (D24), even when sent.
    expired_root = root(not_before=NB - dt.timedelta(days=400), not_after=NB - dt.timedelta(days=300))
    assert x509.TrustAnchor.from_certificate(expired_root) == ANCHOR
    assert verify([leaf(), inter(), expired_root], [ANCHOR]).alg == ALG
    direct = leaf(issuer_cn="root", issuer_key=ROOT_KEY, issuer_spki=ROOT_SPKI)
    assert verify([direct], [ANCHOR]).alg == ALG


def test_clock_is_never_read() -> None:
    source = Path(x509.__file__).read_text()
    assert not re.search(r"\.now\(|utcnow|time\.time|\.today\(", source)


# --------------------------------------------------------------------------- #
# Path validation: negatives, one defect each
# --------------------------------------------------------------------------- #


def test_empty_chain() -> None:
    fails(Alert.bad_certificate, "empty-chain", lambda: verify([], [ANCHOR]))


def test_anchors() -> None:
    other_root_key = chains.signing_key(ALG, b"other", "root")
    other_spki = x509.spki(ALG, other_root_key.public_key)
    same_name_other_key = x509.TrustAnchor(ANCHOR.name_raw, other_spki)
    other_name_same_key = x509.TrustAnchor(x509.name("someone else"), ANCHOR.spki_raw)
    fails(Alert.unknown_ca, "unknown-anchor", lambda: verify([leaf(), inter()], []))
    fails(Alert.unknown_ca, "unknown-anchor", lambda: verify([leaf(), inter()], [other_name_same_key]))
    fails(Alert.bad_certificate, "signature", lambda: verify([leaf(), inter()], [same_name_other_key]))


def test_per_link_checks() -> None:
    fails(Alert.bad_certificate, "issuer-name", lambda: verify([leaf(issuer_cn="someone"), inter()], [ANCHOR]))
    good = leaf()
    tbs, alg, sig = der.parse(good).children()
    flipped_sig = der.seq(tbs.raw, alg.raw, der.bit_string(sig.as_bit_string()[:-1] + bytes([sig.as_bit_string()[-1] ^ 1])))
    fails(Alert.bad_certificate, "signature", lambda: verify([flipped_sig, inter()], [ANCHOR]))
    fails(Alert.bad_certificate, "not-a-ca", lambda: verify([leaf(), inter(ca=False, key_usage={x509.KEY_CERT_SIGN})], [ANCHOR]))
    fails(Alert.bad_certificate, "key-usage", lambda: verify([leaf(), inter(key_usage={x509.CRL_SIGN})], [ANCHOR]))
    fails(Alert.bad_certificate, "leaf-is-ca", lambda: verify([leaf(ca=True, key_usage={x509.DIGITAL_SIGNATURE, x509.KEY_CERT_SIGN}), inter()], [ANCHOR]))
    fails(Alert.bad_certificate, "leaf-key-usage", lambda: verify([leaf(key_usage={x509.KEY_ENCIPHERMENT}), inter()], [ANCHOR]))


def test_path_length() -> None:
    i2_key = chains.signing_key(ALG, b"neg", "inter2")
    i2_spki = x509.spki(ALG, i2_key.public_key)
    i2 = x509.issue(subject_cn="inter2", subject_spki=i2_spki, issuer_cn="inter", issuer_key=INTER_KEY,
                    issuer_spki=INTER_SPKI, serial=4, not_before=NB, not_after=NA, signing_seed=b"", ca=True)  # fmt: skip
    leaf2 = leaf(issuer_cn="inter2", issuer_key=i2_key, issuer_spki=i2_spki)
    assert verify([leaf2, i2, inter()], [ANCHOR]).alg == ALG  # pathLen absent: unlimited
    assert verify([leaf2, i2, inter(path_len=1)], [ANCHOR]).alg == ALG
    fails(Alert.bad_certificate, "path-len", lambda: verify([leaf2, i2, inter(path_len=0)], [ANCHOR]))


@pytest.mark.parametrize("position", ["leaf", "intermediate"])
def test_validity_boundaries(position: str) -> None:
    def chain(**times):  # noqa: ANN003, ANN202
        return [leaf(**times), inter()] if position == "leaf" else [leaf(), inter(**times)]

    start, end = NOW - dt.timedelta(hours=1), NOW + dt.timedelta(hours=1)
    certs = chain(not_before=start, not_after=end)
    for ok in (start, end):
        verify(certs, [ANCHOR], now=ok)
    for bad in (start - dt.timedelta(seconds=1), end + dt.timedelta(seconds=1)):
        fails(Alert.certificate_expired, "validity", lambda bad=bad: verify(certs, [ANCHOR], now=bad))


def test_algorithm_confusion_is_an_alert_not_a_crash() -> None:
    # An ML-DSA-signed child under an ECDSA issuer key.
    child = resign(leaf(), INTER_KEY, lambda c: c[:2] + [der.seq(der.oid(x509.BY_NAME["ML-DSA-44"].oid))] + c[3:])
    tbs, _, sig = der.parse(child).children()
    ml_alg = der.seq(der.oid(x509.BY_NAME["ML-DSA-44"].oid))
    confused = der.seq(tbs.raw, ml_alg, sig.raw)
    fails(Alert.bad_certificate, "issuer-key-type", lambda: verify([confused, inter()], [ANCHOR]))
    # Wrong-length and malformed keys never reach crypto.
    bad_ml = der.seq(der.seq(der.oid(x509.BY_NAME["ML-DSA-44"].oid)), der.bit_string(bytes(1311)))
    fails(Alert.bad_certificate, "key-length", lambda: x509.parse(leaf(subject_spki=bad_ml)))
    compressed = der.seq(der.seq(der.oid(x509.EC_PUBLIC_KEY), der.oid(x509.PRIME256V1)), der.bit_string(b"\x02" + bytes(32)))
    fails(Alert.bad_certificate, "ec-point", lambda: x509.parse(leaf(subject_spki=compressed)))
    other_curve = der.seq(der.seq(der.oid(x509.EC_PUBLIC_KEY), der.oid("1.3.132.0.34")), der.bit_string(LEAF_KEY.public_key))
    fails(Alert.bad_certificate, "ec-curve", lambda: x509.parse(leaf(subject_spki=other_curve)))
    with_null = der.seq(der.seq(der.oid(x509.BY_NAME["ML-DSA-44"].oid), der.null()), der.bit_string(bytes(1312)))
    fails(Alert.bad_certificate, "spki-params", lambda: x509.parse(leaf(subject_spki=with_null)))


def test_accepted_signature_algorithms() -> None:
    fails(Alert.unsupported_certificate, "algorithm", lambda: verify([leaf(), inter()], [ANCHOR], accepted={0x0904}))


@pytest.mark.parametrize(
    ("dns_names", "server_name"),
    [(["*.qtls.test"], "a.qtls.test"), (["*.qtls.test"], "*.qtls.test"), (["qtls.test"], "a.qtls.test"), (["a.qtls.test"], "qtls.test"),
     (["qtls.test."], "qtls.test"), (["qtls.test"], "qtls.test."), ([], NAME)],
    ids=["wildcard", "literal-wildcard", "suffix", "prefix", "san-trailing-dot", "name-trailing-dot", "no-san-cn-matches"],
)  # fmt: skip
def test_name_mismatches(dns_names: list[str], server_name: str) -> None:
    fails(Alert.bad_certificate, "name", lambda: verify([leaf(dns_names=dns_names), inter()], [ANCHOR], server_name=server_name))


def test_malformed_der_anywhere_is_bad_certificate() -> None:
    fails(Alert.bad_certificate, "der", lambda: verify([leaf()[:-1], inter()], [ANCHOR]))
    fails(Alert.bad_certificate, "der", lambda: verify([leaf(), inter()[:50]], [ANCHOR]))


# --------------------------------------------------------------------------- #
# Which alert wins (D24's fixed order)
# --------------------------------------------------------------------------- #

OTHER_ALG_ONLY = {0x0904}


def _flip_signature(cert_der: bytes) -> bytes:
    tbs, alg, sig = der.parse(cert_der).children()
    s = sig.as_bit_string()
    return der.seq(tbs.raw, alg.raw, der.bit_string(s[:-1] + bytes([s[-1] ^ 1])))


@pytest.mark.parametrize(
    ("label", "chain", "kwargs", "expected"),
    [
        ("der beats unknown anchor", lambda: [leaf()[:-1], inter()], {"anchors": []}, (Alert.bad_certificate, "der")),
        ("unknown anchor beats algorithm", lambda: [leaf(), inter()], {"anchors": [], "accepted": OTHER_ALG_ONLY}, (Alert.unknown_ca, "unknown-anchor")),
        ("algorithm beats signature", lambda: [leaf(issuer_cn="x"), inter()], {"accepted": OTHER_ALG_ONLY}, (Alert.unsupported_certificate, "algorithm")),
        ("issuer name beats not-a-ca", lambda: [leaf(issuer_cn="x"), inter(ca=False, key_usage={x509.KEY_CERT_SIGN})], {}, (Alert.bad_certificate, "issuer-name")),
        ("signature beats not-a-ca", lambda: [_flip_signature(leaf()), inter(ca=False, key_usage={x509.KEY_CERT_SIGN})], {}, (Alert.bad_certificate, "signature")),
        ("not-a-ca beats expiry", lambda: [leaf(), inter(ca=False, key_usage={x509.KEY_CERT_SIGN})], {"now": NA + dt.timedelta(days=1)}, (Alert.bad_certificate, "not-a-ca")),
        ("expiry beats name", lambda: [leaf(), inter()], {"now": NA + dt.timedelta(days=1), "server_name": "other.test"}, (Alert.certificate_expired, "validity")),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)  # fmt: skip
def test_alert_precedence(label: str, chain, kwargs: dict, expected: tuple) -> None:  # noqa: ANN001
    anchors = kwargs.pop("anchors", [ANCHOR])
    fails(*expected, lambda: verify(chain(), anchors, **kwargs))


# --------------------------------------------------------------------------- #
# Sizes and determinism (D19)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("leaf_alg", "issuer_alg"), MATRIX, ids=lambda v: v)
@pytest.mark.parametrize("scts", [0, 2])
def test_chain_sizes_and_determinism(request: pytest.FixtureRequest, leaf_alg: str, issuer_alg: str, scts: int) -> None:
    if "ECDSA" not in leaf_alg:
        request.getfixturevalue("require_liboqs")
    a, b = chain_for(leaf_alg, issuer_alg, scts), chain_for(leaf_alg, issuer_alg, scts)
    assert a.cert_data == b.cert_data and a.root_der == b.root_der
    assert a.size == sum(len(c) for c in a.cert_data)
    for cert_der, signer in ((a.cert_data[0], issuer_alg), (a.cert_data[1], issuer_alg)):
        cert = x509.parse(cert_der)
        assert cert.signature_oid == x509.BY_NAME[signer].oid
        params = crypto.SIGNATURES[signer]
        assert len(cert.signature) == params.max_signature_len if params.fixed_length else 0 < len(cert.signature) <= params.max_signature_len
        assert sum(cert.sizes().values()) == len(cert_der)
        assert cert.sizes()["signature"] == len(cert.signature)
    leaf_cert = x509.parse(a.cert_data[0])
    assert (leaf_cert.extension(x509.SCT_LIST) is not None) == (scts > 0)
    if scts:
        inner = der.parse(leaf_cert.extension(x509.SCT_LIST).value).as_octets()  # double-wrapped OCTET STRING
        assert len(x509._parse_sct_list(inner)) == scts


# --------------------------------------------------------------------------- #
# Added after the Phase 2c review
# --------------------------------------------------------------------------- #


def _rfc7093_key_id(spki_der: bytes) -> bytes:
    """Written out independently: the leftmost 160 bits of SHA-256 of the BIT STRING contents."""
    import hashlib

    from cryptography.hazmat.primitives.serialization import load_der_public_key  # noqa: F401

    bits = der.parse(spki_der).children()[1].contents[1:]  # skip the unused-bits byte
    return hashlib.sha256(bits).digest()[:20]


@pytest.mark.parametrize("scts", [0, 2])
def test_key_identifiers(request: pytest.FixtureRequest, scts: int) -> None:
    for leaf_alg, issuer_alg in MATRIX:
        if "ECDSA" not in leaf_alg:
            request.getfixturevalue("require_liboqs")
        chain = chain_for(leaf_alg, issuer_alg, scts)
        leaf_c, inter_c, root_c = (x509.parse(c) for c in (*chain.cert_data, chain.root_der))
        for cert in (leaf_c, inter_c, root_c):
            assert der.parse(cert.extension(x509.SUBJECT_KEY_ID).value).as_octets() == _rfc7093_key_id(cert.spki_raw)
        assert root_c.extension(x509.AUTHORITY_KEY_ID) is None  # self-signed
        for child, parent in ((leaf_c, inter_c), (inter_c, root_c)):
            akid = der.parse(child.extension(x509.AUTHORITY_KEY_ID).value).children()
            assert [n.tag for n in akid] == [0x80]
            assert akid[0].contents == der.parse(parent.extension(x509.SUBJECT_KEY_ID).value).as_octets()


@pytest.mark.parametrize("issuer_alg", ["ECDSA-P256-SHA256", "ML-DSA-44", "Falcon-512"])
def test_sct_fields(request: pytest.FixtureRequest, issuer_alg: str) -> None:
    """Each SCT, parsed field by field, and its signature checked with the log key."""
    if issuer_alg != "ECDSA-P256-SHA256":
        request.getfixturevalue("require_liboqs")
    chain = chain_for("ECDSA-P256-SHA256" if issuer_alg == ALG else "ML-DSA-44", issuer_alg, scts=2)
    leaf_c = x509.parse(chain.cert_data[0])
    scts = x509._parse_sct_list(der.parse(leaf_c.extension(x509.SCT_LIST).value).as_octets())
    log_keys = [chains.signing_key(issuer_alg, b"qtls fixture v1", f"log{i}") for i in range(2)]
    assert log_keys[0].public_key != log_keys[1].public_key  # distinct logs
    import hashlib

    for i, (sct, log_key) in enumerate(zip(scts, log_keys, strict=True)):
        version, log_id, ts = sct[0], sct[1:33], sct[33:41]
        ext_len, scheme = int.from_bytes(sct[41:43], "big"), int.from_bytes(sct[43:45], "big")
        sig_len = int.from_bytes(sct[45:47], "big")
        signature = sct[47:]
        assert (version, ext_len, len(signature)) == (0, 0, sig_len)
        assert log_id == hashlib.sha256(x509.spki(issuer_alg, log_key.public_key)).digest()  # RFC 6962 §3.2
        assert int.from_bytes(ts, "big") == 1_700_000_000_000 + i
        assert scheme == x509.BY_NAME[issuer_alg].codepoints[0]
        backend = "openssl" if issuer_alg == ALG else "liboqs"
        crypto.sig_verify(issuer_alg, log_key.public_key, b"\x00\x00" + ts + leaf_c.spki_raw, signature, backend)
    if issuer_alg == ALG:  # an RFC 6962 parser accepts ECDSA SCTs as they are
        parsed = cx.load_der_x509_certificate(chain.cert_data[0]).extensions.get_extension_for_oid(
            cx.ObjectIdentifier(x509.SCT_LIST)
        ).value
        assert [s.version for s in parsed] == [cx.certificate_transparency.Version.v1] * 2


def test_san_must_be_a_dns_name() -> None:
    def with_san(general_names: list[bytes]):  # noqa: ANN202
        def edit(children: list[bytes]) -> list[bytes]:
            existing = [n.raw for n in der.parse(children[7]).children()[0].children()]
            kept = [e for e in existing if der.parse(e).children()[0].as_oid() != x509.SUBJECT_ALT_NAME]
            san = _ext_raw(x509.SUBJECT_ALT_NAME, der.seq(*general_names), None)
            return children[:7] + [der.explicit(3, der.seq(*kept, san))]
        return edit

    for tag in (0x86, 0x81):  # uniformResourceIdentifier, rfc822Name equal to the server name
        cert = resign(leaf(), INTER_KEY, with_san([der.tlv(tag, NAME.encode())]))
        fails(Alert.bad_certificate, "name", lambda c=cert: verify([c, inter()], [ANCHOR]))
    fails(Alert.bad_certificate, "san", lambda: x509.parse(resign(leaf(), INTER_KEY, with_san([der.tlv(0x82, b"")]))))
    fails(Alert.bad_certificate, "san", lambda: x509.parse(resign(leaf(), INTER_KEY, with_san([]))))


def test_trailing_dot_and_wildcard_on_both_sides_never_match() -> None:
    for name in ("qtls.test.", "*.qtls.test"):
        fails(Alert.bad_certificate, "name", lambda n=name: verify([leaf(dns_names=[n]), inter()], [ANCHOR], server_name=n))


def test_names_compare_ascii_only() -> None:
    kelvin = "K.test"  # KELVIN SIGN lowercases to 'k' in Unicode, never in ASCII
    fails(Alert.bad_certificate, "name", lambda: verify([leaf(dns_names=["k.test"]), inter()], [ANCHOR], server_name=kelvin))


def test_leaf_key_usage_rules() -> None:
    # RFC 8446 §4.4.2.2: a signature leaf without keyUsage is fine; with it, digitalSignature is required.
    assert verify([leaf(key_usage=set()), inter()], [ANCHOR]).alg == ALG
    fails(Alert.bad_certificate, "leaf-key-usage", lambda: verify([leaf(key_usage={x509.KEY_ENCIPHERMENT}), inter()], [ANCHOR]))


@pytest.mark.usefixtures("require_liboqs")
def test_kem_leaf_needs_key_encipherment() -> None:
    chain = chain_for("ML-KEM-768", "ML-DSA-65")
    kem_spki = x509.spki("ML-KEM-768", chain.leaf_kem_key.public_key)
    no_usage = leaf(subject_spki=kem_spki, key_usage=set())
    fails(Alert.bad_certificate, "leaf-key-usage", lambda: verify([no_usage, inter()], [ANCHOR]))
    assert verify([leaf(subject_spki=kem_spki, key_usage={x509.KEY_ENCIPHERMENT}), inter()], [ANCHOR]).kind == "kem"


def test_ecdsa_key_oid_and_curve_point() -> None:
    sig_oid_as_key = der.seq(der.seq(der.oid(x509.BY_NAME[ALG].oid)), der.bit_string(LEAF_KEY.public_key))
    fails(Alert.unsupported_certificate, "leaf-key", lambda: verify([leaf(subject_spki=sig_oid_as_key), inter()], [ANCHOR]))
    off_curve = LEAF_KEY.public_key[:-1] + bytes([LEAF_KEY.public_key[-1] ^ 1])
    bad_point = der.seq(der.seq(der.oid(x509.EC_PUBLIC_KEY), der.oid(x509.PRIME256V1)), der.bit_string(off_curve))
    fails(Alert.bad_certificate, "ec-point", lambda: x509.parse(leaf(subject_spki=bad_point)))
    no_curve = der.seq(der.seq(der.oid(x509.EC_PUBLIC_KEY)), der.bit_string(LEAF_KEY.public_key))
    fails(Alert.bad_certificate, "ec-curve", lambda: x509.parse(leaf(subject_spki=no_curve)))
    # The same off-curve key as an issuer: also refused at parse, so leaf and issuer agree.
    fails(Alert.bad_certificate, "ec-point", lambda: x509.parse(inter(subject_spki=bad_point)))


@pytest.mark.parametrize("oid", [x509.BY_NAME[ALG].oid, x509.BY_NAME["ML-DSA-44"].oid, x509.MTC_PROOF])
def test_signature_algorithm_parameters_must_be_absent(oid: str) -> None:
    with_null = der.seq(der.oid(oid), der.null())
    cert = resign(leaf(), INTER_KEY, lambda c: c[:2] + [with_null] + c[3:])
    tbs, _, sig = der.parse(cert).children()
    both = der.seq(tbs.raw, with_null, sig.raw)
    fails(Alert.bad_certificate, "alg-params", lambda: x509.parse(both))


def test_inner_and_outer_algorithms_differing_only_in_parameters() -> None:
    tbs, alg, sig = der.parse(leaf()).children()
    rsa_like = der.seq(tbs.raw, der.seq(der.oid("1.2.840.113549.1.1.11"), der.null()), sig.raw)
    fails(Alert.bad_certificate, "alg-mismatch", lambda: x509.parse(rsa_like))


def test_anchors_sharing_a_name_are_order_independent() -> None:
    old_key = chains.signing_key(ALG, b"rollover", "old-root")
    old_spki = x509.spki(ALG, old_key.public_key)
    old_anchor = x509.TrustAnchor(ANCHOR.name_raw, old_spki)
    for anchors in ([old_anchor, ANCHOR], [ANCHOR, old_anchor]):
        assert verify([leaf(), inter()], anchors).alg == ALG


def test_mtc_certificate_under_a_non_x509_issuer_is_unknown_ca() -> None:
    """D24: Phase 3 dispatches MTCs before anchor lookup; until then an MTC CA is unknown."""
    mtc_alg = der.seq(der.oid(x509.MTC_PROOF))
    tbs, _, _ = der.parse(leaf()).children()
    children = [c.raw for c in tbs.children()]
    new_tbs = der.seq(*children[:2], mtc_alg, x509.name("mtc-ca"), *children[4:])
    cert = der.seq(new_tbs, mtc_alg, der.bit_string(bytes(40)))
    fails(Alert.unknown_ca, "unknown-anchor", lambda: verify([cert], [ANCHOR]))


def test_kem_oid_as_a_signature_algorithm_is_unsupported() -> None:
    kem_alg = der.seq(der.oid(x509.BY_NAME["ML-KEM-768"].oid))
    cert = resign(leaf(), INTER_KEY, lambda c: c[:2] + [kem_alg] + c[3:])
    tbs, _, sig = der.parse(cert).children()
    fails(Alert.unsupported_certificate, "algorithm", lambda: verify([der.seq(tbs.raw, kem_alg, sig.raw), inter()], [ANCHOR]))


def test_unknown_leaf_key_is_unsupported() -> None:
    unknown = der.seq(der.seq(der.oid("1.2.3.4.5")), der.bit_string(b"\x01\x02"))
    fails(Alert.unsupported_certificate, "leaf-key", lambda: verify([leaf(subject_spki=unknown), inter()], [ANCHOR]))


def test_sent_root_edge_cases() -> None:
    fails(Alert.bad_certificate, "leaf-is-ca", lambda: verify([root()], [ANCHOR]))  # only the root: an alert, no crash
    impostor_key = chains.signing_key(ALG, b"impostor", "root")
    impostor = root(subject_spki=x509.spki(ALG, impostor_key.public_key), issuer_key=impostor_key,
                    issuer_spki=x509.spki(ALG, impostor_key.public_key))  # fmt: skip
    # Same name as the anchor, different key: not dropped, and its signature fails under the anchor.
    fails(Alert.bad_certificate, "signature", lambda: verify([leaf(), inter(), impostor], [ANCHOR]))


def test_trust_anchor_takes_the_subject() -> None:
    anchor = x509.TrustAnchor.from_certificate(inter())
    assert anchor.name_raw == x509.name("inter") and anchor.spki_raw == INTER_SPKI


def test_size_breakdown() -> None:
    plain = x509.parse(leaf())
    assert plain.sizes()["public_key"] == len(LEAF_KEY.public_key) == 65
    assert plain.sizes()["scts"] == 0
    assert plain.sizes()["overhead"] == len(plain.raw) - 65 - len(plain.signature)


@pytest.mark.usefixtures("require_liboqs")
def test_size_breakdown_with_scts() -> None:
    chain = chain_for("ML-DSA-44", "ML-DSA-44", scts=2)
    cert = x509.parse(chain.cert_data[0])
    assert cert.sizes()["public_key"] == 1312 and cert.sizes()["signature"] == 2420
    assert cert.sizes()["scts"] == len(cert.extension(x509.SCT_LIST).raw) > 2 * 2420
    assert x509.parse(chain.cert_data[1]).profile.path_len == 0  # the chain's intermediate


def test_phase3_spans_are_slices_of_the_tbs() -> None:
    cert = x509.parse(leaf())
    for span in (cert.version_raw, cert.validity_raw, cert.spki_alg_raw, cert.extensions_raw,
                 cert.issuer_raw, cert.subject_raw, cert.spki_raw):  # fmt: skip
        assert span and span in cert.tbs_raw
    assert cert.spki_raw.index(cert.spki_alg_raw) > 0 and cert.extensions_raw[0] == 0xA3


PROFILE_REJECTIONS = {
    "pathlen-without-ca": (lambda c: _with_ext(c, x509.BASIC_CONSTRAINTS, der.seq(der.integer(0)), True), "basic-constraints"),
    "negative-pathlen": (lambda c: _with_ext(c, x509.BASIC_CONSTRAINTS, der.seq(der.boolean(True), der.integer(-1)), True), "basic-constraints"),
    "bc-extra-element": (lambda c: _with_ext(c, x509.BASIC_CONSTRAINTS, der.seq(der.boolean(True), der.integer(0), der.integer(0)), True), "basic-constraints"),
    "ca-bc-not-critical": (lambda c: _with_ext(c, x509.BASIC_CONSTRAINTS, der.seq(der.boolean(True)), None), "basic-constraints"),
    "akid-critical": (lambda c: _with_ext(c, x509.AUTHORITY_KEY_ID, der.seq(der.tlv(0x80, bytes(20))), True), "akid-critical"),
    "malformed-skid": (lambda c: _with_ext(c, x509.SUBJECT_KEY_ID, der.integer(5), None), "der"),
    "malformed-akid": (lambda c: _with_ext(c, x509.AUTHORITY_KEY_ID, der.seq(der.integer(5)), None), "der"),
    "empty-sct-list": (lambda c: _with_ext(c, x509.SCT_LIST, der.octet_string(b"\x00\x00"), None), "der"),
    "zero-length-sct": (lambda c: _with_ext(c, x509.SCT_LIST, der.octet_string(b"\x00\x02\x00\x00"), None), "der"),
    "empty-rdn": (lambda c: c[:5] + [der.seq(der.tlv(der.SET, b""))] + c[6:], "name-empty"),
    "empty-issuer": (lambda c: c[:3] + [der.seq()] + c[4:], "name-empty"),
    "non-string-attribute": (lambda c: c[:5] + [der.seq(der.set_of(der.seq(der.oid(x509.COMMON_NAME), der.integer(1))))] + c[6:], "der"),
    "three-element-validity": (lambda c: c[:4] + [der.seq(der.time(NB), der.time(NA), der.time(NA))] + c[5:], "der"),
    "wrong-extensions-tag": (lambda c: c[:7] + [der.tlv(0xA2, der.parse(c[7]).children()[0].raw)], "tbs-shape"),
}


def _with_ext(children: list[bytes], oid: str, value: bytes, critical: bool | None) -> list[bytes]:
    existing = [n.raw for n in der.parse(children[7]).children()[0].children()]
    kept = [e for e in existing if der.parse(e).children()[0].as_oid() != oid]
    return children[:7] + [der.explicit(3, der.seq(*kept, _ext_raw(oid, value, critical)))]


@pytest.mark.parametrize("case", PROFILE_REJECTIONS)
def test_profile_rejections(case: str) -> None:
    edit, reason = PROFILE_REJECTIONS[case]
    fails(Alert.bad_certificate, reason, lambda: x509.parse(resign(leaf(), INTER_KEY, edit)))


def test_builder_and_caller_misuse() -> None:
    from qtls.alerts import CodecUsageError

    with pytest.raises(CodecUsageError):
        leaf(serial=1 << 160)
    with pytest.raises(CodecUsageError):
        verify([leaf(), inter()], [ANCHOR], now=dt.datetime(2026, 11, 13))
    with pytest.raises(CodecUsageError):
        verify([leaf(), inter()], [ANCHOR], backends={})


@pytest.mark.usefixtures("require_liboqs")
def test_pinned_chain_digest() -> None:
    """Determinism across processes and platforms, not just within one run."""
    import hashlib

    digest = hashlib.sha256()
    for leaf_alg, issuer_alg in MATRIX:
        chain = chain_for(leaf_alg, issuer_alg, 2)
        digest.update(b"".join(chain.cert_data) + chain.root_der)
    assert digest.hexdigest() == PINNED_MATRIX_DIGEST


# Measured on macOS arm64; CI (Linux x86-64) must reproduce it byte for byte.
PINNED_MATRIX_DIGEST = "f92fa4bc27ad29391fcb76bf63643a017d2dd566fe39f55785c393218bfec498"


def test_verify_chain_only_raises_alert_errors() -> None:
    """Seeded fuzz: raw mutations, and TBS mutations re-signed so they reach the later checks."""
    import random

    rng = random.Random(5280)
    good = [leaf(), inter()]
    for i in range(1500):
        target = rng.randrange(2)
        cert = bytearray(good[target])
        if rng.random() < 0.5:
            for _ in range(rng.randint(1, 3)):
                cert[rng.randrange(len(cert))] ^= 1 << rng.randrange(8)
            mutated = bytes(cert)
        else:
            tbs, _, _ = der.parse(good[target]).children()
            raw = bytearray(tbs.raw)
            raw[rng.randrange(4, len(raw))] ^= 1 << rng.randrange(8)
            key = INTER_KEY if target == 0 else ROOT_KEY
            alg = der.seq(der.oid(x509.BY_NAME[ALG].oid))
            mutated = der.seq(bytes(raw), alg, der.bit_string(key.sign(bytes(raw), seed=b"")))
        chain = list(good)
        chain[target] = mutated
        try:
            verify(chain, [ANCHOR])
        except AlertError as exc:
            assert exc.reason, i


def test_kem_oid_never_counts_as_a_signature_algorithm_even_if_offered() -> None:
    """Even when the peer's list (wrongly) includes AuthKEM codepoints, a KEM can't sign a certificate."""
    kem_alg = der.seq(der.oid(x509.BY_NAME["ML-KEM-768"].oid))
    cert = resign(leaf(), INTER_KEY, lambda c: c[:2] + [kem_alg] + c[3:])
    tbs, _, sig = der.parse(cert).children()
    with_kems = ALL_CERT_SCHEMES | set(x509.BY_NAME["ML-KEM-768"].codepoints)
    fails(Alert.unsupported_certificate, "algorithm",
          lambda: verify([der.seq(tbs.raw, kem_alg, sig.raw), inter()], [ANCHOR], accepted=with_kems))  # fmt: skip


def test_sent_root_must_match_the_anchor_by_name_and_key() -> None:
    # The anchor's key under another name is not "the root"; it stays in the chain and breaks it.
    renamed = root(subject_cn="other")
    assert x509.parse(renamed).spki_raw == ANCHOR.spki_raw
    fails(Alert.bad_certificate, "issuer-name", lambda: verify([leaf(), inter(), renamed], [ANCHOR]))


def test_malformed_anchors_are_local_errors() -> None:
    from qtls.alerts import CodecUsageError

    off_curve = der.seq(der.seq(der.oid(x509.EC_PUBLIC_KEY), der.oid(x509.PRIME256V1)), der.bit_string(b"\x04" + bytes(64)))
    for bad_spki in (off_curve, b"\x30\x00"):
        with pytest.raises(CodecUsageError):
            x509.TrustAnchor(ANCHOR.name_raw, bad_spki)
    with pytest.raises(CodecUsageError):
        x509.TrustAnchor(der.seq(), ANCHOR.spki_raw)
    assert (ANCHOR.spki_oid, ANCHOR.public_key) == (x509.EC_PUBLIC_KEY, ROOT_KEY.public_key)


@pytest.mark.usefixtures("require_liboqs")
def test_leaf_kind_must_fit_the_authentication_mode() -> None:
    kem_chain = chain_for("ML-KEM-768", "ML-DSA-65")
    fails(Alert.unsupported_certificate, "leaf-kind",
          lambda: verify(kem_chain.cert_data, [kem_chain.anchor], expected_kind="sig"))  # fmt: skip
    assert verify(kem_chain.cert_data, [kem_chain.anchor], expected_kind="kem").kind == "kem"
    fails(Alert.unsupported_certificate, "leaf-kind", lambda: verify([leaf(), inter()], [ANCHOR], expected_kind="kem"))
    assert verify([leaf(), inter()], [ANCHOR], expected_kind="sig").kind == "sig"


def test_issuer_without_key_usage_is_accepted() -> None:
    # RFC 5280 §6.1.4(n): keyCertSign is only required when keyUsage is present (D24 step 5).
    no_ku = inter(key_usage=set())
    assert x509.parse(no_ku).profile.key_usage is None
    assert verify([leaf(), no_ku], [ANCHOR]).alg == ALG


def test_inner_algorithm_with_null_parameters_differs_from_outer() -> None:
    with_null = der.seq(der.oid(x509.BY_NAME[ALG].oid), der.null())
    cert = resign(leaf(), INTER_KEY, lambda c: c[:2] + [with_null] + c[3:])
    fails(Alert.bad_certificate, "alg-mismatch", lambda: x509.parse(cert))


def test_signature_codepoints_are_signature_algorithms_only() -> None:
    kem_points = {cp for a in x509.ALGORITHMS if a.kind == "kem" for cp in a.codepoints}
    assert x509.SIGNATURE_CODEPOINTS and not (x509.SIGNATURE_CODEPOINTS & kem_points)
