"""The live differential against the MTC WG's Go demo, both ways (specs.md D34, D35, D36).

``go``-marked: they need ``QTLS_GO_DEMO``, the demo built from the pinned tag
and commit with the pinned Go (scripts/install_go.sh, scripts/mtc_demo.py
--build-only). Locally they skip without it; CI sets it, and its
``QTLS_NO_SKIPS``/``QTLS_MIN_GO_TESTS`` gate fails the run if they didn't run.

* qTLS → Go: certificates and a CA certificate issued by ``mtc.IssuanceLog``
  from fixture keys, verified by Go under qTLS policies rendered as the demo's
  text. Go has never seen them, so this is the first check of qTLS issuance by
  an independent verifier.
* Go → qTLS: a fresh ``demo generate`` (fresh signatures every run, an ML-DSA
  and an ECDSA CA), verified by qTLS from Go's CA certificate, and Go's fresh
  checkpoint driving a §7.4 derivation.

Agreement is :func:`mtc_demo.compare_one`'s: the same accept/reject, a reason in
Go's verdict class, the same groups met and cosigners counted. A disagreement
keeps the working directory under .mtc-demo/failed/ (CI uploads it);
``python scripts/mtc_demo.py --replay <dir>`` re-runs the comparison.
"""

from __future__ import annotations

import base64
import datetime as dt
import itertools
import json
import os
import re
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from qtls import der, mtc, x509
from qtls.alerts import CodecUsageError
from qtls.trust_anchor_ids import TrustAnchorID
from test_mtc import DEMO, NOT_AFTER, NOT_BEFORE, NOW, Issued, proof_of, rebuild_tbs, resign

pytestmark = pytest.mark.go

ROOT = Path(__file__).resolve().parent.parent
CA, C1, C2, C3 = (TrustAnchorID.from_ascii(x) for x in ("32473.9", "32473.9.1", "32473.9.2", "32473.9.3"))
MIN, MAX = 3 << 48, (4 << 48) | (2**48 - 1)  # logs 3 and 4: a log-4 serial is in range and fails on its cosignatures
REVOKED = (40, 41)  # indices of the live qTLS log revoked by the "revoked" policy, inclusive


def _differential(go_demo: Path, tmp_path: Path, name: str, ca_der: bytes, policies: dict[str, mtc.CAPolicy],
                  keys: dict[TrustAnchorID, mtc.CosignerKey], certs: dict[str, bytes]) -> None:  # fmt: skip
    """Render each qTLS policy as the demo's text, check that it reads back as the same objects (so the
    agreement is about qTLS's real configuration), then run the differential. A disagreement, or the
    comparison itself failing, keeps the working directory."""
    ca = mtc.parse_ca_certificate(ca_der)
    texts = {}
    for pname, policy in policies.items():
        texts[pname] = DEMO.demo_policy(mtc.MTCTrustStore(keys, (policy,)), policy.ca_id)
        _, back = DEMO.parse_demo_policy(texts[pname], ca)
        assert (back.policy, back.revoked) == (policy.policy, policy.revoked), pname
        assert [(t.log_number, t.start, t.end, t.subtree_hash) for t in back.trusted_subtrees] == [
            (t.log_number, t.start, t.end, t.subtree_hash) for t in policy.trusted_subtrees], pname
    work = tmp_path / name
    try:
        problems = DEMO.differential(go_demo, work, ca_der, texts, certs)
    except Exception:
        DEMO.keep_failed(work, name)
        raise
    if problems:
        kept = DEMO.keep_failed(work, name)
        pytest.fail(f"{len(problems)} disagreement(s) with Go, kept in {kept}:\n" + "\n".join(problems[:40]))


def test_a_failing_comparison_keeps_its_working_directory(go_demo: Path, tmp_path: Path, qtls_issued: QtlsIssued,
                                                          monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    """If the comparison raises (a Go verdict nobody classified), the run is kept and --replay reproduces it."""
    def unknown(verdict: str) -> frozenset[str]:
        raise ValueError(f"no single class for Go's verdict {verdict!r}")

    monkeypatch.setattr(DEMO, "FAILED", tmp_path / "failed")
    monkeypatch.setattr(DEMO, "go_class", unknown)
    policies = {"ca-only": qtls_issued.policies()["ca-only"]}
    with pytest.raises(ValueError, match="no single class"):
        _differential(go_demo, tmp_path, "kept", qtls_issued.ca_der, policies, qtls_issued.keys, {"one": qtls_issued.certs["subset-1-ca"]})
    kept = tmp_path / "failed" / "kept"
    assert (kept / "go.json").is_file() and (kept / "certs" / "one.der").is_file()
    with pytest.raises(ValueError, match="no single class"):
        DEMO.main(["--replay", str(kept)])


def test_the_go_demo_is_the_pinned_build(go_demo: Path) -> None:
    """Provenance: the binary under test is the pinned tag's commit, unmodified, built by the pinned Go."""
    go = Path(os.environ.get("QTLS_GO", ROOT / ".go" / "bin" / "go"))
    info = subprocess.run([go, "version", "-m", go_demo], capture_output=True, text=True, check=True,
                          env={**os.environ, "GOTOOLCHAIN": "local"}).stdout  # fmt: skip
    assert info.splitlines()[0].endswith(f": {DEMO.GO_VERSION}")
    assert f"vcs.revision={DEMO.TAG_COMMIT}" in info and "vcs.modified=false" in info


# --------------------------------------------------------------------------- #
# qTLS → Go
# --------------------------------------------------------------------------- #


class QtlsIssued:
    """A qTLS log for CA 32473.9 (log 3), certificates of every shape §7.2 distinguishes, and qTLS
    policies rendered as the demo's text."""

    def __init__(self, issued: Issued) -> None:
        self.cs = {c: mtc.fixture_cosigner(c, alg, role) for c, (alg, role) in
                   ((CA, ("ML-DSA-44", "mtc-ca")), (C1, ("ML-DSA-65", "mtc-cosigner-1")),
                    (C2, ("ECDSA-P256-SHA256", "mtc-cosigner-2")), (C3, ("ML-DSA-44", "mtc-cosigner-3")))}  # fmt: skip
        log = self.log = mtc.IssuanceLog(CA, 3)
        self.ca_der = log.ca_certificate(self.cs[CA], min_serial=MIN, max_serial=MAX, not_before=NOT_BEFORE, not_after=NOT_AFTER)
        self.ca = mtc.parse_ca_certificate(self.ca_der)
        args = Issued.leaf_args(issued.leaf44)
        log.append_null(3)
        subsets = [frozenset(s) for n in range(5) for s in itertools.combinations((CA, C1, C2, C3), n)]
        index = {s: log.add_certificate(**args) for s in subsets}
        log.append_null(REVOKED[0] - 1 - log.size)
        edges = [log.add_certificate(**args) for _ in range(REVOKED[0] - 1, REVOKED[1] + 2)]  # 39..42 around 40..41
        log.checkpoint()
        landmark = log.add_landmark()
        log.append_null(5)
        late = log.add_certificate(**args)
        log.append_null(7)
        log.checkpoint()
        log.add_landmark()
        mask = lambda s: "-".join(sorted("ca" if c == CA else c.ascii.rsplit(".", 1)[-1] for c in s)) or "none"  # noqa: E731
        self.certs = {f"subset-{mask(s)}": log.standalone(i, [self.cs[c] for c in s]) for s, i in index.items()}
        self.certs |= {f"edge-{i}": log.standalone(i, [self.cs[CA]]) for i in edges}
        self.certs |= {"landmark-1": log.landmark_relative(index[frozenset()]), "landmark-2": log.landmark_relative(late),
                       "late-standalone": log.standalone(late, [self.cs[CA], self.cs[C1]])}  # fmt: skip
        base = self.certs["subset-1-ca"]
        p = proof_of(base)
        self.certs |= {
            "log-4": resign(issued, base, tbs=rebuild_tbs(base, serial=(4 << 48) | (index[frozenset({CA, C1})]))),
            "log-0": resign(issued, base, tbs=rebuild_tbs(base, serial=index[frozenset({CA, C1})])),
            "log-5": resign(issued, base, tbs=rebuild_tbs(base, serial=(5 << 48) | 3)),
            "flipped-signature": resign(issued, base, proof=replace(p, signatures=tuple(
                replace(s, signature=s.signature[:-1] + bytes([s.signature[-1] ^ 1])) for s in p.signatures))),
            "flipped-proof-hash": resign(issued, base, proof=replace(p, inclusion_proof=bytes([p.inclusion_proof[0] ^ 1]) + p.inclusion_proof[1:])),
            "not-subtree": resign(issued, base, proof=replace(p, start=p.start + 1)),
            "index-outside": resign(issued, base, tbs=rebuild_tbs(base, serial=(3 << 48) | p.end)),
            "ragged": resign(issued, base, proof=replace(p, inclusion_proof=p.inclusion_proof + b"\x00")),
            "too-long": resign(issued, base, proof=replace(p, inclusion_proof=p.inclusion_proof + bytes(32))),
            "too-short": resign(issued, base, proof=replace(p, inclusion_proof=p.inclusion_proof[:-32])),
            "truncated-proof": resign(issued, base, value=b"\x00" + p.encode()[:-1]),
            "unused-bit": resign(issued, base, value=b"\x01" + p.encode()),
            "other-ca": resign(issued, base, tbs=rebuild_tbs(base, issuer=mtc.trust_anchor_name(TrustAnchorID.from_ascii("32473.8")))),
            "grease-and-unknown": resign(issued, base, proof=replace(p, signatures=tuple(sorted(
                (*p.signatures, mtc.Cosignature(b"\x01" * 200, b"g"), mtc.Cosignature(CA.child(7).raw, b"x")),
                key=lambda c: (len(c.cosigner_id), c.cosigner_id))))),
        }  # fmt: skip
        self.keys = {c: k.public for c, k in self.cs.items()}
        self.landmark = landmark

    def policies(self) -> dict[str, mtc.CAPolicy]:
        ca = self.ca
        rev = (mtc.RevokedRange((3 << 48) | REVOKED[0], ((3 << 48) | REVOKED[1]) + 1),)
        store = mtc.MTCTrustStore(self.keys, (mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({CA}))),))
        doc = mtc.decode_landmarks(mtc.encode_landmarks(self.log.landmark_sequence(), NOW), NOW)
        update = mtc.LogLandmarks(3, doc, self.log.reference_checkpoint([self.cs[CA]], 1_800_000_000), self.log.landmark_proofs(self.log.size))
        derived = mtc.derive_landmarks(store, CA, [update], max_active_landmarks=1, now=NOW)  # the newest landmark is over the bound
        assert [x.reason for x in derived.discarded] == ["over-bound"]
        pols = {
            "ca-only": mtc.RequireAll(frozenset({CA})),
            "ca-and-1": mtc.RequireAll(frozenset({CA, C1})),
            "quorum-2-of-3": mtc.Quorum("ca-and-two-of-three", 2, (CA, mtc.Quorum("two-of-three", 2, (C1, C2, C3)))),
            "quorum-1-of-3": mtc.Quorum("ca-and-one-of-three", 2, (CA, mtc.Quorum("one-of-three", 1, (C1, C2, C3)))),
            "quorum-3-of-4": mtc.Quorum("three-of-four", 3, (CA, C1, C2, C3)),
            "nested": mtc.Quorum("nested", 2, (CA, mtc.Quorum("inner", 1, (C1, mtc.Quorum("deep", 2, (C2, C3)))))),
        }
        out = {name: mtc.CAPolicy.from_ca_certificate(ca, p) for name, p in pols.items()}
        out["revoked"] = mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({CA})), (), rev)
        out["landmarks"] = mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({CA})), self.log.trusted_subtrees())
        out["landmarks-derived"] = derived.ca
        out["wrong-subtree"] = mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({CA})), tuple(
            replace(t, subtree_hash=bytes(32)) for t in self.log.trusted_subtrees()))
        return out


@pytest.fixture(scope="module")
def qtls_issued(require_liboqs: None) -> QtlsIssued:
    return QtlsIssued(Issued())


def test_go_verifies_qtls_issued_certificates(go_demo: Path, tmp_path: Path, qtls_issued: QtlsIssued) -> None:
    """Every certificate × policy: Go's verdict equals qTLS's, for a reason in the same class; Go's
    cosigners and groups equal qTLS's (D34). Covers every cosigner subset, landmark-relative and
    derived subtrees, revocation edges, wrong logs, tampered proofs and signatures."""
    _differential(go_demo, tmp_path, "qtls-to-go", qtls_issued.ca_der, qtls_issued.policies(), qtls_issued.keys, qtls_issued.certs)
    go = json.loads((tmp_path / "qtls-to-go" / "go.json").read_text())
    verdicts = {(n, p): r["verdict"] for n, by in go.items() for p, r in by.items()}
    assert verdicts[("subset-1-2-ca", "quorum-2-of-3")] == "OK"  # exactly k
    assert verdicts[("subset-1-ca", "quorum-2-of-3")] == "cosigner policy not satisfied"  # k - 1
    assert verdicts[("subset-2-3-ca", "nested")] == "OK"  # only through the nested group
    assert [verdicts[(f"edge-{i}", "revoked")] == "OK" for i in range(REVOKED[0] - 1, REVOKED[1] + 2)] == [True, False, False, True]
    assert verdicts[("landmark-1", "landmarks-derived")] == "OK" and verdicts[("landmark-2", "landmarks-derived")] != "OK"
    assert {r["verdict"] for by in go.values() for r in by.values()} >= {"OK", "cosigner policy not satisfied"}
    assert sum(DEMO.go_class(v) == {"mtc-revoked"} for v in verdicts.values()) > 0


def test_go_reads_qtls_ca_certificate_ranges_as_qtls_does(go_demo: Path, tmp_path: Path, qtls_issued: QtlsIssued) -> None:
    """Go and qTLS derive the same revoked ranges from qTLS's CA certificate: Go names the inclusive
    range it applied to the serials just outside [minSerial, maxSerial]."""
    certs = {"below": resign_serial(qtls_issued, MIN - 1), "above": resign_serial(qtls_issued, MAX + 1)}
    work = tmp_path / "ranges"
    assert DEMO.differential(go_demo, work, qtls_issued.ca_der, {"ca-only": ""}, certs) == []
    go = json.loads((work / "go.json").read_text())
    ranges = [tuple(map(int, re.search(r"range \[(\d+), (\d+)\]", go[n]["ca-only"]["verdict"]).groups())) for n in ("below", "above")]  # type: ignore[union-attr]
    assert [(lo, hi + 1) for lo, hi in ranges] == [(r.lo, r.hi) for r in qtls_issued.ca.revoked()]


def resign_serial(q: QtlsIssued, serial: int) -> bytes:
    base = q.certs["subset-1-ca"]
    return der.seq(rebuild_tbs(base, serial=serial), *(n.raw for n in der.parse(base).children()[1:]))


def test_both_decode_the_proof_before_checking_revocation(go_demo: Path, tmp_path: Path, qtls_issued: QtlsIssued) -> None:
    """The plan expected a divergence here; there is none. Go parses the MTCProof before its revocation
    check, and so does qTLS (§7.2 step 2 before step 4; D33): a revoked serial with a malformed proof
    is a malformed proof to both, and a revoked serial with a well-formed but wrong proof is revoked."""
    base = qtls_issued.certs["truncated-proof"]
    malformed = der.seq(rebuild_tbs(base, serial=MIN - 1), *(n.raw for n in der.parse(base).children()[1:]))
    wrong = resign_serial(qtls_issued, MIN - 1)  # the proof is for another serial: inclusion would fail
    work = tmp_path / "order"
    certs = {"revoked-and-malformed": malformed, "revoked-and-wrong-proof": wrong}
    assert DEMO.differential(go_demo, work, qtls_issued.ca_der, {"ca-only": ""}, certs) == []
    go = json.loads((work / "go.json").read_text())
    assert go["revoked-and-malformed"]["ca-only"]["verdict"] == "malformed MTCProof"
    assert DEMO.go_class(go["revoked-and-wrong-proof"]["ca-only"]["verdict"]) == {"mtc-revoked"}


# --------------------------------------------------------------------------- #
# Go → qTLS
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module", params=["ML-DSA-44", "ECDSA-P256-SHA256"], ids=["ml-dsa-ca", "ecdsa-ca"])
def generated(request: pytest.FixtureRequest, go_demo: Path, tmp_path_factory: pytest.TempPathFactory, require_liboqs: None) -> dict:
    """A fresh `demo generate` on the qtls config (and its ECDSA-CA variant): fresh signatures every run."""
    tmp = tmp_path_factory.mktemp(f"gen-{request.param}")
    config = tmp / "config.json"
    config.write_text(json.dumps(DEMO.qtls_config(request.param)))
    _, marks = DEMO.generate(go_demo, config, tmp / "out")
    certs = {p.stem: DEMO.pem_der(p) for p in (tmp / "out").glob("cert_*.pem")}
    return {"alg": request.param, "out": tmp / "out", "marks": marks, "certs": certs,
            "ca_der": DEMO.pem_der(tmp / "out" / "ca_cert.pem"), "tmp": tmp}  # fmt: skip


def test_qtls_verifies_a_fresh_go_corpus(go_demo: Path, generated: dict) -> None:
    """Go → qTLS: the store comes from Go's CA certificate (parse_ca_certificate), the policies are
    the vendored set (quorums, nested, revoked, landmarks, landmarks-derived), the signatures are new."""
    ca = mtc.parse_ca_certificate(generated["ca_der"])
    assert ca.key.alg == generated["alg"] and (ca.ca_id, ca.min_serial, ca.max_serial) == (CA, 3 << 48, (3 << 48) | (2**48 - 1))
    derived = _derive_from(generated, ca)
    keys = DEMO.cosigner_keys(DEMO.qtls_cosigners(generated["alg"]))
    _differential(go_demo, generated["tmp"], f"go-to-qtls-{generated['alg']}", generated["ca_der"],
                  DEMO.qtls_policies(ca, derived.ca), keys, generated["certs"])  # fmt: skip


def _derive_from(generated: dict, ca: mtc.CACertificate) -> mtc.DerivedLandmarks:
    store = mtc.MTCTrustStore({}, (mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({CA}))),))
    keys = {**DEMO.cosigner_keys(DEMO.qtls_cosigners(generated["alg"])), **store.cosigners}
    ref = DEMO.parse_checkpoint((generated["out"] / "checkpoint").read_text(), mtc.log_id(CA, 3), keys)
    tree = DEMO.leaf_tree(DEMO.tile_leaf_hashes(generated["out"] / "tile", ref.size))
    return DEMO.derived_ca(store, CA, 3, ref, tree, generated["marks"])


def test_a_fresh_go_checkpoint_drives_the_derivation(generated: dict) -> None:
    """Go's new timestamped cosignatures verify (each key ID by the demo's rule), every configured
    cosigner vouches for the checkpoint, and the derived subtrees are the ones Go printed."""
    ca = mtc.parse_ca_certificate(generated["ca_der"])
    keys = DEMO.cosigner_keys(DEMO.qtls_cosigners(generated["alg"]))
    policy = mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset(keys)))
    store = mtc.MTCTrustStore({c: k for c, k in keys.items() if c != CA}, (policy,))
    ref = DEMO.parse_checkpoint((generated["out"] / "checkpoint").read_text(), mtc.log_id(CA, 3), keys)
    assert mtc.checkpoint_cosigners(store, policy, 3, ref) == {c.raw for c in keys}
    stale = replace(ref, cosignatures=tuple(replace(s, timestamp=s.timestamp - 1) for s in ref.cosignatures))
    assert mtc.checkpoint_cosigners(store, policy, 3, stale) == frozenset()
    d = _derive_from(generated, ca)
    assert d.discarded == ()
    printed = {(s["start"], s["end"], base64.b64decode(s["hash"]), m["landmark"])
               for m in generated["marks"] for s in m["subtrees"] if s["start"] < s["end"]}  # fmt: skip
    assert {(t.start, t.end, t.subtree_hash, t.landmark) for t in d.ca.trusted_subtrees} == printed


# --------------------------------------------------------------------------- #
# The CA certificate rules Go enforces, on Go-built certificates
# --------------------------------------------------------------------------- #

ALG = lambda oid, *params: der.seq(der.oid(oid), *params)  # noqa: E731
CA_KNOBS = {  # name: (OverrideMTCCAExtensionOID, OverrideMTCCAExtensionValue, Go accepts)
    "sigalg-spki-mismatch": (None, der.seq(ALG(x509.BY_NAME["ML-DSA-65"].oid), der.integer(3 << 48), der.integer(4 << 48)), False),
    "sigalg-null-params": (None, der.seq(ALG(x509.BY_NAME["ML-DSA-44"].oid, der.null()), der.integer(3 << 48), der.integer(4 << 48)), False),
    "sigalg-ed25519-for-an-ml-dsa-key": (None, der.seq(ALG("1.3.101.112"), der.integer(3 << 48), der.integer(4 << 48)), False),
    "extra-field": (None, der.seq(ALG(x509.BY_NAME["ML-DSA-44"].oid), der.integer(3 << 48), der.integer(4 << 48), der.integer(0)), False),
    "wrong-oid": ("1.3.6.1.5.5.7.1.39", None, False),
    # Go accepts these; qTLS refuses them (D35): §5.5's ASN.1 range, and an empty serial range.
    "min-below-2^48": (None, der.seq(ALG(x509.BY_NAME["ML-DSA-44"].oid), der.integer(5), der.integer(4 << 48)), True),
    "min-above-max": (None, der.seq(ALG(x509.BY_NAME["ML-DSA-44"].oid), der.integer(4 << 48), der.integer(3 << 48)), True),
}


@pytest.mark.parametrize("knob", sorted(CA_KNOBS))
def test_ca_certificate_mutants_built_by_go(go_demo: Path, tmp_path: Path, knob: str, require_liboqs: None) -> None:
    oid, value, go_accepts = CA_KNOBS[knob]
    config = DEMO.qtls_config()
    config["Entries"] = [{**config["Entries"][1], "Checkpoints": ["standalone", "landmark"],
                          "Certificates": [{"Checkpoint": "standalone", "Cosigners": [CA.ascii]}]}]  # fmt: skip
    if oid is not None:
        config["CACert"]["OverrideMTCCAExtensionOID"] = oid
    if value is not None:
        config["CACert"]["OverrideMTCCAExtensionValue"] = base64.b64encode(value).decode()
    (tmp_path / "config.json").write_text(json.dumps(config))
    DEMO.generate(go_demo, tmp_path / "config.json", tmp_path / "out")
    ca_der = DEMO.pem_der(tmp_path / "out" / "ca_cert.pem")
    proc = DEMO.run(go_demo, "verify", "-version", DEMO.DRAFT_VERSION, "-ca-cert", tmp_path / "out" / "ca_cert.pem",
                    tmp_path / "out" / "cert_0_0.pem")  # fmt: skip
    assert ("failed to add CA certificate" not in proc.stdout + proc.stderr) is go_accepts, proc.stdout + proc.stderr
    with pytest.raises(CodecUsageError):
        mtc.parse_ca_certificate(ca_der)
