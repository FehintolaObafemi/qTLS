"""The vector-extraction scripts fail loudly and parse the formats they claim to."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str):  # noqa: ANN202
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up while the class is built
    spec.loader.exec_module(module)
    return module


def test_trim_acvp_refuses_an_empty_source(tmp_path: Path) -> None:
    trim = _load("trim_acvp")
    with pytest.raises(SystemExit, match="no ACVP input files"):
        trim.main(tmp_path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_extract_rfc8448_joins_wrapped_titles_and_checks_lengths() -> None:
    extract = _load("extract_rfc8448")
    lines = [
        "   {client}  extract secret \"handshake\" (same as server handshake",
        "         secret)",
        "",
        "   {server}  derive secret for handshake \"tls13 derived\":",
        "",
        "      PRK (4 octets):  01 02 03",
        "         04",
        "",
        "      salt:  0 (all zero octets)",
    ]
    events = extract.parse(lines)
    assert events[0]["step"] == 'extract secret "handshake" (same as server handshake secret)'
    assert events[1]["values"] == {"PRK": "01020304", "salt": ""}
    with pytest.raises(ValueError, match="declared 5 octets"):
        extract.parse(["   {server}  x:", "", "      PRK (5 octets):  01 02 03 04"])


MTC_SNIPPET = """\
   C.1.1.  Subtree Hashes . . . . . . . . . . . . . 94
C.1.1.  Subtree Hashes
   (a table-of-contents line above; the body's heading is the last exact match)
C.1.1.  Subtree Hashes
   The final hash value is

   {h1}
   assert h.hexdigest() == '{h1}'
C.1.2.  Subtree Inclusion Proofs
   The final hash value is

   {h2}
   assert h.hexdigest() == '{h2}'
C.1.3.  Subtree Consistency Proofs
   The final hash value is

   {h3}
   assert h.hexdigest() == '{h3}'
C.1.4.  Efficient Covering Subtrees
   The final hash value is

   {h4}
   assert h.hexdigest() == '{h4}'
C.2.  Large Subtree Test Vectors
C.2.1.  Subtree Validity
   *  start is 0 and end is 2^47 + 1
   *  start is 0 and end is 2^48 - 1
   *  start is 0 and end is 2^62 + 1
   *  start is 0 and end is 2^63 - 1
   *  start is 0 and end is 2^63 + 1
   *  start is 0 and end is 2^64 - 1
   The following are not valid subtrees:
   *  start is 2^46 and end is 2^47 + 1
   *  start is 2^46 and end is 2^48 - 1
   *  start is 2^61 and end is 2^62 + 1
   *  start is 2^61 and end is 2^63 - 1
   *  start is 2^62 and end is 2^63 + 1
   *  start is 2^62 and end is 2^64 - 1
C.2.2.  Subtree Inclusion Proofs
C.2.4.  Efficient Covering Subtrees
   Given range [0x5, 0xd), the subtrees are:

   *  [0x4, 0x8)

   *  [0x8, 0xd)
Change log
"""


def test_extract_mtc_vectors_parses_appendix_c() -> None:
    extract = _load("extract_mtc_vectors")
    hashes = {f"h{i}": f"{i}" * 64 for i in range(1, 5)}
    out = extract.appendix_c(MTC_SNIPPET.format(**hashes))
    assert out["accumulated"] == {"C.1.1": "1" * 64, "C.1.2": "2" * 64, "C.1.3": "3" * 64, "C.1.4": "4" * 64}
    assert out["valid_subtrees"][0] == [0, 2**47 + 1] and out["invalid_subtrees"][-1] == [2**62, 2**64 - 1]
    assert out["covering"] == [{"range": [5, 13], "left": [4, 8], "right": [8, 13]}]


@pytest.mark.parametrize(
    ("old", "new", "why"),
    [
        ("   assert h.hexdigest() == '{h2}'", "   assert h.hexdigest() == '{h1}'", "matching the Python listing"),
        ("   *  start is 0 and end is 2^63 + 1\n", "", "six valid"),
        ("   *  [0x8, 0xd)", "   *  [0x8 0xd)", "didn't parse"),
        ("2^47 + 1\n", "2**47+1\n", "can't read"),
    ],
    ids=["digest-mismatch", "dropped-row", "garbled-covering", "garbled-power"],
)
def test_extract_mtc_vectors_fails_loudly(old: str, new: str, why: str) -> None:
    extract = _load("extract_mtc_vectors")
    text = MTC_SNIPPET.replace(old, new, 1).format(**{f"h{i}": f"{i}" * 64 for i in range(1, 5)})
    with pytest.raises(ValueError, match=why):
        extract.appendix_c(text)


TAI_SNIPPET = """\
Appendix B.  Trust Anchor ID Pattern Test Vectors
   The following IDs are contained in the pattern
   81fd5981fd597b8348861580 (32473.{123-456}.{789-}):
""" + "".join(f"   *  0{i} ({i})\n" for i in range(1, 6)) + """\
   The following IDs are not contained in the pattern
   81fd5981fd597b8348861580 (32473.{123-456}.{789-}):
""" + "".join(f"   *  1{i} ({i})\n" for i in range(7)) + """\
   The following IDs are contained in the pattern
   81fd5981fd598280808080808080800182808080808080808003 (32473.{2^64+1 -
   2^64+3}):
""" + "".join(f"   *  2{i} ({i})\n" for i in range(3)) + """\
   The following IDs are not contained in the pattern
   81fd5981fd598280808080808080800182808080808080808003 (32473.{2^64+1 -
   2^64+3}):
""" + "".join(f"   *  3{i} ({i})\n" for i in range(3)) + """\
B.1.  Invalid IDs or Patterns
   The ID 81fd59 (32473) is not contained in the pattern 81fd59.
   The ID 81fd59 (32473) is not contained in the pattern 81fd.
   The ID 81fd59 (32473) is not contained in the pattern
   81fd5981ffff.
   The ID 00 (0) is not contained in the pattern 8042.
Acknowledgements
"""


def test_extract_mtc_vectors_parses_appendix_b() -> None:
    out = _load("extract_mtc_vectors").appendix_b(TAI_SNIPPET)
    assert [g["contained"] for g in out["groups"]] == [True, False, True, False]
    assert [g["pattern_text"] for g in out["groups"]] == ["32473.{123-456}.{789-}"] * 2 + ["32473.{2^64+1-2^64+3}"] * 2
    assert out["groups"][1]["ids"] == [f"1{i}" for i in range(7)]
    assert out["invalid"][2] == {"id": "81fd59", "pattern": "81fd5981ffff"}
    assert len(out["invalid"]) == 4


@pytest.mark.parametrize(
    ("old", "new", "why"),
    [
        ("   *  03 (3)\n", "", "groups of"),
        ("   The ID 00 (0) is not contained in the pattern 8042.\n", "", "four cases"),
        ("Appendix B.  Trust Anchor ID Pattern Test Vectors", "Appendix B.  Something Else", "not found"),
    ],
    ids=["missing-id", "missing-b1-case", "missing-heading"],
)
def test_extract_mtc_vectors_needs_all_of_appendix_b(old: str, new: str, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        _load("extract_mtc_vectors").appendix_b(TAI_SNIPPET.replace(old, new, 1))


def test_extract_mtc_vectors_refuses_other_c2_files(tmp_path: Path) -> None:
    extract = _load("extract_mtc_vectors")
    for name in extract.LARGE:
        (tmp_path / name).write_text("[]")
    with pytest.raises(ValueError, match="not the draft-ietf-plants-merkle-tree-certs-08 file"):
        extract.check_large(tmp_path)


def test_extract_mtc_vectors_writes_nothing_when_parsing_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extract = _load("extract_mtc_vectors")
    monkeypatch.setattr(extract, "MTC_OUT", tmp_path / "mtc")
    monkeypatch.setattr(extract, "TAI_OUT", tmp_path / "tai")
    mtc = tmp_path / "mtc.txt"
    mtc.write_text(MTC_SNIPPET.format(**{f"h{i}": f"{i}" * 64 for i in range(1, 5)}))
    tai = tmp_path / "tai.txt"
    tai.write_text("junk")
    with pytest.raises(ValueError, match="not found"):
        extract.main(mtc, tai, tmp_path)
    assert not (tmp_path / "mtc").exists() and not (tmp_path / "tai").exists()


def test_mtc_demo_reads_landmark_output() -> None:
    demo = _load("mtc_demo")
    out = demo.landmarks("Wrote certificate...\nLandmark 1 at tree size 34:\n"
                         "  Landmark subtree [0, 32) with hash AAAA\n  Landmark subtree [32, 34) with hash BBBB\n"
                         "Landmark 2 at tree size 40:\n  Landmark subtree [32, 40) with hash CCCC\n")  # fmt: skip
    assert out == [
        {"landmark": 1, "tree_size": 34, "subtrees": [{"start": 0, "end": 32, "hash": "AAAA"}, {"start": 32, "end": 34, "hash": "BBBB"}]},
        {"landmark": 2, "tree_size": 40, "subtrees": [{"start": 32, "end": 40, "hash": "CCCC"}]},
    ]


def test_mtc_demo_needs_both_known_answers(tmp_path: Path) -> None:
    demo = _load("mtc_demo")
    go = tmp_path / "demo" / "encode_test.go"
    go.parent.mkdir()
    case = '\n\t\t{\n\t\t\tversion: VersionPlants07,\n\t\t\texpectedTBSHex: "30",\n\t\t\texpectedLogEntryHex: "00" + "01",\n\t\t},'
    go.write_text("func TestMarshalTBSCertificate(t *testing.T) {" + case + case + "\n}\nfunc TestCreateCACertificate(")
    assert demo.wg_kats(tmp_path) == [{"tbs": "30", "log_entry": "0001"}] * 2
    go.write_text("func TestMarshalTBSCertificate(t *testing.T) {" + case + "\n}\nfunc TestCreateCACertificate(")
    with pytest.raises(RuntimeError, match="expected 2"):
        demo.wg_kats(tmp_path)


def _stub(tmp_path: Path, stdout: str, code: int) -> Path:
    stub = tmp_path / "demo"
    stub.write_text(f"#!/bin/sh\ncat <<'EOF'\n{stdout}\nEOF\nexit {code}\n")
    stub.chmod(0o755)
    return stub


def test_mtc_demo_verdict_is_strict(tmp_path: Path) -> None:
    """Only a verdict line or Go failing to parse *this* certificate is a verdict; any other demo
    failure (a bad policy, a bad CA certificate) stops the run instead of being pinned as the oracle."""
    demo = _load("mtc_demo")
    cert, ca = tmp_path / "cert_1_0.pem", tmp_path / "ca.pem"
    assert demo.verdict(_stub(tmp_path, f"{cert}: OK", 0), ca, None, cert) == "OK"
    unparsable = f'Error verifying certificates: failed to parse certificate from "{cert}": x509: bad thing'
    assert demo.verdict(_stub(tmp_path, unparsable, 1), ca, None, cert) == "unparsable: x509: bad thing"
    for text in ("Error verifying certificates: policy.txt:1: invalid base64 public key", "", f"{cert}: OK\n{cert}: OK"):
        with pytest.raises(RuntimeError, match="expected one verdict"):
            demo.verdict(_stub(tmp_path, text, 1), ca, None, cert)


INSTALL_GO = ROOT / "scripts" / "install_go.sh"


def _install_go(tmp_path: Path, tarball: Path, platform: str = "linux-amd64") -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "QTLS_GO_ROOT": str(tmp_path / "go"), "QTLS_GO_TARBALL": str(tarball), "QTLS_GO_PLATFORM": platform}
    return subprocess.run(["bash", str(INSTALL_GO)], capture_output=True, text=True, env=env)


def test_install_go_refuses_a_tarball_with_the_wrong_hash(tmp_path: Path) -> None:
    """specs.md D34: the toolchain that builds the oracle is the pinned one, byte for byte."""
    junk = tmp_path / "go.tgz"
    junk.write_bytes(b"not the go1.27.4 tarball")
    proc = _install_go(tmp_path, junk)
    assert proc.returncode != 0 and "has sha256" in proc.stderr and "expected 7226736c" in proc.stderr
    assert not (tmp_path / "go").exists()
    proc = _install_go(tmp_path, junk, "windows-386")
    assert proc.returncode != 0 and "no pinned go1.27.4 tarball for windows-386" in proc.stderr


def test_install_go_pins_what_mtc_demo_records() -> None:
    demo = _load("mtc_demo")
    script = INSTALL_GO.read_text()
    assert f'GO_VERSION="{demo.GO_VERSION}"' in script
    table = dict(re.findall(r'^  ([a-z0-9-]+)\) GO_SHA256="([0-9a-f]{64})" ;;$', script, re.M))
    assert table == demo.GO_TARBALL_SHA256 and set(table) == {"darwin-arm64", "linux-amd64"}
    assert "export GOTOOLCHAIN=local" in script


def _git_repo(path: Path) -> None:
    path.mkdir()
    for args in (["init", "-q"], ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty", "-m", "x"]):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)


def test_mtc_demo_prepare_refuses_the_wrong_go_or_commit(tmp_path: Path) -> None:
    demo = _load("mtc_demo")
    for version, why in (("go1.26.0", "not the pinned go1.27.4"), (demo.GO_VERSION, "not draft-ietf-plants")):
        go = tmp_path / f"go-{version}"
        go.write_text(f"#!/bin/sh\necho 'go version {version} linux/amd64'\n")
        go.chmod(0o755)
        src = tmp_path / f"src-{version}"
        _git_repo(src)
        with pytest.raises(SystemExit, match=why):
            demo.prepare(go, src)


def test_mtc_demo_build_only_stops_after_building(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    demo = _load("mtc_demo")
    built = []
    monkeypatch.setattr(demo, "prepare", lambda go, src: built.append((go, src)) or tmp_path / "demo")
    monkeypatch.setattr(demo, "corpus", lambda *a, **k: pytest.fail("--build-only vendored a corpus"))
    demo.main(["--build-only", "--go", str(tmp_path / "go")])
    assert built == [(tmp_path / "go", None)]


VERIFY_OUTPUT = """\
a.pem: OK
- Cosigned by:
    32473.9
    32473.9.1
- Cosigner groups satisfied:
    inner
    nested

b.pem: trusted subtree hash mismatch: expected 00, got 01

c.pem: OK
- Subtree was trusted

d.pem: cosigner policy not satisfied
- Signature verification errors:
    invalid signature from cosigner 32473.9.2: bad
- Cosigned by:
- Cosigner groups satisfied:
- Unsatisfied requirements:
    nested

Error verifying certificates: some certificates failed verification
"""


def test_mtc_demo_reads_verify_blocks() -> None:
    demo = _load("mtc_demo")
    paths = [Path(f"{n}.pem") for n in "abcd"]
    got = demo.parse_verify_output(VERIFY_OUTPUT, paths)
    assert got[paths[0]] == demo.GoResult("OK", ("32473.9", "32473.9.1"), ("inner", "nested"), False)
    assert got[paths[1]] == demo.GoResult("trusted subtree hash mismatch: expected 00, got 01")
    assert got[paths[2]] == demo.GoResult("OK", None, None, True)
    assert got[paths[3]] == demo.GoResult("cosigner policy not satisfied", (), (), False)
    assert demo.parse_verify_output(VERIFY_OUTPUT, paths[:1]) == {paths[0]: got[paths[0]]}
    with pytest.raises(RuntimeError, match="two verdicts"):
        demo.parse_verify_output("a.pem: OK\n\na.pem: OK\n", paths[:1])
    for r in got.values():
        assert demo.GoResult.from_json(json.loads(json.dumps(r.as_json()))) == r


def test_mtc_demo_replays_a_saved_differential(tmp_path: Path) -> None:
    """--replay: qTLS's side recomputed against the Go results a failed live run saved."""
    demo = _load("mtc_demo")
    vectors = ROOT / "tests" / "vectors" / "mtc-demo" / "qtls"
    details = json.loads((vectors / "details.json").read_text())
    names = sorted(details)[:12]
    work = tmp_path / "saved"
    (work / "certs").mkdir(parents=True)
    shutil.copy(vectors / "ca_cert.der", work / "ca_cert.der")
    for name in names:
        shutil.copy(vectors / "certs" / f"{name}.der", work / "certs" / f"{name}.der")
    for policy in ("ca-only", "nested"):
        shutil.copy(vectors / f"policy-{policy}.txt", work / f"policy-{policy}.txt")
    go = {n: {p: details[n][p] for p in ("ca-only", "nested")} for n in names}
    (work / "go.json").write_text(json.dumps(go))
    assert demo.replay(work) == []
    with pytest.raises(SystemExit) as info:
        demo.main(["--replay", str(work)])
    assert info.value.code == 0
    first = names[0]
    go[first]["nested"]["verdict"] = "OK" if go[first]["nested"]["verdict"] != "OK" else "cosigner policy not satisfied"
    (work / "go.json").write_text(json.dumps(go))
    assert [p.split(":")[0] for p in demo.replay(work)] == [f"{first} under nested"]
    with pytest.raises(SystemExit) as info:
        demo.main(["--replay", str(work)])
    assert info.value.code == 1


QTLS_VECTORS = ROOT / "tests" / "vectors" / "mtc-demo" / "qtls"


def _store(demo, policy: str):  # noqa: ANN001, ANN202
    return demo.demo_store((QTLS_VECTORS / "ca_cert.der").read_bytes(), (QTLS_VECTORS / f"policy-{policy}.txt").read_text())


def _cert(name: str) -> bytes:
    return (QTLS_VECTORS / "certs" / f"{name}.der").read_bytes()


@pytest.mark.usefixtures("require_liboqs")
def test_compare_one_catches_every_kind_of_disagreement() -> None:
    """The differential's comparison is more than accept/reject (D34): each crafted Go result below
    differs from qTLS in one respect and must be reported; the genuine ones must not."""
    demo = _load("mtc_demo")
    G = demo.GoResult
    quorum, ca_and_1, landmarks = _store(demo, "quorum-2-of-3"), _store(demo, "ca-and-1"), _store(demo, "landmarks")
    accepted = _cert("cert_92_11")  # CA, C1, C2: accepted by the 2-of-3 quorum
    ok = G("OK", ("32473.9", "32473.9.1", "32473.9.2"), ("two-of-three", "ca-and-two-of-three"), False)
    agree = [
        (accepted, quorum, ok),
        (accepted, quorum, G("OK", ok.cosigned_by, tuple(reversed(ok.groups)), False)),  # order doesn't matter
        (accepted, ca_and_1, G("OK", ("32473.9", "32473.9.1"), (), False)),
        (accepted, ca_and_1, G("OK", ("32473.9", "32473.9.1", "32473.9.2"), (), False)),  # outside the policy: ignored
        (_cert("cert_13_1"), landmarks, G("OK", None, None, True)),  # landmark-relative, trusted
        (_cert("cert_5_0"), quorum, G("cosigner policy not satisfied", ("32473.9", "32473.9.1"), (), False)),
        (_cert("cert_5_5"), quorum, G("signature was not a whole number of bytes")),
    ]
    for cert, store, go in agree:
        assert demo.compare_one(cert, store, go) is None, go
    disagree = {
        "reject-vs-accept": (accepted, quorum, G("cosigner policy not satisfied", ok.cosigned_by, ok.groups, False)),
        "other-reject-class": (_cert("cert_5_5"), quorum, G("cosigner policy not satisfied", (), (), False)),
        "accept-vs-reject": (_cert("cert_5_0"), quorum, G("OK", ("32473.9", "32473.9.1"), (), False)),
        "group-missing": (accepted, quorum, G("OK", ok.cosigned_by, ("ca-and-two-of-three",), False)),
        "group-extra": (_cert("cert_5_0"), quorum, G("cosigner policy not satisfied", ("32473.9", "32473.9.1"), ("two-of-three",), False)),
        "groups-none": (accepted, quorum, G("OK", ok.cosigned_by, None, False)),
        "cosigner-missing": (accepted, quorum, G("OK", ("32473.9", "32473.9.1", "32473.9.2")[:2] + ("32473.9.3",),
                                                 ("two-of-three", "ca-and-two-of-three"), False)),  # fmt: skip
        "cosigner-dropped": (accepted, ca_and_1, G("OK", ("32473.9",), (), False)),
        "cosigner-added": (_cert("cert_92_9"), quorum, G("cosigner policy not satisfied", ("32473.9", "32473.9.1", "32473.9.3"),
                                                         (), False)),  # fmt: skip
        "trusted-vs-cosigned": (accepted, quorum, G("OK", None, None, True)),
        "not-trusted": (_cert("cert_13_1"), landmarks, G("OK", None, None, False)),
        "section-on-a-trusted-accept": (_cert("cert_13_1"), landmarks, G("OK", (), (), False)),
    }
    for name, (cert, store, go) in disagree.items():
        assert demo.compare_one(cert, store, go) is not None, name


def test_go_verdict_classes_known_answers() -> None:
    """Each Go verdict the differential knows, and the qTLS reasons it stands for (D34): exact, so a
    class can't be widened unnoticed."""
    demo = _load("mtc_demo")
    table = {
        "OK": {"OK"},
        "signature was not a whole number of bytes": {"mtc-proof"},
        "malformed MTCProof": {"mtc-proof"},
        "malformed signature in MTCProof": {"mtc-proof"},
        "cosigners not in canonical order or duplicate: 32473.9.1 and 32473.9": {"mtc-proof"},
        "signature algorithm was not mtcProof": {"mtc-alg"},
        "unparsable: x509: inner and outer signature algorithm identifiers don't match": {"mtc-alg"},
        "unparsable: x509: malformed signature": {"mtc-proof"},
        "unparsable: x509: negative serial number": {"mtc-serial"},
        "malformed TBSCertificate": {"mtc-alg", "mtc-serial"},
        "certificate serial 5 is revoked (range [0, 281474976710655])": {"mtc-revoked"},
        "invalid log number 0 in serial": {"mtc-log-number"},
        "inclusion proof evaluation failed: invalid subtree": {"mtc-not-subtree"},
        "inclusion proof evaluation failed: index not in subtree": {"mtc-index-range"},
        "inclusion proof evaluation failed: truncated hash in proof": {"mtc-ragged"},
        "inclusion proof evaluation failed: proof too long": {"mtc-too-long"},
        "inclusion proof evaluation failed: proof too short": {"mtc-too-short"},
        "trusted subtree hash mismatch: expected 00, got 01": {"mtc-trusted-subtree"},
        "cosigner policy not satisfied": {"mtc-cosigners"},
        "issuer 32473.8 not a known MTC CA": {"mtc-unknown-ca"},
        "issuer not an MTC CA: malformed X.509 name": {"mtc-unknown-ca"},
    }
    assert {v: set(demo.go_class(v)) for v in table} == table
    assert all(any(pattern.match(v) for v in table) for pattern, _ in demo.GO_CLASSES)  # every class has a known answer
