"""The vector-extraction scripts fail loudly and parse the formats they claim to."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str):  # noqa: ANN202
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
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
