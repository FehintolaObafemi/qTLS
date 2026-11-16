#!/usr/bin/env python3
"""Vendor the MTC -08 and trust-anchor-ids -07 test vectors (docs/PLAN.md Phase 3a).

Usage:
    python scripts/extract_mtc_vectors.py <draft-ietf-plants-merkle-tree-certs-08.txt> \\
        <draft-ietf-tls-trust-anchor-ids-07.txt> <dir with large_*_proofs.json>

Writes:
    tests/vectors/mtc/appendix_c.json          C.1.1–C.1.4 accumulated digests, C.2.1 validity
                                               and C.2.4 covering samples, parsed from the draft text
    tests/vectors/mtc/large_inclusion_proofs.json, large_consistency_proofs.json
                                               C.2.2 / C.2.3, copied byte for byte from the WG
                                               repository at the -08 tag
    tests/vectors/trust-anchor-ids/appendix_b.json
                                               App. B and B.1 pattern vectors, parsed from the draft
and a SOURCE in each directory pinning every file (tests/test_environment.py).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MTC_OUT = ROOT / "tests" / "vectors" / "mtc"
TAI_OUT = ROOT / "tests" / "vectors" / "trust-anchor-ids"
REPO = "https://github.com/ietf-plants-wg/merkle-tree-certs"
TAG = "draft-ietf-plants-merkle-tree-certs-08"
TAG_COMMIT = "766dbfe6519819ff2771b1f429106706178bb16a"
# The C.2 files as published at the tag; anything else is refused, so SOURCE's provenance holds.
LARGE = {
    "large_inclusion_proofs.json": "19ffc377d123613de6cfe3ad98c858da7a0af9abbcd8e9bd69cfa9f225e542c4",
    "large_consistency_proofs.json": "7fcc6d9d0283ecf7d19e221049f477964dfbf048ef43601a640a8c5a62e47d9f",
}
APPENDIX_B_COUNTS = [5, 7, 3, 3]  # IDs per group in trust-anchor-ids -07 App. B
TXT_HASHES = ("large_inclusion_proofs.txt 20173f58f6b212a52b44c391af73b437d45ec890c3039ba42a69cc5b066b58fa, "
              "large_consistency_proofs.txt 61de93c69e49003bb2d1a345b8d5d23eb8996df5a796456048f794bd4f14f79b")
PAGE_BREAK = re.compile(r"^(Benjamin|Beck), et al\..*$|^Internet-Draft .*$|^\f", re.M)


def body(text: str) -> str:
    """The draft text without page headers and footers."""
    return PAGE_BREAK.sub("", text)


def section(text: str, start: str, end: str) -> str:
    """From the line that is exactly ``start`` to the line that is exactly ``end`` (body, not TOC)."""
    lines = text.splitlines()
    starts = [n for n, line in enumerate(lines) if line.strip() == start]
    if not starts:
        raise ValueError(f"heading {start!r} not found")
    i = starts[-1]
    j = next((n for n in range(i + 1, len(lines)) if lines[n].strip() == end), None)
    if j is None:
        raise ValueError(f"heading {end!r} not found after {start!r}")
    return "\n".join(lines[i:j])


def power_expr(expr: str) -> int:
    """``0``, ``2^46``, ``2^47 + 1``, ``2^64 - 1`` → int."""
    m = re.fullmatch(r"(?:(\d+)\^(\d+)|(\d+))(?: ([+-]) (\d+))?", expr.strip())
    if not m:
        raise ValueError(f"can't read {expr!r}")
    value = int(m[1]) ** int(m[2]) if m[1] else int(m[3])
    if m[4]:
        value = value + int(m[5]) if m[4] == "+" else value - int(m[5])
    return value


def appendix_c(mtc: str) -> dict[str, object]:
    digests = {}
    for name in ("C.1.1.  Subtree Hashes", "C.1.2.  Subtree Inclusion Proofs",
                 "C.1.3.  Subtree Consistency Proofs", "C.1.4.  Efficient Covering Subtrees"):  # fmt: skip
        nxt = {"C.1.1": "C.1.2.  Subtree Inclusion Proofs", "C.1.2": "C.1.3.  Subtree Consistency Proofs",
               "C.1.3": "C.1.4.  Efficient Covering Subtrees", "C.1.4": "C.2.  Large Subtree Test Vectors"}  # fmt: skip
        key = name.split()[0].rstrip(".")
        part = section(mtc, name, nxt[key])
        found = re.findall(r"The final hash value is\s+([0-9a-f]{64})", part)
        asserted = re.findall(r"assert h\.hexdigest\(\) == '([0-9a-f]{64})'", part)
        if len(found) != 1 or found != asserted:
            raise ValueError(f"{key}: expected one final hash, matching the Python listing")
        digests[key] = found[0]

    validity = section(mtc, "C.2.1.  Subtree Validity", "C.2.2.  Subtree Inclusion Proofs")
    valid_part, invalid_part = validity.split("The following are not valid subtrees:")
    row = re.compile(r"\*\s+start is (.+?) and end is (.+?)\s*$", re.M)
    valid = [[power_expr(a), power_expr(b)] for a, b in row.findall(valid_part)]
    invalid = [[power_expr(a), power_expr(b)] for a, b in row.findall(invalid_part)]
    if (len(valid), len(invalid)) != (6, 6):
        raise ValueError("C.2.1: expected six valid and six invalid subtrees")

    covering_text = section(mtc, "C.2.4.  Efficient Covering Subtrees", "Change log")
    interval = r"\[(0x[0-9a-f]+), (0x[0-9a-f]+)\)"
    flat = " ".join(covering_text.split())
    covering = []
    for m in re.finditer(rf"Given range {interval}, the subtrees\s+are: \* {interval} \* {interval}", flat):
        a, b, l0, l1, r0, r1 = (int(x, 16) for x in m.groups())
        covering.append({"range": [a, b], "left": [l0, l1], "right": [r0, r1]})
    if len(covering) != flat.count("Given range"):
        raise ValueError("C.2.4: a sample didn't parse")
    return {"accumulated": digests, "valid_subtrees": valid, "invalid_subtrees": invalid, "covering": covering}


def appendix_b(tai: str) -> dict[str, object]:
    part = section(tai, "Appendix B.  Trust Anchor ID Pattern Test Vectors", "Acknowledgements")
    main, invalid_part = part.split("B.1.  Invalid IDs or Patterns")
    flat = " ".join(main.split())
    groups = []
    for m in re.finditer(r"The following IDs are (not )?contained in the pattern ([0-9a-f]+) \((.*?)\): (.*?)(?=The following|$)", flat):
        ids = re.findall(r"\* ([0-9a-f]+) \(", m[4])
        if not ids:
            raise ValueError("App. B: a group has no IDs")
        groups.append({"pattern": m[2], "pattern_text": " ".join(m[3].split()).replace(" - ", "-"),
                       "contained": m[1] is None, "ids": ids})  # fmt: skip
    if [len(g["ids"]) for g in groups] != APPENDIX_B_COUNTS:
        raise ValueError(f"App. B: expected four groups of {APPENDIX_B_COUNTS} IDs")
    flat_invalid = " ".join(invalid_part.split())
    invalid = [{"id": i, "pattern": p}
               for i, p in re.findall(r"The ID ([0-9a-f]+) \(\d+\) is not contained in the pattern ([0-9a-f]+)\.", flat_invalid)]  # fmt: skip
    if len(invalid) != 4:
        raise ValueError("App. B.1: expected four cases")
    return {"groups": groups, "invalid": invalid}


def write_source(out: Path, header: list[str]) -> None:
    lines = list(header)
    for path in sorted(p for p in out.rglob("*") if p.is_file() and p.name != "SOURCE"):
        lines.append(f"sha256 {path.relative_to(out)}: {hashlib.sha256(path.read_bytes()).hexdigest()}")
    (out / "SOURCE").write_text("\n".join(lines) + "\n")


def check_large(large_dir: Path) -> None:
    for name, digest in LARGE.items():
        got = hashlib.sha256((large_dir / name).read_bytes()).hexdigest()
        if got != digest:
            raise ValueError(f"{name} has sha256 {got}, not the {TAG} file's {digest}")


def main(mtc_txt: Path, tai_txt: Path, large_dir: Path) -> None:
    mtc_raw, tai_raw = mtc_txt.read_bytes(), tai_txt.read_bytes()
    # Everything is parsed and checked before anything is written.
    c = appendix_c(body(mtc_raw.decode()))
    b = appendix_b(body(tai_raw.decode()))
    check_large(large_dir)
    MTC_OUT.mkdir(parents=True, exist_ok=True)
    TAI_OUT.mkdir(parents=True, exist_ok=True)
    (MTC_OUT / "appendix_c.json").write_text(json.dumps(c, indent=1) + "\n")
    for name in LARGE:
        shutil.copyfile(large_dir / name, MTC_OUT / name)
    (TAI_OUT / "appendix_b.json").write_text(json.dumps(b, indent=1) + "\n")
    write_source(MTC_OUT, [
        f"document: {TAG}, Appendix C, https://www.ietf.org/archive/id/{TAG}.txt",
        f"source sha256: {hashlib.sha256(mtc_raw).hexdigest()}",
        f"repository: {REPO} tag {TAG} (commit {TAG_COMMIT}), demo/{' and demo/'.join(LARGE)} (C.2.2, C.2.3; input hashes checked)",
        "cited by the draft as: tree/main/demo/large_{inclusion,consistency}_proofs.txt (a moving branch), so the tag is pinned",
        f"same cases as the .txt forms at the tag (cross-checked field by field 2026-11-15; not vendored): {TXT_HASHES}",
        "regenerate: python scripts/extract_mtc_vectors.py <mtc-08.txt> <trust-anchor-ids-07.txt> <dir with the two JSON files>",
        "oracle: independent (IETF draft authors' test vectors)",
    ])  # fmt: skip
    write_source(TAI_OUT, [
        "document: draft-ietf-tls-trust-anchor-ids-07, Appendix B, https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-07.txt",
        f"source sha256: {hashlib.sha256(tai_raw).hexdigest()}",
        "regenerate: python scripts/extract_mtc_vectors.py <mtc-08.txt> <trust-anchor-ids-07.txt> <dir with the two JSON files>",
        "oracle: independent (IETF draft authors' test vectors)",
    ])  # fmt: skip


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
