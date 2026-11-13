"""Trim NIST ACVP JSON vectors to the subset qTLS tests use.

Source: https://github.com/usnistgov/ACVP-Server, gen-val/json-files/<dir>/internalProjection.json
at the commit recorded in tests/vectors/acvp/SOURCE. Usage:

    python scripts/trim_acvp.py <dir with ML-KEM-keyGen-FIPS203.json, ...> tests/vectors/acvp

Kept (everything else is irrelevant to TLS's use of these algorithms):
* ML-KEM-512/768 keyGen: seed (d, z) -> ek.
* ML-KEM-512/768 decapsulation: (dk, c) -> k, including implicit-rejection cases,
  plus the first AFT encapsulation vectors read as (dk, c) -> k.
* ML-DSA-44/65 sigVer, external interface, pure (no pre-hash): pass and fail cases.
* ML-DSA-44/65 keyGen: seed (xi) -> pk, sk.

Each output is (re)written only from its own input file, so one vector set can
be added without re-downloading the others. No inputs at all is an error.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

KEMS = {"ML-KEM-512", "ML-KEM-768"}
SIGS = {"ML-DSA-44", "ML-DSA-65"}
KEYGEN_PER_SET = 5
ENCAP_AS_DECAP_PER_SET = 2
DECAP_PER_REASON = 3
SIGVER_PER_REASON = 1
MLDSA_KEYGEN_PER_SET = 3


def load(src: Path, name: str) -> dict:
    return json.loads((src / f"{name}.json").read_text())


def main(src: Path, dst: Path) -> None:
    outputs = {
        "ML-KEM-keyGen-FIPS203.json": mlkem_keygen,
        "ML-KEM-encapDecap-FIPS203.json": mlkem_decap,
        "ML-DSA-sigVer-FIPS204.json": mldsa_sigver,
        "ML-DSA-keyGen-FIPS204.json": mldsa_keygen,
    }
    present = [name for name in outputs if (src / name).is_file()]
    if not present:
        raise SystemExit(f"no ACVP input files found in {src}")
    dst.mkdir(parents=True, exist_ok=True)
    for name in present:
        outputs[name](src, dst)


def mldsa_keygen(src: Path, dst: Path) -> None:
    keygen = load(src, "ML-DSA-keyGen-FIPS204")
    out = []
    for g in keygen["testGroups"]:
        if g["parameterSet"] in SIGS:
            for t in g["tests"][:MLDSA_KEYGEN_PER_SET]:
                out.append({"parameterSet": g["parameterSet"], "tcId": t["tcId"],
                            "seed": t["seed"], "pk": t["pk"], "sk": t["sk"]})
    write(dst / "mldsa_keygen.json", keygen, out)


def mlkem_keygen(src: Path, dst: Path) -> None:
    keygen = load(src, "ML-KEM-keyGen-FIPS203")
    out = []
    for g in keygen["testGroups"]:
        if g["parameterSet"] in KEMS:
            for t in g["tests"][:KEYGEN_PER_SET]:
                out.append({"parameterSet": g["parameterSet"], "tcId": t["tcId"],
                            "d": t["d"], "z": t["z"], "ek": t["ek"]})
    write(dst / "mlkem_keygen.json", keygen, out)


def mlkem_decap(src: Path, dst: Path) -> None:
    encdec = load(src, "ML-KEM-encapDecap-FIPS203")
    out = []
    for g in encdec["testGroups"]:
        if g["parameterSet"] not in KEMS:
            continue
        if g["function"] == "decapsulation":
            seen: dict[str, int] = {}
            tests = []
            for t in g["tests"]:
                seen[t["reason"]] = seen.get(t["reason"], 0) + 1
                if seen[t["reason"]] <= DECAP_PER_REASON:
                    tests.append(t)
        elif g["function"] == "encapsulation":
            tests = g["tests"][:ENCAP_AS_DECAP_PER_SET]
        else:
            continue
        for t in tests:
            row = {"parameterSet": g["parameterSet"], "tgId": g["tgId"], "tcId": t["tcId"],
                   "function": g["function"], "reason": t.get("reason", "valid"),
                   "dk": t["dk"], "c": t["c"], "k": t["k"]}
            if g["function"] == "encapsulation":
                row.update({"ek": t["ek"], "m": t["m"]})  # for derandomised encapsulation KATs
            out.append(row)
    write(dst / "mlkem_decap.json", encdec, out)


def mldsa_sigver(src: Path, dst: Path) -> None:
    sigver = load(src, "ML-DSA-sigVer-FIPS204")
    out = []
    for g in sigver["testGroups"]:
        if (g["parameterSet"] in SIGS and g["signatureInterface"] == "external"
                and g["preHash"] == "pure"):
            by_reason: dict[str, list[dict]] = {}
            for t in g["tests"]:
                by_reason.setdefault(t["reason"], []).append(t)
            for tests in by_reason.values():
                # Every failure category, shortest messages first, to keep the repo small.
                for t in sorted(tests, key=lambda t: len(t["message"]))[:SIGVER_PER_REASON]:
                    out.append({"parameterSet": g["parameterSet"], "tcId": t["tcId"],
                                "pk": t["pk"], "message": t["message"],
                                "context": t["context"], "signature": t["signature"],
                                "testPassed": t["testPassed"], "reason": t["reason"]})
    write(dst / "mldsa_sigver.json", sigver, out)


def write(path: Path, source: dict, tests: list[dict]) -> None:
    doc = {"algorithm": source["algorithm"], "mode": source["mode"],
           "revision": source["revision"], "vsId": source.get("vsId"), "tests": tests}
    path.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"{path}: {len(tests)} vectors")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
