#!/usr/bin/env python3
"""Vendor certificates and verdicts from the MTC WG's Go demo, an independent oracle (specs.md D33).

The demo (github.com/ietf-plants-wg/merkle-tree-certs, demo/) generates Merkle
Tree certificates from a JSON config and verifies them. Its ``plants-07`` mode
is the -08 wire format (the -08 changelog: "draft-07 and draft-08 are
compatible"). This script, at the pinned tag and Go version:

1. builds the demo;
2. generates two corpora: ``wg`` from the demo's own ``mtc.json`` (with its
   deliberate malformations) and ``qtls`` from a config written here, whose
   certificates are in qTLS's X.509 profile (D24) and use qTLS fixture keys;
3. runs ``demo verify`` on every certificate on its own (one bad certificate
   aborts a batch run) under each relying-party policy, and records the
   verdict;
4. writes everything to tests/vectors/mtc-demo/ with a SOURCE pinning it.

Go's ML-DSA and ECDSA signing is randomized, so a fresh run changes signature
bytes; tests read the vendored files and never compare against a regeneration.

Usage: OQS_INSTALL_PATH=.oqs python scripts/mtc_demo.py [--go .go/bin/go] [--src <clone>]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qtls import chains, crypto, der, x509  # noqa: E402

REPO = "https://github.com/ietf-plants-wg/merkle-tree-certs"
TAG = "draft-ietf-plants-merkle-tree-certs-08"
TAG_COMMIT = "766dbfe6519819ff2771b1f429106706178bb16a"
GO_VERSION = "go1.27.4"
GO_TARBALL_SHA256 = {  # https://go.dev/dl/?mode=json
    "darwin-arm64": "91a44a2b8a716600ad94a4f143e156116620db8828086a6e3602291be9bd0bb4",
}
DRAFT_VERSION = "plants-07"  # the -08 wire format
OUT = ROOT / "tests" / "vectors" / "mtc-demo"
WORK = ROOT / ".mtc-demo"

# The qtls corpus (D34): a CA, cosigners and leaves from qTLS fixture seeds.
FIXTURE_SEED = b"qtls fixture v1"
CA_ID = "32473.9"
LOG_NUMBER = 3  # not 1, so log arithmetic is exercised
COSIGNERS = {  # ID: (qTLS algorithm, demo name, fixture role)
    CA_ID: ("ML-DSA-44", "mldsa44", "mtc-ca"),
    f"{CA_ID}.1": ("ML-DSA-65", "mldsa65", "mtc-cosigner-1"),
    f"{CA_ID}.2": ("ECDSA-P256-SHA256", "ecdsa_p256_sha256", "mtc-cosigner-2"),
    f"{CA_ID}.3": ("ML-DSA-44", "mldsa44", "mtc-cosigner-3"),  # never configured in qTLS: ignored
}
NOT_BEFORE, NOT_AFTER = "2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z"
GREASE_ID = f"{CA_ID}.200"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def pkcs8(alg: str, role: str) -> bytes:
    """The cosigner's private key, as the demo reads it: the same seed mtc.fixture_cosigner uses."""
    seed = chains.signing_key(alg, FIXTURE_SEED, role).seed
    assert seed is not None
    if alg.startswith("ML-DSA"):
        oid = {"ML-DSA-44": "2.16.840.1.101.3.4.3.17", "ML-DSA-65": "2.16.840.1.101.3.4.3.18"}[alg]
        return der.seq(der.integer(0), der.seq(der.oid(oid)), der.octet_string(der.tlv(0x80, seed)))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.derive_private_key(int.from_bytes(seed, "big"), ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())  # fmt: skip


def cosigner_public_key(alg: str, role: str) -> bytes:
    return chains.signing_key(alg, FIXTURE_SEED, role).public_key


def leaf_spki(alg: str) -> bytes:
    if x509.BY_NAME[alg].kind == "sig":
        return x509.spki(alg, chains.signing_key(alg, FIXTURE_SEED, "leaf").public_key)
    key = crypto.kem_generate(alg, "liboqs" if alg == "ML-KEM-512" else "openssl",
                              seed=chains._derive(FIXTURE_SEED, "leaf/kem", 64))  # fmt: skip
    return x509.spki(alg, key.public_key)


def qtls_config() -> dict:
    def entry(alg: str, certs: list[dict], **extra: object) -> dict:
        usage = ["DigitalSignature"] if x509.BY_NAME[alg].kind == "sig" else ["KeyEncipherment"]
        e = {"Subject": {"CommonName": "qtls.test"}, "PublicKey": b64(leaf_spki(alg)), "NotBefore": NOT_BEFORE,
             "NotAfter": NOT_AFTER, "DNSNames": ["qtls.test"], "KeyUsage": usage,
             "Checkpoints": ["standalone"], "Certificates": certs}  # fmt: skip
        e.update(extra)
        return e

    ca, c1, c2, c3 = COSIGNERS
    std = {"Checkpoint": "standalone"}
    mldsa44_alg = b64(der.seq(der.oid(x509.BY_NAME["ML-DSA-44"].oid)))
    entries = [
        {"Repeat": 5, "Null": True},
        entry("ML-DSA-44", [
            {**std, "Cosigners": [ca, c1]},  # 0: the D14 default shape
            {**std, "Cosigners": [ca]},  # 1
            {**std, "Cosigners": [c1]},  # 2: no CA signature
            {**std, "Cosigners": [ca, c1, c2, c3]},  # 3
            {**std, "Cosigners": [ca], "BitFlipProof": True},  # 4
            {**std, "Cosigners": [ca], "UnusedBit": True},  # 5
            {**std, "Cosigners": [c1, ca], "DontSortCosigners": True},  # 6: longer ID first
            {**std, "Cosigners": [ca], "OverrideSignatureAlgorithm": mldsa44_alg},  # 7
            {**std, "Cosigners": [ca], "OverrideTBSSignatureAlgorithm": mldsa44_alg},  # 8
            {**std, "Cosigners": [ca], "ExtraCosignatures": [
                {"CosignerID": GREASE_ID, "Signature": b64(b"grease")},  # unrecognized: ignored
                {"CosignerID": c2, "Signature": b64(b"\x30\x00")},  # recognized, invalid, not required
            ]},  # 9
            {"Checkpoint": "landmark"},  # 10: landmark-relative
        ]),
        {"Repeat": 7, "Null": True},
        entry("ML-DSA-65", [{**std, "Cosigners": [ca, c1]}, {"Checkpoint": "landmark"}]),
        entry("ECDSA-P256-SHA256", [{**std, "Cosigners": [ca, c2]}, {"Checkpoint": "landmark"}]),
        entry("ML-KEM-512", [{**std, "Cosigners": [ca, c1]}, {"Checkpoint": "landmark"}]),
        entry("ML-KEM-768", [{**std, "Cosigners": [ca, c1]}, {"Checkpoint": "landmark"}]),
        entry("ML-DSA-44", [{**std, "Cosigners": [ca]}], MTCEntryExtensions=b64(bytes.fromhex("00010000"))),
        entry("ML-DSA-44", [{**std, "Cosigners": [ca]}], MTCEntryExtensions=b64(bytes.fromhex("0002000000010000"))),
        entry("ML-DSA-44", [{**std, "Cosigners": [ca]}], MTCEntryExtensions=b64(bytes.fromhex("0001000000010000"))),
        entry("ML-DSA-44", [{**std, "Cosigners": [ca]}], MTCEntryExtensions=b64(bytes.fromhex("000100"))),
        {"Repeat": 40, "Null": True, "Checkpoints": ["landmark"]},
        entry("ML-DSA-44", [{"SubtreeStart": 32, "SubtreeEnd": 64, "Cosigners": [ca]}]),  # explicit subtree
        {"Repeat": 30, "Null": True, "Checkpoints": ["standalone", "landmark"]},
    ]
    return {
        "Version": DRAFT_VERSION, "ID": CA_ID, "LogNumber": LOG_NUMBER,
        "Cosigners": [{"CosignerID": cid, "SignatureAlgorithm": name, "PrivateKey": b64(pkcs8(alg, role))}
                      for cid, (alg, name, role) in COSIGNERS.items()],
        "CACert": {"NotBefore": NOT_BEFORE, "NotAfter": NOT_AFTER, "IsCA": True, "KeyUsage": ["CertSign"],
                   "MinSerial": {"Log": LOG_NUMBER, "Index": 0}, "MaxSerial": {"Log": LOG_NUMBER, "Index": 2**48 - 1}},
        "Entries": entries,
    }  # fmt: skip


# --------------------------------------------------------------------------- #


def run(*args: str | Path, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True, text=True)


def checked(proc: subprocess.CompletedProcess[str], what: str) -> str:
    if proc.returncode != 0:
        raise RuntimeError(f"{what} failed:\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout


def prepare(go: Path, src: Path | None) -> Path:
    version = checked(run(go, "version"), "go version").split()[2]
    if version != GO_VERSION:
        sys.exit(f"{go} is {version}, not the pinned {GO_VERSION}")
    if src is None:
        src = WORK / "src"
        if not src.exists():
            checked(run("git", "clone", "--quiet", "--depth", "1", "--branch", TAG, REPO, src), "git clone")
    head = checked(run("git", "rev-parse", "HEAD", cwd=src), "git rev-parse").strip()
    if head != TAG_COMMIT:
        sys.exit(f"{src} is at {head}, not {TAG} ({TAG_COMMIT})")
    binary = WORK / "demo"
    WORK.mkdir(exist_ok=True)
    checked(run(go, "build", "-o", binary.resolve(), ".", cwd=src / "demo"), "go build")
    return binary


PEM = re.compile(r"-----BEGIN CERTIFICATE-----\n(.*?)-----END CERTIFICATE-----", re.S)
LANDMARK = re.compile(r"^\s+Landmark subtree \[(\d+), (\d+)\) with hash (\S+)$")
LANDMARK_HEAD = re.compile(r"^Landmark (\d+) at tree size (\d+):$")


def pem_der(path: Path) -> bytes:
    m = PEM.search(path.read_text())
    if not m:
        raise RuntimeError(f"{path} has no CERTIFICATE block")
    return base64.b64decode(m.group(1))


def landmarks(stdout: str) -> list[dict]:
    out, current = [], None
    for line in stdout.splitlines():
        if (m := LANDMARK_HEAD.match(line)):
            current = {"landmark": int(m[1]), "tree_size": int(m[2]), "subtrees": []}
            out.append(current)
        elif (m := LANDMARK.match(line)) and current is not None:
            current["subtrees"].append({"start": int(m[1]), "end": int(m[2]), "hash": m[3]})
    return out


def verdict(binary: Path, ca: Path, policy: Path | None, cert: Path) -> str:
    args = [binary, "verify", "-version", DRAFT_VERSION, "-ca-cert", ca, *(["-policy", policy] if policy else []), cert]
    proc = run(*args)
    text = proc.stdout + proc.stderr
    lines = [line for line in text.splitlines() if line.startswith(f"{cert}: ")]
    if len(lines) == 1:
        return lines[0][len(f"{cert}: "):]
    # Only Go failing to parse this certificate is a verdict; any other failure (a policy or CA
    # certificate the demo refuses) is ours and must stop the run.
    marker = f'failed to parse certificate from "{cert}": '
    if proc.returncode != 0 and not lines and marker in text:
        return "unparsable: " + text.split(marker, 1)[1].strip().splitlines()[0]
    raise RuntimeError(f"expected one verdict for {cert}, got:\n{text}")


def corpus(binary: Path, name: str, config: Path, ca_id: str, extra_policies: dict[str, str]) -> dict:
    out = OUT / name
    with tempfile.TemporaryDirectory() as tmp:
        gen = Path(tmp) / "out"
        stdout = checked(run(binary, "generate", "-config", config, "-out", gen), f"generate {name}")
        if out.exists():
            shutil.rmtree(out)
        (out / "certs").mkdir(parents=True)
        (out / "ca_cert.der").write_bytes(pem_der(gen / "ca_cert.pem"))
        (out / "checkpoint").write_bytes((gen / "checkpoint").read_bytes())
        marks = landmarks(stdout)
        if not marks:
            raise RuntimeError(f"generate {name} printed no landmarks")
        (out / "landmarks.json").write_text(json.dumps(marks, indent=1) + "\n")
        trusted = "".join(f"trusted-subtree {ca_id} {log} {s['start']} {s['end']} {s['hash']}\n"
                          for log in [json.loads(config.read_text())["LogNumber"]]
                          for mk in marks for s in mk["subtrees"])  # fmt: skip
        policies = {"ca-only": "", "landmarks": trusted, **extra_policies}
        for pname, body in policies.items():
            (out / f"policy-{pname}.txt").write_text(body)
        verdicts: dict[str, dict[str, str]] = {}
        for pem in sorted(gen.glob("cert_*.pem"), key=lambda p: [int(x) for x in re.findall(r"\d+", p.name)]):
            stem = pem.stem
            try:
                (out / "certs" / f"{stem}.der").write_bytes(pem_der(pem))
            except (RuntimeError, ValueError) as exc:
                raise RuntimeError(f"{pem}: {exc}") from None
            verdicts[stem] = {
                pname: verdict(binary, gen / "ca_cert.pem", (out / f"policy-{pname}.txt") if body else None, pem)
                for pname, body in policies.items()
            }
        (out / "verdicts.json").write_text(json.dumps(verdicts, indent=1, sort_keys=True) + "\n")
    shutil.copyfile(config, out / "config.json")
    return verdicts


KAT_FIELD = re.compile(r'expected(TBS|LogEntry)Hex:\s*((?:"[0-9a-f]*"\s*\+?\s*)+),')


def wg_kats(src: Path) -> list[dict]:
    """TestMarshalTBSCertificate's plants-07 cases: TBSCertificate → MTCLogEntry (demo/encode_test.go)."""
    text = (src / "demo" / "encode_test.go").read_text()
    body = text[text.index("func TestMarshalTBSCertificate"):text.index("func TestCreateCACertificate")]
    cases = []
    for block in re.split(r"\n\t\t\{\n", body)[1:]:
        if "version: VersionPlants07," not in block:
            continue
        fields = {k: "".join(re.findall(r'"([0-9a-f]*)"', v)) for k, v in KAT_FIELD.findall(block)}
        if set(fields) != {"TBS", "LogEntry"}:
            raise RuntimeError(f"a plants-07 case without both expected values:\n{block[:300]}")
        cases.append({"tbs": fields["TBS"], "log_entry": fields["LogEntry"]})
    if len(cases) != 2:
        raise RuntimeError(f"expected 2 plants-07 TBS cases in encode_test.go, found {len(cases)}")
    return cases


def write_source() -> None:
    lines = [
        f"repository: {REPO} tag {TAG} (commit {TAG_COMMIT}), demo/ built with {GO_VERSION} (checked by "
        f"`go version`; installed from the darwin-arm64 tarball, sha256 {GO_TARBALL_SHA256['darwin-arm64']}, "
        f"checked at download); draft version {DRAFT_VERSION}",
        "corpora: wg = the demo's own demo/mtc.json; qtls = scripts/mtc_demo.py qtls_config() (qTLS profile and fixture keys)",
        "verdicts: `demo verify` on each certificate alone, per policy file; signatures are randomized, so a "
        "regeneration differs in signature bytes",
        "regenerate: OQS_INSTALL_PATH=.oqs python scripts/mtc_demo.py",
        "oracle: independent (the MTC WG's reference implementation)",
    ]
    for path in sorted(p for p in OUT.rglob("*") if p.is_file() and p.name != "SOURCE"):
        lines.append(f"sha256 {path.relative_to(OUT)}: {hashlib.sha256(path.read_bytes()).hexdigest()}")
    (OUT / "SOURCE").write_text("\n".join(lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--go", type=Path, default=ROOT / ".go" / "bin" / "go")
    ap.add_argument("--src", type=Path, default=None)
    args = ap.parse_args()
    binary = prepare(args.go, args.src)
    src = args.src or WORK / "src"
    with tempfile.TemporaryDirectory() as tmp:
        qcfg = Path(tmp) / "qtls.json"
        qcfg.write_text(json.dumps(qtls_config(), indent=1) + "\n")
        extra = {}
        for n in (1, 2):  # an ML-DSA-65 and an ECDSA cosigner, each required by one policy
            alg, demo_name, role = COSIGNERS[f"{CA_ID}.{n}"]
            spki = x509.spki(alg, cosigner_public_key(alg, role))
            extra[f"ca-and-{n}"] = (f"cosigner {CA_ID}.{n} {demo_name} {b64(spki)}\n"
                                    f"require-cosigners {CA_ID} {CA_ID}.{n}\n")  # fmt: skip
        OUT.mkdir(parents=True, exist_ok=True)
        corpus(binary, "wg", src / "demo" / "mtc.json", "32473.1", {})
        corpus(binary, "qtls", qcfg, CA_ID, extra)
        (OUT / "wg_kat.json").write_text(json.dumps(wg_kats(src), indent=1) + "\n")
    write_source()
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
