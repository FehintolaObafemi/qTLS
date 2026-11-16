#!/usr/bin/env python3
"""Vendor certificates and verdicts from the MTC WG's Go demo, an independent oracle (specs.md D33–D36).

The demo (github.com/ietf-plants-wg/merkle-tree-certs, demo/) generates Merkle
Tree certificates from a JSON config and verifies them. Its ``plants-07`` mode
is the -08 wire format (the -08 changelog: "draft-07 and draft-08 are
compatible"). This script, at the pinned tag and Go version:

1. builds the demo (``--build-only`` stops there; CI runs it as its own step);
2. generates two corpora: ``wg`` from the demo's own ``mtc.json`` (with its
   deliberate malformations) and ``qtls`` from a config written here, whose
   certificates are in qTLS's X.509 profile (D24) and use qTLS fixture keys;
3. runs ``demo verify`` on every certificate under each relying-party policy
   (qTLS ``CAPolicy`` objects rendered by :func:`demo_policy`, plus the WG's
   sample policy without its ML-DSA-87 cosigner), and records the verdict and
   what Go printed about cosigners and groups;
4. writes everything to tests/vectors/mtc-demo/ with a SOURCE pinning it.

Go's ML-DSA and ECDSA signing is randomized, so a fresh run changes signature
bytes; tests read the vendored files and never compare against a regeneration.

The same module is the live differential's library (tests/test_mtc_go.py): the
policy renderer and parser, Go's verdict classes, and :func:`compare`. A failed
live run keeps its working directory under .mtc-demo/failed/; ``--replay DIR``
re-runs the comparison from it (qTLS's side recomputed, Go's side as saved).

Usage: OQS_INSTALL_PATH=.oqs python scripts/mtc_demo.py [--go .go/bin/go] [--src <clone>] [--build-only]
       OQS_INSTALL_PATH=.oqs python scripts/mtc_demo.py --replay .mtc-demo/failed/<name>
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qtls import chains, crypto, der, merkle, mtc, x509  # noqa: E402
from qtls.alerts import AlertError, CodecUsageError  # noqa: E402
from qtls.trust_anchor_ids import TrustAnchorID  # noqa: E402

REPO = "https://github.com/ietf-plants-wg/merkle-tree-certs"
TAG = "draft-ietf-plants-merkle-tree-certs-08"
TAG_COMMIT = "766dbfe6519819ff2771b1f429106706178bb16a"
GO_VERSION = "go1.27.4"
GO_TARBALL_SHA256 = {  # https://go.dev/dl/?mode=json&include=all; kept in sync with scripts/install_go.sh
    "darwin-arm64": "91a44a2b8a716600ad94a4f143e156116620db8828086a6e3602291be9bd0bb4",
    "linux-amd64": "7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840",
}
DRAFT_VERSION = "plants-07"  # the -08 wire format
OUT = ROOT / "tests" / "vectors" / "mtc-demo"
WORK = ROOT / ".mtc-demo"
FAILED = WORK / "failed"

# The qtls corpus (D34): a CA, cosigners and leaves from qTLS fixture seeds.
FIXTURE_SEED = b"qtls fixture v1"
CA_ID = "32473.9"
LOG_NUMBER = 3  # not 1, so log arithmetic is exercised
COSIGNERS = {  # ID: (qTLS algorithm, fixture role)
    CA_ID: ("ML-DSA-44", "mtc-ca"),
    f"{CA_ID}.1": ("ML-DSA-65", "mtc-cosigner-1"),
    f"{CA_ID}.2": ("ECDSA-P256-SHA256", "mtc-cosigner-2"),
    f"{CA_ID}.3": ("ML-DSA-44", "mtc-cosigner-3"),
}
DEMO_ALG = {"ML-DSA-44": "mldsa44", "ML-DSA-65": "mldsa65", "ECDSA-P256-SHA256": "ecdsa_p256_sha256"}
NOT_BEFORE, NOT_AFTER = "2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z"
GREASE_ID = f"{CA_ID}.200"
SUBSETS_ENTRY = 92  # the entry carrying one certificate per cosigner subset (after the 3b1 entries, so names are kept)
REVOKED_FIRST, REVOKED_LAST = 94, 95  # revoked indices, inclusive; certificates at 93..96 sit on both edges
WG_EXCLUDED = "32473.2.3"  # the WG sample's ML-DSA-87 cosigner: not a cosigner algorithm qTLS verifies (D33)


def tai(text: str) -> TrustAnchorID:
    return TrustAnchorID.from_ascii(text)


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


def cosigner_keys(cosigners: Mapping[str, tuple[str, str]] = COSIGNERS) -> dict[TrustAnchorID, mtc.CosignerKey]:
    return {tai(cid): mtc.CosignerKey(alg, cosigner_public_key(alg, role)) for cid, (alg, role) in cosigners.items()}


def leaf_spki(alg: str) -> bytes:
    if x509.BY_NAME[alg].kind == "sig":
        return x509.spki(alg, chains.signing_key(alg, FIXTURE_SEED, "leaf").public_key)
    key = crypto.kem_generate(alg, "liboqs" if alg == "ML-KEM-512" else "openssl",
                              seed=chains._derive(FIXTURE_SEED, "leaf/kem", 64))  # fmt: skip
    return x509.spki(alg, key.public_key)


def qtls_cosigners(ca_alg: str = "ML-DSA-44") -> dict[str, tuple[str, str]]:
    """The qtls corpus' cosigners; ``ca_alg`` gives the ECDSA-CA variant of the live differential."""
    return {**COSIGNERS, CA_ID: (ca_alg, "mtc-ca")}


def qtls_config(ca_alg: str = "ML-DSA-44") -> dict:
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
    subsets = [[c for c, bit in zip((ca, c1, c2, c3), (8, 1, 2, 4)) if mask & bit] for mask in range(16)]
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
        # 3b2 (D35): entry 92, every subset of {C1, C2, C3} with and without the CA (cert_92_<mask>,
        # mask bits CA=8, C1=1, C2=2, C3=4), then four certificates on the edges of the revoked range.
        entry("ML-DSA-44", [{**std, "Cosigners": s} for s in subsets]),
        *(entry("ML-DSA-44", [{**std, "Cosigners": [ca]}]) for _ in range(REVOKED_FIRST - 1, REVOKED_LAST + 2)),
        {"Repeat": 7, "Null": True, "Checkpoints": ["standalone", "landmark"]},
    ]
    return {
        "Version": DRAFT_VERSION, "ID": CA_ID, "LogNumber": LOG_NUMBER,
        "Cosigners": [{"CosignerID": cid, "SignatureAlgorithm": DEMO_ALG[alg], "PrivateKey": b64(pkcs8(alg, role))}
                      for cid, (alg, role) in qtls_cosigners(ca_alg).items()],
        "CACert": {"NotBefore": NOT_BEFORE, "NotAfter": NOT_AFTER, "IsCA": True, "KeyUsage": ["CertSign"],
                   "MinSerial": {"Log": LOG_NUMBER, "Index": 0}, "MaxSerial": {"Log": LOG_NUMBER, "Index": 2**48 - 1}},
        "Entries": entries,
    }  # fmt: skip


# --------------------------------------------------------------------------- #
# Policies: qTLS CAPolicy ↔ the demo's policy text (demo/policy.txt documents the grammar)
# --------------------------------------------------------------------------- #


def _go_id(ident: TrustAnchorID) -> str:
    """The demo parses each component as a uint32 (config.go TrustAnchorIDFromString)."""
    if any(c > 0xFFFFFFFF for c in ident.components):
        raise ValueError(f"{ident} has a component the demo can't parse")
    return ident.ascii


def demo_policy(store: mtc.MTCTrustStore, ca_id: TrustAnchorID) -> str:
    """One CA's ``CAPolicy`` as the demo's policy text. The CA's key comes from its certificate (never a
    ``cosigner`` line); quorums become groups, children first and each once; [lo, hi) becomes the
    demo's inclusive ``lo hi-1`` (``max`` for 2^64 - 1)."""
    ca = store.ca_for(ca_id.raw)
    if ca is None:
        raise ValueError(f"no CA {ca_id}")
    cid = _go_id(ca.ca_id)
    lines = []
    for c in sorted(ca.policy.cosigners() - {ca.ca_id}, key=lambda t: (len(t.raw), t.raw)):
        key = store.cosigners[c]
        lines.append(f"cosigner {_go_id(c)} {DEMO_ALG[key.alg]} {b64(x509.spki(key.alg, key.public_key))}")
    policy = ca.policy
    if isinstance(policy, mtc.RequireAll):
        for c in sorted(policy.required - {ca.ca_id}, key=lambda t: (len(t.raw), t.raw)):
            lines.append(f"require-cosigners {cid} {_go_id(c)}")
    elif isinstance(policy, mtc.Quorum):
        done: set[str] = set()

        def emit(q: mtc.Quorum) -> None:
            if q.name in done:
                return
            for x in q.members:
                if isinstance(x, mtc.Quorum):
                    emit(x)
            names = [x.name if isinstance(x, mtc.Quorum) else _go_id(x) for x in q.members]
            lines.append(f"group {q.name} {q.threshold} {' '.join(names)}")
            done.add(q.name)

        emit(policy)
        lines.append(f"require-cosigners {cid} {policy.name}")
    else:
        raise ValueError(f"the demo can't express a {type(policy).__name__} policy")
    for r in ca.revoked:
        lines.append(f"revoke-range {cid} {r.lo} {'max' if r.hi == 1 << 64 else r.hi - 1}")
    for t in ca.trusted_subtrees:
        lines.append(f"trusted-subtree {cid} {t.log_number} {t.start} {t.end} {b64(t.subtree_hash)}")
    return "".join(line + "\n" for line in lines)


_DEMO_ALG_NAMES = {v: k for k, v in DEMO_ALG.items()}
REQUIREMENTS = "all-requirements"  # the root quorum when the demo text has several requirements


def _serial(text: str) -> int:
    """verify.go parseSerial: LOG:INDEX, a decimal serial, or "max" (2^64 - 1)."""
    if text == "max":
        return mtc.UINT64_MAX
    if ":" in text:
        log, index = text.split(":")
        return (int(log) << 48) | int(index)
    return int(text)


def parse_demo_policy(text: str, ca: mtc.CACertificate) -> tuple[dict[TrustAnchorID, mtc.CosignerKey], mtc.CAPolicy]:
    """The demo's policy text for one CA as qTLS configuration (the inverse of :func:`demo_policy`).
    Requirements combine as all-of; a policy that leaves the CA out gets it added (§7.3, D33)."""
    keys: dict[TrustAnchorID, mtc.CosignerKey] = {}
    names: dict[str, TrustAnchorID | mtc.Quorum] = {ca.ca_id.ascii: ca.ca_id}
    required: list[TrustAnchorID | mtc.Quorum] = []
    revoked: list[mtc.RevokedRange] = []
    subtrees: list[mtc.TrustedSubtree] = []
    for raw in text.splitlines():
        f = raw.split("#", 1)[0].split()
        if not f:
            continue
        if f[0] == "cosigner" and len(f) == 4:
            oid, key = x509.parse_spki(base64.b64decode(f[3], validate=True))
            if f[2] not in _DEMO_ALG_NAMES or x509.BY_NAME[_DEMO_ALG_NAMES[f[2]]].spki_oid != oid:
                raise ValueError(f"cosigner {f[1]}: {f[2]} isn't a cosigner algorithm qTLS verifies")
            keys[tai(f[1])] = mtc.CosignerKey(_DEMO_ALG_NAMES[f[2]], key)
            names[f[1]] = tai(f[1])
        elif f[0] == "group" and len(f) >= 4:
            members = tuple(names[n] for n in f[3:])
            k = {"any": 1, "all": len(members)}.get(f[2]) or int(f[2])
            names[f[1]] = mtc.Quorum(f[1], k, members)
        elif f[0] == "require-cosigners" and len(f) == 3 and f[1] in ("all", ca.ca_id.ascii):
            required.append(names[f[2]])
        elif f[0] == "revoke-range" and len(f) == 4 and f[1] == ca.ca_id.ascii:
            revoked.append(mtc.RevokedRange(_serial(f[2]), _serial(f[3]) + 1))
        elif f[0] == "trusted-subtree" and len(f) == 6 and f[1] == ca.ca_id.ascii:
            subtrees.append(mtc.TrustedSubtree(int(f[2]), int(f[3]), int(f[4]), base64.b64decode(f[5], validate=True)))
        elif f[0] not in ("require-cosigners", "revoke-range", "trusted-subtree"):  # another CA's lines are skipped
            raise ValueError(f"policy line {raw!r} isn't one this parser reads")
    policy: mtc.CosignerPolicy
    if all(isinstance(r, TrustAnchorID) for r in required):
        policy = mtc.RequireAll(frozenset({ca.ca_id, *required}))  # type: ignore[list-item]
    elif len(required) == 1 and ca.ca_id in required[0].cosigners():  # type: ignore[union-attr]
        policy = required[0]  # type: ignore[assignment]
    else:
        members = tuple(required) + (() if any(ca.ca_id in _union(r) for r in required) else (ca.ca_id,))
        policy = mtc.Quorum(REQUIREMENTS, len(members), members)
    # demo_policy writes the certificate's own ranges first; read them back once, keep the rest as written.
    own = list(ca.revoked())
    extra = revoked[len(own):] if revoked[: len(own)] == own else revoked
    return keys, mtc.CAPolicy.from_ca_certificate(ca, policy, subtrees, extra)


def _union(member: TrustAnchorID | mtc.Quorum) -> frozenset[TrustAnchorID]:
    return frozenset({member}) if isinstance(member, TrustAnchorID) else member.cosigners()


def demo_store(ca_der: bytes, policy_text: str) -> mtc.MTCTrustStore:
    ca = mtc.parse_ca_certificate(ca_der)
    keys, policy = parse_demo_policy(policy_text, ca)
    return mtc.MTCTrustStore(keys, (policy,))


# --------------------------------------------------------------------------- #
# Go's verdicts and what it printed
# --------------------------------------------------------------------------- #

# Each Go verdict as the qTLS reasons it may correspond to (§7.2 level; D33, D34).
GO_CLASSES: tuple[tuple[re.Pattern[str], frozenset[str]], ...] = tuple((re.compile(p), frozenset(r)) for p, r in (
    (r"signature was not a whole number of bytes$", {"mtc-proof"}),
    (r"malformed MTCProof$", {"mtc-proof"}),
    (r"malformed signature in MTCProof$", {"mtc-proof"}),
    (r"cosigners not in canonical order or duplicate: ", {"mtc-proof"}),
    (r"signature algorithm was not mtcProof$", {"mtc-alg"}),
    (r"unparsable: x509: inner and outer signature algorithm identifiers don't match$", {"mtc-alg"}),
    (r"unparsable: x509: malformed signature$", {"mtc-proof"}),  # BIT STRING padding bits: Go's x509 refuses them
    (r"unparsable: x509: negative serial number$", {"mtc-serial"}),
    (r"malformed TBSCertificate$", {"mtc-alg", "mtc-serial"}),  # Go reads the serial and TBS algorithm together
    (r"certificate serial \d+ is revoked \(range \[\d+, \d+\]\)$", {"mtc-revoked"}),
    (r"invalid log number 0 in serial$", {"mtc-log-number"}),
    (r"inclusion proof evaluation failed: invalid subtree$", {"mtc-not-subtree"}),
    (r"inclusion proof evaluation failed: index not in subtree$", {"mtc-index-range"}),
    (r"inclusion proof evaluation failed: truncated hash in proof$", {"mtc-ragged"}),
    (r"inclusion proof evaluation failed: proof too long$", {"mtc-too-long"}),
    (r"inclusion proof evaluation failed: proof too short$", {"mtc-too-short"}),
    (r"trusted subtree hash mismatch: ", {"mtc-trusted-subtree"}),
    (r"cosigner policy not satisfied$", {"mtc-cosigners"}),
    (r"issuer (\S+ not a known MTC CA|not an MTC CA: .*)$", {"mtc-unknown-ca"}),
))  # fmt: skip


def go_class(verdict: str) -> frozenset[str]:
    """The qTLS reasons a Go rejection may be ("OK" for an accept); unknown verdicts are an error."""
    if verdict == "OK":
        return frozenset({"OK"})
    found = [r for p, r in GO_CLASSES if p.match(verdict)]
    if len(found) != 1:
        raise ValueError(f"no single class for Go's verdict {verdict!r}")
    return found[0]


@dataclass(frozen=True)
class GoResult:
    verdict: str
    cosigned_by: tuple[str, ...] | None = None  # None when Go printed no cosigner section
    groups: tuple[str, ...] | None = None
    trusted: bool = False

    def as_json(self) -> dict:
        lists = {k: None if v is None else list(v) for k, v in (("cosigned_by", self.cosigned_by), ("groups", self.groups))}
        return {"verdict": self.verdict, **lists, "trusted": self.trusted}

    @staticmethod
    def from_json(d: dict) -> GoResult:
        return GoResult(d["verdict"], *(tuple(d[k]) if d[k] is not None else None for k in ("cosigned_by", "groups")),
                        d["trusted"])  # fmt: skip


def run(*args: str | Path, cwd: Path | None = None, env: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True, text=True,
                          env={**os.environ, **env} if env else None)  # fmt: skip


def checked(proc: subprocess.CompletedProcess[str], what: str) -> str:
    if proc.returncode != 0:
        raise RuntimeError(f"{what} failed:\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout


def parse_verify_output(text: str, certs: Iterable[Path]) -> dict[Path, GoResult]:
    """``demo verify``'s per-certificate blocks (verify.go): ``<path>: <verdict>``, then optional
    "- Subtree was trusted" or "- Cosigned by:" / "- Cosigner groups satisfied:" lists, then a blank line."""
    wanted = {f"{c}: ": c for c in certs}
    out: dict[Path, GoResult] = {}
    blocks: list[tuple[Path, str, list[str]]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        head = next((p for p in wanted if line.startswith(p)), None)
        if head is not None:
            current = []
            blocks.append((wanted[head], line[len(head):], current))
        elif not line.strip():
            current = None  # a block ends at its blank line
        elif current is not None:
            current.append(line)
    for cert, verdict, lines in blocks:
        if cert in out:
            raise RuntimeError(f"two verdicts for {cert}")
        lists: dict[str, list[str]] = {}
        section: list[str] | None = None
        for line in lines:
            if line == "- Subtree was trusted":
                lists["trusted"] = []
            elif line in ("- Cosigned by:", "- Cosigner groups satisfied:"):
                section = lists.setdefault(line, [])
            elif line.startswith("- "):
                section = None
            elif line.startswith("    ") and section is not None:
                section.append(line.strip())
        cosigned, groups = (tuple(lists[k]) if k in lists else None for k in ("- Cosigned by:", "- Cosigner groups satisfied:"))
        out[cert] = GoResult(verdict, cosigned, groups, "trusted" in lists)
    return out


def go_verify(binary: Path, ca: Path, policy: Path | None, certs: list[Path]) -> dict[Path, GoResult]:
    """Go's verdict on each certificate, in batches. Go stops at the first certificate it can't parse
    (verify.go), so that one is run alone, where only Go failing to parse *it* is a verdict."""
    def call(batch: list[Path]) -> subprocess.CompletedProcess[str]:
        return run(binary, "verify", "-version", DRAFT_VERSION, "-ca-cert", ca, *(["-policy", policy] if policy else []), *batch)

    out: dict[Path, GoResult] = {}
    rest = list(certs)
    while rest:
        got = parse_verify_output(call(rest).stdout, rest)
        out.update(got)
        rest = [c for c in rest if c not in got]
        if rest:
            out[rest[0]] = GoResult(_unparsable(call(rest[:1]), rest[0]))
            rest = rest[1:]
    return out


def _unparsable(proc: subprocess.CompletedProcess[str], cert: Path) -> str:
    # Only Go failing to parse this certificate is a verdict; any other failure (a policy or CA
    # certificate the demo refuses) is ours and must stop the run.
    text = proc.stdout + proc.stderr
    marker = f'failed to parse certificate from "{cert}": '
    if proc.returncode != 0 and marker in text:
        return "unparsable: " + text.split(marker, 1)[1].strip().splitlines()[0]
    raise RuntimeError(f"expected one verdict for {cert}, got:\n{text}")


def verdict(binary: Path, ca: Path, policy: Path | None, cert: Path) -> str:
    """Go's verdict on one certificate alone."""
    proc = run(binary, "verify", "-version", DRAFT_VERSION, "-ca-cert", ca, *(["-policy", policy] if policy else []), cert)
    text = proc.stdout + proc.stderr
    lines = [line for line in text.splitlines() if line.startswith(f"{cert}: ")]
    if len(lines) == 1:
        return lines[0][len(f"{cert}: "):]
    if not lines:
        return _unparsable(proc, cert)
    raise RuntimeError(f"expected one verdict for {cert}, got:\n{text}")


# --------------------------------------------------------------------------- #
# qTLS's side, and the comparison
# --------------------------------------------------------------------------- #


def qtls_verdict(cert: bytes, store: mtc.MTCTrustStore) -> tuple[str, mtc.VerifiedProof | None]:
    """("OK", proof) or (reason, None), from :func:`qtls.mtc.verify_proof`."""
    try:
        return "OK", mtc.verify_proof(cert, store)
    except AlertError as exc:
        assert exc.reason is not None
        return exc.reason, None


def satisfied_groups(policy: mtc.CosignerPolicy, cosigned: Iterable[str]) -> frozenset[str]:
    """The quorum names ``cosigned`` (dotted IDs) meets, as Go prints "Cosigner groups satisfied"."""
    if not isinstance(policy, mtc.Quorum):
        return frozenset()
    met = policy.satisfied(frozenset(tai(c).raw for c in cosigned))
    return met - {REQUIREMENTS} if policy.name == REQUIREMENTS else met  # the parser's root isn't a demo group


def compare_one(cert: bytes, store: mtc.MTCTrustStore, go: GoResult) -> str | None:
    """None if qTLS agrees with Go on this certificate, else what differs. Agreement is: the same
    accept/reject, a reason in the Go verdict's class, the same quorums met by Go's cosigners, and on an
    accept by step 12 the cosigners that counted (Go's, less any outside the CA and policy)."""
    ours, proof = qtls_verdict(cert, store)
    if ours not in go_class(go.verdict):
        return f"qTLS {ours}, Go {go.verdict!r}"
    ca = store.cas[0]
    if go.cosigned_by is not None:
        if go.groups is None or satisfied_groups(ca.policy, go.cosigned_by) != set(go.groups):
            return f"groups: qTLS {sorted(satisfied_groups(ca.policy, go.cosigned_by))}, Go {go.groups}"
        if proof is not None:
            wanted = {c.ascii for c in ca.policy.cosigners() | {ca.ca_id}}
            mine = {TrustAnchorID(c).ascii for c in proof.valid_cosigners}
            if proof.trusted_subtree is not None or mine != set(go.cosigned_by) & wanted:
                return f"cosigners: qTLS {sorted(mine)}, Go {list(go.cosigned_by)}"
    elif proof is not None and (proof.trusted_subtree is None) == go.trusted:
        return f"trusted subtree: qTLS {proof.trusted_subtree}, Go trusted={go.trusted}"
    return None


def pem(der_bytes: bytes) -> str:
    body = base64.encodebytes(der_bytes).decode()
    return f"-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n"


PEM = re.compile(r"-----BEGIN CERTIFICATE-----\n(.*?)-----END CERTIFICATE-----", re.S)


def pem_der(path: Path) -> bytes:
    m = PEM.search(path.read_text())
    if not m:
        raise RuntimeError(f"{path} has no CERTIFICATE block")
    return base64.b64decode(m.group(1))


def differential(binary: Path, work: Path, ca_der: bytes, policies: Mapping[str, str], certs: Mapping[str, bytes]) -> list[str]:
    """Go and qTLS on every certificate × policy, in ``work`` (kept by the caller on failure): what
    Go said is saved to go.json, so :func:`replay` can recompute qTLS's side without Go."""
    (work / "certs").mkdir(parents=True, exist_ok=True)
    (work / "ca_cert.der").write_bytes(ca_der)
    (work / "ca_cert.pem").write_text(pem(ca_der))
    paths = {}
    for name, cert in certs.items():
        (work / "certs" / f"{name}.der").write_bytes(cert)
        paths[name] = work / "certs" / f"{name}.pem"
        paths[name].write_text(pem(cert))
    go: dict[str, dict[str, dict]] = {name: {} for name in certs}
    for pname, text in policies.items():
        (work / f"policy-{pname}.txt").write_text(text)
        results = go_verify(binary, work / "ca_cert.pem", work / f"policy-{pname}.txt" if text else None, list(paths.values()))
        for name, path in paths.items():
            go[name][pname] = results[path].as_json()
    (work / "go.json").write_text(json.dumps(go, indent=1, sort_keys=True) + "\n")
    return replay(work)


def replay(work: Path) -> list[str]:
    """qTLS's verdicts recomputed against the Go results saved in ``work``: the mismatches."""
    go = json.loads((work / "go.json").read_text())
    ca_der = (work / "ca_cert.der").read_bytes()
    stores = {p.stem.removeprefix("policy-"): demo_store(ca_der, p.read_text()) for p in work.glob("policy-*.txt")}
    out = []
    for name in sorted(go):
        cert = (work / "certs" / f"{name}.der").read_bytes()
        for pname in sorted(go[name]):
            problem = compare_one(cert, stores[pname], GoResult.from_json(go[name][pname]))
            if problem:
                out.append(f"{name} under {pname}: {problem}")
    return out


def keep_failed(work: Path, name: str) -> Path:
    dest = FAILED / name
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(work, dest)
    return dest


# --------------------------------------------------------------------------- #
# Checkpoints (the C2SP signed note the demo writes; parsed here, not in qtls/: §7.4 names no format)
# --------------------------------------------------------------------------- #


def note_key_id(cosigner_id: str, alg: str, public_key: bytes) -> bytes:
    """cosign.go NewCosignerFromConfig: SHA-256(origin ‖ "\\n\\x06" ‖ key)[:4] for ML-DSA-44 (the
    tlog-cosignature scheme), otherwise SHA-256(origin ‖ "\\n\\xffmtc-checkpoint/v1")[:4]."""
    origin = mtc.origin(tai(cosigner_id))
    tail = b"\n\x06" + public_key if alg == "ML-DSA-44" else b"\n\xffmtc-checkpoint/v1"
    return hashlib.sha256(origin + tail).digest()[:4]


def parse_checkpoint(text: str, log: TrustAnchorID, keys: Mapping[TrustAnchorID, mtc.CosignerKey]) -> mtc.ReferenceCheckpoint:
    """The demo's signed-note checkpoint (generate.go): origin, size, base64 root, a blank line, then
    "— <cosigner origin> base64(key ID ‖ uint64 timestamp ‖ signature)" lines. A key ID that doesn't
    match a known cosigner's (the Go rule) is a malformed note."""
    lines = text.split("\n")
    if lines[0] != mtc.origin(log).decode() or lines[3] != "" or lines[-1] != "":
        raise ValueError("not a checkpoint for this log")
    sigs = []
    for line in lines[4:-1]:
        dash, name, payload = line.split(" ")
        cid = name.removeprefix("oid/1.3.6.1.4.1.")
        raw = base64.b64decode(payload, validate=True)
        if dash != "—" or not name.startswith("oid/1.3.6.1.4.1.") or len(raw) < 12:
            raise ValueError(f"bad signature line {line[:60]!r}")
        key = keys.get(tai(cid))
        if key is not None and raw[:4] != note_key_id(cid, key.alg, key.public_key):
            raise ValueError(f"{cid}: key ID {raw[:4].hex()} isn't the demo's for this key")
        sigs.append(mtc.CheckpointSignature(tai(cid).raw, int.from_bytes(raw[4:12], "big"), raw[12:]))
    return mtc.ReferenceCheckpoint(int(lines[1]), base64.b64decode(lines[2], validate=True), tuple(sigs))


def tile_leaf_hashes(tiles: Path, size: int) -> bytes:
    """The level-0 hashes (each entry's leaf hash) of the tlog tiles the demo writes (generate.go):
    tile/0/NNN holds 256, the last partial tile is tile/0/NNN.p/<count>. Fewer than 256,000 entries."""
    out = b""
    for i in range((size + 255) // 256):
        full = tiles / "0" / f"{i:03d}"
        out += (full if full.is_file() else tiles / "0" / f"{i:03d}.p" / str(size - 256 * i)).read_bytes()
    if len(out) != 32 * size:
        raise RuntimeError(f"{tiles}: {len(out)} bytes of leaf hashes for {size} entries")
    return out


def leaf_tree(leaf_hashes: bytes) -> merkle.Tree:
    return merkle.Tree(len(leaf_hashes) // 32, {i: leaf_hashes[32 * i: 32 * i + 32] for i in range(len(leaf_hashes) // 32)})


def corpus_tree(certs: Iterable[bytes], size: int) -> merkle.Tree:
    """The log a corpus' certificates come from: each one's entry at its index, null_entry elsewhere."""
    leaves = {}
    for cert in certs:
        split = mtc.split_certificate(cert)
        value = split.signature_value.contents[1:]
        extensions_raw = value[: 2 + int.from_bytes(value[:2], "big")]
        leaves[split.tbs.serial & mtc.UINT48_MAX] = mtc.entry_hash(split.tbs, extensions_raw)
    return merkle.Tree(size, leaves, merkle.leaf_hash(mtc.NULL_LOG_ENTRY))


def landmark_document(marks: list[dict], expiry: int, now: dt.datetime) -> bytes:
    """The §6.4.3 document for the landmarks the demo printed, each expiring at ``expiry``."""
    seq = [mtc.Landmark(0, 0, 0)] + [mtc.Landmark(m["landmark"], m["tree_size"], expiry) for m in marks]
    return mtc.encode_landmarks(seq, now)


def subtree_proofs(tree: merkle.Tree, marks: list[dict], reference_size: int) -> tuple[mtc.SubtreeProof, ...]:
    return tuple(mtc.SubtreeProof(s["start"], s["end"], tree.hash(s["start"], s["end"]),
                                  tree.consistency_proof(s["start"], s["end"], reference_size))
                 for m in marks if m["tree_size"] <= reference_size for s in m["subtrees"])  # fmt: skip


DERIVE_NOW = dt.datetime(2026, 2, 1, tzinfo=dt.timezone.utc)
DERIVE_EXPIRY = int(dt.datetime(2026, 4, 1, tzinfo=dt.timezone.utc).timestamp())  # = the corpora's notAfter at most


def derived_ca(store: mtc.MTCTrustStore, ca_id: TrustAnchorID, log_number: int, checkpoint: mtc.ReferenceCheckpoint,
               tree: merkle.Tree, marks: list[dict]) -> mtc.DerivedLandmarks:  # fmt: skip
    """§7.4 against a demo checkpoint: the landmarks it printed, qTLS's proofs over the same log."""
    doc = mtc.decode_landmarks(landmark_document(marks, DERIVE_EXPIRY, DERIVE_NOW), DERIVE_NOW)
    update = mtc.LogLandmarks(log_number, doc, checkpoint, subtree_proofs(tree, marks, checkpoint.size))
    return mtc.derive_landmarks(store, ca_id, [update], max_active_landmarks=len(marks), now=DERIVE_NOW)


# --------------------------------------------------------------------------- #
# Building and vendoring
# --------------------------------------------------------------------------- #


GO_ENV = {"GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly"}


def prepare(go: Path, src: Path | None) -> Path:
    version = checked(run(go, "version", env=GO_ENV), "go version").split()[2]
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
    checked(run(go, "build", "-o", binary.resolve(), ".", cwd=src / "demo", env=GO_ENV), "go build")
    return binary


LANDMARK = re.compile(r"^\s+Landmark subtree \[(\d+), (\d+)\) with hash (\S+)$")
LANDMARK_HEAD = re.compile(r"^Landmark (\d+) at tree size (\d+):$")


def landmarks(stdout: str) -> list[dict]:
    out, current = [], None
    for line in stdout.splitlines():
        if (m := LANDMARK_HEAD.match(line)):
            current = {"landmark": int(m[1]), "tree_size": int(m[2]), "subtrees": []}
            out.append(current)
        elif (m := LANDMARK.match(line)) and current is not None:
            current["subtrees"].append({"start": int(m[1]), "end": int(m[2]), "hash": m[3]})
    return out


def generate(binary: Path, config: Path, out: Path) -> tuple[str, list[dict]]:
    stdout = checked(run(binary, "generate", "-config", config, "-out", out), f"generate {config}")
    marks = landmarks(stdout)
    if not marks:
        raise RuntimeError(f"generate {config} printed no landmarks")
    return stdout, marks


def wg_sample_policy(src: Path) -> str:
    """The WG's sample policy (demo/policy.txt) without its ML-DSA-87 cosigner, which qTLS can't verify."""
    lines = []
    for line in (src / "demo" / "policy.txt").read_text().splitlines():
        f = line.split("#", 1)[0].split()
        if f[:2] == ["cosigner", WG_EXCLUDED]:
            continue
        if f[:1] == ["group"] and WG_EXCLUDED in f:
            line = " ".join(x for x in f if x != WG_EXCLUDED)
        lines.append(line)
    text = "\n".join(lines) + "\n"
    if WG_EXCLUDED in text.split("# Import the cosigners", 1)[1]:
        raise RuntimeError("the WG sample policy still names the ML-DSA-87 cosigner")
    return text


def qtls_policies(ca: mtc.CACertificate, derived: mtc.CAPolicy) -> dict[str, mtc.CAPolicy]:
    """The relying-party policies the qtls corpus is verified under (D34, D35, D36)."""
    ca_id, (c1, c2, c3) = ca.ca_id, (ca.ca_id.child(1), ca.ca_id.child(2), ca.ca_id.child(3))
    two_of_three = mtc.Quorum("two-of-three", 2, (c1, c2, c3))
    deep = mtc.Quorum("deep", 2, (c2, c3))
    revoked = (mtc.RevokedRange((LOG_NUMBER << 48) | REVOKED_FIRST, ((LOG_NUMBER << 48) | REVOKED_LAST) + 1),
               mtc.RevokedRange(4 << 48, 1 << 64))  # fmt: skip
    return {
        "ca-only": mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({ca_id}))),
        "ca-and-1": mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({ca_id, c1}))),
        "ca-and-2": mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({ca_id, c2}))),
        "quorum-2-of-3": mtc.CAPolicy.from_ca_certificate(ca, mtc.Quorum("ca-and-two-of-three", 2, (ca_id, two_of_three))),
        "nested": mtc.CAPolicy.from_ca_certificate(ca, mtc.Quorum("nested", 2, (ca_id, mtc.Quorum("inner", 1, (c1, deep))))),
        "revoked": mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({ca_id})), (), revoked),
        "landmarks-derived": derived,
    }


def corpus(binary: Path, name: str, config: Path, src: Path, extra_policies: str = "") -> dict:
    out = OUT / name
    cfg = json.loads(config.read_text())
    with tempfile.TemporaryDirectory() as tmp:
        gen = Path(tmp) / "out"
        _, marks = generate(binary, config, gen)
        if out.exists():
            shutil.rmtree(out)
        (out / "certs").mkdir(parents=True)
        ca_der = pem_der(gen / "ca_cert.pem")
        (out / "ca_cert.der").write_bytes(ca_der)
        checkpoint_text = (gen / "checkpoint").read_text()
        (out / "checkpoint").write_text(checkpoint_text)
        (out / "landmarks.json").write_text(json.dumps(marks, indent=1) + "\n")
        pems = sorted(gen.glob("cert_*.pem"), key=lambda p: [int(x) for x in re.findall(r"\d+", p.name)])
        certs = {}
        for p in pems:
            try:
                certs[p.stem] = pem_der(p)
            except (RuntimeError, ValueError) as exc:
                raise RuntimeError(f"{p}: {exc}") from None
            (out / "certs" / f"{p.stem}.der").write_bytes(certs[p.stem])

        ca = mtc.parse_ca_certificate(ca_der)
        log_number = cfg["LogNumber"]
        hand = "".join(f"trusted-subtree {ca.ca_id} {log_number} {s['start']} {s['end']} {s['hash']}\n"
                       for mk in marks for s in mk["subtrees"])  # fmt: skip
        base = mtc.MTCTrustStore({}, (mtc.CAPolicy.from_ca_certificate(ca, mtc.RequireAll(frozenset({ca.ca_id}))),))
        checkpoint = parse_checkpoint(checkpoint_text, mtc.log_id(ca.ca_id, log_number), base.cosigners)
        leaf_hashes = tile_leaf_hashes(gen / "tile", checkpoint.size)
        (out / "leaf_hashes.bin").write_bytes(leaf_hashes)
        tree = leaf_tree(leaf_hashes)
        if tree.hash(0, checkpoint.size) != checkpoint.root_hash:
            raise RuntimeError(f"{name}: the demo's tiles don't hash to its checkpoint")
        derived = derived_ca(base, ca.ca_id, log_number, checkpoint, tree, marks)
        if derived.discarded:
            raise RuntimeError(f"{name}: landmarks discarded: {derived.discarded}")
        if name == "qtls":
            keys = cosigner_keys()
            texts = {p: demo_policy(mtc.MTCTrustStore(keys, (c,)), ca.ca_id) for p, c in qtls_policies(ca, derived.ca).items()}
        else:
            texts = {"ca-only": demo_policy(base, ca.ca_id),
                     "landmarks-derived": demo_policy(base.with_derived(derived), ca.ca_id),
                     "wg-sample": wg_sample_policy(src)}  # fmt: skip
        texts["landmarks"] = hand
        for pname, body in texts.items():
            (out / f"policy-{pname}.txt").write_text(body)
        paths = {p.stem: p for p in pems}
        verdicts: dict[str, dict[str, str]] = {stem: {} for stem in paths}
        details: dict[str, dict[str, dict]] = {stem: {} for stem in paths}
        for pname, body in texts.items():
            results = go_verify(binary, gen / "ca_cert.pem", (out / f"policy-{pname}.txt") if body else None, list(paths.values()))
            for stem, p in paths.items():
                verdicts[stem][pname] = results[p].verdict
                details[stem][pname] = results[p].as_json()
        (out / "verdicts.json").write_text(json.dumps(verdicts, indent=1, sort_keys=True) + "\n")
        (out / "details.json").write_text(json.dumps(details, indent=1, sort_keys=True) + "\n")
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
        f"`go version`; installed by scripts/install_go.sh from the go.dev tarball, sha256 checked: "
        f"darwin-arm64 {GO_TARBALL_SHA256['darwin-arm64']}, linux-amd64 {GO_TARBALL_SHA256['linux-amd64']}); "
        f"draft version {DRAFT_VERSION}",
        "corpora: wg = the demo's own demo/mtc.json; qtls = scripts/mtc_demo.py qtls_config() (qTLS profile and fixture keys)",
        "policies: qTLS CAPolicy objects rendered by scripts/mtc_demo.py demo_policy(); wg-sample = demo/policy.txt "
        f"without the ML-DSA-87 cosigner {WG_EXCLUDED}; landmarks = the demo's printed landmark subtrees; "
        "landmarks-derived = qTLS's §7.4 derivation against the demo's checkpoint",
        "verdicts: `demo verify` per policy file; details: its 'Cosigned by' and 'Cosigner groups satisfied' lists; "
        "signatures are randomized, so a regeneration differs in signature bytes",
        "regenerate: OQS_INSTALL_PATH=.oqs python scripts/mtc_demo.py",
        "oracle: independent (the MTC WG's reference implementation)",
    ]
    for path in sorted(p for p in OUT.rglob("*") if p.is_file() and p.name != "SOURCE"):
        lines.append(f"sha256 {path.relative_to(OUT)}: {hashlib.sha256(path.read_bytes()).hexdigest()}")
    (OUT / "SOURCE").write_text("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--go", type=Path, default=ROOT / ".go" / "bin" / "go")
    ap.add_argument("--src", type=Path, default=None)
    ap.add_argument("--build-only", action="store_true", help="build the pinned demo into .mtc-demo/demo and stop")
    ap.add_argument("--replay", type=Path, default=None, help="re-run a saved live differential's comparison")
    args = ap.parse_args(argv)
    if args.replay is not None:
        problems = replay(args.replay)
        print("\n".join(problems) or "qTLS agrees with the saved Go results")
        sys.exit(1 if problems else 0)
    binary = prepare(args.go, args.src)
    if args.build_only:
        print(f"built {binary}")
        return
    src = args.src or WORK / "src"
    with tempfile.TemporaryDirectory() as tmp:
        qcfg = Path(tmp) / "qtls.json"
        qcfg.write_text(json.dumps(qtls_config(), indent=1) + "\n")
        OUT.mkdir(parents=True, exist_ok=True)
        corpus(binary, "wg", src / "demo" / "mtc.json", src)
        corpus(binary, "qtls", qcfg, src)
        (OUT / "wg_kat.json").write_text(json.dumps(wg_kats(src), indent=1) + "\n")
    write_source()
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
