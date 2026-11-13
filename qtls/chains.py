"""Deterministic certificate chains for the configuration matrix (specs.md D19, D24).

A chain is root → intermediate → leaf. The root is the trust anchor and isn't
sent. Every key and every signature is derived from a fixture seed and the
role ("root", "intermediate", "leaf", "sct0", ...), so the same inputs always
give the same bytes: Falcon and ECDSA signature lengths vary, and Phase 5
reports bytes on the wire.

Signature keys use the liboqs backend for ML-DSA and Falcon (OpenSSL can't
sign ML-DSA deterministically) and OpenSSL for ECDSA (RFC 6979).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from qtls import crypto, x509

VALIDITY = dt.timedelta(days=90)


def _derive(fixture_seed: bytes, role: str, length: int) -> bytes:
    out, counter = b"", 0
    while len(out) < length:
        out += crypto.sha256(fixture_seed + role.encode() + bytes([counter])).digest()
        counter += 1
    return out[:length]


def signing_key(alg: str, fixture_seed: bytes, role: str) -> crypto.SigPrivateKey:
    params = crypto.SIGNATURES[alg]
    backend: crypto.Backend = "openssl" if alg == "ECDSA-P256-SHA256" else "liboqs"
    for attempt in range(256):
        seed = _derive(fixture_seed, f"{role}/key/{attempt}", params.seed_len)
        if alg == "ECDSA-P256-SHA256" and not 0 < int.from_bytes(seed, "big") < crypto.P256_ORDER:
            continue  # astronomically rare; try the next derivation
        return crypto.sig_generate(alg, backend, seed=seed)
    raise RuntimeError("could not derive an ECDSA scalar")  # pragma: no cover


def signing_seed(alg: str, fixture_seed: bytes, role: str) -> bytes:
    return _derive(fixture_seed, f"{role}/sign", crypto.SIGNATURES[alg].sign_seed_len)


@dataclass(frozen=True)
class Chain:
    anchor: x509.TrustAnchor
    root_der: bytes
    cert_data: tuple[bytes, ...]  # what the server sends: leaf, intermediate
    leaf_alg: str
    leaf_signing_key: crypto.SigPrivateKey | None  # None for KEM leaves
    leaf_kem_key: crypto.KEMPrivateKey | None
    issuer_alg: str
    scts: int

    @property
    def size(self) -> int:
        return sum(len(c) for c in self.cert_data)


def build_chain(
    *,
    leaf_alg: str,
    issuer_alg: str,
    scts: int = 0,
    server_name: str = "qtls.test",
    not_before: dt.datetime,
    fixture_seed: bytes = b"qtls fixture v1",
) -> Chain:
    """A deterministic chain; ``leaf_alg`` may be a signature algorithm or (Phase 4) a KEM."""
    not_after = not_before + VALIDITY
    root_key = signing_key(issuer_alg, fixture_seed, "root")
    inter_key = signing_key(issuer_alg, fixture_seed, "intermediate")
    root_spki = x509.spki(issuer_alg, root_key.public_key)
    inter_spki = x509.spki(issuer_alg, inter_key.public_key)

    leaf_sig = leaf_kem = None
    if x509.BY_NAME[leaf_alg].kind == "sig":
        leaf_sig = signing_key(leaf_alg, fixture_seed, "leaf")
        leaf_spki, usage = x509.spki(leaf_alg, leaf_sig.public_key), {x509.DIGITAL_SIGNATURE}
    else:
        leaf_kem = crypto.kem_generate(
            leaf_alg, "liboqs" if leaf_alg == "ML-KEM-512" else "openssl",
            seed=_derive(fixture_seed, "leaf/kem", 64),
        )  # fmt: skip
        leaf_spki, usage = x509.spki(leaf_alg, leaf_kem.public_key), {x509.KEY_ENCIPHERMENT}

    def seed(role: str) -> bytes:
        return signing_seed(issuer_alg, fixture_seed, role)

    root = x509.issue(
        subject_cn="qTLS root", subject_spki=root_spki, issuer_cn="qTLS root", issuer_key=root_key,
        issuer_spki=root_spki, serial=1, not_before=not_before, not_after=not_after,
        signing_seed=seed("root"), ca=True,
    )  # fmt: skip
    inter = x509.issue(
        subject_cn="qTLS intermediate", subject_spki=inter_spki, issuer_cn="qTLS root",
        issuer_key=root_key, issuer_spki=root_spki, serial=2, not_before=not_before,
        not_after=not_after, signing_seed=seed("intermediate"), ca=True, path_len=0,
    )  # fmt: skip
    sct_specs = [
        x509.SctSpec(signing_key(issuer_alg, fixture_seed, f"log{i}"), 1_700_000_000_000 + i, seed(f"sct{i}"))
        for i in range(scts)
    ]
    leaf = x509.issue(
        subject_cn=server_name, subject_spki=leaf_spki, issuer_cn="qTLS intermediate",
        issuer_key=inter_key, issuer_spki=inter_spki, serial=3, not_before=not_before,
        not_after=not_after, signing_seed=seed("leaf"), key_usage=usage,
        dns_names=[server_name], scts=sct_specs,
    )  # fmt: skip
    return Chain(
        anchor=x509.TrustAnchor.from_certificate(root), root_der=root, cert_data=(leaf, inter),
        leaf_alg=leaf_alg, leaf_signing_key=leaf_sig, leaf_kem_key=leaf_kem,
        issuer_alg=issuer_alg, scts=scts,
    )  # fmt: skip
