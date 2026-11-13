"""Security-level pairing: the single source of every level-dependent choice.

Comparisons are made only *within* a level (docs/PLAN.md §3). Code outside
qtls/crypto.py must not infer a pairing from the algorithms' NIST categories;
it reads this table instead (tests/test_levels.py enforces that).
"""

from __future__ import annotations

from dataclasses import dataclass

# RFC 10024 hybrid key exchange, the same at every level (specs.md §2, D16).
KEY_EXCHANGE_GROUP = 0x11EC

# Config A: today's web. Not part of any level; it's the classical baseline.
BASELINE_SIGNATURE = "ECDSA-P256-SHA256"


@dataclass(frozen=True)
class Level:
    name: str
    auth_kem: str  # AuthKEM certificate key (configs D, E; specs.md D11)
    leaf_signatures: tuple[str, ...]  # certificate key for signature auth (B, C)
    issuer_signatures: tuple[str, ...]  # X.509 intermediate/root/SCT signer (specs.md D19)
    mtc_cosigner: str  # MTC standalone cosignatures (specs.md D14)


LEVELS: dict[str, Level] = {
    "cat1-2": Level(
        name="cat1-2",
        auth_kem="ML-KEM-512",
        leaf_signatures=("ML-DSA-44", "Falcon-512"),
        issuer_signatures=("ML-DSA-44", "Falcon-512"),
        mtc_cosigner="ML-DSA-44",
    ),
    "cat3": Level(
        name="cat3",
        auth_kem="ML-KEM-768",
        leaf_signatures=("ML-DSA-65",),
        issuer_signatures=("ML-DSA-65",),
        mtc_cosigner="ML-DSA-65",
    ),
}
