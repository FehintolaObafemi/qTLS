"""Named points of the configuration matrix for signature authentication (PLAN §3).

Config A is today's web: ECDSA-P256 leaf and issuers. Config B is a
post-quantum signature leaf with issuers chosen per specs.md D19, from the
same level in qtls/levels.py. SCT counts are 0 or 2. Each client offers only
its own configuration's schemes, so a client of one configuration and a
server of another fail to negotiate (P8, D25).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass

from qtls import chains, crypto, x509
from qtls.handshake import DEFAULT_BACKENDS, ClientConfig, Randomness, ServerConfig, SystemRandomness
from qtls.levels import BASELINE_SIGNATURE, LEVELS

SCT_COUNTS = (0, 2)


@dataclass(frozen=True)
class SigConfig:
    name: str
    leaf_alg: str
    issuer_alg: str
    scts: int = 0

    def __post_init__(self) -> None:
        if self.scts not in SCT_COUNTS:
            raise ValueError(f"SCT count must be one of {SCT_COUNTS}")
        baseline = self.leaf_alg == self.issuer_alg == BASELINE_SIGNATURE
        in_level = any(
            self.leaf_alg in lv.leaf_signatures and self.issuer_alg in lv.issuer_signatures for lv in LEVELS.values()
        )
        if not (baseline or in_level):
            raise ValueError(f"{self.leaf_alg} leaf with {self.issuer_alg} issuers isn't a configuration (D19)")

    def schemes(self) -> tuple[tuple[int, ...], tuple[int, ...] | None]:
        """(signature_algorithms, signature_algorithms_cert or None) for the client."""
        leaf = x509.BY_NAME[self.leaf_alg].codepoints[:1]
        if self.issuer_alg == self.leaf_alg:
            return leaf, None
        return leaf, x509.BY_NAME[self.issuer_alg].codepoints[:1]


def config_a(scts: int = 0) -> SigConfig:
    return SigConfig("A" if scts == 0 else f"A/{scts}", BASELINE_SIGNATURE, BASELINE_SIGNATURE, scts)


CONFIG_A = config_a()


def config_b(leaf_alg: str, issuer_alg: str | None = None, scts: int = 0) -> SigConfig:
    if leaf_alg == BASELINE_SIGNATURE:
        raise ValueError("config B has a post-quantum leaf; ECDSA is config A")
    return SigConfig(f"B/{leaf_alg}/{issuer_alg or leaf_alg}/{scts}", leaf_alg, issuer_alg or leaf_alg, scts)


def endpoints(
    config: SigConfig,
    *,
    not_before: dt.datetime,
    now: dt.datetime,
    client_randomness: Randomness | None = None,
    server_randomness: Randomness | None = None,
    backends: Mapping[str, crypto.Backend] = DEFAULT_BACKENDS,
    fixture_seed: bytes = b"qtls fixture v1",
) -> tuple[ClientConfig, ServerConfig, chains.Chain]:
    chain = chains.build_chain(
        leaf_alg=config.leaf_alg, issuer_alg=config.issuer_alg, scts=config.scts,
        not_before=not_before, fixture_seed=fixture_seed,
    )  # fmt: skip
    # The server signs on the configured backend (seeded keys are the same on every backend).
    signing_key = chains.signing_key(config.leaf_alg, fixture_seed, "leaf", backend=backends[config.leaf_alg])
    assert chain.leaf_signing_key is not None and signing_key.public_key == chain.leaf_signing_key.public_key
    sig_algs, sig_algs_cert = config.schemes()
    client = ClientConfig(
        anchors=(chain.anchor,), signature_algorithms=sig_algs, signature_algorithms_cert=sig_algs_cert,
        now=now, randomness=client_randomness or SystemRandomness(), backends=backends,
    )  # fmt: skip
    server = ServerConfig(
        cert_data=chain.cert_data, signing_key=signing_key,
        randomness=server_randomness or SystemRandomness(), backends=backends,
    )  # fmt: skip
    return client, server, chain
