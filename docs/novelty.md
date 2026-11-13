# Novelty statement

*Phase 0 deliverable, 2026-11-13. The search wasn't exhaustive: revisit before writing up results (Phase 6).*

## Closest prior work

| Work | What it does | What it doesn't do |
|---|---|---|
| Schwabe, Stebila, Wiggers, *Post-Quantum TLS Without Handshake Signatures* (CCS 2020) and the KEMTLS line of papers | Introduces KEMTLS; implements and benchmarks it against signature-based PQ TLS, including on embedded devices. **Probably** already used level-matched parameters (including Falcon) and emulated networks (RTT, loss). This is from memory and not yet verified. | No Merkle Tree Certificates; X.509 chains with round-3 candidates; predates AuthKEM -08 and ML-KEM |
| Schwabe, Stebila, Wiggers, *More efficient post-quantum KEMTLS with pre-distributed public keys* (KEMTLS-PDK, ESORICS 2021) | Implements and measures the pre-distributed-key variant | No MTC; predates the authkem-psk drafts |
| T. Wiggers, *Post-Quantum TLS*, PhD thesis (2024) | The consolidated KEMTLS and AuthKEM work, cited by AuthKEM -08 §5.3 | Not yet read; check for MTC content |
| `draft-celi-wiggers-tls-authkem-08` | Specifies AuthKEM for TLS 1.3 and includes size tables | Calls MTC "complementary" (§1.4.2) without measuring the combination; no ML-KEM codepoints; no test vectors |
| M. Pohl, *Implementation and Analysis of Merkle Tree Certificates for Post-Quantum Secure Authentication in TLS*, Radboud MSc thesis (Jan 2025) | Analytical byte and CPU-cycle counts for MTC vs X.509 at classical and PQ levels. MTC implemented in Rustls (with **signatures**). Counts one ML-KEM-768 row with MTC and concludes the KEM saves about 1,460 bytes either way, a larger *relative* gain with MTC. | Says it ignores the difference between KEM and signature authentication in its analysis. Doesn't implement KEMTLS/AuthKEM. Uses the old batch/tree-head MTC design (`draft-davidben-…-03`), not -08 landmarks and standalone certificates. No network emulation, latency, round-trip or initcwnd measurements. No security-level matching. No Falcon baseline. |
| Recent MTC measurement papers (for example arXiv 2604.04191 on MTC for Kubernetes/5G; arXiv 2604.24869 on PQ chain size vs time to first byte) | MTC and PQ chain benchmarks | Signature authentication only, as far as the search showed |
| Cloudflare–Chrome MTC experiment (2026) | MTC measured on real traffic | Signature authentication; no AuthKEM |

## What qTLS adds

1. **An implemented and measured AuthKEM + MTC handshake**, against the current specs (AuthKEM -08, MTC -08 with landmark-relative and standalone certificates and fallback, RFC 10024 hybrid key exchange). Prior work counted this combination on paper at most.
2. **Level-matched, network-level comparisons applied to AuthKEM -08 + MTC -08.** The KEMTLS papers probably already did level matching and network emulation for KEMTLS with X.509 (to be verified). What's new here is doing it for this combination, with round trips to *implicit* and *explicit* authentication reported separately, and the initcwnd threshold under MTC's smaller flights.
3. **Per-role CPU** measured as operation counts × C-level cost, recorded with backend and build.

Before Phase 6, read Wiggers (2024) and SSW20 §6 to confirm points 1 and 2 still hold.

## Prior result to reproduce

Pohl's 1,460-byte saving (ML-DSA-44 key and signature → ML-KEM-768 key and ciphertext) is plain arithmetic on primitive sizes: (1312 + 2420) − (1184 + 1088) = 1460, which is also AuthKEM -08 Table 1. It's a **sanity check**, not an independent oracle: qTLS adds SPKI encoding and record framing, so its total difference will be larger. Note also that the pairing crosses levels (ML-DSA-44 is category 2, ML-KEM-768 category 3).

## Sources

- [Pohl, Radboud MSc thesis (2025)](https://www.cs.ru.nl/masters-theses/2025/M_Pohl___Implementation_and_Analysis_of_Merkle_Tree_Certificates_for_Post-Quantum_Secure_Authentication_in_TLS.pdf)
- [KEMTLS (2020)](https://cryptojedi.org/papers/kemtls-20200507.pdf)
- KEMTLS-PDK (ESORICS 2021) and Wiggers' PhD thesis (2024): cited by AuthKEM -08 §5.3
- [KEMTLS vs PQ TLS on embedded systems](https://kemtls.org/publication/kemtls-embedded/kemtls-embedded.pdf)
- [AuthKEM -08](https://www.ietf.org/archive/id/draft-celi-wiggers-tls-authkem-08.html)
- [MTC PKI for Kubernetes / 5G (arXiv 2604.04191)](https://arxiv.org/abs/2604.04191)
- [PQ chain size and time to first byte (arXiv 2604.24869)](https://arxiv.org/abs/2604.24869)
