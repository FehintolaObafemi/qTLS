# qTLS project plan: AuthKEM + Merkle Tree Certificates

*Drafted 2026-11-13. Revisit at the end of each phase.*

## 1. Goal

Build and measure a TLS 1.3–shaped handshake that is post-quantum for **both** key exchange and server authentication. Authentication uses a KEM rather than a signature (AuthKEM), and the certificate is a Merkle Tree Certificate (MTC). Compare it against today's web and the other post-quantum candidates (configs A–E in the [README](../README.md)).

**Research question:** does AuthKEM + MTC (config E) beat signature-based post-quantum TLS (B, C) on handshake size, latency and server CPU? And what does it cost in round trips, deployment complexity and security properties?

## 2. Landscape (as of November 2026)

These checks shaped the plan. Re-verify them in Phase 0.

| Fact | Implication for qTLS |
|---|---|
| Hybrid ML-KEM key exchange is the default in major browsers and CDNs. | Key exchange is solved. Use `X25519MLKEM768` in every config, so it isn't something we vary. |
| ML-DSA web certificates aren't publicly trusted yet; `draft-ietf-tls-mldsa` is still in the IETF process. | Post-quantum server authentication is the real open gap. |
| Chrome favours MTCs for post-quantum web PKI (draft-only root policy, August 2026). A Cloudflare–Chrome experiment reportedly found MTC handshakes faster than classical chains. | Treat MTCs as the **realistic baseline** (config C), not plain ML-DSA chains. Our contribution must improve on C. |
| MTCs remove CA signatures from the chain, but the server's `CertificateVerify` signature and post-quantum public key remain. | That leftover signature (about 2.4 KB for ML-DSA-44, plus signing cost) is the specific target for AuthKEM. |
| The TLS AuthKEM draft is an individual draft without TLS working-group adoption. The LAKE working group adopted a KEM-auth variant for EDHOC. | There's room for independent evidence. Combining AuthKEM with MTCs doesn't appear to have been benchmarked yet; confirm this in Phase 0. |

## 3. Scope

**In:**
- A handshake prototype for configs A–E with byte-accurate messages.
- A key schedule and record encryption close to TLS 1.3.
- A minimal MTC issuer: batch tree, inclusion proof, tree-head distribution stub.
- A benchmark harness, notebooks and a results write-up.

**Out:**
- Interop with real TLS stacks.
- Full X.509 and ASN.1 fidelity: approximate sizes with realistic encodings and document the gaps.
- Resumption and 0-RTT, except as a stretch goal (AuthKEM-PSK).
- Client authentication.
- QKD and new primitives.

## 4. Phases

Twelve weeks, matching the original plan's length. Each phase has an exit criterion. Don't start the next phase until it's met.

### Phase 0: Literature check (week 1)
- Read the KEMTLS paper (CCS 2020), the KEMTLS-PDK follow-up, the `draft-celi-wiggers-tls-authkem` text, and the MTC draft.
- Search for prior work that combines AuthKEM with MTCs. If it exists, re-scope toward extending it (for example, loss and latency profiles or constrained clients) rather than repeating it.
- Write `docs/threat-model.md`: a network attacker who will have a quantum computer later, and the security properties we target or knowingly give up.

**Exit:** a one-page novelty statement and threat model, reviewed and committed.

### Phase 1: Repository reset (week 2)
- Move legacy files into `legacy/` with a `legacy/README.md` explaining that they're broken. Delete `obj/` and add a `.gitignore`.
- Add `pyproject.toml` with `liboqs-python`, `cryptography`, `pytest`, `jupyter` and `matplotlib` pinned, plus a GitHub Actions CI job that runs `pytest`.
- Write a smoke test proving ML-KEM-768 and ML-DSA-44 round-trip through `liboqs-python`.

**Exit:** `pytest` passes in CI on a fresh clone.

### Phase 2: Baseline handshakes A and B (weeks 3–4)
- Build `qtls/messages.py`: byte-level encoders and decoders for ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify and Finished.
- Build `qtls/keyschedule.py`: the TLS 1.3 HKDF key schedule. Test it against RFC 8448 vectors wherever classical X25519 parts allow.
- Implement configs A (ECDSA chain) and B (ML-DSA chain) over TCP sockets.

**Exit:** A and B complete handshakes, exchange encrypted application data, and reject a tampered certificate or signature in tests.

### Phase 3: Merkle Tree Certificates, config C (weeks 5–6)
- Build `qtls/mtc.py`: a batch issuer, inclusion proofs, and a client-side tree-head store.
- Add a config where the Certificate message carries an MTC and CertificateVerify stays ML-DSA.

**Exit:** C works end to end. Tests cover a stale tree head and a bad inclusion proof.

### Phase 4: AuthKEM, configs D and E (weeks 7–8)
- Implement the AuthKEM message flow and key schedule changes from the draft:
  - The client encapsulates to the server's certificate KEM key.
  - The authenticated handshake secret mixes both KEM shared secrets.
  - There's no CertificateVerify, and Finished messages confirm the keys.
- Add a "cached server key" variant, following KEMTLS-PDK, to measure the version without the extra round trip.

**Exit:** D and E work end to end. Tests show that a server without the KEM private key can't complete the handshake.

### Phase 5: Benchmarks (weeks 9–10)
- Build `bench/run.py`: sweep configs A–E across RTT (10, 50, 150, 300 ms), loss (0%, 1%, 3%), and TCP initial window (10 segments, about 14.6 KB).
- Metrics:
  - bytes per flight
  - round trips to the first authenticated application byte, for both client and server
  - handshake latency (p50/p95)
  - server and client CPU per handshake
- Run every point at least 1,000 times. Record the machine spec and library versions with each results file.

**Exit:** a single command reproduces `results/*.csv` from a clean checkout.

### Phase 6: Analysis and write-up (weeks 11–12)
- Write `notebooks/01–05`: one walkthrough per config, plus a results notebook that regenerates every chart from `results/`.
- Write `docs/results.md`: findings, threats to validity, and recommendations.
- Stretch goals:
  - a Tamarin model of config E's key schedule
  - AuthKEM-PSK resumption
  - FN-DSA (Falcon) as an extra signature baseline

**Exit:** README "Results" section filled in, plus a tagged `v0.1` release.

## 5. Proposed layout

```
qtls/          handshake prototype (messages, key schedule, configs A–E, mtc)
bench/         benchmark harness + network emulation
notebooks/     walkthroughs + results
results/       raw benchmark CSVs (committed, small)
docs/          PLAN.md, threat-model.md, results.md
tests/         pytest suite
legacy/        2023 QKD/QCA experiments (broken, historical)
```

## 6. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| AuthKEM + MTC has already been studied | Medium | Phase 0 checks. If so, pivot to new conditions (lossy or mobile networks, constrained clients) or to formal verification. |
| Prototype sizes diverge from real TLS encodings | Medium | Use real TLS 1.3 framing, document each simplification, and cross-check config A's sizes against an OpenSSL capture. |
| `liboqs-python` API or algorithm-name churn | Low–medium | Pin versions, and keep a thin wrapper module so only one file changes. |
| Python timing noise hides CPU differences | High | Report CPU with `liboqs`'s own benchmarks alongside end-to-end timings, and treat Python-overhead numbers as relative. |
| Scope creep into a full TLS library | Medium | Keep to section 3's "out" list. |
| Security overclaim | Medium | Results must state that this is an unaudited prototype, and point to the formal analyses in the literature. |

## 7. Decisions still open

1. **ML-DSA level:** ML-DSA-44 (smallest) or ML-DSA-65 (more common in drafts)? Proposal: 44 as the headline, with 65 in the appendix.
2. **Pure or hybrid authentication:** do configs D and E also mix in a classical X25519 static key, as in hybrid AuthKEM? Proposal: pure ML-KEM first, then hybrid as a variant.
3. **Network emulation:** Linux `tc netem`, which needs Linux and root, or a pure-Python emulator, which is portable but less faithful? Proposal: netem in a Linux container for results, and the Python emulator for unit tests.
