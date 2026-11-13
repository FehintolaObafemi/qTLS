# qTLS project plan: AuthKEM + Merkle Tree Certificates

*Drafted 2026-11-13. Revised 2026-11-13 after a three-way review (architect, engineer, tester) of the first draft. Revisit at the end of each phase.*

## 1. Goal

Build and measure a TLS 1.3–shaped handshake that is post-quantum for **both** key exchange and server authentication. Authentication uses a KEM rather than a signature (AuthKEM), and the certificate is a Merkle Tree Certificate (MTC). Compare it against today's web and the signature-based post-quantum candidates, at **matched security levels**.

**Research question:** at each NIST security level, does KEM authentication over MTCs beat the best signature-based option on:
- bytes on the wire,
- round trips to each kind of authentication,
- latency, and
- per-role CPU?

And what does it cost in latency to explicit authentication, server-first data, and deployment complexity?

## 2. Landscape and pinned specs (as of November 2026)

| Fact | Implication for qTLS |
|---|---|
| Hybrid ML-KEM key exchange is the default in major browsers and CDNs. | Use `X25519MLKEM768` in every config, so key exchange is never a variable. |
| ML-DSA web certificates aren't publicly trusted yet; `draft-ietf-tls-mldsa` is still in the IETF process. | Post-quantum server authentication is the open gap. |
| Chrome favours MTCs for post-quantum web PKI. MTC -08 defines **standalone** certificates (with signatures) and **landmark-relative** certificates (signatureless, used only for up-to-date clients, with fallback to standalone). | Model both kinds and the fallback. Best-case-only MTC numbers are not acceptable. |
| MTCs remove CA signatures from the chain, but the server's `CertificateVerify` signature and post-quantum public key remain. | That leftover signature is what AuthKEM replaces. |
| AuthKEM is an individual draft. Its -08 key schedule differs from RFC 8446, it publishes no test vectors, and it contains ambiguities. | Pin the revision, record our reading of each ambiguity, and build an independent reference derivation (Phase 4). |
| Level matters. ML-KEM-768 ↔ ML-DSA-65 are NIST category 3; ML-KEM-512 ↔ ML-DSA-44 are category 1–2. FN-DSA-512 (Falcon) is the smallest signature at category 1. | Compare only level-matched pairs, and make FN-DSA-512 a core baseline. Otherwise the answer comes from the parameter choice rather than the design. |

**Pinned specs.** `docs/specs.md` records the exact revisions and private-use codepoints in force, and all tests cite them:
- `draft-celi-wiggers-tls-authkem-08`
- `draft-wiggers-tls-authkem-psk-06`
- `draft-ietf-plants-merkle-tree-certs-08`
- RFC 10024 (formerly `draft-ietf-tls-ecdhe-mlkem`)
- RFC 8446
- RFC 8448
- FIPS 203 and FIPS 204

## 3. Configuration matrix

Configs are points in a matrix of independent axes, not five hard-coded letters. That way variants added later don't force a refactor.

| Axis | Values |
|---|---|
| Server auth mechanism | `sig`, `kem` |
| Certificate format | `x509`, `mtc-standalone`, `mtc-landmark` (falls back to standalone) |
| Auth algorithm | ML-DSA-44, ML-DSA-65, FN-DSA-512, ECDSA-P256 (A only), ML-KEM-512, ML-KEM-768 |
| KEM key delivery (kem only) | `in-cert`, `pre-distributed` (authkem-psk-06) |
| SCTs in x509 chains | 0, 2 |

The README's A–E are named points in this matrix.

**Level-matched pairs, both reported, no single headline:**
- **Cat 1–2:** ML-DSA-44 / FN-DSA-512 ↔ ML-KEM-512
- **Cat 3:** ML-DSA-65 ↔ ML-KEM-768

**Fixed modelling choices.** Each choice decides who "wins", so it's fixed here rather than left to "approximate sizes":
- One intermediate certificate.
- A real DER X.509, built and parsed by qTLS's own strict codec (specs.md D20, D24).
- TLS records fragmented at 2¹⁴ bytes.
- SCT count swept as a matrix axis.

## 4. Scope

**In:**
- A sans-I/O handshake for the matrix above, with byte-accurate messages and records.
- A TLS 1.3 key schedule plus the AuthKEM stages.
- MTC issuance and verification as in -08: logs, subtrees, landmarks, standalone and landmark-relative certificates, cosigners.
- A benchmark harness, notebooks and a results write-up.

**Out:**
- Interop with real TLS stacks (OpenSSL is used only as a *test oracle*).
- Resumption and 0-RTT, apart from the authkem-psk pre-distributed key.
- Client authentication.
- QKD.
- New primitives.

## 5. Crypto backends

| Backend | Provides | Role |
|---|---|---|
| `cryptography` ≥ 48 (bundles OpenSSL) | X25519, ECDSA-P256, ML-KEM-768/1024, ML-DSA-44/65/87, X.509 | Primary backend. A binary wheel, so it needs no build. |
| `liboqs` 0.16.0 (via `liboqs-python`) | ML-KEM-512, Falcon-512, and the same algorithms as above | Required for the cat 1–2 pair and FN-DSA. It also gives a second implementation for differential tests. liboqs exposes round-3 Falcon-512, which stands in for FN-DSA-512 until FIPS 206 is final and implemented. |

**Rules for using the backends:**
- `qtls/crypto.py` is the **only** module that imports either library.
- It normalises the APIs: verification always raises on failure, and lengths are checked.
- It never aliases or falls back between algorithm names.
- It counts primitive operations per role, which feeds the CPU method in Phase 5.
- liboqs is built **only** by `scripts/build_liboqs.sh`, at a pinned tag and commit. `liboqs-python`'s import-time auto-installer must never run.
- The two backends' speeds for the same primitive differ by up to about 5× (measured on the dev machine for ML-DSA-44 signing). So every result records the backend, and headline numbers use one backend per primitive.

## 6. Phases

Each phase has an exit criterion. Don't start the next phase until it's met. The estimate is about 14 weeks, against 12 for the first draft, because of the extra test and modelling work.

### Phase 0: Specs, threat model, novelty (week 1)
- Read KEMTLS (CCS 2020), AuthKEM -08, authkem-psk-05 and MTC -08. Search for prior work that combines AuthKEM with MTCs, and re-scope if it exists.
- Confirm that MTC -08 allows a KEM `subjectPublicKeyInfo`, and define how an ML-KEM SPKI is encoded in the log entry.
- Write `docs/specs.md`:
  - pinned revisions and codepoints
  - the context-label handling for `Encapsulate(pk, "server authentication")`
  - **our reading of each AuthKEM ambiguity:** whether the shared secret is the raw ML-KEM secret or an HPKE export (§2.2, issue #32), and which key protects the Certificate message (§3.3 text vs Figure 1)
- Write `docs/threat-model.md`:
  - **Attacker:** a network attacker who will have a quantum computer later.
  - **Authentication:** define *implicit* vs *explicit* server authentication. Under AuthKEM the client's first data goes to an implicitly authenticated peer.
  - **Cross-config downgrade:** an explicit property.
  - **Traceability:** a **property → test-ID table**, which CI checks against `tests/`.

**Exit:** `specs.md` and `threat-model.md` are committed and reviewed, and the novelty statement is written.

**Met on 2026-11-13.** `docs/specs.md` (D1–D19), `docs/threat-model.md` (A1–A5, P1–P15), `docs/novelty.md`. Reviewed by architect, engineer and tester; their blocking findings were fixed before merge. Entry criteria carried forward: read RFC 9846 before Phase 2, and `draft-ietf-tls-trust-anchor-ids` before Phase 3.

### Phase 1: Repository reset and crypto foundation (week 2)
- **Repository clean-up:**
  - Move all 2023 files into `legacy/`: sources, `.txt` notes, `qTLS.csproj`, `qTLS.docx` and `.vscode/`.
  - Delete `obj/` and add a `.gitignore`.
  - Point pytest at `tests/` only, so `legacy/` is never collected.
- **Packaging:** `pyproject.toml` with `cryptography` as the runtime dependency and `test`, `oqs` and `notebooks` extras, plus a hashed lock file for CI.
- **liboqs:** `scripts/build_liboqs.sh` builds the pinned commit. CI caches the build and sets `OQS_INSTALL_PATH`.
- **Crypto wrapper:** `qtls/crypto.py`, following the rules in §5.
- **Tests:**
  - exact sizes for every algorithm and backend
  - round trips
  - ML-KEM implicit rejection (a tampered ciphertext gives a different secret, with no exception)
  - wrong-length inputs rejected
  - signature rejections (flipped message, flipped signature, wrong key, truncated signature, wrong context string)
  - **cross-backend differential tests:** the same seed gives the same key pair in both backends; encapsulate in one and decapsulate in the other; sign in one and verify in the other
  - **NIST ACVP known-answer tests** for ML-KEM and ML-DSA, vendored under `tests/vectors/`
  - the exact native liboqs version, with warnings turned into errors
  - unknown algorithm names raise
- **CI:** GitHub Actions runs the full suite. **Any skipped test fails the run**, so crypto can't be silently bypassed.

**Exit:** CI is green on a fresh clone with no skips. A deliberately broken known-answer test is shown to turn CI red.

**Met on 2026-11-13.**
- **Green:** [run 43453757836](https://github.com/FehintolaObafemi/qTLS/actions/runs/43453757836). 173 passed, 0 skipped, on Python 3.11 and 3.13.
- **Red:** [run 43457010922](https://github.com/FehintolaObafemi/qTLS/actions/runs/43457010922). One ML-KEM-512 KAT value was corrupted, with its SHA-256 updated so only the KAT itself could catch it. 1 failed (`test_mlkem_decapsulation[ML-KEM-512-tc1]`) and 172 passed.

**Deferred from the Phase 1 review:** all resolved in Phase 2a (2026-11-13).
- **Falcon-512 KAT:** reproduces liboqs's published single and 100-count hashes through the wrapper. Re-anchoring to NIST's round-3 `.rsp` directly is still open, because it needs that archive.
- **ML-DSA key generation KAT on both backends:** ACVP ξ → pk; liboqs also matches the expanded sk.
- **Deterministic fixtures:** seeded keys, deterministic signing, and a fail-closed liboqs RNG hook scoped to one execution context (thread or asyncio task). Blocks in different contexts can run at once. An independent FIPS 204 `rnd` oracle (ACVP sigGen) is still open; seeded ML-DSA signing is tied to the liboqs KAT path instead.
- **X25519 private-key import,** with RFC 7748 and RFC 8448 vectors.
- **Where X.509 is built:** decided in specs.md D20.
- **Hashing, HKDF and AEAD in the wrapper,** counted in operations and bytes.
- **Security-level pairing:** `qtls/levels.py`.
- **AuthKEM golden vectors** take SSs and the ciphertext as inputs, or use liboqs's derandomised encapsulation (Phase 4).

### Phase 2: Handshake core and baselines A and B (weeks 3–5)
- **`qtls/messages.py`:** encoders and decoders that reject truncated input, trailing bytes and oversized lengths.
- **One exception → alert table** (specs.md D10), defined once in the protocol layer and tested.
- **Strict DER codec** `qtls/der.py` and hand-built certificates (specs.md D20).
- **Handshake-level checks the codec leaves to the state machine** (from the 2b review):
  - which extensions are allowed in which message (RFC 8446 §4.2 → `illegal_parameter`);
  - no handshake fragments interleaved with other record types (RFC 9846 §5.1), using `HandshakeReader.pending()`;
  - the ChangeCipherSpec window passed to `record.receive`;
  - the server's policy on duplicate or out-of-list `client_shares`;
  - an empty server Certificate → `decode_error` (RFC 8446 §4.4.2.4);
  - a received alert raises `PeerAlert` and is never answered.
- **From the 2c review:** pass `expected_kind` to `verify_chain` on every authentication path (P8), and decide the `signature_algorithms_cert` fallback to `signature_algorithms` (RFC 8446 §4.2.3) that feeds its `accepted` set.
- **From the 2c review:** add ML-DSA and ML-KEM leaves to the x509 fuzz corpus, and pin KEM-leaf chain bytes when Phase 4 uses them.
- **From the 2c review:** run the OpenSSL ≥ 3.5 oracle tests (the `openssl` marker, including `-x509_strict` chain verification) in CI by pinning an OpenSSL build there, which the interop test needs anyway.
- **Sans-I/O handshake state machine.** Transports are separate, in `qtls/transport/`:
  - **in-memory**, for tests
  - **TCP**, with `TCP_NODELAY` and one write per flight
- **`qtls/keyschedule.py`:** a *staged* schedule that takes raw shared secrets and transcript bytes. It has an optional Authenticated Handshake Secret stage and a configurable source for the Finished key, so AuthKEM is an addition, not a rewrite.
- **Record layer:** fragmentation at 2¹⁴ bytes, and sequence numbers.
- **Configs A and B.**
- **Oracles:**
  - RFC 8448 §3, driven by **injected inputs** (keys, randoms, messages) through the codec, key schedule and record layer. The state machine can't negotiate RFC 8448's X25519 and RSA-PSS (D16). The handshake therefore takes an explicit randomness provider rather than calling `os.urandom` itself. It supplies the client random and ephemeral keys, and can also **inject KEM encapsulation results (ct, ss) and signing randomness**. OpenSSL can derandomise neither ML-KEM encapsulation nor ML-DSA signing, so byte-exact fixtures either inject these or use the liboqs backend.
  - An X25519MLKEM768 share-layout test, and a test that swapping the order of the combined secrets changes the result.
  - A gated OpenSSL ≥ 3.5 interop test for hybrid key exchange, plus a vendored OpenSSL 3.6 handshake capture (with keylog) as a second independent oracle for multi-record flights and record protection (moved here from 2b).
  - A size cross-check of config A against an OpenSSL capture.
- **Negative tests:** tampered certificate or signature, wrong CertificateVerify context, truncated transcript, an algorithm the client didn't offer, an untrusted root, an expired leaf, messages out of order or missing, and record tampering or replay.

**Exit:** all of the above pass, and RFC 8448 matches exactly.

### Phase 3: Merkle Tree Certificates, config C (weeks 6–7)
- **`qtls/mtc.py`, implementing MTC -08:**
  - issuance log
  - subtrees (§4)
  - inclusion and consistency proofs
  - cosigners
  - landmarks
  - standalone (§6.3) and landmark-relative (§6.4) certificates
  - trust-anchor-ID negotiation, with fallback to standalone (§8.2)
- **New dependency:** `pyasn1`, or hand-written DER, for MTCProof encoding.
- **Tests:**
  - MTC -08 Appendix C vectors and the pinned C.2 vector files
  - a mutant without the 0x00/0x01 domain separation must fail
  - one rejection test per §7.2 acceptance step
  - cosigner quorum and ordering
  - **key binding:** a valid proof with a substituted SPKI is rejected
  - fallback from landmark-relative to standalone
  - a C client receiving Certificate then Finished with no CertificateVerify aborts

**Exit:** C works with both kinds of certificate, and all MTC vectors and rejections pass.

### Phase 4: AuthKEM, configs D and E (weeks 8–10)
- **AuthKEM -08 message flow:**
  - KEMEncapsulation
  - the Authenticated Handshake Secret stage
  - Main Secret = Extract(dAHS, 0)
  - Finished keys derived from the Main Secret
  - the **client's Finished first**
- **Pre-distributed key variant,** following `draft-wiggers-tls-authkem-psk-06` (not "KEMTLS-PDK"; see specs.md D12).
- **Independent oracle:**
  - a straight-line reference derivation kept *outside* `qtls/`, written from the draft text
  - frozen golden vectors, signed off by a reviewer
  - a small mutant set (a swapped label, salt or transcript range) that the vectors must catch
- **Active-attacker test:** a server holding the victim's certificate but not its KEM secret key. The **client** must abort at server Finished, and its early application data must not decrypt under any key the attacker can derive. A mutant client that skips the server-auth secret must fail this test.
- **Downgrade matrix:** every client config × server config either negotiates correctly or aborts. A KEM leaf is never accepted under signature auth, and a missing CertificateVerify is never accepted.
- **Negotiation and ordering rejections:**
  - AuthKEM codepoints in `signature_algorithms_cert`
  - a KEM the client didn't offer
  - CertificateVerify received under AuthKEM
  - wrong Finished order
- **Cached key:** a stale key after server rotation, and a key for the wrong server identity, each fail in a defined way with no hang.

**Exit:** D and E complete, and all of the above pass.

### Phase 5: Benchmarks (weeks 11–12)
- **Network:** Linux network namespaces joined by a veth pair (MTU 1500) with `tc netem`. The plan *asserts* the setup before each run: MTU, `TCP_NODELAY`, and initcwnd set per route. Loopback alone hides the initcwnd effect, because its MTU is 64 KiB.
- **Sweep:**
  - RTT: 10, 50, 150, 300 ms
  - loss: 0%, 1%, 3%
  - initcwnd: 4 and 10 segments
  - every point of the config matrix
  - MTC landmark fallback rate
- **Metrics, per role:**
  - bytes per flight
  - round trips to client-sent first application data, to *implicit* server authentication, to *explicit* server authentication, and to server-sent first application data
  - latency (p50/p95)
  - CPU
- **CPU method:** count primitive operations per handshake per role, multiply by per-operation C-level microbenchmarks from the recorded build, and report Python wall-clock separately. Use `thread_time_ns` per role, and show ML-DSA signing as a distribution, because its timing varies.
- **Sample size:** state the expected effect size, then choose the number of runs per point to resolve it at p95, rather than a flat 1,000.
- **Calibration tests:**
  - measured RTT within ±5% of the configured RTT
  - loss within its confidence interval
  - B's flight above initcwnd takes 2 RTT, and A's takes 1
  - bytes per flight equals the sum of record lengths on the wire
  - injected server busy-work shows up only in server CPU

**Exit:**
- Deterministic outputs (bytes, records, round-trip counts) reproduce byte for byte from fixtures.
- Timing outputs reproduce within tolerances recorded in the repo.
- Both are run from a pinned container image digest, with an environment manifest recording: liboqs tag and commit, CMake flags, backend versions, CPU flags, kernel, and queueing discipline.

### Phase 6: Analysis and write-up (weeks 13–14)
- **Notebooks:** `notebooks/01–05`, executed headless in CI from `results/` only.
- **Results check:** a script checks every number in `docs/results.md` and the README against `results/*.csv`.
- **Stretch goals:** a Tamarin model of E's key schedule, and AuthKEM-PSK resumption.

**Exit:** results published, and a `v0.1` tag on a fully green commit.

## 7. Layout

```
qtls/            crypto.py (only backend importer), messages.py, keyschedule.py,
                 handshake/ (sans-I/O state machine), transport/, record.py, mtc.py
bench/           harness, netns/netem setup, fixtures/ (pre-generated keys + certs)
reference/       independent spec-derived derivations (Phase 4 oracle)
tests/           pytest suite; tests/vectors/ (ACVP, RFC 8448, MTC -08)
notebooks/       walkthroughs + results
results/         raw benchmark CSVs + environment manifests
docs/            PLAN.md, specs.md, threat-model.md, results.md
scripts/         build_liboqs.sh and other tooling
docker/          pinned Linux image for CI benchmarks and netem
legacy/          2023 QKD/QCA experiments (broken, historical)
```

## 8. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| AuthKEM + MTC has already been studied | Medium | Phase 0 checks. If so, pivot to new conditions or to formal verification. |
| Baseline selection bias | High | Level-matched pairs, FN-DSA as a core baseline, and SCTs as a swept axis. |
| A symmetric bug passes "works end to end" tests | High | External oracles in every phase: ACVP, RFC 8448, OpenSSL interop, MTC vectors, the independent AuthKEM reference, and mutant tests. |
| liboqs build drift, or the auto-installer running at import | High | Pinned build script, an exact version check in tests, and the wrapper refusing to import `oqs` without the pinned build. |
| Draft churn (AuthKEM, MTC) | Medium | Pinned revisions in `specs.md`, and vectors tied to a revision. |
| Network emulation hides the initcwnd effect | High | Veth with MTU 1500 plus assertions before each run. |
| CPU differences lost in Python noise, or dependent on the backend | High | The operation-count × C-microbenchmark method, with the backend recorded. |
| Scope creep into a full TLS library | Medium | Keep to §4's "out" list. |
| Security overclaim | Medium | Results state that this is an unaudited prototype. |

## 9. Decisions

1. **ML-DSA level:** *closed*. Use level-matched pairs at categories 1–2 and 3. No single headline.
2. **Pure or hybrid KEM authentication:** *open*. Proposal: pure ML-KEM first, then hybrid as a variant with its own vectors.
3. **Network emulation:** *closed*. Netns plus veth plus netem in a pinned Linux container for every timing result. The in-memory transport is for tests only.
4. **`obj/` in git history:** *open*. Deleting `obj/` doesn't remove it from history, and its files contain absolute local paths. Rewriting history is the owner's decision.
