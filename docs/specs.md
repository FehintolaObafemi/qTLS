# Pinned specifications and interpretation decisions

*Phase 0 deliverable. Revised 2026-11-13 after a three-way review. Every test that checks protocol behaviour cites a decision (`Dn`) in this file. Changing a pin or a decision means changing the tests that cite it in the same commit. `tests/test_traceability.py` checks that every decision has a rejected reading and a test status.*

## 1. Pinned documents

| Document | Pinned revision | Status (2026-11-13) | Used for |
|---|---|---|---|
| KEM-based Authentication for TLS 1.3 | `draft-celi-wiggers-tls-authkem-08` (30 Oct 2026) | Individual draft, Informational. No test vectors. | Configs D and E |
| KEM-based pre-shared-key handshakes for TLS 1.3 | `draft-wiggers-tls-authkem-psk-06` (30 Oct 2026) | Individual draft. Same text as -05 apart from dates and one reference. | `pre-distributed` key delivery |
| Merkle Tree Certificates | `draft-ietf-plants-merkle-tree-certs-08` (2 Nov 2026) | PLANTS WG draft, Standards Track | Configs C and E |
| Hybrid ML-KEM key agreement for TLS 1.3 | **RFC 10024** (Aug 2026), formerly `draft-ietf-tls-ecdhe-mlkem` | Proposed Standard. No test vectors. | `X25519MLKEM768` in every config |
| ML-DSA in TLS 1.3 | `draft-ietf-tls-mldsa-06` | IANA has registered its codepoints | Configs B and C |
| HPKE with post-quantum KEMs | `draft-ietf-hpke-pq-05` | CFRG draft. Appendix A has vectors. | D1 (HPKE derivation of SSs) |
| TLS 1.3 | RFC 8446, as revised by **RFC 9846** (July 2026) | Read 2026-11-13: no change to the key schedule labels, HKDF-Expand-Label, record or message formats, or alerts that qTLS uses. New rules qTLS follows: never reuse a key share; handshake messages never span a key change. RFC 8448 remains the reference trace. | Everything |
| TLS 1.3 example handshakes | RFC 8448 | | Phase 2 key schedule oracle |
| HPKE | RFC 9180 | | D1 |
| ML-KEM / ML-DSA | FIPS 203 / FIPS 204 | | Primitives |
| Falcon | Round-3 specification (liboqs `Falcon-512`) | Stand-in for FN-DSA until FIPS 206 is final | FN-DSA-512 baseline |
| X25519 | RFC 7748 | | Key exchange |
| Deterministic ECDSA | RFC 6979 | | ECDSA KAT (config A) |

**Not yet read.** `draft-ietf-tls-trust-anchor-ids`, which MTC uses to choose a certificate (D15). It's a **Phase 3 entry criterion**.

## 2. Wire constants

| Item | Value | Source |
|---|---|---|
| Cipher suite (only one) | `TLS_AES_128_GCM_SHA256` = `0x1301`, so Hash = SHA-256 and Hash.length = 32 | qTLS choice (D16). The suite RFC 8448 uses. |
| NamedGroup `X25519MLKEM768` | `0x11EC` | RFC 10024 §7.1 |
| Client key share | ML-KEM-768 ek (1184) ‖ X25519 (32) = 1216 bytes | RFC 10024 §4.1 |
| Server key share | ML-KEM-768 ct (1088) ‖ X25519 (32) = 1120 bytes | RFC 10024 §4.2 |
| Hybrid shared secret | ML-KEM ss (32) ‖ X25519 ss (32) = 64 bytes, ML-KEM first | RFC 10024 §4.3 |
| SignatureScheme `ecdsa_secp256r1_sha256` | `0x0403` | RFC 8446 |
| SignatureScheme `mldsa44` / `mldsa65` | `0x0904` / `0x0905`. The FIPS 204 context string must be **empty** in CertificateVerify. | draft-ietf-tls-mldsa-06 §3.2 and IANA |
| SignatureScheme Falcon-512 | `0xFE50` (**qTLS private use**) | No standard codepoint |
| SPKI / signature OID, Falcon-512 | `1.3.6.1.4.1.32473.1.1` (**qTLS**, under the documentation-only enterprise arc of RFC 5612) | No standard OID; never leaves qTLS (D20) |
| AuthKEM SignatureScheme, HPKE variant (D1): ML-KEM-512 / ML-KEM-768 | `0xFE40` / `0xFE41` (**qTLS private use**) | -08 §4.1 assigns no ML-KEM codepoint. `0xFE00–0xFFFF` is private use. |
| AuthKEM SignatureScheme, raw variant (D1): ML-KEM-512 / ML-KEM-768 | `0xFE42` / `0xFE43` (**qTLS private use**) | Separate codepoints, so mixing variants fails at negotiation |
| HandshakeType `kem_encapsulation` | `30` (**experimental, not IANA-registered**; 27–253 are unassigned, and there's no private range) | AuthKEM -08 §4.2 |
| ExtensionType `stored_auth_key` / `early_auth` | `0xFF40` / `0xFF41` (**qTLS private use**; avoids `0xFF01` renegotiation_info) | psk-06 §4.2 says TBD |
| HPKE KEM ML-KEM-512 / ML-KEM-768; KDF; AEAD | `0x0040` / `0x0041`; HKDF-SHA256 `0x0001`; AES-128-GCM `0x0001` | hpke-pq-05 §3 and IANA. RFC 9180. KDF and AEAD are a qTLS choice (D1). |
| SPKI OID ML-KEM-512 / ML-KEM-768 | `2.16.840.1.101.3.4.4.1` / `.4.4.2`, parameters absent | Machine-checked: OpenSSL 3.6.3 (512) and `cryptography` 50.0.2 (768) |
| SPKI OID ML-DSA-44 / ML-DSA-65 | `2.16.840.1.101.3.4.3.17` / `.3.18`, parameters absent | Machine-checked: `cryptography` 50.0.2 |
| MTC `id-alg-mtcProof` | `1.3.6.1.5.5.7.6.67`, parameters absent | MTC -08 §6.2, §13.1.2 |
| MTC log hash | SHA-256 (MTC -08 §5 says "RECOMMENDED"; this is a **qTLS choice**). Leaf `H(0x00‖entry)`, node `H(0x01‖l‖r)`. | MTC -08 §5, §4.3.2; RFC 9162 §2.1.1 |

qTLS private-use and experimental codepoints never reach third-party TLS stacks. The OpenSSL interop oracle covers only config A with `X25519MLKEM768`.

## 3. Which key protects which message

The default is RFC 8446. Rows marked AuthKEM follow AuthKEM -08 Figure 1 and §4.3.1 (D2, D4, D5, D17).

| Message | Sender | Protected under | Transcript that secret is derived over |
|---|---|---|---|
| ClientHello, ServerHello | C, S | plaintext | — |
| EncryptedExtensions, Certificate | S | `s hs traffic` | CH..SH |
| CertificateVerify, Finished (signature configs) | S | `s hs traffic` | CH..SH |
| Client Finished (signature configs) | C | `c hs traffic` | CH..SH |
| **AuthKEM** KEMEncapsulation | C | `c hs traffic` | CH..SH |
| **AuthKEM** client Finished | C | `c ahs traffic` | CH..KEMEncapsulation |
| **AuthKEM** client application data sent before server Finished | C | `c ap traffic 0` | CH..client Finished |
| **AuthKEM** server Finished | S | `s ahs traffic` | CH..KEMEncapsulation |
| **AuthKEM** server alert after a bad client Finished | S | `s ahs traffic` (D17) | CH..KEMEncapsulation |
| Application data after the handshake | C, S | `c/s ap traffic 0` | RFC 8446, or D4 for AuthKEM |

## 4. Interpretation decisions

Each decision states the reading chosen, the reading rejected, and the test that would fail under the rejected reading.

### D1. How the server-authentication secret SSs is derived
- **Ambiguity:** AuthKEM -08 §2.2 uses HPKE: `SetupBaseS(pk, info)` then `Export(ctx, HKDF.Length)`. It names no KDF or AEAD, which feed the HPKE `suite_id`, so SSs is undefined. Issue #32 asks whether to drop HPKE altogether.
- **Decision:** HPKE base mode, under these exact parameters:
  - **Suite:** KEM `0x0040`/`0x0041`, KDF HKDF-SHA256 (`0x0001`), AEAD AES-128-GCM (`0x0001`). Choosing these AEAD and KDF ids lets hpke-pq-05 Appendix A.1/A.2 vectors serve as an oracle.
  - **Info:** `info = "tls13 auth-kem"`, ASCII, no terminator.
  - **Export:** `exporter_context = "server authentication"`, and `L = Hash.length = 32`. The draft says "HKDF.Length", which means Hash.length here.
  - **Raw variant:** SSs is the raw ML-KEM shared secret, under its own codepoints (§2).
  - **Effect on results:** the two variants send the same message lengths (`Nenc` = the raw ML-KEM ciphertext, 768 or 1088 bytes) but derive different SSs values. They differ in CPU only by the HPKE key schedule.
- **Rejected reading:** export-only AEAD `0xFFFF`. It's equally valid per the draft, but no published vectors exist for it.
- **Tests:** planned: Phase 4 — hpke-pq-05 A.1/A.2 exporter vectors checked from the decapsulation side; changing the AEAD or KDF id changes SSs; raw and HPKE send equal per-flight byte counts but different SSs; mixing raw and HPKE fails at negotiation.

### D2. Which key protects the server Certificate message
- **Ambiguity:** -08 Figure 1 marks Certificate `<>`, the server handshake traffic key. §3.3 says "a new handshake encryption key".
- **Decision:** `s hs traffic`. The §4.3.1 key schedule defines no other key at that point.
- **Rejected reading:** `s ahs traffic`. It can't be derived before KEMEncapsulation, so the server couldn't send its Certificate.
- **Tests:** planned: Phase 4 — the Certificate record decrypts under `s hs traffic` and fails AEAD under every other derived key.

### D3. The "0" input to Main Secret
- **Ambiguity:** with no client authentication, -08 §4.3.1 writes `SSc||0 -> HKDF-Extract = Main Secret`.
- **Decision:** IKM = Hash.length zero bytes, the RFC 8446 §7.1 convention. Client authentication is out of scope, so the `SSc||` reading never arises.
- **Rejected reading:** an empty IKM.
- **Tests:** planned: Phase 4 — a golden Main Secret value for a fixed dAHS; a mutant with empty IKM fails it.

### D4. The AuthKEM key schedule
- **Ambiguity:** none in the text. Each item is pinned so that a mutation of it is detectable.
- **Decision:**
  - **Handshake Secret:** HS = Extract(Derive-Secret(ES, "derived", ""), hybrid ss).
  - **Handshake traffic keys:** `c hs traffic` and `s hs traffic` over CH..SH.
  - **Authenticated Handshake Secret:** dHS = Derive-Secret(HS, "derived", ""), then AHS = Extract(dHS, SSs).
  - **Authenticated handshake traffic keys:** `c ahs traffic` and `s ahs traffic` over CH..KEMEncapsulation.
  - **Main Secret:** dAHS = Derive-Secret(AHS, "derived", ""), then MS = Extract(dAHS, 0³²).
  - **Application secrets:** `c ap traffic` over CH..client Finished. `s ap traffic`, `exp master` and `res master` over CH..server Finished.
- **Rejected reading:** `c/s ahs traffic` over CH..Certificate, or `c ap traffic` over CH..server Finished (the RFC 8446 habit).
- **Tests:** planned: Phase 4 — vectors from an independent reference derivation for every secret. Mutants the vectors must kill: the wrong ahs range, `c ap` over server Finished, a missing `derived` step, swapped c/s labels, and a client that skips SSs (AHS = Extract(dHS, 0)).

### D5. Finished messages
- **Ambiguity:** -08 §4.3.3 writes the transcript as `Handshake Context, Certificate*, KEMEncapsulation*, Finished**`. It doesn't spell out what "Handshake Context" includes.
- **Decision:**
  - **Key:** `finished_key = HKDF-Expand-Label(MS, Label, "", Hash.length)`, with the exact label set in D18.
  - **Client transcript:** the client's verify_data covers every handshake message CH..KEMEncapsulation, including SH, EE and Certificate.
  - **Server transcript:** the server's covers CH..client Finished.
  - **Record protection** follows §3: separate from the verify_data key.
- **Rejected reading:** a transcript of only the listed messages (Certificate, KEMEncapsulation, Finished), without SH and EE.
- **Tests:** planned: Phase 4 — verify_data vectors. Mutants: a transcript without SH/EE, a finished_key taken from AHS, a record protected under the finished_key.

### D6. Message order in the full AuthKEM handshake
- **Ambiguity:** -08 §4.2 refers to "the order defined in Section 4", but the order is actually given in §3, Figure 1.
- **Decision:**
  - **Sequence:** CH → SH, EE, Certificate → KEMEncapsulation, client Finished, [client application data] → server Finished.
  - **Rejected with `unexpected_message`:** CertificateVerify under AuthKEM; a server Finished before the client's; a duplicate or missing KEMEncapsulation; CertificateRequest (client authentication is out of scope).
  - **Scope:** this applies to the **full** handshake. The pre-distributed handshake has its own order (D12).
- **Rejected reading:** accepting CertificateVerify, or a server-Finished-first order, in the full handshake.
- **Tests:** planned: Phase 4 — each out-of-order, duplicate or missing message aborts with `unexpected_message`.

### D7. How the server's KEM choice is signalled
- **Ambiguity:** -08 doesn't say how the server signals which KEM it selected.
- **Decision:**
  - **Signal:** the server certificate's SPKI algorithm.
  - **Rejection:** if the matching codepoint (§2) wasn't offered in the client's `signature_algorithms`, the client aborts with `unsupported_certificate`. This extends -08 §4.2-7 to the server certificate.
- **Rejected reading:** accepting any KEM certificate key.
- **Tests:** planned: Phase 4 — an ML-KEM-512 certificate key when only `0xFE41` was offered aborts with `unsupported_certificate`; a matching offer succeeds.

### D8. The KEMEncapsulation `certificate_request_context`
- **Ambiguity:** -08 §4.2-11 says the context MUST equal the one in the Certificate message it answers, but never states its value for the server's certificate.
- **Decision:** empty, matching the server Certificate's context. A non-empty value aborts with `illegal_parameter`.
- **Rejected reading:** ignoring the field.
- **Tests:** planned: Phase 4 — a non-empty context aborts with `illegal_parameter`.

### D9. Client data sent before server Finished
- **Ambiguity:** -08 §5.1 says application data MUST NOT be sent before "the Finished message", which could mean either party's. Figure 1 shows the client sending data after its own Finished.
- **Decision:**
  - **Allowed:** the client may send data after its own Finished, under `c ap traffic 0`.
  - **Status:** that data counts as **implicitly** authenticated (threat model §3, P6).
  - **Metrics:** it's reported separately from explicitly authenticated data.
- **Rejected reading:** forbidding all client data before server Finished. That would contradict Figure 1 and §3.3.
- **Tests:** planned: Phase 4 — the server decrypts that data under `c ap traffic 0`. Phase 5's metrics tag it implicit, and a mutant that tags it explicit fails.

### D10. Alerts
- **Ambiguity:** -08 specifies few alerts. RFC 10024 specifies its own for key shares.
- **Decision:**
  - **Structural decode errors** (truncated message, trailing bytes, vector length overflow) → `decode_error`.
  - **Key-share content** (wrong ciphertext or share length for the group, a failed FIPS 203 encapsulation-key check, X25519 validity or all-zero) → `illegal_parameter` (RFC 10024 §4.2, §4.3). Any other ML-KEM decapsulation failure → `internal_error`.
  - **KEMEncapsulation wrong length** for the KEM → `illegal_parameter`, by analogy with RFC 10024.
  - **AuthKEM codepoint in `signature_algorithms_cert`** → `illegal_parameter`.
  - **Tampered KEMEncapsulation:** ML-KEM decapsulation doesn't fail (implicit rejection), so the server derives a different SSs and **the client Finished record fails decryption** → `bad_record_mac`.
  - **A server without the certificate's secret key:** the client fails to decrypt the server Finished record → `bad_record_mac`.
  - **verify_data mismatch** inside a record that decrypts → `decrypt_error`.
- **Rejected reading:** mapping every length error to `decode_error` (contradicts RFC 10024), or expecting `decrypt_error` when the record itself can't be decrypted.
- **Tests:** planned: Phase 2 — a 1119- or 1121-byte server share, an unreduced ML-KEM key and an X25519 low-order point each give `illegal_parameter`. Phase 4 — a tampered KEMEncapsulation and an attacker server each give `bad_record_mac`, and a flipped verify_data gives `decrypt_error`.

### D11. AuthKEM certificate key type
- **Ambiguity:** whether the certificate key may be a hybrid (ML-KEM plus X25519) or must be pure ML-KEM. -08 only lists draft KEM placeholders.
- **Decision:** pure ML-KEM only. A hybrid certificate key stays open (PLAN §9, decision 2).
- **Rejected reading:** accepting a hybrid key.
- **Tests:** planned: Phase 4 — a 1216-byte or hybrid-OID certificate key is rejected with `unsupported_certificate`.

### D12. The pre-distributed key handshake
- **Ambiguity:** psk-06 leaves the fingerprint input, the extension bodies and the handling of rejected early data unspecified.
- **Decision:**
  - **Flow** (psk-06 Figure 3): CH carries `stored_auth_key` {fingerprint, ciphertext}. The server sends SH, then EE and **server Finished first**. The client sends client Finished last. There's no Certificate on the wire.
  - **Key schedule** (psk-06 §4.4.1):
    - **Early Secret:** ES = Extract(0, SSs).
    - **Early handshake key:** `c e hs traffic` over CH.
    - **Main Secret:** comes from dHS with IKM 0³². There's **no AHS stage**.
  - **Fingerprint:** SHA-256 over the DER SPKI of the server's KEM key, all 32 bytes (§4.2.1: "Use the output").
  - **Rejected key** (unknown or rotated): the server omits `stored_auth_key`. The client recomputes ES without SSs and continues as a full AuthKEM handshake (D6), and any early data is discarded (as in RFC 8446 §4.2.10).
  - **Encoding:** the server's acknowledgement is an empty extension body (psk-06 writes `AcceptedAuthKey '1'`, which has no defined encoding).
  - **Configs:** the pre-distributed points of D and E are **the same handshake**. The certificate format appears only on the fallback path, which is measured as its own point.
- **Rejected reading:** reusing D6's order and the AHS stage for this flow.
- **Tests:** planned: Phase 4 — server-Finished-first is accepted only when `stored_auth_key` is echoed. Key-schedule mutants (AHS present, `c e hs traffic` missing) fail. A rotated key falls back and drops early data. D-pdk and E-pdk send the same bytes. A fingerprint vector, with mutants that hash the raw key or truncate.

### D13. ML-KEM certificate keys in MTC
- **Ambiguity:** MTC -08 doesn't restrict the subject key to signature algorithms, and never mentions KEMs.
- **Decision:**
  - **Subject key:** the SPKI uses the FIPS 203 OID (§2), and `subjectPublicKeyInfoHash` = SHA-256(DER SPKI).
  - **Proof of possession:** neither MTC nor X.509 proves possession at issuance. The TLS handshake proves it per connection (AuthKEM decapsulation). A CA could certify a key the subject doesn't hold (threat model A4, L3).
- **Rejected reading:** hashing the raw key instead of the DER SPKI.
- **Tests:** planned: Phase 3 — an SPKI-hash vector; mutants that hash the raw key or use the wrong OID are rejected.

### D14. MTC certificate shape and size parameters
- **Ambiguity:** MTC -08 leaves the number of cosignatures to relying-party policy and doesn't fix proof depth.
- **Decision:**
  - **Landmark-relative:** an MTCProof with an empty `signatures` list.
  - **Standalone:** two cosignatures (the CA and one external cosigner), each ML-DSA-44 at categories 1–2 or ML-DSA-65 at category 3.
  - **Proof depth:** defaults to MTC -08 §6.5's estimates, 12 hashes (384 B) for standalone and 23 hashes (736 B) for landmark-relative.
  - **Benchmark axes:** cosignature count {1, 2, 3} and proof depth. Both are recorded in every result row.
- **Rejected reading:** leaving these to run-time defaults, so results depend on unstated parameters.
- **Tests:** planned: Phase 3 — at 12 and 23 hashes the proofs are 384 and 736 bytes; standalone carries exactly the configured number of cosignatures; size grows monotonically along both axes.

### D15. Choosing landmark-relative or standalone
- **Ambiguity:** MTC -08 §8.2 defers selection to `draft-ietf-tls-trust-anchor-ids`, which hasn't been read.
- **Decision:**
  - **Status:** modelled until trust-anchor-ids is read (a Phase 3 entry criterion).
  - **Selection:** the client advertises the landmark group it holds. The server sends landmark-relative if that group covers the certificate, and standalone otherwise.
  - **ClientHello bytes:** the signal's size is decided when the draft is read, and is then counted in C and E ClientHellos.
  - **Measurement:** the fallback rate is a benchmark axis.
- **Rejected reading:** always sending landmark-relative, which would measure only the best case.
- **Tests:** planned: Phase 3 — a client whose group covers the certificate gets landmark-relative; a stale client gets standalone; the fallback counter matches a seeded population.

### D16. ClientHello and connection profile
- **Ambiguity:** none of the pinned drafts fix ClientHello contents, compatibility mode or HelloRetryRequest handling, yet these change byte counts.
- **Decision:**
  - **Suite:** one cipher suite, `0x1301`.
  - **Extensions:** `supported_versions` (TLS 1.3 only), `supported_groups` = [`0x11EC`], one `key_share` (`0x11EC`), `signature_algorithms` for the config, and `server_name` = `qtls.test`.
  - **Compatibility mode off:** an empty `legacy_session_id` and no ChangeCipherSpec records.
  - **No HelloRetryRequest:** receiving one aborts with `unexpected_message`.
  - **Downgrade:** a server choosing any group other than `0x11EC` aborts with `illegal_parameter`.
  - **OpenSSL size check:** the oracle runs OpenSSL with `-groups X25519MLKEM768` and middlebox compatibility off, so it compares like with like.
- **Rejected reading:** OpenSSL defaults: compatibility mode on, and an extra X25519 key share.
- **Tests:** planned: Phase 2 — the ClientHello bytes for each config are pinned; a HelloRetryRequest or a non-`0x11EC` group aborts; config A's sizes match the OpenSSL capture made with these flags.

### D17. Record packing and alert keys
- **Ambiguity:** RFC 8446 lets an implementation pack handshake messages into records freely. -08 §4.3.3 says alerts after Finished use "the appropriate application traffic key", but that key may not exist yet.
- **Decision:**
  - **Packing:** consecutive handshake messages under the same key go into one record, fragmented at 2¹⁴. A key change starts a new record. There's no padding. So the AuthKEM client's second flight is three records and the TLS 1.3 client's is two.
  - **Alert key:** a server alert after a bad client Finished is sent under `s ahs traffic`. `s ap traffic` needs the server Finished transcript, which doesn't exist yet.
- **Rejected reading:** one record per message, or an alert under `s ap traffic`.
- **Tests:** planned: Phase 2 — per-flight record counts (TLS 1.3 client flight 2). Phase 4 — the AuthKEM client's second flight is 3 records, and the alert decrypts under `s ahs traffic`.

### D18. The Finished-key label
- **Ambiguity:** -08 §4.3.3 writes `HKDF-Expand-Label(MainSecret, server_label, ...)` with `server_label = "tls13 server finished"`. HKDF-Expand-Label already prepends `"tls13 "` (RFC 8446 §7.1), so a literal reading gives `"tls13 tls13 server finished"`.
- **Decision:** Label = `"server finished"` / `"client finished"`, so `HkdfLabel.label` is `"tls13 server finished"` / `"tls13 client finished"`. The draft wrote out the full label.
- **Rejected reading:** `HkdfLabel.label = "tls13 tls13 server finished"`.
- **Tests:** planned: Phase 4 — a finished_key vector; a mutant using the doubled prefix fails it.

### D19. X.509 chains for configs B and D
- **Ambiguity:** the PLAN §3 algorithm axis covers only the leaf key. The issuer signatures in the chain change sizes by kilobytes.
- **Decision:**
  - **Chain shape:** one intermediate; the root isn't sent.
  - **Issuer signatures:** the intermediate and root sign with the same family as the level's signature baseline: ML-DSA-44 *or* Falcon-512 at categories 1–2 (an axis), and ML-DSA-65 at category 3.
  - **Config D:** uses the same issuer choice, so B and D differ only in the leaf key and the handshake.
  - **SCTs:** 0 or 2, per PLAN §3, signed with the issuer algorithm.
- **Rejected reading:** issuer signatures left implicit, or chosen differently for B and D.
- **Tests:** planned: Phase 2 — the chain built for each (level, issuer) has the expected issuer algorithm OIDs, and its size equals the sum of its parts.

### D20. Certificates: one strict DER codec, built and parsed by qTLS
- **Ambiguity:** `cryptography`'s certificate builder can't sign with liboqs keys (Falcon, liboqs ML-DSA), and only qtls/crypto.py may import crypto libraries, so neither building nor parsing X.509 can use it.
- **Decision:**
  - **One codec:** `qtls/der.py`, used for X.509 in Phase 2 and MTC in Phase 3.
  - **Strict:** it rejects BER forms, indefinite lengths, non-minimal lengths and integers, and trailing bytes.
  - **Signing and verification** go through crypto.py, by algorithm name.
  - **Falcon-512** uses the qTLS OID in §2.
  - **Validation time** is an explicit input to path validation, never the wall clock, so expiry tests and benchmarks are reproducible.
- **Rejected reading:** a lenient (BER-accepting) parser, or a second codec for MTC.
- **Tests:** planned: Phase 2 — round trips for every certificate the matrix builds. Rejections: indefinite length, non-minimal length, a non-minimal integer, trailing bytes, and a long-form length where short form fits. Expiry against an injected time.

## 5. How to change this file

- **Re-pin:** update §1, read the diff, update the affected decisions, and update the tests that cite them in the same commit.
- **New ambiguity:** add the next `Dn` with all four fields (Ambiguity, Decision, Rejected reading, Tests). The traceability test enforces this.
