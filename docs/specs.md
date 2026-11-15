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
| TLS 1.3 | RFC 8446, as revised by **RFC 9846** (July 2026) | Read 2026-11-13: no change to the key schedule labels, HKDF-Expand-Label, record format, or alerts that qTLS uses. One message-format change matters: `ClientHello.extensions` is now `<7..2^16-1>` (was 8); qTLS follows RFC 9846. New rules qTLS follows: never reuse a key share; handshake messages never span a key change. RFC 8448 remains the reference trace. | Everything |
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

qTLS private-use and experimental codepoints never reach third-party TLS stacks. The OpenSSL interop oracle covers `X25519MLKEM768` with configs A and B (ML-DSA-44 and ML-DSA-65 leaves); Falcon-512's codepoint is private, so B with a Falcon leaf never meets OpenSSL.

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
  - **Where the mapping lives:** `qtls/alerts.py:alert_for` is the single fallback table for exceptions that reach the top of a connection. Context-specific failures don't go through it: certificate-chain verification (Phase 2c) and AuthKEM certificate keys (Phase 4) catch crypto exceptions and raise the right `AlertError` themselves (for example `bad_certificate` for a chain signature, where the table would say `decrypt_error`). A received alert (`PeerAlert`) maps to no alert at all (RFC 8446 §6.2).
- **Rejected reading:** mapping every length error to `decode_error` (contradicts RFC 10024), or expecting `decrypt_error` when the record itself can't be decrypted.
- **Tests:** planned: Phase 4 — a tampered KEMEncapsulation and an attacker server each give `bad_record_mac`, and a flipped verify_data gives `decrypt_error`. The Phase 2 part is implemented: wrong share lengths, an unreduced ML-KEM key and an X25519 low-order point each give `illegal_parameter`, a backend decapsulation failure is a local error (`internal_error` is sent and the exception re-raised), a tampered ServerHello key share gives `bad_record_mac` on both sides, and a flipped CertificateVerify or Finished gives `decrypt_error` (`tests/test_hybrid.py::test_server_share_length_is_illegal_parameter`, `tests/test_hybrid.py::test_client_share_length_is_illegal_parameter`, `tests/test_hybrid.py::test_unreduced_encapsulation_key_is_illegal_parameter`, `tests/test_hybrid.py::test_low_order_x25519_is_illegal_parameter_both_ways`, `tests/test_hybrid.py::test_decapsulation_failure_is_a_local_error`, `tests/test_handshake.py::test_a_backend_decapsulation_failure_is_a_local_bug`, `tests/test_handshake.py::test_tampered_key_share_fails_at_the_first_encrypted_record_on_both_sides`, `tests/test_handshake.py::test_encrypted_flight_rules`, `tests/test_handshake.py::test_a_local_bug_is_reraised_after_queueing_internal_error`).

### D11. AuthKEM certificate key type
- **Ambiguity:** whether the certificate key may be a hybrid (ML-KEM plus X25519) or must be pure ML-KEM. -08 only lists draft KEM placeholders.
- **Decision:** pure ML-KEM only. A hybrid certificate key stays open (PLAN §9, decision 2).
- **Rejected reading:** accepting a hybrid key.
- **Tests:** planned: Phase 4 — a hybrid-OID certificate key is rejected with `unsupported_certificate`; a wrong-length key under an ML-KEM OID is malformed and already rejected at parse with `bad_certificate` (D24); the FIPS 203 encapsulation-key check on certificate keys is added with AuthKEM.

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
  - **Compatibility mode off:** an empty `legacy_session_id`, and qTLS never sends ChangeCipherSpec. A peer's valid one is dropped (D22).
  - **No HelloRetryRequest:** receiving one aborts with `unexpected_message`.
  - **Downgrade:** a server choosing any group other than `0x11EC` aborts with `illegal_parameter`.
  - **OpenSSL size check:** the vendored captures used for sizes run OpenSSL with `-groups X25519MLKEM768`, `TLS_AES_128_GCM_SHA256`, the config's one signature scheme, and `-no_middlebox`, so they compare like with like. A qTLS server answering the captured ClientHello with the captured chain produces, per message:

    | Message | qTLS vs OpenSSL 3.6.3 | Why |
    |---|---|---|
    | ServerHello | equal | same session id echo, same two extensions |
    | EncryptedExtensions | +4 bytes | qTLS acknowledges `server_name` with an empty extension (RFC 6066 §3); s_server doesn't |
    | Certificate | byte-identical | same chain, no entry extensions |
    | CertificateVerify | equal apart from the signature | 8 bytes of framing; ECDSA DER length varies, ML-DSA-65 is always 3309 |
    | Finished | equal (36) | |
    | Records | qTLS 3 × 22 bytes smaller | qTLS packs the encrypted flight into as few records as fit (D17); OpenSSL uses one per message |

    So Phase 5's sizes are a real stack's sizes up to these named differences, which favour neither configuration.
- **Rejected reading:** OpenSSL defaults: compatibility mode on, and an extra X25519 key share. (The fragmented captures keep OpenSSL's default compatibility mode on purpose, to exercise ChangeCipherSpec and session-id framing; they aren't used for sizes.)
- **Tests:** implemented — `tests/test_capture.py::test_message_sizes_match_openssl`, `tests/test_capture.py::test_vendored_files_are_pinned`, `tests/test_handshake.py::test_seeded_handshakes_are_pinned`, `tests/test_handshake.py::test_server_hello_rules`, `tests/test_handshake.py::test_client_hello_rules`, `tests/test_handshake.py::test_compatibility_mode_client_hello_is_echoed_and_its_ccs_dropped`

### D17. Record packing and alert keys
- **Ambiguity:** RFC 8446 lets an implementation pack handshake messages into records freely. -08 §4.3.3 says alerts after Finished use "the appropriate application traffic key", but that key may not exist yet.
- **Decision:**
  - **Packing:** consecutive handshake messages under the same key go into one record, fragmented at 2¹⁴. A key change starts a new record. There's no padding. So under signature authentication the client's second flight is one record (Finished), plus one record per application-data write made before any reply. The AuthKEM client's second flight is three records (KEMEncapsulation, Finished, data), each under its own key.
  - **AuthKEM alert key:** under AuthKEM, a server alert after a bad client Finished is sent under `s ahs traffic`, because `s ap traffic` needs the server Finished transcript, which doesn't exist yet. (Under signature authentication the server has already sent Finished, so it uses `s ap traffic`; see the next item.)
  - **Alert key per state** (signature authentication): an alert goes under the write key the peer can read in the sender's current state, from an explicit table in `qtls/handshake.py`, never "whatever key is current":
    - client: plaintext before it has processed ServerHello; `c hs traffic` until it sends Finished; `c ap traffic` afterwards;
    - server: plaintext while handling ClientHello (everything is computed before anything is queued); `s ap traffic` once it has sent Finished, since a client that sends anything after its own Finished has `s ap traffic`.
  - **Flights** are defined by the protocol, not by when the transport drains: a side starts a new flight when it queues a record after receiving the peer's input. Client application data sent after its Finished, before any reply, is part of its second flight.
- **Rejected reading:** one record per message; under AuthKEM, an alert under `s ap traffic`; for either mode, an alert under whatever key happens to be installed.
- **Tests:** planned: Phase 4 — the AuthKEM client's second flight is 3 records, and the alert decrypts under `s ahs traffic`. The Phase 2 part is implemented: per-flight record counts, flights independent of drain timing, the alert key in every failing state (decrypted, not just its description), and RFC 8448's four-message server flight in one record (`tests/test_handshake.py::test_matrix_handshakes`, `tests/test_handshake.py::test_flights_dont_depend_on_when_the_transport_drains`, `tests/test_handshake.py::test_alert_keys_per_state`, `tests/test_handshake.py::test_a_bad_client_finished_reaches_the_client_as_its_alert`, `tests/test_handshake.py::test_rfc8448_records_from_pack`, `tests/test_handshake.py::test_client_alerts_under_c_hs_in_every_handshake_state`, `tests/test_handshake.py::test_every_live_state_has_an_alert_key`, `tests/test_handshake.py::test_flight_labels`).

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
- **Tests:** implemented — `tests/test_x509.py::test_chain_sizes_and_determinism`, `tests/test_x509.py::test_matrix_chains_verify`, `tests/test_x509.py::test_matrix_chains_cross_check`

### D20. Certificates: one strict DER codec, built and parsed by qTLS
- **Ambiguity:** `cryptography`'s certificate builder can't sign with liboqs keys (Falcon, liboqs ML-DSA), and only qtls/crypto.py may import crypto libraries, so neither building nor parsing X.509 can use it.
- **Decision:**
  - **One codec:** `qtls/der.py`, used for X.509 in Phase 2 and MTC in Phase 3.
  - **Strict:** it rejects BER forms, indefinite lengths, non-minimal lengths and integers, and trailing bytes.
  - **Signing and verification** go through crypto.py, by algorithm name.
  - **Falcon-512** uses the qTLS OID in §2.
  - **Validation time** is an explicit input to path validation, never the wall clock, so expiry tests and benchmarks are reproducible.
- **Rejected reading:** a lenient (BER-accepting) parser, or a second codec for MTC.
- **Tests:** implemented — `tests/test_der.py::test_structural_rejections`, `tests/test_der.py::test_bad_lengths_are_rejected`, `tests/test_der.py::test_non_minimal_integers_are_rejected`, `tests/test_der.py::test_rfc8448_certificate_round_trips`, `tests/test_x509.py::test_validity_boundaries`, `tests/test_x509.py::test_clock_is_never_read`

### D21. A repeated extension type
- **Ambiguity:** RFC 8446 §4.2 says there MUST NOT be more than one extension of the same type in a block, but names no alert.
- **Decision:** any repeated type in any extension block (ClientHello, ServerHello, EncryptedExtensions, CertificateEntry) aborts with `illegal_parameter`. It's a semantic violation in a well-formed encoding, which RFC 8446 §6 calls `illegal_parameter` rather than `decode_error`.
- **Rejected reading:** `decode_error`, or keeping the first or last occurrence.
- **Tests:** implemented — `tests/test_messages.py::test_client_hello_rejections`, `tests/test_messages.py::test_server_hello_rejections`, `tests/test_messages.py::test_duplicate_extension_in_encrypted_extensions`, `tests/test_messages.py::test_duplicate_extension_in_a_certificate_entry`

### D22. Record-layer receive rules
- **Ambiguity:** RFC 8446 §5 leaves several receive-side choices to the implementation.
- **Decision:**
  - **Legacy record version:** ignored on receipt. qTLS sends `0x0301` in the record carrying the first ClientHello (as RFC 8448 and OpenSSL do) and `0x0303` everywhere else.
  - **Unprotected ChangeCipherSpec:** returned only if its body is exactly `0x01`; anything else is `unexpected_message`. The handshake drops a valid one between the first ClientHello and the peer's Finished (RFC 8446 §5). qTLS never sends one (D16).
  - **Zero-length handshake or alert content,** protected or not: `unexpected_message`. Zero-length application data is allowed.
  - **A record that fails AEAD:** `bad_record_mac`, and the sequence number doesn't advance. The connection is torn down anyway.
  - **Sequence numbers:** 2⁶⁴−1 is the last usable number; using the next one is a local error that requires a new key.
  - **A handshake message may not span a key change,** and a message that precedes one (ServerHello, Finished) must end its record: `unexpected_message` (RFC 8446 §5.1). `HandshakeReader.require_record_end` enforces both.
  - **Routing by state:** `record.receive` accepts only plaintext handshake and alert records before receive keys exist, only protected records afterwards, and drops a valid ChangeCipherSpec only while the handshake allows it.
  - **Plaintext alerts after ServerHello:** a server accepts an unprotected alert from when it sends ServerHello until the client's first protected record. A client that rejects the ServerHello has no keys yet, so its alert arrives in plaintext; it must be seen as the peer's alert (never answered), not as `unexpected_message`. OpenSSL behaves the same way.
  - **An alert while a handshake message is incomplete:** honoured as the peer's alert (the connection ends), rather than reported as an interleaving violation.
  - **Anything else while a handshake message is incomplete** (application data, or a ChangeCipherSpec even inside its window): `unexpected_message` (RFC 9846 §5.1 forbids interleaving).
  - **Application data before application read keys exist:** `unexpected_message`.
- **Rejected reading:** checking the legacy version on receipt, or advancing the sequence number after a failure.
- **Tests:** implemented — `tests/test_record.py::test_plaintext_hello_records`, `tests/test_record.py::test_plaintext_record_rules`, `tests/test_record.py::test_inner_plaintext_rules`, `tests/test_record.py::test_failed_record_leaves_the_sequence_number_alone`, `tests/test_record.py::test_last_sequence_number_is_usable_then_exhausted`, `tests/test_messages.py::test_partial_messages_are_pending_and_may_not_span_a_key_change`, `tests/test_messages.py::test_record_end_is_required_before_a_key_change`, `tests/test_record.py::test_receive_routes_by_state`, `tests/test_record.py::test_plaintext_alert_window_after_server_hello`, `tests/test_handshake.py::test_change_cipher_spec_window`, `tests/test_handshake.py::test_ccs_inside_a_handshake_message_is_interleaving`, `tests/test_handshake.py::test_application_data_inside_a_handshake_message_is_interleaving`, `tests/test_handshake.py::test_an_alert_inside_a_handshake_message_is_honoured`, `tests/test_handshake.py::test_application_data_before_the_handshake_finishes`, `tests/test_handshake.py::test_plaintext_alert_window_on_the_server`, `tests/test_handshake.py::test_replayed_and_tampered_records_mid_handshake`, `tests/test_handshake.py::test_server_hello_must_end_its_record`

### D23. Handshake message size limit
- **Ambiguity:** a handshake message may announce up to 2²⁴−1 bytes (RFC 8446 §4), and the RFC sets no receive limit, so an unauthenticated peer could make the reader buffer 16 MiB.
- **Decision:** `HandshakeReader` refuses a message whose header announces more than 128 KiB, as soon as the 4-byte header arrives, with `illegal_parameter` (what OpenSSL sends for an excessive message size). 128 KiB covers every certificate chain in the matrix, including category-3 post-quantum chains with SCTs. The limit is a constructor parameter, so Phase 5 can raise it.
- **Rejected reading:** no limit, or `decode_error` (the encoding is well formed).
- **Tests:** implemented — `tests/test_messages.py::test_reader_rejects_oversized_and_unknown_headers_immediately`, `tests/test_messages.py::test_reader_reassembly_is_linear`

### D24. The X.509 profile and path validation (configs A, B and D)
- **Ambiguity:** RFC 5280 allows many profiles, RFC 8446 doesn't say which alert each path-validation failure gets, and a chain with several defects could get a different alert depending on check order.
- **Decision:**
  - **Profile qTLS builds and accepts:**
    - v3 only, with extensions and no unique IDs; serial positive, at most 20 octets.
    - Names: one CN RDN (UTF8String) when built; compared byte for byte.
    - Signature-algorithm parameters absent (checked, including `id-alg-mtcProof`). Key OIDs are distinct from signature OIDs: an ECDSA key is `id-ecPublicKey` with `prime256v1`, and must be an uncompressed point *on the curve*. Post-quantum key lengths are checked at parse, and an ML-KEM key must pass the FIPS 203 §7.2 modulus check (`kem-key`; found by the OpenSSL differential in Phase 2e).
    - Names are non-empty; a CA's basicConstraints is critical (RFC 5280 §4.2.1.9); authorityKeyIdentifier is non-critical; a dNSName is non-empty.
    - Extensions: basicConstraints and keyUsage (both critical), subjectKeyIdentifier and authorityKeyIdentifier (RFC 7093 method 1: the first 160 bits of SHA-256 of the key), subjectAltName dNSName on the leaf, and optionally an SCT list on the leaf.
    - DER DEFAULT values are never encoded: version v1, `critical FALSE` and `cA FALSE` are rejected if written out.
    - Unknown critical extensions are rejected; unknown non-critical ones are ignored.
  - **Parsing is algorithm-agnostic** and keeps exact bytes (TBS, SPKI, names, extensions). An unknown signature algorithm, such as an MTC's `id-alg-mtcProof`, parses; validation then refuses it with `unsupported_certificate`.
  - **Validation order**, which decides the alert when a chain has several defects:
    1. Parse every certificate → `bad_certificate`.
    2. Find the trust anchors that could have issued the top certificate, by name → `unknown_ca`. Several anchors may share a name (key rollover); each is tried, so anchor order never changes the result. A sent root that matches an anchor exactly is ignored; a chain with no intermediates is fine. Anchors are a bare name and key, so their validity isn't checked.
    3. Every signature algorithm must be one the peer accepts (`signature_algorithms_cert`) → `unsupported_certificate`.
    4. Per link: issuer name, issuer key type matching the signature algorithm, then the signature → `bad_certificate`.
    5. Issuers are CAs, with keyCertSign if keyUsage is present (RFC 5280 §6.1.4(n)), within their pathLen → `bad_certificate`.
    6. Every certificate valid at the injected `now` (inclusive bounds) → `certificate_expired`, including not-yet-valid.
    7. Leaf: not a CA → `bad_certificate`; a key algorithm qTLS knows → `unsupported_certificate`; a key of the kind the handshake's authentication mode needs (signature for CertificateVerify, KEM for AuthKEM) → `unsupported_certificate`; keyUsage that fits its key kind → `bad_certificate`: for a signature key, digitalSignature if keyUsage is present (RFC 8446 §4.4.2.2 allows it to be absent); for a KEM key, keyUsage must be present with keyEncipherment. Finally a dNSName equal to the server name, ASCII case-insensitive, with no wildcards, no trailing dots and no CN fallback → `bad_certificate`.
  - **Deliberately narrower than RFC 5280/8446:** the chain must arrive in order, leaf first, with no extra certificates (RFC 8446 says SHOULD tolerate); pathLen counts every issuer, including self-issued ones (RFC 5280 exempts those; qTLS never issues them); any critical extension qTLS doesn't interpret, such as a critical extendedKeyUsage, is rejected.
  - **Trust anchors** are local configuration: a malformed one is refused when it's created, never blamed on the peer.
  - **MTCs:** an `id-alg-mtcProof` certificate parses, but its issuer is an MTC CA rather than an X.509 anchor, so until Phase 3 adds a dispatch on the signature algorithm *before* step 2, it gets `unknown_ca`.
  - **SCTs:** carried as RFC 6962 says (an OCTET STRING inside extnValue holding the TLS-encoded list; `log_id` is SHA-256 of the log key's DER SubjectPublicKeyInfo). The 2-byte algorithm field holds the TLS SignatureScheme; for ECDSA that's exactly RFC 6962's (hash 4, signature 3), and RFC 6962 has no codepoint for post-quantum signatures. Each SCT is signed by a stand-in log key of the issuer's algorithm. CT validation itself is out of scope; SCTs are there for size realism.
  - **Fixtures are deterministic:** every key and signature derives from a fixture seed and a role (`qtls/chains.py`).
- **Rejected reading:** OpenSSL's choices of `decode_error` for malformed certificates and `bad_certificate` for not-yet-valid ones; `certificate_unknown` for a name mismatch; accepting a CN fallback or wildcards.
- **Tests:** implemented — `tests/test_x509.py::test_parse_rejections`, `tests/test_x509.py::test_alert_precedence`, `tests/test_x509.py::test_anchors`, `tests/test_x509.py::test_per_link_checks`, `tests/test_x509.py::test_path_length`, `tests/test_x509.py::test_algorithm_confusion_is_an_alert_not_a_crash`, `tests/test_x509.py::test_name_mismatches`, `tests/test_x509.py::test_sent_root_is_ignored_and_no_intermediates_is_fine`, `tests/test_x509.py::test_mtc_style_certificate_parses_but_is_unsupported`, `tests/test_x509.py::test_kem_leaf_comes_back_as_kem`, `tests/test_x509.py::test_profile_rejections`, `tests/test_x509.py::test_anchors_sharing_a_name_are_order_independent`, `tests/test_x509.py::test_leaf_key_usage_rules`, `tests/test_x509.py::test_kem_leaf_needs_key_encipherment`, `tests/test_x509.py::test_ecdsa_key_oid_and_curve_point`, `tests/test_x509.py::test_signature_algorithm_parameters_must_be_absent`, `tests/test_x509.py::test_mtc_certificate_under_a_non_x509_issuer_is_unknown_ca`, `tests/test_x509.py::test_sct_fields`, `tests/test_x509.py::test_key_identifiers`, `tests/test_x509.py::test_san_must_be_a_dns_name`, `tests/test_x509.py::test_leaf_kind_must_fit_the_authentication_mode`, `tests/test_x509.py::test_malformed_anchors_are_local_errors`, `tests/test_x509.py::test_kem_leaf_with_an_unreduced_key_is_a_bad_certificate`, `tests/test_crypto.py::test_kem_public_key_check_agrees_with_the_backends`, `tests/test_x509.py::test_pq_fuzz_only_raises_alert_errors_with_reasons`, `tests/test_x509.py::test_openssl_agrees_with_every_accepted_mutant`

### D25. Server certificate and CertificateVerify scheme selection
- **Ambiguity:** RFC 8446 §4.4.2.2 lets a server send a chain the client may not accept, and §4.4.3 even lets it use a CertificateVerify scheme the client didn't offer when it has no other chain. It doesn't fix the client's alerts for a scheme mismatch.
- **Decision:**
  - **Server:** it has one chain. It picks its leaf key's scheme if the client offered it in `signature_algorithms`, else aborts with `handshake_failure`. It doesn't check `signature_algorithms_cert`: it sends the chain anyway, and the client decides.
  - **Client:** the chain's signatures must be in `signature_algorithms_cert` if it sent one, else in `signature_algorithms` (RFC 8446 §4.2.3), else `unsupported_certificate` (D24). The leaf must be a signature key (`expected_kind="sig"`, P8).
  - **CertificateVerify:** a scheme the client didn't offer → `illegal_parameter`; a scheme that doesn't fit the leaf key → `illegal_parameter`; a signature that doesn't verify over the server context string and H(CH..Certificate) → `decrypt_error`.
  - **Each configuration's client offers only its own scheme**, so a client of one configuration and a server of another fail to negotiate.
- **Rejected reading:** accepting a CertificateVerify scheme the client didn't offer, or the server refusing to send a chain whose issuer schemes the client didn't list.
- **Tests:** implemented — `tests/test_handshake.py::test_cv_scheme_must_fit_the_leaf`, `tests/test_handshake.py::test_encrypted_flight_rules`, `tests/test_handshake.py::test_cross_config_matrix`, `tests/test_handshake.py::test_signature_algorithms_cert_fallback`, `tests/test_handshake.py::test_kem_leaf_is_refused_under_signature_authentication`, `tests/test_handshake.py::test_client_hello_rules`

### D26. Post-handshake messages, alerts and closure
- **Ambiguity:** RFC 8446 §6 and §4.6 leave open what a client without resumption does with NewSessionTicket, how a warning-level error alert is treated, and what happens when the transport ends without close_notify.
- **Decision:**
  - **NewSessionTicket** after the handshake is framed and dropped, never hashed (resumption is out of scope; OpenSSL servers send them). Before the handshake ends it's `unexpected_message`.
  - **KeyUpdate and every other post-handshake message** → `unexpected_message`. The server accepts no handshake message once connected.
  - **close_notify** (at any point, the handshake included) ends the connection cleanly. The receiver answers with its own close_notify unless it already sent one.
  - **Half-close:** after sending close_notify, a side still delivers the peer's application data until the peer's close_notify.
  - **Every other alert**, whatever its level (`user_canceled`, a warning-level error alert, an unknown description), ends the connection and is never answered (RFC 8446 §6: unknown alerts and error alerts are fatal).
  - **EOF without close_notify** is truncation: the connection fails with reason `truncated` and no alert.
  - **After our own close_notify** nothing more is sent: a later failure reports no alert.
  - **Nothing after a peer's alert** in the same delivery is processed.
  - **`pre_shared_key`** must be the last ClientHello extension (`illegal_parameter`, RFC 8446 §4.2.11); otherwise it's ignored, since there's no resumption.
- **Rejected reading:** answering a peer's error alert, treating a warning-level error alert as non-fatal, or hashing a NewSessionTicket into the transcript.
- **Tests:** implemented — `tests/test_handshake.py::test_new_session_ticket_is_dropped_after_the_handshake`, `tests/test_handshake.py::test_other_post_handshake_messages_are_unexpected`, `tests/test_handshake.py::test_new_session_ticket_before_the_handshake_ends_is_unexpected`, `tests/test_handshake.py::test_half_close_still_delivers_the_peers_data`, `tests/test_handshake.py::test_peer_alerts_end_the_connection_and_are_never_answered`, `tests/test_handshake.py::test_close_notify_during_the_handshake`, `tests/test_handshake.py::test_eof_without_close_notify_is_truncation`, `tests/test_handshake.py::test_server_state_message_matrix`, `tests/test_handshake.py::test_after_our_close_notify_a_failure_sends_and_reports_no_alert`, `tests/test_handshake.py::test_nothing_after_a_peer_alert_in_the_same_delivery_is_processed`, `tests/test_handshake.py::test_pre_shared_key_must_be_the_last_extension`, `tests/test_handshake.py::test_eof_mid_handshake_and_after_our_close`, `tests/test_interop.py::test_openssl_key_update_is_refused`, `tests/test_interop.py::test_qtls_client_with_openssl_server`

### D27. A TLS 1.2 ServerHello
- **Ambiguity:** RFC 8446 §4.1.3 says a TLS 1.3 client receiving a ServerHello for TLS 1.2 or below MUST check the downgrade sentinel and abort with `illegal_parameter`. qTLS's codec decodes only the TLS 1.3 shape (an extension block of at least 6 bytes), so a real TLS 1.2 ServerHello might fail to decode before the sentinel is seen.
- **Decision:**
  - **Precedence:** the client checks the sentinel (`DOWNGRD\x01` or `DOWNGRD\x00` in the last 8 bytes of the random) and the HelloRetryRequest random *before* the strict decode. A sentinel → `illegal_parameter`.
  - **Without a sentinel:** a ServerHello that fails the TLS 1.3 shape (no extensions, or fewer than 6 bytes of them) → `decode_error`; one that decodes but has no `supported_versions` → `protocol_version`. The version is checked before the session ID and cipher suite, so a TLS 1.2 ServerHello always gets one of these.
- **Rejected reading:** decoding first, so the sentinel never gets a chance; or checking the cipher suite before the version.
- **Tests:** implemented — `tests/test_handshake.py::test_genuine_tls12_server_hello`, `tests/test_handshake.py::test_server_hello_rules`

### D28. One encoding per Falcon-512 signature
- **Ambiguity:** the round-3 Falcon specification defines the compressed signature encoding, but liboqs's Falcon-512 verifier also accepts a compressed signature zero-padded to exactly 666 bytes (the Falcon-padded-512 length). So every signature has two encodings that verify, and so does every certificate it signs: two byte strings, two certificate identities, one signature.
- **Decision:** `crypto.sig_verify` accepts a Falcon-512 signature only in its canonical compressed encoding, checked by `crypto.falcon_canonical` before either backend verifies: header `0x39`, a 40-byte nonce, then exactly 512 coefficients (sign bit, 7 low bits, unary high part; |s| ≤ 2047; no −0) that end in the last byte, whose unused bits are zero. Anything else is `InvalidSignature` (in a certificate `bad_certificate`, in CertificateVerify `decrypt_error`). A genuine compressed signature that happens to be 666 bytes long is accepted.
- **Rejected reading:** trusting the backend's verifier as the definition of a valid encoding; or rejecting every 666-byte signature, which would reject genuine ones.
- **Tests:** implemented — `tests/test_crypto.py::test_falcon_padded_signature_is_rejected_though_liboqs_accepts_it`, `tests/test_crypto.py::test_falcon_synthetic_encoding_of_exactly_666_bytes_is_canonical`, `tests/test_crypto.py::test_falcon_noncanonical_encodings_are_rejected`, `tests/test_crypto.py::test_falcon_encoder_controls_are_canonical`, `tests/test_crypto.py::test_falcon_canonical_check_never_rejects_a_real_signature`, `tests/test_handshake.py::test_padded_falcon_certificate_verify_is_rejected`, `tests/test_x509.py::test_falcon_certificate_with_the_padded_signature_encoding_is_rejected`

### D29. The TCP transport
- **Ambiguity:** the sans-I/O connection fixes what goes on the wire, but not how it is written, and Phase 5 measures round trips and bytes per flight. A transport that splits flights, waits on Nagle, makes the application's first data wait for an extra write, or reports a failure differently depending on timing changes those numbers or hides the cause.
- **Decision:** `qtls/transport/tcp.py`:
  - `TCP_NODELAY` on every socket.
  - **One write per reaction:** everything a connection queues in reaction to one `receive` (a flight, or several protocol flights queued in one reaction) is handed to the kernel in one `send` call. Only a full socket buffer splits it, and the rest follows as soon as the socket is writable.
  - **The application hook runs first:** `on_receive(session, events)` runs before that write (for every receive except one that ends the connection, which raises instead) and may call only `queue()`, so the client's Finished and its first application data share a write, and so do the server's first flight and its 0.5-RTT data (what Phases 4 and 5 measure). Any other call from the hook is `CodecUsageError`.
  - **Full duplex, reads first:** a non-blocking socket driven by a selector that reads before it writes, so both peers can send large data at once and a peer's alert is seen even when our write then fails.
  - **One deadline per call** on the monotonic clock, bounding the whole call (`connect` and `accept` included), so a peer that trickles bytes can't hold it open (`TimeoutError`). `accept` leaves the listener's own timeout alone.
  - **Failures are typed, whatever the timing.** A TLS failure is `TLSFailed(event)`. For our own failure, the alert follows everything already queued, in order: those records are encrypted under consecutive sequence numbers (RFC 8446 §5.3), so skipping any would make the alert undecryptable; a peer's alert is never answered, so our pending output is dropped and `TLSFailed` is raised at once. A socket error after a TLS failure is `TLSFailed` chained to it; otherwise a reset is `OSError`. EOF is `receive_eof` (truncation, D26). A local bug inside the connection flushes its `internal_error` and is re-raised. An exception from the hook abandons the reaction: nothing more is written, so the peer sees EOF, never a flight from a connection the application gave up.
  - **A failure that arrives with data:** `recv` returns the data, and the next call (`recv`, `send`, `queue` or `close`) raises the failure. Any failure closes the socket. `close` on a closed or reported-failed session is a no-op; any other use of a closed session is `CodecUsageError`. `close` raises `TimeoutError` if the peer never answers close_notify, and closes the socket either way.
  - **Timing records** on `perf_counter_ns`: every `send` call with the bytes offered and taken (`sends`), every `recv` before processing (`arrivals`, so segment arrival under a small initcwnd is visible), and every event after processing (`events`).
- **Rejected reading:** a blocking socket with a per-`recv` timeout (a trickling peer defeats it, and two peers sending at once deadlock); writing record by record; returning from `connect` before the application could add data to the client's second flight; timestamping only after processing, which adds signature verification to every measured round trip.
- **Tests:** implemented — `tests/test_tcp.py::test_handshake_over_tcp_writes_each_flight_once`, `tests/test_tcp.py::test_a_per_record_transport_fails_the_flight_check`, `tests/test_tcp.py::test_finished_and_first_data_share_a_write`, `tests/test_tcp.py::test_half_rtt_data_joins_the_server_flight`, `tests/test_tcp.py::test_nodelay_is_set_on_both_sockets`, `tests/test_tcp.py::test_large_data_both_ways_at_once_does_not_deadlock`, `tests/test_tcp.py::test_trickling_peer_cannot_extend_the_deadline`, `tests/test_tcp.py::test_silent_peer_times_out_at_the_deadline`, `tests/test_tcp.py::test_accept_times_out_without_a_client_and_leaves_the_listener_alone`, `tests/test_tcp.py::test_accept_is_one_deadline_for_accept_and_handshake`, `tests/test_tcp.py::test_peer_closing_mid_handshake_is_truncation`, `tests/test_tcp.py::test_close_notify_then_silence_mid_handshake_is_an_error`, `tests/test_tcp.py::test_reset_is_an_oserror_and_the_session_is_dead`, `tests/test_tcp.py::test_our_alert_is_flushed_before_the_failure_is_raised`, `tests/test_tcp.py::test_a_partially_written_alert_is_flushed_before_the_failure_is_raised`, `tests/test_tcp.py::test_our_failure_while_data_is_queued_sends_the_alert_after_it_in_order`, `tests/test_tcp.py::test_a_peer_alert_while_our_output_is_stuck_is_tlsfailed_at_once`, `tests/test_tcp.py::test_a_socket_error_after_our_failure_is_tlsfailed_chained_to_it`, `tests/test_tcp.py::test_data_and_a_fatal_alert_together_then_every_call_raises_the_alert`, `tests/test_tcp.py::test_a_pending_peer_alert_is_raised_by_the_next_call`, `tests/test_tcp.py::test_a_local_bug_flushes_internal_error_and_is_reraised`, `tests/test_tcp.py::test_local_bug_alert_is_flushed_whole_through_partial_writes`, `tests/test_tcp.py::test_an_exception_in_the_hook_abandons_the_reaction`, `tests/test_tcp.py::test_only_queue_may_be_called_from_the_hook`, `tests/test_tcp.py::test_clean_close_both_ways_and_eof_ends_the_loop`, `tests/test_tcp.py::test_recv_returns_at_close_notify_while_the_peer_holds_the_socket_open`, `tests/test_tcp.py::test_close_is_idempotent_and_closed_sessions_refuse_use`, `tests/test_tcp.py::test_peer_eof_with_our_output_pending_is_an_error_never_a_silent_return`, `tests/test_tcp.py::test_every_send_call_and_every_arrival_is_recorded`, `tests/test_tcp.py::test_arrivals_are_logged_per_segment_before_processing`, `tests/test_tcp.py::test_events_and_writes_are_timestamped_in_order`, `tests/test_tcp.py::test_a_peer_alert_then_close_while_we_write_is_the_alert_not_a_reset`, `tests/test_tcp.py::test_recv_raises_a_peer_alert_that_arrives_alone`, `tests/test_tcp.py::test_connect_is_one_deadline_for_connecting_and_the_handshake`, `tests/test_tcp.py::test_a_successful_accept_leaves_the_listener_as_it_was`, `tests/test_tcp.py::test_the_hook_is_not_called_for_a_receive_that_ends_the_connection`, `tests/test_tcp.py::test_nothing_is_written_after_the_peer_alert_arrives`, `tests/test_tcp.py::test_close_notify_then_true_silence_mid_handshake_is_prompt`, `tests/test_tcp.py::test_a_send_the_kernel_refuses_is_recorded_with_nothing_sent`, `tests/test_tcp.py::test_a_hook_exception_with_output_pending_writes_nothing_more`

### D30. The server-certificate verifier
- **Ambiguity:** MTC (Phase 3) changes what a Certificate message contains, not where it sits in the handshake. If chain validation is hard-wired into the client's Certificate handler, Phase 3 rewrites the state machine; if it is pluggable, a verifier could return a leaf the handshake must not use (P8).
- **Decision:** `ClientConfig.certificate_verifier` (a `CertificateVerifier`; default `X509Verifier(anchors, now)`, today's D24 validation). The state machine keeps the message checks (empty context, a non-empty list, no entry extensions) and runs them first, then calls `verify(cert_data, server_name=, accepted=, expected_kind="sig", backends=)` once. A verifier owns its trust policy (anchors, time; landmarks in Phase 3) and reports a bad chain with `AlertError`; anything else it raises is a local bug (`internal_error`, re-raised). Whatever it returns, the state machine re-checks it: a leaf that isn't the certificate the server sent → `bad_certificate` (`leaf-mismatch`), a non-signature leaf → `unsupported_certificate` (`leaf-kind`), a key none of the offered schemes fits → `unsupported_certificate` (`leaf-alg`). CertificateVerify uses the returned leaf.
  - **Phase 3 grows this interface.** MTC needs the client to advertise the landmark group it holds (D15) in the ClientHello, which `verify` can't express, and may need Certificate-entry or EncryptedExtensions data, which the state machine rejects before the verifier runs today. Those additions are decided once `draft-ietf-tls-trust-anchor-ids` is read (a Phase 3 entry criterion), not guessed now. Until then `ClientConfig.anchors` and `now` stay required fields, used only by the default verifier.
- **Rejected reading:** passing the whole `ClientConfig` to the verifier; trusting its result without postconditions; or adding a speculative ClientHello hook before the trust-anchor-ids draft says what it must carry.
- **Tests:** implemented — `tests/test_handshake.py::test_the_verifier_is_called_once_with_the_entries_and_the_handshake_needs`, `tests/test_handshake.py::test_the_verifier_gets_signature_algorithms_cert_when_it_is_sent`, `tests/test_handshake.py::test_message_checks_run_before_the_verifier`, `tests/test_handshake.py::test_certificate_verify_uses_the_leaf_the_verifier_returned`, `tests/test_handshake.py::test_the_state_machine_rechecks_the_returned_leaf`, `tests/test_handshake.py::test_a_verifier_alert_fails_the_connection_with_its_reason`, `tests/test_handshake.py::test_a_verifier_bug_is_internal_error_and_reraised`, `tests/test_handshake.py::test_anchors_are_required_only_by_the_default_verifier`, `tests/test_handshake.py::test_the_verifier_must_return_the_presented_leaf`

## 5. How to change this file

- **Re-pin:** update §1, read the diff, update the affected decisions, and update the tests that cite them in the same commit.
- **New ambiguity:** add the next `Dn` with all four fields (Ambiguity, Decision, Rejected reading, Tests). The traceability test enforces this.
