# Threat model

*Phase 0 deliverable. Revised 2026-11-13 after a three-way review. The property table in §5 is checked by `tests/test_traceability.py`:*
- *every test cited for an implemented property must be a collected, module-level pytest test;*
- *every planned property must name a phase that hasn't finished yet.*

## 1. What qTLS is, for this purpose

qTLS is a research prototype. It runs a TLS 1.3–shaped handshake between one client and one server, and measures it. Its security claims are about **protocol design**: what each configuration in the matrix (PLAN §3) guarantees, and when. They are not about the implementation, which is unaudited, not constant-time Python and must never protect real traffic.

## 2. Attackers

| ID | Attacker | Capabilities | Why it matters here |
|---|---|---|---|
| **A1** | Passive, quantum later ("harvest now, decrypt later") | Records traffic today. Later gets a cryptographically relevant quantum computer (CRQC) and breaks X25519, ECDSA and RSA. | Key exchange must be quantum-safe today. Every **full** handshake uses `X25519MLKEM768`. Pre-distributed-key 0-RTT data is keyed from ML-KEM alone (specs.md D12), so it has no classical hedge (L6). |
| **A2** | Active, quantum now | Full control of the network (Dolev–Yao) *and* a CRQC during the handshake. Can forge classical signatures and impersonate servers that authenticate with classical keys. | Server authentication must be quantum-safe. Config A fails here by design; it's the baseline for today's web. |
| **A3** | Active, classical | Dolev–Yao without a CRQC: replays, reorders, drops and rewrites messages, and steers negotiation. | Downgrade between configs, transcript and record manipulation. |
| **A4** | Malicious or compromised CA, or a log not followed by monitors | Issues certificates for keys the subject doesn't hold or for names it doesn't own. | MTC binds keys by hash only (MTC -08 §12). Neither MTC nor X.509 proves key possession at issuance (specs.md D13). |
| **A5** | Long-term key compromise *after* the session | Learns the server's long-term KEM or signing secret key after recording a session. | Forward secrecy. Full handshakes stay secret (ephemeral hybrid key exchange). Pre-distributed-key 0-RTT data doesn't (L2). |

Out of scope:
- **Implementation attacks:** side channels (timing, power, cache) and fault attacks.
- **Denial of service.**
- **Traffic analysis:** beyond what the drafts already note (AuthKEM -08 §5.2).
- **Compromise of a long-term key *during* a session.**
- **The MTC landmark update channel.** It is modelled as a parameter, not attacked.
- **Client authentication.**

## 3. Authentication: two kinds, kept separate

- **Implicit authentication.** Only a party holding the server's long-term secret key can derive the keys protecting the data. If the client sends data, it is confidential to the real server, but the client hasn't yet confirmed that the server took part.
- **Explicit authentication.** The client has verified proof that the server took part in *this* handshake. Under signature authentication that proof is CertificateVerify plus Finished. Under AuthKEM it is the server's Finished, keyed from the Main Secret (specs.md D5).

| Config | Client's first application data | Explicit server authentication |
|---|---|---|
| A, B, C (signature) | 1 RTT, after server Finished: explicit | 1 RTT |
| D, E (AuthKEM, key in certificate) | 1 RTT, after its own Finished and before server Finished: **implicit** (specs.md D9) | **2 RTT**, on server Finished |
| D/E with pre-distributed key (one handshake, specs.md D12) | 0-RTT possible, under a key **without forward secrecy** (L2) | 1 RTT, on server Finished |

Benchmarks report the round trips to each kind of authentication separately (PLAN Phase 5). Counting implicitly authenticated data as "authenticated" would overstate AuthKEM by a **full round trip**.

## 4. Accepted limitations

These come from the drafts' design, not from qTLS bugs. They're reported, not fixed.

- **L1.** Under AuthKEM, data the client sends before server Finished goes to an implicitly authenticated peer. A3 can downgrade the symmetric parameters for that data, but only to ones the client offered (AuthKEM -08 §5.1).
- **L2.** Pre-distributed-key 0-RTT data has no forward secrecy (A5) and can be replayed, as with TLS 1.3 0-RTT (authkem-psk-06 §3.2).
- **L3.** MTC binds the subject key by hash only. A CA can log a hash with no known preimage (A4). Detection is by monitors, outside qTLS.
- **L4.** Landmark-relative MTCs need an up-to-date client. Stale clients fall back to larger standalone certificates (specs.md D15), and the fallback rate is measured.
- **L5.** Explicit server authentication under AuthKEM costs one extra RTT (§3).
- **L6.** Pre-distributed-key 0-RTT data is protected by ML-KEM alone, without the X25519 hedge that full handshakes get.

## 5. Properties and the tests that prove them

Status: **implemented** means the listed tests exist and pass in CI. **planned** names the phase that must add them; that phase can't be recorded as met while the row is still planned.

| ID | Property | Against | Configs | Status | Tests |
|---|---|---|---|---|---|
| P1 | ML-KEM, ML-DSA and ECDSA are the specified FIPS / RFC algorithms on every backend that offers them, with no look-alikes, aliases or fallbacks | Implementation error | all | implemented | `tests/test_kat.py::test_mlkem_keygen`, `tests/test_kat.py::test_mlkem_decapsulation`, `tests/test_kat.py::test_mldsa_sigver`, `tests/test_crypto.py::test_ecdsa_rfc6979_known_answer`, `tests/test_cross_backend.py::test_seeded_keygen_agrees`, `tests/test_cross_backend.py::test_encapsulate_in_one_decapsulate_in_other`, `tests/test_cross_backend.py::test_implicit_rejection_agrees`, `tests/test_cross_backend.py::test_sign_in_one_verify_in_other`, `tests/test_crypto.py::test_unknown_names_raise`, `tests/test_crypto.py::test_openssl_does_not_fall_back_for_liboqs_only_algorithms`, `tests/test_crypto.py::test_unsupported_names_raise_from_every_entry_point`, `tests/test_kat.py::test_mldsa_keygen`, `tests/test_kat.py::test_mlkem_encapsulation`, `tests/test_rfc_vectors.py::test_ecdsa_rfc6979_deterministic_signature` |
| P2 | Signatures bind the whole message, context and key; any change is rejected | A3 | all | implemented | `tests/test_crypto.py::test_every_message_byte_is_signed`, `tests/test_crypto.py::test_sig_rejects_corruptions`, `tests/test_crypto.py::test_sig_rejects_another_keys_signature`, `tests/test_crypto.py::test_mldsa_context_strings_bind` |
| P3 | Malformed public keys and inputs are rejected the same way on every backend | A3 | all | implemented | `tests/test_crypto.py::test_invalid_mlkem_public_key_raises_the_same_error_on_every_backend`, `tests/test_crypto.py::test_malformed_signer_public_key_is_an_invalid_signature`, `tests/test_crypto.py::test_malformed_pq_signer_public_keys_are_invalid_signatures`, `tests/test_crypto.py::test_x25519_low_order_point_is_invalid_public_key`, `tests/test_crypto.py::test_kem_wrong_length_inputs_are_rejected`, `tests/test_crypto.py::test_non_bytes_inputs_raise_type_error` |
| P4 | X25519, Falcon-512 and the TLS 1.3 symmetric primitives (SHA-256, HMAC, HKDF, AES-128-GCM) are the specified algorithms: RFC 7748 and RFC 8448 vectors; Falcon-512 against liboqs's published KAT hashes (anchored to NIST round 3 by liboqs, not re-verified here) | Implementation error | all | implemented | `tests/test_rfc_vectors.py::test_x25519_scalar_mult`, `tests/test_rfc_vectors.py::test_x25519_iterations`, `tests/test_rfc_vectors.py::test_x25519_diffie_hellman`, `tests/test_rfc_vectors.py::test_rfc8448_x25519_key_exchange`, `tests/test_rfc_vectors.py::test_rfc8448_hkdf_extract`, `tests/test_rfc_vectors.py::test_rfc8448_hkdf_expand`, `tests/test_rfc_vectors.py::test_rfc8448_traffic_key_and_iv`, `tests/test_rfc_vectors.py::test_rfc8448_server_finished`, `tests/test_rfc_vectors.py::test_rfc8448_record_protection`, `tests/test_symmetric.py::test_sha256_known_answers`, `tests/test_kat.py::test_liboqs_signature_kat_single`, `tests/test_kat.py::test_liboqs_signature_kat_all`, `tests/test_kat.py::test_padded_falcon_has_a_different_kat`, `tests/test_kat.py::test_seeded_keygen_matches_the_drbg_kat` |
| P5 | Session keys are secret against A1: hybrid shares and secret laid out exactly as RFC 10024 specifies, and both halves contribute | A1 | all | planned: Phase 2 | Share and secret layout; zeroing either half changes every key; RFC 8448 vectors; OpenSSL interop |
| P6 | Implicit authentication of early client data: an attacker without the server's KEM secret key can't decrypt it | A2, A3 | D, E | planned: Phase 4 | Attacker server; early record fails AEAD under every key the attacker can derive; a mutant client with SSs = 0 must fail the test |
| P7 | Explicit server authentication: the client aborts unless the server proves possession of the certified key in this handshake | A2, A3 | B–E | planned: Phases 2 and 4 | CertificateVerify rejection set (Phase 2); AuthKEM attacker server aborts with `bad_record_mac` (specs.md D10), and a mutant client that skips SSs fails (Phase 4) |
| P8 | No downgrade: a KEM leaf is never accepted under signature auth, a missing CertificateVerify is never accepted, the client accepts only parameters it offered, and only `0x11EC` | A3 | all | planned: Phase 4 | Client × server config matrix; non-`0x11EC` group and HelloRetryRequest rejected (specs.md D16, Phase 2) |
| P9 | Transcript integrity and message order (specs.md D6, D12) | A3 | all | planned: Phases 2 and 4 | Missing, duplicate and swapped messages abort with `unexpected_message`; tampered transcript or Finished rejected |
| P10 | Record-layer integrity: tampered, replayed, reordered or oversized records are rejected | A3 | all | implemented | `tests/test_record.py::test_tampering_each_region`, `tests/test_record.py::test_replay_and_reorder_are_rejected`, `tests/test_record.py::test_failed_record_leaves_the_sequence_number_alone`, `tests/test_record.py::test_garbage_ciphertexts_are_bad_record_mac`, `tests/test_record.py::test_oversized_ciphertext_is_record_overflow_before_decrypting`, `tests/test_record.py::test_inner_plaintext_boundaries`, `tests/test_record.py::test_inner_plaintext_rules`, `tests/test_record.py::test_high_sequence_numbers`, `tests/test_record.py::test_last_sequence_number_is_usable_then_exhausted` |
| P11 | X.509 path validation and name binding: untrusted root, expired leaf, wrong issuer signature, and a certificate for another server name are all rejected | A2, A3, A4 | A, B, D | planned: Phase 2 | Each case aborts with its RFC 8446 alert |
| P12 | MTC certificates are accepted only if every MTC -08 §7.2 step passes, and the key is bound by its SPKI hash | A3, A4 | C, E | planned: Phase 3 | Appendix C vectors, one test per §7.2 step, substituted-SPKI test, domain-separation mutant |
| P13 | Forward secrecy: after the server's long-term key is revealed, full-handshake data stays secret while pre-distributed 0-RTT data doesn't (documents L2) | A5 | B–E | planned: Phase 4 | Reveal the secret key after the session; attempt decryption |
| P14 | A stale or rotated pre-distributed key falls back or aborts in a defined way, never hangs | A3 | D/E pre-distributed | planned: Phase 4 | Rotated key, wrong-identity key; the state machine ends `connected` or `closed` |
| P15 | Benchmarks measure what they claim | Experimental error | all | planned: Phase 5 | Calibration: RTT, loss, initcwnd effect, bytes on the wire = sum of records, per-role CPU, round trips to implicit and explicit authentication |
