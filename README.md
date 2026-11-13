# qTLS — KEM-authenticated, post-quantum TLS 1.3

> **Status: research prototype, pre-alpha.** Nothing here is production-ready, and none of it should protect real traffic.

## Why this project exists

By late 2026, TLS on the public web is **half** quantum-safe:

| Part of the handshake | Deployed today | Quantum-safe? |
|---|---|---|
| Key exchange | Hybrid `X25519MLKEM768` (default in Chrome, Edge, Cloudflare, OpenSSL 3.5) | Yes |
| Server authentication (certificate chain + `CertificateVerify` signature) | RSA / ECDSA | **No** |

Authentication is behind because post-quantum signatures are big. One ML-DSA-44 signature is 2,420 bytes, against about 72 for ECDSA, and a normal chain carries several signatures and public keys. The industry's leading fix is **Merkle Tree Certificates (MTC)**, an IETF draft that Chrome favours for post-quantum web PKI. MTCs swap the CA signatures in the chain for a short Merkle inclusion proof. **The server's own handshake signature stays**, though, and so does its post-quantum public key.

qTLS asks: **what if that last signature were a KEM instead?**

## The idea

This idea is called KEMTLS, or AuthKEM (Schwabe–Stebila–Wiggers, 2020; IETF draft `draft-celi-wiggers-tls-authkem`). The server's certificate holds an **ML-KEM public key** instead of a signature key. The server proves its identity by decrypting a challenge the client encapsulates to that key, and no handshake signature is sent.

- ML-KEM-768 ciphertext: 1,088 bytes. ML-DSA-44 signature: 2,420 bytes.
- KEM operations are far cheaper than signing.

qTLS will **combine AuthKEM with Merkle Tree Certificates**, then measure it against the alternatives under realistic network conditions:

| Config | Key exchange | Certificate | Server proves identity by |
|---|---|---|---|
| **A**: today's web | X25519MLKEM768 | ECDSA X.509 chain | ECDSA signature |
| **B**: naive post-quantum | X25519MLKEM768 | ML-DSA X.509 chain | ML-DSA signature |
| **C**: post-quantum web as planned | X25519MLKEM768 | Merkle Tree Certificate | ML-DSA signature |
| **D**: AuthKEM | X25519MLKEM768 | ML-DSA X.509 chain, ML-KEM leaf | ML-KEM decapsulation |
| **E**: qTLS | X25519MLKEM768 | Merkle Tree Certificate, ML-KEM leaf | ML-KEM decapsulation |

**Hypothesis:** E is fully post-quantum and makes the smallest, cheapest handshake of B–E, without the extra round trip that B's oversized flight causes. The trade-offs we expect to quantify:
- AuthKEM delays server authentication by half a round trip.
- It needs the client to learn the server's KEM key, either from the certificate or from a cache.
- MTCs need clients to stay synced with tree heads.

## What "better" means here (and what it doesn't)

- ✅ A better **protocol composition**, backed by measurements, published as reproducible results.
- ✅ Standard, NIST-approved primitives only: ML-KEM (FIPS 203), ML-DSA (FIPS 204), X25519, HKDF, AES-GCM or ChaCha20-Poly1305.
- ❌ No new cryptographic primitives. No "quantum cryptography" of our own.
- ❌ No quantum key distribution (QKD). That needs dedicated quantum hardware and links, and it isn't a TLS replacement. See [`legacy/`](#legacy-code).
- ❌ Not a drop-in TLS library. The impact path is evidence that can feed IETF discussion.

## Planned deliverables

1. **`qtls/`**: a Python prototype of a TLS 1.3–shaped handshake supporting configs A–E. It produces real message bytes over real sockets.
2. **`bench/`**: a benchmark harness for bytes on the wire, round trips, handshake latency under varied RTT and loss, and CPU per handshake.
3. **`notebooks/`**: Jupyter notebooks that walk through each handshake and reproduce every chart.
4. **`docs/`**: design notes, threat model and results write-up. Stretch goal: a Tamarin model of config E.

See [docs/PLAN.md](docs/PLAN.md) for the phased plan, exit criteria and risks.

## Getting started

*Not runnable yet.* Phase 1 of the plan sets up the environment. The planned stack is:

- Python ≥ 3.11
- [`liboqs-python`](https://github.com/open-quantum-safe/liboqs-python) for ML-KEM and ML-DSA
- [`cryptography`](https://cryptography.io) for X25519, HKDF and AEAD
- Linux `tc netem`, or the built-in emulator, for network conditions

## Legacy code

The repository's first iteration (April–May 2023) explored QKD and "quantum cryptography" simulations: `qkdProtocol.*`, `QCA.*`, `qTLS.py`, `Program.cs`, and the `.txt` design notes. Those files are **known broken** and are kept only for history:

- The C# doesn't compile.
- The Python targets Qiskit < 1.0 and has logic errors.
- The BB84 simulation reports eavesdropping about 94% of the time with no eavesdropper.

They'll move to `legacy/` in Phase 1 and are not part of the new design.

## References

- Schwabe, Stebila, Wiggers. *Post-Quantum TLS Without Handshake Signatures.* ACM CCS 2020. <https://kemtls.org>
- Celi, Wiggers et al. *KEM-based Authentication for TLS 1.3.* `draft-celi-wiggers-tls-authkem`. <https://datatracker.ietf.org/doc/html/draft-celi-wiggers-tls-authkem>
- Benjamin et al. *Merkle Tree Certificates.* `draft-ietf-plants-merkle-tree-certs`. <https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/>
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA).
- Let's Encrypt, *A Post-Quantum Future for Let's Encrypt* (June 2026). <https://letsencrypt.org/2026/06/03/pq-certs>

## License

MIT. See [LICENSE](LICENSE).
