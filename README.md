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

At matched security levels, what replaces the signature is smaller:

| Level | Signature | KEM ciphertext |
|---|---|---|
| Category 3 | ML-DSA-65: 3,309 bytes | ML-KEM-768: 1,088 bytes |
| Category 1–2 | ML-DSA-44: 2,420 bytes; FN-DSA-512: about 666 bytes | ML-KEM-512: 768 bytes |

KEM decapsulation is also typically cheaper than signing. FN-DSA-512 is the hardest baseline to beat, so it's included.

qTLS will **combine AuthKEM with Merkle Tree Certificates**, then measure it against the alternatives under realistic network conditions:

| Config | Key exchange | Certificate | Server proves identity by |
|---|---|---|---|
| **A**: today's web | X25519MLKEM768 | ECDSA X.509 chain | ECDSA signature |
| **B**: naive post-quantum | X25519MLKEM768 | ML-DSA / FN-DSA X.509 chain | post-quantum signature |
| **C**: post-quantum web as planned | X25519MLKEM768 | Merkle Tree Certificate | post-quantum signature |
| **D**: AuthKEM | X25519MLKEM768 | post-quantum X.509 chain, ML-KEM leaf | ML-KEM decapsulation |
| **E**: qTLS | X25519MLKEM768 | Merkle Tree Certificate, ML-KEM leaf | ML-KEM decapsulation |

These five are named points in a larger matrix. The other axes are certificate kind (standalone vs landmark-relative MTC), number of SCTs, and key delivery. Comparisons are always at **matched NIST security levels**:
- ML-DSA-44 or FN-DSA-512 against ML-KEM-512 (categories 1–2)
- ML-DSA-65 against ML-KEM-768 (category 3)

See [docs/PLAN.md §3](docs/PLAN.md).

**Hypothesis:** at each security level, E sends fewer server bytes and uses less server CPU than the best signature-based option (C, or B with FN-DSA).

**Costs we expect to quantify, in round trips** (AuthKEM -08, Figure 1):
- **Explicit server authentication:** 2 RTT instead of 1 (on server Finished).
- **Server-sent first data:** possible only after 1.5 RTT instead of 0.5.
- **Client's first request and its response:** unchanged at 1 RTT and 2 RTT. The client's first request goes to an *implicitly* authenticated server.
- **Key delivery:** the client must learn the server's KEM key, from the certificate or from a cache.
- **MTC freshness:** clients must keep up-to-date landmarks, or fall back to larger standalone MTCs.

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

So far only the crypto foundation (Phase 1) exists. You need Python ≥ 3.11, plus a C compiler and git to build liboqs.

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[test,oqs]" cmake
OQS_INSTALL_PATH="$PWD/.oqs" PATH="$PWD/.venv/bin:$PATH" scripts/build_liboqs.sh
OQS_INSTALL_PATH="$PWD/.oqs" .venv/bin/pytest
```

**Backends:**
- [`cryptography`](https://cryptography.io) is the primary backend: X25519, ECDSA, ML-KEM-768, ML-DSA, X.509.
- [`liboqs`](https://github.com/open-quantum-safe/liboqs) 0.16.0 adds ML-KEM-512 and FN-DSA-512, and acts as a second implementation for differential tests. It's built by `scripts/build_liboqs.sh` at a pinned commit. `liboqs-python`'s automatic downloader is never used.

Timing results will come from a pinned Linux container using network namespaces and `tc netem` (Phase 5).

## Legacy code

The repository's first iteration (April–May 2023) explored QKD and "quantum cryptography" simulations. It now lives in [`legacy/`](legacy/), which explains what is broken and why. It is not part of the new design.

## References

- Schwabe, Stebila, Wiggers. *Post-Quantum TLS Without Handshake Signatures.* ACM CCS 2020. <https://kemtls.org>
- Celi, Wiggers et al. *KEM-based Authentication for TLS 1.3.* `draft-celi-wiggers-tls-authkem`. <https://datatracker.ietf.org/doc/html/draft-celi-wiggers-tls-authkem>
- Benjamin et al. *Merkle Tree Certificates.* `draft-ietf-plants-merkle-tree-certs`. <https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/>
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA).
- Let's Encrypt, *A Post-Quantum Future for Let's Encrypt* (June 2026). <https://letsencrypt.org/2026/06/03/pq-certs>

## License

MIT. See [LICENSE](LICENSE).
