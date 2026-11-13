# Legacy (2023): QKD and "quantum cryptography" experiments

These files are the project's first iteration (April–May 2023). They're kept only for history. **They are broken and are not part of qTLS.** pytest never collects this folder.

| File | What it tried | Why it doesn't work |
|---|---|---|
| `qkdProtocol.cs` | BB84 key distribution, simulated classically | Bob's "measurement" is a fixed bit flip, not a random outcome, and fixed positions `{0,3,6,9}` are checked without matching bases. Over 200 runs it reported eavesdropping 187 times with no eavesdropper. |
| `QCA.cs` | BB84 with error correction | `QuantumChannel` and `QuantumState` are never defined, so it doesn't compile. Even if it did, every bit is discarded, so the shared key is always empty. |
| `qkdProtocol.py` | BB84 in Qiskit | Asks for a 2¹⁰⁰-amplitude random state, which can't fit in memory. `initialize` overwrites Alice's encoding. Uses APIs removed in Qiskit 1.0. |
| `QCA.py` | A quantum one-time pad | Encrypts with an H gate but decrypts with an XOR, and `initialize` replaces the state, so it fails about 255 times in 256. |
| `qTLS.py` | A "quantum TLS" | Missing imports. A 264-qubit simulation. Its signature check only round-trips and proves nothing. Uses 256-bit RSA. |
| `Program.cs`, `qTLS.csproj`, `.vscode/` | .NET 7 project scaffolding | The template "Hello, World!" overrides the other entry points. .NET 7 is out of support. |
| `*.txt`, `qTLS.docx` | Design prose | They describe code that doesn't exist. The play-by-play recommends SIDH, which was broken in 2022. |

The project's current direction, post-quantum TLS with KEM-based authentication, is described in the [top-level README](../README.md).
