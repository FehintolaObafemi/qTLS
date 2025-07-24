# Quantum TLS (qTLS)

A research implementation of quantum-resistant Transport Layer Security (TLS) that combines quantum key distribution (QKD) with post-quantum cryptography to provide security against both classical and quantum attacks.

## Overview

qTLS is a hybrid approach to TLS that integrates:
- **Quantum Key Distribution (QKD)** for secure key generation
- **Post-quantum cryptography** for long-term security
- **Classical cryptography** for backward compatibility and performance
- **Hybrid signatures** combining both classical and post-quantum algorithms

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    qTLS Architecture                        │
├─────────────────────────────────────────────────────────────┤
│  Application Layer                                          │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   Client App    │  │   Server App    │                  │
│  └─────────────────┘  └─────────────────┘                  │
├─────────────────────────────────────────────────────────────┤
│  qTLS Session Layer                                         │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │  Client Session │  │  Server Session │                  │
│  └─────────────────┘  └─────────────────┘                  │
├─────────────────────────────────────────────────────────────┤
│  Hybrid TLS Handshake                                       │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │ Client Handshake│  │ Server Handshake│                  │
│  └─────────────────┘  └─────────────────┘                  │
├─────────────────────────────────────────────────────────────┤
│  Quantum Key Distribution                                   │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   BB84 Protocol │  │   E91 Protocol  │                  │
│  └─────────────────┘  └─────────────────┘                  │
├─────────────────────────────────────────────────────────────┤
│  Hybrid Cryptography                                        │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │ Post-Quantum KEM│  │ Hybrid Cipher   │                  │
│  │ (Kyber, NTRU)   │  │ (AES, ChaCha20) │                  │
│  └─────────────────┘  └─────────────────┘                  │
├─────────────────────────────────────────────────────────────┤
│  Quantum & Classical Channels                               │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │ Quantum Channel │  │ Classical Channel│                 │
│  └─────────────────┘  └─────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

## Features

### 🔐 Quantum Key Distribution
- **BB84 Protocol**: Single-photon QKD for key generation
- **E91 Protocol**: Entanglement-based QKD with Bell inequality testing
- **Error Correction**: Automatic error detection and correction
- **Privacy Amplification**: Post-processing for enhanced security

### 🛡️ Post-Quantum Cryptography
- **Kyber**: Lattice-based key encapsulation (512/768/1024 bit security)
- **NTRU Prime**: Lattice-based encryption
- **Dilithium**: Lattice-based digital signatures
- **SPHINCS+**: Hash-based signatures

### 🔄 Hybrid Approach
- **Hybrid Key Exchange**: Combines classical ECDH with post-quantum KEM
- **Hybrid Signatures**: Dual signatures for maximum security
- **Backward Compatibility**: Works with existing TLS infrastructure
- **Gradual Migration**: Allows incremental adoption

### 📊 Security Properties
- **Quantum Resistance**: Secure against quantum computer attacks
- **Forward Secrecy**: Keys are ephemeral and not stored
- **Man-in-the-Middle Protection**: QKD provides eavesdropping detection
- **Perfect Forward Secrecy**: New keys for each session

## Project Structure

```
qTLS/
├── core/                          # Core cryptographic implementations
│   ├── qkd/                      # Quantum Key Distribution
│   │   ├── bb84.rs              # BB84 protocol implementation
│   │   ├── e91.rs               # E91 protocol implementation
│   │   ├── quantum_channel.rs   # Quantum channel simulation
│   │   └── classical_channel.rs # Classical channel for QKD
│   ├── hybrid_tls/              # Hybrid TLS implementation
│   │   ├── handshake.rs         # TLS handshake protocol
│   │   ├── session.rs           # Secure session management
│   │   └── certificate.rs       # Hybrid certificates
│   └── crypto/                  # Cryptographic primitives
│       ├── hybrid_cipher.rs     # Hybrid cipher suite
│       ├── post_quantum.rs      # Post-quantum algorithms
│       └── symmetric.rs         # Symmetric encryption
├── integration/                  # Language integrations
│   ├── rust/                    # Rust implementation
│   ├── dotnet/                  # .NET integration
│   └── python/                  # Python bindings
├── simulation/                   # Simulation and testing
│   ├── quantum/                 # Quantum circuit simulation
│   └── network/                 # Network simulation
├── tests/                       # Test suites
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   └── security/                # Security tests
└── docs/                        # Documentation
    ├── protocol/                # Protocol specifications
    ├── api/                     # API documentation
    └── examples/                # Usage examples
```

## Quick Start

### Prerequisites
- Rust 1.70+ with Cargo
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/FehintolaObafemi/qTLS.git
cd qtls

# Build the Rust implementation
cd integration/rust
cargo build --release

# Run the demonstration
cargo run --release
```

### Basic Usage

```rust
use qtls_core::{QTLSConfig, QuantumTLS, QKDProtocolType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = QTLSConfig::default();
    
    // Create quantum TLS instance
    let mut qtls = QuantumTLS::new(config)?;
    
    // Generate QKD keys
    let qkd_keys = qtls.generate_qkd_keys().await?;
    println!("Generated {} bits of quantum key", qkd_keys.key_length);
    
    // Perform handshake
    let mut client_handshake = qtls.start_client_handshake().await?;
    let session = client_handshake.perform_handshake().await?;
    
    // Send secure message
    let message = b"Hello, Quantum World!";
    let encrypted = session.send(message).await?;
    let decrypted = session.receive(&encrypted).await?;
    
    println!("Secure communication established!");
    Ok(())
}
```

## Protocol Flow

### 1. QKD Key Generation
```
Alice                    Bob
  |                       |
  |-- Prepare qubits ---->|
  |                       |
  |<-- Measure qubits ----|
  |                       |
  |-- Basis reveal ------>|
  |<-- Basis reveal ------|
  |                       |
  |-- Error estimation -->|
  |<-- Error estimation --|
  |                       |
  |-- Privacy ampl. ----->|
  |<-- Privacy ampl. -----|
  |                       |
  |-- Shared key ready ---|
```

### 2. Hybrid TLS Handshake
```
Client                   Server
  |                        |
  |-- ClientHello -------->|
  |                        |
  |<-- ServerHello --------|
  |                        |
  |-- QKD Init ----------->|
  |<-- QKD Complete -------|
  |                        |
  |-- Hybrid Cert -------->|
  |<-- Hybrid Cert --------|
  |                        |
  |-- Key Exchange ------->|
  |<-- Key Exchange -------|
  |                        |
  |-- Finished ----------->|
  |<-- Finished -----------|
  |                        |
  |-- Secure Session ----->|
```

## Security Analysis

### Quantum Resistance
- **Key Exchange**: Post-quantum KEM provides quantum resistance
- **Signatures**: Hybrid signatures combine classical and post-quantum security
- **Key Generation**: QKD provides information-theoretic security

### Performance Characteristics
- **QKD Key Rate**: ~1-10 kbps (simulated)
- **Handshake Time**: ~100-500ms (including QKD)
- **Encryption Overhead**: ~20-30% compared to classical TLS
- **Memory Usage**: ~2-5MB per session

### Security Levels
- **128-bit**: Kyber512 + AES-128-GCM
- **192-bit**: Kyber768 + AES-256-GCM
- **256-bit**: Kyber1024 + AES-256-GCM

## Research Status

This is a **research implementation** for educational and experimental purposes. Key areas for future work:

- [ ] Real quantum hardware integration
- [ ] Performance optimization
- [ ] Formal security proofs
- [ ] Standardization efforts
- [ ] Production-ready implementation

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Install development dependencies
cargo install cargo-watch
cargo install cargo-tarpaulin

# Run tests
cargo test

# Run benchmarks
cargo bench

# Check code coverage
cargo tarpaulin
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- NIST Post-Quantum Cryptography Standardization
- Open Quantum Safe project
- Quantum Internet Research Group (QIRG)
- TLS Working Group

## References

1. Bennett, C. H., & Brassard, G. (1984). Quantum cryptography: Public key distribution and coin tossing.
2. Ekert, A. K. (1991). Quantum cryptography based on Bell's theorem.
3. Ducas, L., et al. (2018). CRYSTALS-Dilithium: A lattice-based digital signature scheme.
4. Bos, J., et al. (2018). CRYSTALS-Kyber: A CCA-secure module-lattice-based KEM.

## Contact

For questions, suggestions, or collaboration opportunities:
- Email: taofeekobafemibabatunde@gmail.com
- GitHub Issues: [Create an issue](https://github.com/FehintolaObafemi/qTLS/issues)

---

**⚠️ Disclaimer**: This is research software. Do not use in production without thorough security audits and compliance verification.
