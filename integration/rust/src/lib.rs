pub mod qkd;
pub mod hybrid_tls;
pub mod crypto;
pub mod errors;

pub use qkd::QKDProtocol;
pub use hybrid_tls::QuantumTLSHandshake;
pub use crypto::HybridCipherSuite;
pub use errors::QTLSResult;

use serde::{Deserialize, Serialize};

/// Main configuration for qTLS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QTLSConfig {
    pub qkd_protocol: QKDConfig,
    pub cipher_suite: CipherSuiteConfig,
    pub key_length: usize,
    pub enable_hybrid_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QKDConfig {
    pub protocol_type: QKDProtocolType,
    pub key_length: usize,
    pub error_threshold: f64,
    pub privacy_amplification_rounds: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QKDProtocolType {
    BB84,
    E91,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherSuiteConfig {
    pub post_quantum_kem: PostQuantumKEM,
    pub symmetric_cipher: SymmetricCipher,
    pub signature_scheme: SignatureScheme,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PostQuantumKEM {
    Kyber512,
    Kyber768,
    Kyber1024,
    NTRUPrime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SymmetricCipher {
    AES256GCM,
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureScheme {
    Dilithium2,
    Dilithium3,
    Dilithium5,
    SPHINCSPlus,
}

impl Default for QTLSConfig {
    fn default() -> Self {
        Self {
            qkd_protocol: QKDConfig {
                protocol_type: QKDProtocolType::BB84,
                key_length: 256,
                error_threshold: 0.11,
                privacy_amplification_rounds: 2,
            },
            cipher_suite: CipherSuiteConfig {
                post_quantum_kem: PostQuantumKEM::Kyber768,
                symmetric_cipher: SymmetricCipher::AES256GCM,
                signature_scheme: SignatureScheme::Dilithium3,
            },
            key_length: 256,
            enable_hybrid_mode: true,
        }
    }
} 