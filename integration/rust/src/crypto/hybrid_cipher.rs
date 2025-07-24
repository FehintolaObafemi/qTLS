use crate::errors::{QTLSResult, CryptoError};
use crate::QTLSConfig;
use super::{HybridCrypto, HybridKeyPair, HybridSignature};

/// Hybrid cipher suite combining classical and post-quantum cryptography
pub struct HybridCipherSuite {
    config: crate::CipherSuiteConfig,
    crypto: HybridCrypto,
}

impl HybridCipherSuite {
    pub fn new(config: crate::CipherSuiteConfig) -> QTLSResult<Self> {
        let qtls_config = QTLSConfig {
            cipher_suite: config.clone(),
            ..Default::default()
        };
        
        let crypto = HybridCrypto::new(qtls_config)?;
        
        Ok(Self {
            config,
            crypto,
        })
    }

    /// Generate a hybrid key pair
    pub async fn generate_key_pair(&self) -> QTLSResult<HybridKeyPair> {
        self.crypto.generate_key_pair().await
    }

    /// Encrypt data using hybrid encryption
    pub async fn encrypt(&self, data: &[u8], public_key: &HybridKeyPair) -> QTLSResult<Vec<u8>> {
        self.crypto.encrypt(data, public_key).await
    }

    /// Decrypt data using hybrid decryption
    pub async fn decrypt(&self, encrypted_data: &[u8], private_key: &HybridKeyPair) -> QTLSResult<Vec<u8>> {
        self.crypto.decrypt(encrypted_data, private_key).await
    }

    /// Sign data using hybrid signatures
    pub async fn sign(&self, data: &[u8], private_key: &HybridKeyPair) -> QTLSResult<HybridSignature> {
        self.crypto.sign(data, private_key).await
    }

    /// Verify a hybrid signature
    pub async fn verify(&self, data: &[u8], signature: &HybridSignature, public_key: &HybridKeyPair) -> QTLSResult<bool> {
        self.crypto.verify(data, signature, public_key).await
    }

    /// Get the cipher suite identifier
    pub fn cipher_suite_id(&self) -> u16 {
        match (self.config.post_quantum_kem, self.config.symmetric_cipher) {
            (crate::PostQuantumKEM::Kyber768, crate::SymmetricCipher::AES256GCM) => 0x1301,
            (crate::PostQuantumKEM::Kyber1024, crate::SymmetricCipher::AES256GCM) => 0x1302,
            (crate::PostQuantumKEM::NTRUPrime, crate::SymmetricCipher::AES256GCM) => 0x1303,
            _ => 0x1301, // Default
        }
    }

    /// Get the signature algorithm identifier
    pub fn signature_algorithm_id(&self) -> u16 {
        match self.config.signature_scheme {
            crate::SignatureScheme::Dilithium2 => 0x0801,
            crate::SignatureScheme::Dilithium3 => 0x0802,
            crate::SignatureScheme::Dilithium5 => 0x0803,
            crate::SignatureScheme::SPHINCSPlus => 0x0804,
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &crate::CipherSuiteConfig {
        &self.config
    }

    /// Check if the cipher suite is quantum-safe
    pub fn is_quantum_safe(&self) -> bool {
        true // All hybrid cipher suites are quantum-safe by design
    }

    /// Get the security level in bits
    pub fn security_level(&self) -> u32 {
        match self.config.post_quantum_kem {
            crate::PostQuantumKEM::Kyber512 => 128,
            crate::PostQuantumKEM::Kyber768 => 192,
            crate::PostQuantumKEM::Kyber1024 => 256,
            crate::PostQuantumKEM::NTRUPrime => 256,
        }
    }
}

impl Clone for HybridCipherSuite {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            crypto: HybridCrypto::new(QTLSConfig {
                cipher_suite: self.config.clone(),
                ..Default::default()
            }).expect("Failed to clone HybridCipherSuite"),
        }
    }
}

impl Default for HybridCipherSuite {
    fn default() -> Self {
        Self::new(crate::CipherSuiteConfig::default()).expect("Failed to create default HybridCipherSuite")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hybrid_cipher_suite_basic() {
        let cipher_suite = HybridCipherSuite::default();
        
        // Test key generation
        let key_pair = cipher_suite.generate_key_pair().await.unwrap();
        assert!(!key_pair.classical_public_key.is_empty());
        assert!(!key_pair.post_quantum_public_key.is_empty());
        
        // Test encryption/decryption
        let test_data = b"Hello, Quantum World!";
        let encrypted = cipher_suite.encrypt(test_data, &key_pair).await.unwrap();
        let decrypted = cipher_suite.decrypt(&encrypted, &key_pair).await.unwrap();
        
        assert_eq!(test_data, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_hybrid_cipher_suite_signatures() {
        let cipher_suite = HybridCipherSuite::default();
        let key_pair = cipher_suite.generate_key_pair().await.unwrap();
        
        // Test signing/verification
        let test_data = b"Test message for signature";
        let signature = cipher_suite.sign(test_data, &key_pair).await.unwrap();
        let is_valid = cipher_suite.verify(test_data, &signature, &key_pair).await.unwrap();
        
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_cipher_suite_identifiers() {
        let cipher_suite = HybridCipherSuite::default();
        
        assert!(cipher_suite.cipher_suite_id() > 0);
        assert!(cipher_suite.signature_algorithm_id() > 0);
        assert!(cipher_suite.is_quantum_safe());
        assert!(cipher_suite.security_level() >= 128);
    }
} 