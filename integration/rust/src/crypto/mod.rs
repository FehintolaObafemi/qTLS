pub mod hybrid_cipher;
pub mod post_quantum;
pub mod symmetric;

use crate::errors::{QTLSResult, CryptoError};
use crate::QTLSConfig;
use serde::{Deserialize, Serialize};

pub use hybrid_cipher::HybridCipherSuite;
pub use post_quantum::PostQuantumKEM;
pub use symmetric::SymmetricCipher;

/// Hybrid key pair combining classical and post-quantum keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridKeyPair {
    pub classical_public_key: Vec<u8>,
    pub classical_private_key: Vec<u8>,
    pub post_quantum_public_key: Vec<u8>,
    pub post_quantum_private_key: Vec<u8>,
    pub key_id: Vec<u8>,
}

/// Hybrid ciphertext containing both classical and post-quantum encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    pub classical_ciphertext: Vec<u8>,
    pub post_quantum_ciphertext: Vec<u8>,
    pub symmetric_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Hybrid signature combining classical and post-quantum signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub classical_signature: Vec<u8>,
    pub post_quantum_signature: Vec<u8>,
    pub signature_algorithm: SignatureAlgorithm,
}

/// Signature algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    ECDSA256,
    ECDSA384,
    Dilithium2,
    Dilithium3,
    Dilithium5,
    SPHINCSPlus,
    Hybrid(Box<SignatureAlgorithm>, Box<SignatureAlgorithm>),
}

/// Key encapsulation mechanism result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KEMResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Main hybrid cryptography implementation
pub struct HybridCrypto {
    config: QTLSConfig,
    kem: PostQuantumKEM,
    symmetric: SymmetricCipher,
}

impl HybridCrypto {
    pub fn new(config: QTLSConfig) -> QTLSResult<Self> {
        let kem = PostQuantumKEM::new(config.cipher_suite.post_quantum_kem.clone())?;
        let symmetric = SymmetricCipher::new(config.cipher_suite.symmetric_cipher.clone())?;
        
        Ok(Self {
            config,
            kem,
            symmetric,
        })
    }

    /// Generate a hybrid key pair
    pub async fn generate_key_pair(&self) -> QTLSResult<HybridKeyPair> {
        log::info!("Generating hybrid key pair");
        
        // Generate classical key pair (ECDSA)
        let classical_key_pair = self.generate_classical_key_pair().await?;
        
        // Generate post-quantum key pair
        let post_quantum_key_pair = self.kem.generate_key_pair().await?;
        
        // Generate key ID
        let key_id = self.generate_key_id(&classical_key_pair.public_key, &post_quantum_key_pair.public_key)?;
        
        Ok(HybridKeyPair {
            classical_public_key: classical_key_pair.public_key,
            classical_private_key: classical_key_pair.private_key,
            post_quantum_public_key: post_quantum_key_pair.public_key,
            post_quantum_private_key: post_quantum_key_pair.private_key,
            key_id,
        })
    }

    /// Encapsulate a symmetric key using hybrid encryption
    pub async fn encapsulate(&self, public_key: &HybridKeyPair) -> QTLSResult<HybridCiphertext> {
        log::debug!("Performing hybrid key encapsulation");
        
        // Generate random symmetric key
        let symmetric_key = self.generate_random_key(32)?;
        
        // Encapsulate using classical encryption
        let classical_ciphertext = self.encapsulate_classical(&public_key.classical_public_key, &symmetric_key).await?;
        
        // Encapsulate using post-quantum encryption
        let post_quantum_ciphertext = self.kem.encapsulate(&public_key.post_quantum_public_key).await?;
        
        // Generate nonce for symmetric encryption
        let nonce = self.generate_random_key(12)?;
        
        Ok(HybridCiphertext {
            classical_ciphertext,
            post_quantum_ciphertext: post_quantum_ciphertext.ciphertext,
            symmetric_key,
            nonce,
        })
    }

    /// Decapsulate a symmetric key using hybrid decryption
    pub async fn decapsulate(&self, private_key: &HybridKeyPair, ciphertext: &HybridCiphertext) -> QTLSResult<Vec<u8>> {
        log::debug!("Performing hybrid key decapsulation");
        
        // Decapsulate classical part
        let classical_secret = self.decapsulate_classical(&private_key.classical_private_key, &ciphertext.classical_ciphertext).await?;
        
        // Decapsulate post-quantum part
        let post_quantum_secret = self.kem.decapsulate(&private_key.post_quantum_private_key, &ciphertext.post_quantum_ciphertext).await?;
        
        // Combine secrets to derive final symmetric key
        let combined_secret = self.combine_secrets(&classical_secret, &post_quantum_secret)?;
        
        Ok(combined_secret)
    }

    /// Encrypt data using hybrid encryption
    pub async fn encrypt(&self, data: &[u8], public_key: &HybridKeyPair) -> QTLSResult<Vec<u8>> {
        log::debug!("Encrypting data using hybrid encryption");
        
        // Perform key encapsulation
        let ciphertext = self.encapsulate(public_key).await?;
        
        // Encrypt data with symmetric key
        let encrypted_data = self.symmetric.encrypt(data, &ciphertext.symmetric_key, &ciphertext.nonce).await?;
        
        // Combine ciphertext and encrypted data
        let mut result = Vec::new();
        result.extend_from_slice(&ciphertext.classical_ciphertext);
        result.extend_from_slice(&ciphertext.post_quantum_ciphertext);
        result.extend_from_slice(&ciphertext.nonce);
        result.extend_from_slice(&encrypted_data);
        
        Ok(result)
    }

    /// Decrypt data using hybrid decryption
    pub async fn decrypt(&self, encrypted_data: &[u8], private_key: &HybridKeyPair) -> QTLSResult<Vec<u8>> {
        log::debug!("Decrypting data using hybrid decryption");
        
        // Parse the encrypted data structure
        let (ciphertext, data) = self.parse_encrypted_data(encrypted_data)?;
        
        // Decapsulate the symmetric key
        let symmetric_key = self.decapsulate(private_key, &ciphertext).await?;
        
        // Decrypt data with symmetric key
        let decrypted_data = self.symmetric.decrypt(&data, &symmetric_key, &ciphertext.nonce).await?;
        
        Ok(decrypted_data)
    }

    /// Create a hybrid signature
    pub async fn sign(&self, data: &[u8], private_key: &HybridKeyPair) -> QTLSResult<HybridSignature> {
        log::debug!("Creating hybrid signature");
        
        // Create classical signature
        let classical_signature = self.sign_classical(data, &private_key.classical_private_key).await?;
        
        // Create post-quantum signature
        let post_quantum_signature = self.sign_post_quantum(data, &private_key.post_quantum_private_key).await?;
        
        Ok(HybridSignature {
            classical_signature,
            post_quantum_signature,
            signature_algorithm: SignatureAlgorithm::Hybrid(
                Box::new(SignatureAlgorithm::ECDSA256),
                Box::new(self.config.cipher_suite.signature_scheme.clone().into()),
            ),
        })
    }

    /// Verify a hybrid signature
    pub async fn verify(&self, data: &[u8], signature: &HybridSignature, public_key: &HybridKeyPair) -> QTLSResult<bool> {
        log::debug!("Verifying hybrid signature");
        
        // Verify classical signature
        let classical_valid = self.verify_classical(data, &signature.classical_signature, &public_key.classical_public_key).await?;
        
        // Verify post-quantum signature
        let post_quantum_valid = self.verify_post_quantum(data, &signature.post_quantum_signature, &public_key.post_quantum_public_key).await?;
        
        // Both signatures must be valid
        Ok(classical_valid && post_quantum_valid)
    }

    // Helper methods

    async fn generate_classical_key_pair(&self) -> QTLSResult<KeyPair> {
        use p256::ecdsa::SigningKey;
        use rand::Rng;
        
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        
        Ok(KeyPair {
            public_key: verifying_key.to_encoded_point(false).as_bytes().to_vec(),
            private_key: signing_key.to_bytes().to_vec(),
        })
    }

    async fn encapsulate_classical(&self, public_key: &[u8], symmetric_key: &[u8]) -> QTLSResult<Vec<u8>> {
        // Simple simulation - in real implementation, this would use ECDH
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        hasher.update(symmetric_key);
        let result = hasher.finalize();
        
        Ok(result.to_vec())
    }

    async fn decapsulate_classical(&self, private_key: &[u8], ciphertext: &[u8]) -> QTLSResult<Vec<u8>> {
        // Simple simulation - in real implementation, this would use ECDH
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(private_key);
        hasher.update(ciphertext);
        let result = hasher.finalize();
        
        Ok(result.to_vec())
    }

    async fn sign_classical(&self, data: &[u8], private_key: &[u8]) -> QTLSResult<Vec<u8>> {
        // Simple simulation - in real implementation, this would use ECDSA
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(private_key);
        let result = hasher.finalize();
        
        Ok(result.to_vec())
    }

    async fn sign_post_quantum(&self, data: &[u8], private_key: &[u8]) -> QTLSResult<Vec<u8>> {
        // Simple simulation - in real implementation, this would use the actual post-quantum signature scheme
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(private_key);
        let result = hasher.finalize();
        
        Ok(result.to_vec())
    }

    async fn verify_classical(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> QTLSResult<bool> {
        // Simple simulation - in real implementation, this would verify ECDSA signature
        let expected_signature = self.sign_classical(data, public_key).await?;
        Ok(signature == expected_signature)
    }

    async fn verify_post_quantum(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> QTLSResult<bool> {
        // Simple simulation - in real implementation, this would verify post-quantum signature
        let expected_signature = self.sign_post_quantum(data, public_key).await?;
        Ok(signature == expected_signature)
    }

    fn generate_random_key(&self, length: usize) -> QTLSResult<Vec<u8>> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        Ok((0..length).map(|_| rng.gen_range(0..256)).collect())
    }

    fn generate_key_id(&self, classical_pub: &[u8], post_quantum_pub: &[u8]) -> QTLSResult<Vec<u8>> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(classical_pub);
        hasher.update(post_quantum_pub);
        let result = hasher.finalize();
        
        Ok(result[..16].to_vec()) // Use first 16 bytes as key ID
    }

    fn combine_secrets(&self, classical_secret: &[u8], post_quantum_secret: &[u8]) -> QTLSResult<Vec<u8>> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(classical_secret);
        hasher.update(post_quantum_secret);
        let result = hasher.finalize();
        
        Ok(result.to_vec())
    }

    fn parse_encrypted_data(&self, data: &[u8]) -> QTLSResult<(HybridCiphertext, Vec<u8>)> {
        // This is a simplified parser - in real implementation, this would use proper serialization
        if data.len() < 64 {
            return Err(CryptoError::DecryptionError("Invalid encrypted data format".to_string()));
        }
        
        let classical_ciphertext = data[..32].to_vec();
        let post_quantum_ciphertext = data[32..64].to_vec();
        let nonce = data[64..76].to_vec();
        let encrypted_data = data[76..].to_vec();
        
        let ciphertext = HybridCiphertext {
            classical_ciphertext,
            post_quantum_ciphertext,
            symmetric_key: Vec::new(), // Will be derived during decapsulation
            nonce,
        };
        
        Ok((ciphertext, encrypted_data))
    }
}

/// Simple key pair structure
#[derive(Debug, Clone)]
struct KeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl From<crate::SignatureScheme> for SignatureAlgorithm {
    fn from(scheme: crate::SignatureScheme) -> Self {
        match scheme {
            crate::SignatureScheme::Dilithium2 => SignatureAlgorithm::Dilithium2,
            crate::SignatureScheme::Dilithium3 => SignatureAlgorithm::Dilithium3,
            crate::SignatureScheme::Dilithium5 => SignatureAlgorithm::Dilithium5,
            crate::SignatureScheme::SPHINCSPlus => SignatureAlgorithm::SPHINCSPlus,
        }
    }
} 