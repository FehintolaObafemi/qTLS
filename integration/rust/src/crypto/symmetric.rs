use crate::errors::{QTLSResult, CryptoError};
use crate::SymmetricCipher;
use serde::{Deserialize, Serialize};

/// Symmetric cipher implementation
pub struct SymmetricCipher {
    cipher_type: SymmetricCipher,
}

impl SymmetricCipher {
    pub fn new(cipher_type: SymmetricCipher) -> QTLSResult<Self> {
        Ok(Self { cipher_type })
    }

    /// Encrypt data using the symmetric cipher
    pub async fn encrypt(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> QTLSResult<Vec<u8>> {
        log::debug!("Encrypting data with {:?}", self.cipher_type);
        
        match self.cipher_type {
            SymmetricCipher::AES256GCM => self.encrypt_aes_gcm(data, key, nonce).await,
            SymmetricCipher::ChaCha20Poly1305 => self.encrypt_chacha20_poly1305(data, key, nonce).await,
        }
    }

    /// Decrypt data using the symmetric cipher
    pub async fn decrypt(&self, encrypted_data: &[u8], key: &[u8], nonce: &[u8]) -> QTLSResult<Vec<u8>> {
        log::debug!("Decrypting data with {:?}", self.cipher_type);
        
        match self.cipher_type {
            SymmetricCipher::AES256GCM => self.decrypt_aes_gcm(encrypted_data, key, nonce).await,
            SymmetricCipher::ChaCha20Poly1305 => self.decrypt_chacha20_poly1305(encrypted_data, key, nonce).await,
        }
    }

    /// Encrypt using AES-256-GCM
    async fn encrypt_aes_gcm(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> QTLSResult<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit, OsRng},
            Aes256Gcm,
        };
        
        if key.len() != 32 {
            return Err(CryptoError::EncryptionError("AES-256-GCM requires 32-byte key".to_string()));
        }
        
        if nonce.len() != 12 {
            return Err(CryptoError::EncryptionError("AES-256-GCM requires 12-byte nonce".to_string()));
        }
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::EncryptionError(format!("Failed to create AES-GCM cipher: {}", e)))?;
        
        let ciphertext = cipher
            .encrypt(nonce.into(), data)
            .map_err(|e| CryptoError::EncryptionError(format!("AES-GCM encryption failed: {}", e)))?;
        
        Ok(ciphertext)
    }

    /// Decrypt using AES-256-GCM
    async fn decrypt_aes_gcm(&self, encrypted_data: &[u8], key: &[u8], nonce: &[u8]) -> QTLSResult<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm,
        };
        
        if key.len() != 32 {
            return Err(CryptoError::DecryptionError("AES-256-GCM requires 32-byte key".to_string()));
        }
        
        if nonce.len() != 12 {
            return Err(CryptoError::DecryptionError("AES-256-GCM requires 12-byte nonce".to_string()));
        }
        
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::DecryptionError(format!("Failed to create AES-GCM cipher: {}", e)))?;
        
        let plaintext = cipher
            .decrypt(nonce.into(), encrypted_data)
            .map_err(|e| CryptoError::DecryptionError(format!("AES-GCM decryption failed: {}", e)))?;
        
        Ok(plaintext)
    }

    /// Encrypt using ChaCha20-Poly1305
    async fn encrypt_chacha20_poly1305(&self, data: &[u8], key: &[u8], nonce: &[u8]) -> QTLSResult<Vec<u8>> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305,
        };
        
        if key.len() != 32 {
            return Err(CryptoError::EncryptionError("ChaCha20-Poly1305 requires 32-byte key".to_string()));
        }
        
        if nonce.len() != 12 {
            return Err(CryptoError::EncryptionError("ChaCha20-Poly1305 requires 12-byte nonce".to_string()));
        }
        
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CryptoError::EncryptionError(format!("Failed to create ChaCha20-Poly1305 cipher: {}", e)))?;
        
        let ciphertext = cipher
            .encrypt(nonce.into(), data)
            .map_err(|e| CryptoError::EncryptionError(format!("ChaCha20-Poly1305 encryption failed: {}", e)))?;
        
        Ok(ciphertext)
    }

    /// Decrypt using ChaCha20-Poly1305
    async fn decrypt_chacha20_poly1305(&self, encrypted_data: &[u8], key: &[u8], nonce: &[u8]) -> QTLSResult<Vec<u8>> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305,
        };
        
        if key.len() != 32 {
            return Err(CryptoError::DecryptionError("ChaCha20-Poly1305 requires 32-byte key".to_string()));
        }
        
        if nonce.len() != 12 {
            return Err(CryptoError::DecryptionError("ChaCha20-Poly1305 requires 12-byte nonce".to_string()));
        }
        
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CryptoError::DecryptionError(format!("Failed to create ChaCha20-Poly1305 cipher: {}", e)))?;
        
        let plaintext = cipher
            .decrypt(nonce.into(), encrypted_data)
            .map_err(|e| CryptoError::DecryptionError(format!("ChaCha20-Poly1305 decryption failed: {}", e)))?;
        
        Ok(plaintext)
    }

    /// Generate a random key for the cipher
    pub fn generate_key(&self) -> QTLSResult<Vec<u8>> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        Ok((0..32).map(|_| rng.gen_range(0..256)).collect())
    }

    /// Generate a random nonce for the cipher
    pub fn generate_nonce(&self) -> QTLSResult<Vec<u8>> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        Ok((0..12).map(|_| rng.gen_range(0..256)).collect())
    }

    /// Get the key size in bytes
    pub fn key_size(&self) -> usize {
        match self.cipher_type {
            SymmetricCipher::AES256GCM => 32,
            SymmetricCipher::ChaCha20Poly1305 => 32,
        }
    }

    /// Get the nonce size in bytes
    pub fn nonce_size(&self) -> usize {
        match self.cipher_type {
            SymmetricCipher::AES256GCM => 12,
            SymmetricCipher::ChaCha20Poly1305 => 12,
        }
    }

    /// Get the tag size in bytes
    pub fn tag_size(&self) -> usize {
        match self.cipher_type {
            SymmetricCipher::AES256GCM => 16,
            SymmetricCipher::ChaCha20Poly1305 => 16,
        }
    }

    /// Get the cipher type
    pub fn cipher_type(&self) -> &SymmetricCipher {
        &self.cipher_type
    }
}

impl Default for SymmetricCipher {
    fn default() -> Self {
        Self::new(SymmetricCipher::AES256GCM).expect("Failed to create default SymmetricCipher")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aes_gcm_encryption() {
        let cipher = SymmetricCipher::new(SymmetricCipher::AES256GCM).unwrap();
        
        let key = cipher.generate_key().unwrap();
        let nonce = cipher.generate_nonce().unwrap();
        let test_data = b"Hello, Quantum World!";
        
        let encrypted = cipher.encrypt(test_data, &key, &nonce).await.unwrap();
        let decrypted = cipher.decrypt(&encrypted, &key, &nonce).await.unwrap();
        
        assert_eq!(test_data, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_chacha20_poly1305_encryption() {
        let cipher = SymmetricCipher::new(SymmetricCipher::ChaCha20Poly1305).unwrap();
        
        let key = cipher.generate_key().unwrap();
        let nonce = cipher.generate_nonce().unwrap();
        let test_data = b"Hello, Quantum World!";
        
        let encrypted = cipher.encrypt(test_data, &key, &nonce).await.unwrap();
        let decrypted = cipher.decrypt(&encrypted, &key, &nonce).await.unwrap();
        
        assert_eq!(test_data, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_cipher_sizes() {
        let aes_cipher = SymmetricCipher::new(SymmetricCipher::AES256GCM).unwrap();
        assert_eq!(aes_cipher.key_size(), 32);
        assert_eq!(aes_cipher.nonce_size(), 12);
        assert_eq!(aes_cipher.tag_size(), 16);
        
        let chacha_cipher = SymmetricCipher::new(SymmetricCipher::ChaCha20Poly1305).unwrap();
        assert_eq!(chacha_cipher.key_size(), 32);
        assert_eq!(chacha_cipher.nonce_size(), 12);
        assert_eq!(chacha_cipher.tag_size(), 16);
    }

    #[tokio::test]
    async fn test_invalid_key_size() {
        let cipher = SymmetricCipher::new(SymmetricCipher::AES256GCM).unwrap();
        let invalid_key = vec![0u8; 16]; // Too short
        let nonce = cipher.generate_nonce().unwrap();
        let test_data = b"Test data";
        
        let result = cipher.encrypt(test_data, &invalid_key, &nonce).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_nonce_size() {
        let cipher = SymmetricCipher::new(SymmetricCipher::AES256GCM).unwrap();
        let key = cipher.generate_key().unwrap();
        let invalid_nonce = vec![0u8; 8]; // Too short
        let test_data = b"Test data";
        
        let result = cipher.encrypt(test_data, &key, &invalid_nonce).await;
        assert!(result.is_err());
    }
} 