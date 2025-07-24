use crate::errors::{QTLSResult, CryptoError};
use crate::qkd::KeyPair;
use crate::crypto::HybridCipherSuite;
use crate::QTLSConfig;
use crate::hybrid_tls::Endpoint;
use serde::{Deserialize, Serialize};
use std::time::{Instant, Duration};

/// Quantum TLS session for secure communication
pub struct QuantumTLSSession {
    config: QTLSConfig,
    qkd_keys: KeyPair,
    cipher_suite: HybridCipherSuite,
    endpoint: Endpoint,
    session_id: Vec<u8>,
    created_at: Instant,
    last_activity: Instant,
    sequence_number: u64,
    is_active: bool,
}

impl QuantumTLSSession {
    /// Create a new quantum TLS session
    pub async fn new(
        config: QTLSConfig,
        qkd_keys: KeyPair,
        cipher_suite: HybridCipherSuite,
        endpoint: Endpoint,
    ) -> QTLSResult<Self> {
        let session_id = Self::generate_session_id(&qkd_keys)?;
        
        Ok(Self {
            config,
            qkd_keys,
            cipher_suite,
            endpoint,
            session_id,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            sequence_number: 0,
            is_active: true,
        })
    }

    /// Send encrypted data through the session
    pub async fn send(&mut self, data: &[u8]) -> QTLSResult<Vec<u8>> {
        if !self.is_active {
            return Err(CryptoError::EncryptionError("Session is not active".to_string()));
        }
        
        log::debug!("Sending {} bytes through quantum TLS session", data.len());
        
        // Create application data record
        let record = ApplicationDataRecord {
            sequence_number: self.sequence_number,
            data: data.to_vec(),
            timestamp: Instant::now(),
        };
        
        // Encrypt the record
        let encrypted_record = self.encrypt_record(&record).await?;
        
        // Update session state
        self.sequence_number += 1;
        self.last_activity = Instant::now();
        
        Ok(encrypted_record)
    }

    /// Receive and decrypt data from the session
    pub async fn receive(&mut self, encrypted_data: &[u8]) -> QTLSResult<Vec<u8>> {
        if !self.is_active {
            return Err(CryptoError::DecryptionError("Session is not active".to_string()));
        }
        
        log::debug!("Receiving {} bytes through quantum TLS session", encrypted_data.len());
        
        // Decrypt the record
        let record = self.decrypt_record(encrypted_data).await?;
        
        // Update session state
        self.last_activity = Instant::now();
        
        Ok(record.data)
    }

    /// Encrypt an application data record
    async fn encrypt_record(&self, record: &ApplicationDataRecord) -> QTLSResult<Vec<u8>> {
        // Serialize the record
        let serialized = serde_json::to_vec(record)
            .map_err(|e| CryptoError::EncryptionError(format!("Serialization error: {}", e)))?;
        
        // In a real implementation, this would use the session keys derived from QKD
        // For simulation, we'll use a simple encryption approach
        let encrypted = self.simple_encrypt(&serialized).await?;
        
        Ok(encrypted)
    }

    /// Decrypt an application data record
    async fn decrypt_record(&self, encrypted_data: &[u8]) -> QTLSResult<ApplicationDataRecord> {
        // Decrypt the data
        let decrypted = self.simple_decrypt(encrypted_data).await?;
        
        // Deserialize the record
        let record: ApplicationDataRecord = serde_json::from_slice(&decrypted)
            .map_err(|e| CryptoError::DecryptionError(format!("Deserialization error: {}", e)))?;
        
        Ok(record)
    }

    /// Simple encryption for simulation (in real implementation, this would use proper session keys)
    async fn simple_encrypt(&self, data: &[u8]) -> QTLSResult<Vec<u8>> {
        use sha2::{Sha256, Digest};
        
        // Use QKD keys for encryption
        let key = &self.qkd_keys.alice_key;
        let mut encrypted = Vec::new();
        
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key[i % key.len()];
            encrypted.push(byte ^ key_byte);
        }
        
        // Add a simple integrity check
        let mut hasher = Sha256::new();
        hasher.update(&encrypted);
        let hash = hasher.finalize();
        encrypted.extend_from_slice(&hash[..4]); // Add first 4 bytes of hash
        
        Ok(encrypted)
    }

    /// Simple decryption for simulation
    async fn simple_decrypt(&self, encrypted_data: &[u8]) -> QTLSResult<Vec<u8>> {
        use sha2::{Sha256, Digest};
        
        if encrypted_data.len() < 4 {
            return Err(CryptoError::DecryptionError("Invalid encrypted data".to_string()));
        }
        
        let data_len = encrypted_data.len() - 4;
        let data = &encrypted_data[..data_len];
        let provided_hash = &encrypted_data[data_len..];
        
        // Verify integrity
        let mut hasher = Sha256::new();
        hasher.update(data);
        let computed_hash = hasher.finalize();
        
        if provided_hash != &computed_hash[..4] {
            return Err(CryptoError::DecryptionError("Integrity check failed".to_string()));
        }
        
        // Decrypt using QKD keys
        let key = &self.qkd_keys.bob_key;
        let mut decrypted = Vec::new();
        
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key[i % key.len()];
            decrypted.push(byte ^ key_byte);
        }
        
        Ok(decrypted)
    }

    /// Generate a session ID from QKD keys
    fn generate_session_id(qkd_keys: &KeyPair) -> QTLSResult<Vec<u8>> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&qkd_keys.alice_key);
        hasher.update(&qkd_keys.bob_key);
        let result = hasher.finalize();
        
        Ok(result[..16].to_vec()) // Use first 16 bytes as session ID
    }

    /// Check if the session is still valid
    pub fn is_valid(&self) -> bool {
        self.is_active && self.last_activity.elapsed() < Duration::from_secs(3600) // 1 hour timeout
    }

    /// Get session information
    pub fn session_info(&self) -> SessionInfo {
        SessionInfo {
            session_id: self.session_id.clone(),
            endpoint: self.endpoint.clone(),
            created_at: self.created_at,
            last_activity: self.last_activity,
            sequence_number: self.sequence_number,
            is_active: self.is_active,
            qkd_error_rate: self.qkd_keys.error_rate,
            key_length: self.qkd_keys.key_length,
        }
    }

    /// Close the session
    pub fn close(&mut self) {
        log::info!("Closing quantum TLS session");
        self.is_active = false;
    }

    /// Get the session ID
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Get the endpoint type
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Get the QKD keys
    pub fn qkd_keys(&self) -> &KeyPair {
        &self.qkd_keys
    }

    /// Get the cipher suite
    pub fn cipher_suite(&self) -> &HybridCipherSuite {
        &self.cipher_suite
    }

    /// Get the configuration
    pub fn config(&self) -> &QTLSConfig {
        &self.config
    }
}

/// Application data record
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApplicationDataRecord {
    sequence_number: u64,
    data: Vec<u8>,
    timestamp: Instant,
}

/// Session information
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: Vec<u8>,
    pub endpoint: Endpoint,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub sequence_number: u64,
    pub is_active: bool,
    pub qkd_error_rate: f64,
    pub key_length: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_creation() {
        let config = QTLSConfig::default();
        let qkd_keys = crate::qkd::KeyPair {
            alice_key: vec![1, 2, 3, 4, 5],
            bob_key: vec![1, 2, 3, 4, 5],
            key_length: 5,
            error_rate: 0.05,
            privacy_amplified: false,
        };
        let cipher_suite = HybridCipherSuite::default();
        
        let session = QuantumTLSSession::new(config, qkd_keys, cipher_suite, Endpoint::Client).await.unwrap();
        
        assert!(session.is_valid());
        assert_eq!(session.session_id().len(), 16);
    }

    #[tokio::test]
    async fn test_session_send_receive() {
        let config = QTLSConfig::default();
        let qkd_keys = crate::qkd::KeyPair {
            alice_key: vec![1, 2, 3, 4, 5, 6, 7, 8],
            bob_key: vec![1, 2, 3, 4, 5, 6, 7, 8],
            key_length: 8,
            error_rate: 0.05,
            privacy_amplified: false,
        };
        let cipher_suite = HybridCipherSuite::default();
        
        let mut session = QuantumTLSSession::new(config, qkd_keys, cipher_suite, Endpoint::Client).await.unwrap();
        
        let test_data = b"Hello, Quantum TLS!";
        let encrypted = session.send(test_data).await.unwrap();
        let decrypted = session.receive(&encrypted).await.unwrap();
        
        assert_eq!(test_data, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_session_info() {
        let config = QTLSConfig::default();
        let qkd_keys = crate::qkd::KeyPair {
            alice_key: vec![1, 2, 3, 4],
            bob_key: vec![1, 2, 3, 4],
            key_length: 4,
            error_rate: 0.05,
            privacy_amplified: false,
        };
        let cipher_suite = HybridCipherSuite::default();
        
        let session = QuantumTLSSession::new(config, qkd_keys, cipher_suite, Endpoint::Server).await.unwrap();
        let info = session.session_info();
        
        assert_eq!(info.session_id.len(), 16);
        assert!(info.is_active);
        assert_eq!(info.key_length, 4);
        assert_eq!(info.qkd_error_rate, 0.05);
    }
} 