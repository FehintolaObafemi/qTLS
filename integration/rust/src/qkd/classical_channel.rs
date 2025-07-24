use crate::errors::{QTLSResult, QKDError};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tokio::sync::mpsc;

/// Simulated classical channel for secure communication during QKD
pub struct ClassicalChannel {
    message_queue: VecDeque<Vec<u8>>,
    authenticated: bool,
    encryption_enabled: bool,
    session_key: Option<Vec<u8>>,
}

impl ClassicalChannel {
    pub fn new() -> Self {
        Self {
            message_queue: VecDeque::new(),
            authenticated: false,
            encryption_enabled: false,
            session_key: None,
        }
    }

    pub fn with_authentication(authenticated: bool) -> Self {
        Self {
            message_queue: VecDeque::new(),
            authenticated,
            encryption_enabled: false,
            session_key: None,
        }
    }

    /// Send a message through the classical channel
    pub async fn send<T: Serialize>(&mut self, message: &T) -> QTLSResult<()> {
        let serialized = serde_json::to_vec(message)
            .map_err(|e| QKDError::ClassicalChannelError(format!("Serialization error: {}", e)))?;
        
        let encrypted_message = if self.encryption_enabled {
            self.encrypt_message(&serialized)?
        } else {
            serialized
        };
        
        self.message_queue.push_back(encrypted_message);
        log::debug!("Message sent through classical channel: {} bytes", encrypted_message.len());
        Ok(())
    }

    /// Receive a message from the classical channel
    pub async fn receive<T: for<'de> Deserialize<'de>>(&mut self) -> QTLSResult<T> {
        if let Some(encrypted_message) = self.message_queue.pop_front() {
            let decrypted_message = if self.encryption_enabled {
                self.decrypt_message(&encrypted_message)?
            } else {
                encrypted_message
            };
            
            let deserialized: T = serde_json::from_slice(&decrypted_message)
                .map_err(|e| QKDError::ClassicalChannelError(format!("Deserialization error: {}", e)))?;
            
            log::debug!("Message received from classical channel: {} bytes", decrypted_message.len());
            Ok(deserialized)
        } else {
            Err(QKDError::ClassicalChannelError("No messages available in channel".to_string()))
        }
    }

    /// Send raw bytes through the classical channel
    pub async fn send_raw(&mut self, data: &[u8]) -> QTLSResult<()> {
        let encrypted_data = if self.encryption_enabled {
            self.encrypt_message(data)?
        } else {
            data.to_vec()
        };
        
        self.message_queue.push_back(encrypted_data);
        log::debug!("Raw data sent through classical channel: {} bytes", data.len());
        Ok(())
    }

    /// Receive raw bytes from the classical channel
    pub async fn receive_raw(&mut self) -> QTLSResult<Vec<u8>> {
        if let Some(encrypted_data) = self.message_queue.pop_front() {
            let decrypted_data = if self.encryption_enabled {
                self.decrypt_message(&encrypted_data)?
            } else {
                encrypted_data
            };
            
            log::debug!("Raw data received from classical channel: {} bytes", decrypted_data.len());
            Ok(decrypted_data)
        } else {
            Err(QKDError::ClassicalChannelError("No data available in channel".to_string()))
        }
    }

    /// Enable encryption for the classical channel
    pub fn enable_encryption(&mut self, session_key: Vec<u8>) {
        self.encryption_enabled = true;
        self.session_key = Some(session_key);
        log::info!("Classical channel encryption enabled");
    }

    /// Disable encryption for the classical channel
    pub fn disable_encryption(&mut self) {
        self.encryption_enabled = false;
        self.session_key = None;
        log::info!("Classical channel encryption disabled");
    }

    /// Set authentication status
    pub fn set_authenticated(&mut self, authenticated: bool) {
        self.authenticated = authenticated;
        log::info!("Classical channel authentication status: {}", authenticated);
    }

    /// Check if the channel is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Check if encryption is enabled
    pub fn is_encrypted(&self) -> bool {
        self.encryption_enabled
    }

    /// Get the number of messages in the channel
    pub fn message_count(&self) -> usize {
        self.message_queue.len()
    }

    /// Clear all messages from the channel
    pub fn clear(&mut self) {
        self.message_queue.clear();
    }

    /// Simple encryption using XOR with session key
    fn encrypt_message(&self, message: &[u8]) -> QTLSResult<Vec<u8>> {
        let session_key = self.session_key.as_ref()
            .ok_or_else(|| QKDError::ClassicalChannelError("No session key available".to_string()))?;
        
        let mut encrypted = Vec::new();
        for (i, &byte) in message.iter().enumerate() {
            let key_byte = session_key[i % session_key.len()];
            encrypted.push(byte ^ key_byte);
        }
        
        Ok(encrypted)
    }

    /// Simple decryption using XOR with session key
    fn decrypt_message(&self, encrypted_message: &[u8]) -> QTLSResult<Vec<u8>> {
        // XOR encryption is symmetric, so decryption is the same as encryption
        self.encrypt_message(encrypted_message)
    }

    /// Simulate message loss in the classical channel
    pub fn simulate_loss(&mut self, loss_rate: f64) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        if !self.message_queue.is_empty() && rng.gen_range(0.0..1.0) < loss_rate {
            self.message_queue.pop_front();
            log::debug!("Message lost in classical channel");
        }
    }

    /// Simulate message corruption in the classical channel
    pub fn simulate_corruption(&mut self, corruption_rate: f64) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        if !self.message_queue.is_empty() && rng.gen_range(0.0..1.0) < corruption_rate {
            if let Some(message) = self.message_queue.back_mut() {
                if !message.is_empty() {
                    let corrupt_index = rng.gen_range(0..message.len());
                    message[corrupt_index] = rng.gen_range(0..256);
                    log::debug!("Message corrupted in classical channel at index {}", corrupt_index);
                }
            }
        }
    }
}

impl Default for ClassicalChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Message types for classical communication during QKD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QKDMessage {
    BasisReveal(Vec<super::Basis>),
    ErrorEstimation(Vec<u8>),
    PrivacyAmplification(Vec<u8>),
    KeyConfirmation(Vec<u8>),
    ProtocolComplete,
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qkd::Basis;

    #[tokio::test]
    async fn test_classical_channel_basic() {
        let mut channel = ClassicalChannel::new();
        
        // Test basic message sending and receiving
        let test_message = vec![1, 2, 3, 4, 5];
        channel.send_raw(&test_message).await.unwrap();
        
        let received_message = channel.receive_raw().await.unwrap();
        assert_eq!(received_message, test_message);
    }

    #[tokio::test]
    async fn test_classical_channel_serialization() {
        let mut channel = ClassicalChannel::new();
        
        // Test serialized message sending and receiving
        let test_bases = vec![Basis::Computational, Basis::Hadamard, Basis::Computational];
        channel.send(&test_bases).await.unwrap();
        
        let received_bases: Vec<Basis> = channel.receive().await.unwrap();
        assert_eq!(received_bases, test_bases);
    }

    #[tokio::test]
    async fn test_classical_channel_encryption() {
        let mut channel = ClassicalChannel::new();
        let session_key = vec![0x42, 0x43, 0x44, 0x45];
        
        channel.enable_encryption(session_key);
        
        let test_message = vec![1, 2, 3, 4, 5];
        channel.send_raw(&test_message).await.unwrap();
        
        let received_message = channel.receive_raw().await.unwrap();
        assert_eq!(received_message, test_message);
    }

    #[tokio::test]
    async fn test_qkd_message_types() {
        let mut channel = ClassicalChannel::new();
        
        let qkd_message = QKDMessage::BasisReveal(vec![Basis::Computational, Basis::Hadamard]);
        channel.send(&qkd_message).await.unwrap();
        
        let received_message: QKDMessage = channel.receive().await.unwrap();
        match received_message {
            QKDMessage::BasisReveal(bases) => {
                assert_eq!(bases, vec![Basis::Computational, Basis::Hadamard]);
            }
            _ => panic!("Unexpected message type"),
        }
    }
} 