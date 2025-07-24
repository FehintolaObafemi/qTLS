pub mod handshake;
pub mod session;
pub mod certificate;

use crate::errors::{QTLSResult, HandshakeError};
use crate::qkd::{QKDProtocolImpl, KeyPair};
use crate::crypto::HybridCipherSuite;
use crate::QTLSConfig;
use serde::{Deserialize, Serialize};

pub use handshake::QuantumTLSHandshake;
pub use session::QuantumTLSSession;
pub use certificate::HybridCertificate;

/// TLS protocol version
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TLSVersion {
    TLS1_2,
    TLS1_3,
    QTLS1_0, // Quantum TLS version
}

/// TLS handshake state
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeState {
    Initial,
    ClientHello,
    ServerHello,
    QKDInit,
    QKDComplete,
    CertificateExchange,
    KeyExchange,
    Finished,
    Complete,
    Error(String),
}

/// TLS handshake message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    QKDInit(QKDInit),
    QKDComplete(QKDComplete),
    Certificate(Certificate),
    KeyExchange(KeyExchange),
    Finished(Finished),
}

/// Client Hello message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: TLSVersion,
    pub random: Vec<u8>,
    pub session_id: Option<Vec<u8>>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub qkd_support: bool,
}

/// Server Hello message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: TLSVersion,
    pub random: Vec<u8>,
    pub session_id: Option<Vec<u8>>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<Extension>,
    pub qkd_support: bool,
}

/// QKD initialization message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QKDInit {
    pub protocol_type: crate::QKDProtocolType,
    pub key_length: usize,
    pub error_threshold: f64,
}

/// QKD completion message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QKDComplete {
    pub key_id: Vec<u8>,
    pub key_length: usize,
    pub error_rate: f64,
}

/// Certificate message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub certificates: Vec<HybridCertificate>,
}

/// Key exchange message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchange {
    pub classical_key: Vec<u8>,
    pub quantum_key: Vec<u8>,
    pub hybrid_key: Vec<u8>,
}

/// Finished message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

/// TLS extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    pub extension_type: u16,
    pub extension_data: Vec<u8>,
}

/// Main quantum TLS implementation
pub struct QuantumTLS {
    config: QTLSConfig,
    qkd_protocol: QKDProtocolImpl,
    cipher_suite: HybridCipherSuite,
    handshake_state: HandshakeState,
}

impl QuantumTLS {
    pub fn new(config: QTLSConfig) -> QTLSResult<Self> {
        let qkd_protocol = QKDProtocolImpl::new(config.clone())?;
        let cipher_suite = HybridCipherSuite::new(config.cipher_suite.clone())?;
        
        Ok(Self {
            config,
            qkd_protocol,
            cipher_suite,
            handshake_state: HandshakeState::Initial,
        })
    }

    /// Start a client-side handshake
    pub async fn start_client_handshake(&mut self) -> QTLSResult<QuantumTLSHandshake> {
        log::info!("Starting quantum TLS client handshake");
        
        let handshake = QuantumTLSHandshake::new_client(
            self.config.clone(),
            self.qkd_protocol.clone(),
            self.cipher_suite.clone(),
        )?;
        
        self.handshake_state = HandshakeState::ClientHello;
        Ok(handshake)
    }

    /// Start a server-side handshake
    pub async fn start_server_handshake(&mut self) -> QTLSResult<QuantumTLSHandshake> {
        log::info!("Starting quantum TLS server handshake");
        
        let handshake = QuantumTLSHandshake::new_server(
            self.config.clone(),
            self.qkd_protocol.clone(),
            self.cipher_suite.clone(),
        )?;
        
        self.handshake_state = HandshakeState::ServerHello;
        Ok(handshake)
    }

    /// Get the current handshake state
    pub fn handshake_state(&self) -> &HandshakeState {
        &self.handshake_state
    }

    /// Get the configuration
    pub fn config(&self) -> &QTLSConfig {
        &self.config
    }

    /// Generate QKD keys
    pub async fn generate_qkd_keys(&mut self) -> QTLSResult<KeyPair> {
        self.qkd_protocol.generate_keys().await
    }

    /// Estimate QKD error rate
    pub async fn estimate_qkd_error_rate(&self) -> QTLSResult<f64> {
        self.qkd_protocol.estimate_error_rate().await
    }
}

impl Default for QuantumTLS {
    fn default() -> Self {
        Self::new(QTLSConfig::default()).expect("Failed to create default QuantumTLS")
    }
}

/// TLS connection endpoint
#[derive(Debug, Clone)]
pub enum Endpoint {
    Client,
    Server,
}

/// TLS connection parameters
#[derive(Debug, Clone)]
pub struct ConnectionParams {
    pub endpoint: Endpoint,
    pub hostname: String,
    pub port: u16,
    pub timeout: std::time::Duration,
}

impl Default for ConnectionParams {
    fn default() -> Self {
        Self {
            endpoint: Endpoint::Client,
            hostname: "localhost".to_string(),
            port: 443,
            timeout: std::time::Duration::from_secs(30),
        }
    }
} 