use thiserror::Error;

pub type QTLSResult<T> = Result<T, QTLSError>;

#[derive(Error, Debug)]
pub enum QTLSError {
    #[error("QKD protocol error: {0}")]
    QKDError(#[from] QKDError),
    
    #[error("TLS handshake error: {0}")]
    HandshakeError(#[from] HandshakeError),
    
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] CryptoError),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum QKDError {
    #[error("Quantum channel error: {0}")]
    QuantumChannelError(String),
    
    #[error("Classical channel error: {0}")]
    ClassicalChannelError(String),
    
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),
    
    #[error("Error correction failed: {0}")]
    ErrorCorrectionError(String),
    
    #[error("Privacy amplification failed: {0}")]
    PrivacyAmplificationError(String),
    
    #[error("Qubit measurement error: {0}")]
    MeasurementError(String),
    
    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),
}

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("Client hello error: {0}")]
    ClientHelloError(String),
    
    #[error("Server hello error: {0}")]
    ServerHelloError(String),
    
    #[error("Certificate exchange error: {0}")]
    CertificateError(String),
    
    #[error("Key exchange error: {0}")]
    KeyExchangeError(String),
    
    #[error("Finished message error: {0}")]
    FinishedError(String),
    
    #[error("Handshake timeout")]
    Timeout,
    
    #[error("Protocol version mismatch")]
    VersionMismatch,
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    
    #[error("Signature verification failed: {0}")]
    SignatureError(String),
    
    #[error("Hash computation failed: {0}")]
    HashError(String),
    
    #[error("Random number generation failed: {0}")]
    RandomError(String),
} 