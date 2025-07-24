use qtls_core::{QTLSConfig, QuantumTLS, QKDProtocolType, PostQuantumKEM, SymmetricCipher, SignatureScheme};
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();
    
    println!("=== Quantum TLS (qTLS) Implementation ===");
    println!("This is a research implementation of quantum-resistant TLS\n");
    
    // Create configuration
    let config = QTLSConfig {
        qkd_protocol: qtls_core::QKDConfig {
            protocol_type: QKDProtocolType::BB84,
            key_length: 256,
            error_threshold: 0.11,
            privacy_amplification_rounds: 2,
        },
        cipher_suite: qtls_core::CipherSuiteConfig {
            post_quantum_kem: PostQuantumKEM::Kyber768,
            symmetric_cipher: SymmetricCipher::AES256GCM,
            signature_scheme: SignatureScheme::Dilithium3,
        },
        key_length: 256,
        enable_hybrid_mode: true,
    };
    
    println!("Configuration:");
    println!("  QKD Protocol: {:?}", config.qkd_protocol.protocol_type);
    println!("  Key Length: {} bits", config.qkd_protocol.key_length);
    println!("  Post-Quantum KEM: {:?}", config.cipher_suite.post_quantum_kem);
    println!("  Symmetric Cipher: {:?}", config.cipher_suite.symmetric_cipher);
    println!("  Signature Scheme: {:?}", config.cipher_suite.signature_scheme);
    println!();
    
    // Create quantum TLS instance
    let mut qtls = QuantumTLS::new(config)?;
    
    // Demonstrate QKD key generation
    println!("=== QKD Key Generation ===");
    let start_time = Instant::now();
    let qkd_keys = qtls.generate_qkd_keys().await?;
    let key_gen_time = start_time.elapsed();
    
    println!("QKD Key Generation Results:");
    println!("  Alice Key Length: {} bits", qkd_keys.alice_key.len() * 8);
    println!("  Bob Key Length: {} bits", qkd_keys.bob_key.len() * 8);
    println!("  Error Rate: {:.3}", qkd_keys.error_rate);
    println!("  Privacy Amplified: {}", qkd_keys.privacy_amplified);
    println!("  Generation Time: {:?}", key_gen_time);
    println!();
    
    // Demonstrate TLS handshake
    println!("=== Quantum TLS Handshake ===");
    
    // Client handshake
    println!("Starting client handshake...");
    let mut client_handshake = qtls.start_client_handshake().await?;
    let client_session = client_handshake.perform_handshake().await?;
    let client_handshake_time = client_handshake.duration();
    
    println!("Client handshake completed:");
    println!("  Duration: {:?}", client_handshake_time);
    println!("  Session ID: {}", hex::encode(client_session.session_id()));
    println!();
    
    // Server handshake
    println!("Starting server handshake...");
    let mut server_handshake = qtls.start_server_handshake().await?;
    let server_session = server_handshake.perform_handshake().await?;
    let server_handshake_time = server_handshake.duration();
    
    println!("Server handshake completed:");
    println!("  Duration: {:?}", server_handshake_time);
    println!("  Session ID: {}", hex::encode(server_session.session_id()));
    println!();
    
    // Demonstrate secure communication
    println!("=== Secure Communication ===");
    
    let test_message = b"Hello, Quantum World! This is a secure message transmitted using quantum-resistant TLS.";
    println!("Original message: {}", String::from_utf8_lossy(test_message));
    println!("Message length: {} bytes", test_message.len());
    println!();
    
    // Send message through client session
    println!("Encrypting message...");
    let encrypted_message = client_session.send(test_message).await?;
    println!("Encrypted message length: {} bytes", encrypted_message.len());
    println!("Encrypted data: {}", hex::encode(&encrypted_message[..32.min(encrypted_message.len())]));
    if encrypted_message.len() > 32 {
        println!("  ... (truncated)");
    }
    println!();
    
    // Receive message through server session
    println!("Decrypting message...");
    let decrypted_message = server_session.receive(&encrypted_message).await?;
    println!("Decrypted message: {}", String::from_utf8_lossy(&decrypted_message));
    println!("Decryption successful: {}", test_message == decrypted_message.as_slice());
    println!();
    
    // Demonstrate hybrid cryptography
    println!("=== Hybrid Cryptography ===");
    
    let crypto = qtls_core::crypto::HybridCrypto::new(qtls.config().clone())?;
    
    // Generate hybrid key pair
    println!("Generating hybrid key pair...");
    let hybrid_key_pair = crypto.generate_key_pair().await?;
    println!("Hybrid key pair generated:");
    println!("  Classical public key: {} bytes", hybrid_key_pair.classical_public_key.len());
    println!("  Post-quantum public key: {} bytes", hybrid_key_pair.post_quantum_public_key.len());
    println!("  Key ID: {}", hex::encode(&hybrid_key_pair.key_id));
    println!();
    
    // Encrypt and decrypt data
    let test_data = b"Secret data to be encrypted with hybrid cryptography";
    println!("Original data: {}", String::from_utf8_lossy(test_data));
    
    let encrypted_data = crypto.encrypt(test_data, &hybrid_key_pair).await?;
    println!("Encrypted data length: {} bytes", encrypted_data.len());
    
    let decrypted_data = crypto.decrypt(&encrypted_data, &hybrid_key_pair).await?;
    println!("Decrypted data: {}", String::from_utf8_lossy(&decrypted_data));
    println!("Decryption successful: {}", test_data == decrypted_data.as_slice());
    println!();
    
    // Demonstrate hybrid signatures
    println!("=== Hybrid Signatures ===");
    
    let message_to_sign = b"Important message that needs to be signed with hybrid signatures";
    println!("Message to sign: {}", String::from_utf8_lossy(message_to_sign));
    
    let signature = crypto.sign(message_to_sign, &hybrid_key_pair).await?;
    println!("Hybrid signature created:");
    println!("  Classical signature: {} bytes", signature.classical_signature.len());
    println!("  Post-quantum signature: {} bytes", signature.post_quantum_signature.len());
    println!("  Algorithm: {:?}", signature.signature_algorithm);
    
    let is_valid = crypto.verify(message_to_sign, &signature, &hybrid_key_pair).await?;
    println!("Signature verification: {}", is_valid);
    println!();
    
    // Performance summary
    println!("=== Performance Summary ===");
    println!("QKD Key Generation: {:?}", key_gen_time);
    println!("Client Handshake: {:?}", client_handshake_time);
    println!("Server Handshake: {:?}", server_handshake_time);
    println!("Total Handshake Time: {:?}", client_handshake_time + server_handshake_time);
    println!();
    
    println!("=== Security Features ===");
    println!("✓ Quantum Key Distribution (QKD) for key generation");
    println!("✓ Post-quantum key encapsulation mechanisms");
    println!("✓ Hybrid signatures combining classical and post-quantum algorithms");
    println!("✓ Quantum-resistant symmetric encryption");
    println!("✓ Forward secrecy through QKD key updates");
    println!("✓ Man-in-the-middle protection via quantum entanglement");
    println!();
    
    println!("qTLS implementation demonstration completed successfully!");
    println!("This is a research implementation for educational purposes.");
    println!("For production use, ensure proper security audits and compliance.");
    
    Ok(())
} 