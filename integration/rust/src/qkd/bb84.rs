use crate::errors::{QTLSResult, QKDError};
use crate::QTLSConfig;
use crate::qkd::{QKDProtocol, KeyPair, QuantumState, Basis, MeasurementResult};
use std::sync::Arc;
use tokio::sync::Mutex;
use rand::Rng;

pub struct BB84Protocol {
    config: QTLSConfig,
    quantum_channel: Arc<Mutex<super::QuantumChannel>>,
    classical_channel: Arc<Mutex<super::ClassicalChannel>>,
}

impl BB84Protocol {
    pub fn new(
        config: QTLSConfig,
        quantum_channel: Arc<Mutex<super::QuantumChannel>>,
        classical_channel: Arc<Mutex<super::ClassicalChannel>>,
    ) -> Self {
        Self {
            config,
            quantum_channel,
            classical_channel,
        }
    }

    /// Generate random bits for Alice
    fn generate_random_bits(&self, length: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..length).map(|_| rng.gen_range(0..2)).collect()
    }

    /// Generate random bases for Alice
    fn generate_random_bases(&self, length: usize) -> Vec<Basis> {
        let mut rng = rand::thread_rng();
        (0..length).map(|_| if rng.gen_bool(0.5) { Basis::Computational } else { Basis::Hadamard }).collect()
    }

    /// Prepare quantum states based on bits and bases
    fn prepare_quantum_states(&self, bits: &[u8], bases: &[Basis]) -> Vec<QuantumState> {
        bits.iter().zip(bases.iter()).map(|(&bit, &basis)| {
            match (bit, basis) {
                (0, Basis::Computational) => QuantumState::Zero,
                (1, Basis::Computational) => QuantumState::One,
                (0, Basis::Hadamard) => QuantumState::Plus,
                (1, Basis::Hadamard) => QuantumState::Minus,
                _ => unreachable!(),
            }
        }).collect()
    }

    /// Simulate quantum measurement with noise
    fn measure_quantum_state(&self, state: QuantumState, measurement_basis: Basis) -> u8 {
        let mut rng = rand::thread_rng();
        
        // Simulate quantum noise (error rate)
        let noise = rng.gen_range(0.0..1.0) < self.config.qkd_protocol.error_threshold;
        
        let correct_result = match (state, measurement_basis) {
            // Same basis measurements
            (QuantumState::Zero, Basis::Computational) => 0,
            (QuantumState::One, Basis::Computational) => 1,
            (QuantumState::Plus, Basis::Hadamard) => 0,
            (QuantumState::Minus, Basis::Hadamard) => 1,
            
            // Different basis measurements (random result)
            _ => rng.gen_range(0..2),
        };
        
        if noise {
            1 - correct_result // Flip the bit due to noise
        } else {
            correct_result
        }
    }
}

#[async_trait::async_trait]
impl QKDProtocol for BB84Protocol {
    async fn generate_keys(&mut self) -> QTLSResult<KeyPair> {
        let key_length = self.config.qkd_protocol.key_length;
        let num_qubits = key_length * 4; // Send extra qubits to account for basis mismatches
        
        log::info!("Starting BB84 protocol with {} qubits", num_qubits);
        
        // Step 1: Alice generates random bits and bases
        let alice_bits = self.generate_random_bits(num_qubits);
        let alice_bases = self.generate_random_bases(num_qubits);
        let alice_states = self.prepare_quantum_states(&alice_bits, &alice_bases);
        
        // Step 2: Alice sends quantum states to Bob
        {
            let mut quantum_channel = self.quantum_channel.lock().await;
            for state in &alice_states {
                quantum_channel.send_qubit(*state).await?;
            }
        }
        
        // Step 3: Bob generates random measurement bases
        let bob_bases = self.generate_random_bases(num_qubits);
        
        // Step 4: Bob measures the received qubits
        let mut bob_measurements = Vec::new();
        {
            let mut quantum_channel = self.quantum_channel.lock().await;
            for (i, &basis) in bob_bases.iter().enumerate() {
                let qubit = quantum_channel.receive_qubit().await?;
                let measurement = self.measure_quantum_state(qubit, basis);
                bob_measurements.push(MeasurementResult {
                    basis,
                    bit_value: measurement,
                    timestamp: std::time::Instant::now(),
                });
            }
        }
        
        // Step 5: Classical communication - exchange basis information
        {
            let mut classical_channel = self.classical_channel.lock().await;
            classical_channel.send(&alice_bases).await?;
            let received_alice_bases: Vec<Basis> = classical_channel.receive().await?;
            
            classical_channel.send(&bob_bases).await?;
            let received_bob_bases: Vec<Basis> = classical_channel.receive().await?;
        }
        
        // Step 6: Sift the key (keep only matching bases)
        let mut alice_sifted_bits = Vec::new();
        let mut bob_sifted_bits = Vec::new();
        
        for i in 0..num_qubits {
            if alice_bases[i] == bob_bases[i] {
                alice_sifted_bits.push(alice_bits[i]);
                bob_sifted_bits.push(bob_measurements[i].bit_value);
            }
        }
        
        log::info!("Sifted key length: {} bits", alice_sifted_bits.len());
        
        // Step 7: Estimate error rate (using a subset of the key)
        let error_rate = self.estimate_error_rate_from_samples(&alice_sifted_bits, &bob_sifted_bits).await?;
        
        // Step 8: Check if error rate is acceptable
        if error_rate > self.config.qkd_protocol.error_threshold {
            return Err(QKDError::KeyGenerationError(
                format!("Error rate {} exceeds threshold {}", error_rate, self.config.qkd_protocol.error_threshold)
            ));
        }
        
        // Step 9: Truncate to desired key length
        let final_key_length = std::cmp::min(key_length, alice_sifted_bits.len());
        let alice_final_key = alice_sifted_bits[..final_key_length].to_vec();
        let bob_final_key = bob_sifted_bits[..final_key_length].to_vec();
        
        Ok(KeyPair {
            alice_key: alice_final_key,
            bob_key: bob_final_key,
            key_length: final_key_length,
            error_rate,
            privacy_amplified: false,
        })
    }

    async fn estimate_error_rate(&self) -> QTLSResult<f64> {
        // This would typically use a subset of the generated key
        // For now, return a simulated error rate
        Ok(0.05) // 5% error rate
    }

    async fn privacy_amplification(&mut self, key: &[u8]) -> QTLSResult<Vec<u8>> {
        // Simple privacy amplification using SHA-256
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(key);
        let result = hasher.finalize();
        
        // Truncate to desired key length
        let key_length = std::cmp::min(self.config.qkd_protocol.key_length, result.len());
        Ok(result[..key_length].to_vec())
    }

    fn get_protocol_name(&self) -> &'static str {
        "BB84"
    }
}

impl BB84Protocol {
    async fn estimate_error_rate_from_samples(&self, alice_bits: &[u8], bob_bits: &[u8]) -> QTLSResult<f64> {
        if alice_bits.len() != bob_bits.len() {
            return Err(QKDError::ProtocolViolation("Bit arrays have different lengths".to_string()));
        }
        
        let sample_size = std::cmp::min(100, alice_bits.len() / 10); // Use 10% of the key for error estimation
        let mut errors = 0;
        
        for i in 0..sample_size {
            if alice_bits[i] != bob_bits[i] {
                errors += 1;
            }
        }
        
        Ok(errors as f64 / sample_size as f64)
    }
} 