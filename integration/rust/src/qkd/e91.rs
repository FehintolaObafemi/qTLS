use crate::errors::{QTLSResult, QKDError};
use crate::QTLSConfig;
use crate::qkd::{QKDProtocol, KeyPair, QuantumState, Basis, MeasurementResult};
use std::sync::Arc;
use tokio::sync::Mutex;
use rand::Rng;

pub struct E91Protocol {
    config: QTLSConfig,
    quantum_channel: Arc<Mutex<super::QuantumChannel>>,
    classical_channel: Arc<Mutex<super::ClassicalChannel>>,
}

impl E91Protocol {
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

    /// Generate entangled Bell pairs
    fn generate_bell_pairs(&self, num_pairs: usize) -> Vec<(QuantumState, QuantumState)> {
        let mut rng = rand::thread_rng();
        let mut bell_pairs = Vec::new();
        
        for _ in 0..num_pairs {
            // Randomly choose one of the four Bell states
            let bell_state = rng.gen_range(0..4);
            let (state1, state2) = match bell_state {
                0 => (QuantumState::Zero, QuantumState::Zero), // |00⟩ + |11⟩
                1 => (QuantumState::Zero, QuantumState::One),  // |00⟩ - |11⟩
                2 => (QuantumState::One, QuantumState::Zero),  // |01⟩ + |10⟩
                3 => (QuantumState::One, QuantumState::One),   // |01⟩ - |10⟩
                _ => unreachable!(),
            };
            bell_pairs.push((state1, state2));
        }
        
        bell_pairs
    }

    /// Generate random measurement bases for E91
    fn generate_measurement_bases(&self, length: usize) -> Vec<Basis> {
        let mut rng = rand::thread_rng();
        (0..length).map(|_| if rng.gen_bool(0.5) { Basis::Computational } else { Basis::Hadamard }).collect()
    }

    /// Simulate entangled state measurement
    fn measure_entangled_state(&self, state: QuantumState, measurement_basis: Basis) -> u8 {
        let mut rng = rand::thread_rng();
        
        // Simulate quantum noise (error rate)
        let noise = rng.gen_range(0.0..1.0) < self.config.qkd_protocol.error_threshold;
        
        // For entangled states, measurement results are correlated
        let measurement_result = match (state, measurement_basis) {
            (QuantumState::Zero, Basis::Computational) => 0,
            (QuantumState::One, Basis::Computational) => 1,
            (QuantumState::Zero, Basis::Hadamard) => 0, // |+⟩ state
            (QuantumState::One, Basis::Hadamard) => 1,  // |-⟩ state
        };
        
        if noise {
            1 - measurement_result // Flip the bit due to noise
        } else {
            measurement_result
        }
    }

    /// Calculate Bell inequality violation
    fn calculate_bell_violation(&self, alice_results: &[u8], bob_results: &[u8]) -> f64 {
        if alice_results.len() != bob_results.len() {
            return 0.0;
        }
        
        let mut correlation_sum = 0.0;
        let n = alice_results.len() as f64;
        
        for (a, b) in alice_results.iter().zip(bob_results.iter()) {
            // Calculate correlation: E(a,b) = P(a=b) - P(a≠b)
            let correlation = if a == b { 1.0 } else { -1.0 };
            correlation_sum += correlation;
        }
        
        correlation_sum / n
    }
}

#[async_trait::async_trait]
impl QKDProtocol for E91Protocol {
    async fn generate_keys(&mut self) -> QTLSResult<KeyPair> {
        let key_length = self.config.qkd_protocol.key_length;
        let num_bell_pairs = key_length * 3; // Generate extra pairs for error estimation
        
        log::info!("Starting E91 protocol with {} Bell pairs", num_bell_pairs);
        
        // Step 1: Generate entangled Bell pairs
        let bell_pairs = self.generate_bell_pairs(num_bell_pairs);
        
        // Step 2: Distribute entangled pairs between Alice and Bob
        {
            let mut quantum_channel = self.quantum_channel.lock().await;
            for (state1, state2) in &bell_pairs {
                quantum_channel.send_entangled_pair(*state1, *state2).await?;
            }
        }
        
        // Step 3: Alice and Bob generate random measurement bases
        let alice_bases = self.generate_measurement_bases(num_bell_pairs);
        let bob_bases = self.generate_measurement_bases(num_bell_pairs);
        
        // Step 4: Alice and Bob measure their entangled qubits
        let mut alice_measurements = Vec::new();
        let mut bob_measurements = Vec::new();
        
        {
            let mut quantum_channel = self.quantum_channel.lock().await;
            for i in 0..num_bell_pairs {
                let (alice_qubit, bob_qubit) = quantum_channel.receive_entangled_pair().await?;
                
                let alice_result = self.measure_entangled_state(alice_qubit, alice_bases[i]);
                let bob_result = self.measure_entangled_state(bob_qubit, bob_bases[i]);
                
                alice_measurements.push(MeasurementResult {
                    basis: alice_bases[i],
                    bit_value: alice_result,
                    timestamp: std::time::Instant::now(),
                });
                
                bob_measurements.push(MeasurementResult {
                    basis: bob_bases[i],
                    bit_value: bob_result,
                    timestamp: std::time::Instant::now(),
                });
            }
        }
        
        // Step 5: Exchange measurement bases classically
        {
            let mut classical_channel = self.classical_channel.lock().await;
            classical_channel.send(&alice_bases).await?;
            let _received_alice_bases: Vec<Basis> = classical_channel.receive().await?;
            
            classical_channel.send(&bob_bases).await?;
            let _received_bob_bases: Vec<Basis> = classical_channel.receive().await?;
        }
        
        // Step 6: Check Bell inequality violation (security check)
        let alice_bits: Vec<u8> = alice_measurements.iter().map(|m| m.bit_value).collect();
        let bob_bits: Vec<u8> = bob_measurements.iter().map(|m| m.bit_value).collect();
        
        let bell_violation = self.calculate_bell_violation(&alice_bits, &bob_bits);
        log::info!("Bell inequality violation: {}", bell_violation);
        
        // Step 7: Sift the key (keep only matching bases)
        let mut alice_sifted_bits = Vec::new();
        let mut bob_sifted_bits = Vec::new();
        
        for i in 0..num_bell_pairs {
            if alice_bases[i] == bob_bases[i] {
                alice_sifted_bits.push(alice_measurements[i].bit_value);
                bob_sifted_bits.push(bob_measurements[i].bit_value);
            }
        }
        
        log::info!("Sifted key length: {} bits", alice_sifted_bits.len());
        
        // Step 8: Estimate error rate
        let error_rate = self.estimate_error_rate_from_samples(&alice_sifted_bits, &bob_sifted_bits).await?;
        
        // Step 9: Check if error rate is acceptable
        if error_rate > self.config.qkd_protocol.error_threshold {
            return Err(QKDError::KeyGenerationError(
                format!("Error rate {} exceeds threshold {}", error_rate, self.config.qkd_protocol.error_threshold)
            ));
        }
        
        // Step 10: Truncate to desired key length
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
        Ok(0.03) // 3% error rate (typically lower than BB84 due to entanglement)
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
        "E91"
    }
}

impl E91Protocol {
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