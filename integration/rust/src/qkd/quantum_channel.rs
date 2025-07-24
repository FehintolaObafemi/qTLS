use crate::errors::{QTLSResult, QKDError};
use crate::qkd::{QuantumState, Basis};
use std::collections::VecDeque;
use tokio::sync::mpsc;

/// Simulated quantum channel for qubit transmission
pub struct QuantumChannel {
    qubit_queue: VecDeque<QuantumState>,
    entangled_pairs_queue: VecDeque<(QuantumState, QuantumState)>,
    noise_level: f64,
    loss_rate: f64,
}

impl QuantumChannel {
    pub fn new() -> Self {
        Self {
            qubit_queue: VecDeque::new(),
            entangled_pairs_queue: VecDeque::new(),
            noise_level: 0.05, // 5% noise
            loss_rate: 0.02,   // 2% loss rate
        }
    }

    pub fn with_noise(noise_level: f64, loss_rate: f64) -> Self {
        Self {
            qubit_queue: VecDeque::new(),
            entangled_pairs_queue: VecDeque::new(),
            noise_level,
            loss_rate,
        }
    }

    /// Send a single qubit through the quantum channel
    pub async fn send_qubit(&mut self, state: QuantumState) -> QTLSResult<()> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // Simulate quantum channel loss
        if rng.gen_range(0.0..1.0) < self.loss_rate {
            log::debug!("Qubit lost in quantum channel");
            return Ok(()); // Qubit is lost
        }
        
        // Simulate quantum noise
        let noisy_state = if rng.gen_range(0.0..1.0) < self.noise_level {
            self.apply_quantum_noise(state)
        } else {
            state
        };
        
        self.qubit_queue.push_back(noisy_state);
        log::debug!("Qubit sent through quantum channel: {:?}", noisy_state);
        Ok(())
    }

    /// Receive a single qubit from the quantum channel
    pub async fn receive_qubit(&mut self) -> QTLSResult<QuantumState> {
        if let Some(state) = self.qubit_queue.pop_front() {
            log::debug!("Qubit received from quantum channel: {:?}", state);
            Ok(state)
        } else {
            Err(QKDError::QuantumChannelError("No qubits available in channel".to_string()))
        }
    }

    /// Send an entangled pair through the quantum channel
    pub async fn send_entangled_pair(&mut self, state1: QuantumState, state2: QuantumState) -> QTLSResult<()> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // Simulate quantum channel loss for entangled pairs
        if rng.gen_range(0.0..1.0) < self.loss_rate {
            log::debug!("Entangled pair lost in quantum channel");
            return Ok(()); // Pair is lost
        }
        
        // Simulate quantum noise on entangled states
        let (noisy_state1, noisy_state2) = if rng.gen_range(0.0..1.0) < self.noise_level {
            (self.apply_quantum_noise(state1), self.apply_quantum_noise(state2))
        } else {
            (state1, state2)
        };
        
        self.entangled_pairs_queue.push_back((noisy_state1, noisy_state2));
        log::debug!("Entangled pair sent through quantum channel: ({:?}, {:?})", noisy_state1, noisy_state2);
        Ok(())
    }

    /// Receive an entangled pair from the quantum channel
    pub async fn receive_entangled_pair(&mut self) -> QTLSResult<(QuantumState, QuantumState)> {
        if let Some((state1, state2)) = self.entangled_pairs_queue.pop_front() {
            log::debug!("Entangled pair received from quantum channel: ({:?}, {:?})", state1, state2);
            Ok((state1, state2))
        } else {
            Err(QKDError::QuantumChannelError("No entangled pairs available in channel".to_string()))
        }
    }

    /// Apply quantum noise to a quantum state
    fn apply_quantum_noise(&self, state: QuantumState) -> QuantumState {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // Simulate different types of quantum noise
        let noise_type = rng.gen_range(0..3);
        
        match noise_type {
            0 => {
                // Bit flip error
                match state {
                    QuantumState::Zero => QuantumState::One,
                    QuantumState::One => QuantumState::Zero,
                    QuantumState::Plus => QuantumState::Minus,
                    QuantumState::Minus => QuantumState::Plus,
                }
            }
            1 => {
                // Phase flip error (only affects superposition states)
                match state {
                    QuantumState::Zero => QuantumState::Zero,
                    QuantumState::One => QuantumState::One,
                    QuantumState::Plus => QuantumState::Minus,
                    QuantumState::Minus => QuantumState::Plus,
                }
            }
            2 => {
                // Depolarization (random state)
                let random_state = rng.gen_range(0..4);
                match random_state {
                    0 => QuantumState::Zero,
                    1 => QuantumState::One,
                    2 => QuantumState::Plus,
                    3 => QuantumState::Minus,
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    /// Get the number of qubits in the channel
    pub fn qubit_count(&self) -> usize {
        self.qubit_queue.len()
    }

    /// Get the number of entangled pairs in the channel
    pub fn entangled_pair_count(&self) -> usize {
        self.entangled_pairs_queue.len()
    }

    /// Clear all qubits and entangled pairs from the channel
    pub fn clear(&mut self) {
        self.qubit_queue.clear();
        self.entangled_pairs_queue.clear();
    }

    /// Set the noise level of the quantum channel
    pub fn set_noise_level(&mut self, noise_level: f64) {
        self.noise_level = noise_level.clamp(0.0, 1.0);
    }

    /// Set the loss rate of the quantum channel
    pub fn set_loss_rate(&mut self, loss_rate: f64) {
        self.loss_rate = loss_rate.clamp(0.0, 1.0);
    }
}

impl Default for QuantumChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quantum_channel_basic() {
        let mut channel = QuantumChannel::new();
        
        // Test single qubit transmission
        let original_state = QuantumState::Zero;
        channel.send_qubit(original_state).await.unwrap();
        
        let received_state = channel.receive_qubit().await.unwrap();
        assert_eq!(received_state, original_state);
    }

    #[tokio::test]
    async fn test_entangled_pair_transmission() {
        let mut channel = QuantumChannel::new();
        
        // Test entangled pair transmission
        let state1 = QuantumState::Zero;
        let state2 = QuantumState::One;
        
        channel.send_entangled_pair(state1, state2).await.unwrap();
        
        let (received_state1, received_state2) = channel.receive_entangled_pair().await.unwrap();
        assert_eq!(received_state1, state1);
        assert_eq!(received_state2, state2);
    }

    #[tokio::test]
    async fn test_channel_noise() {
        let mut channel = QuantumChannel::with_noise(0.5, 0.0); // High noise, no loss
        
        let original_state = QuantumState::Zero;
        channel.send_qubit(original_state).await.unwrap();
        
        let received_state = channel.receive_qubit().await.unwrap();
        // With high noise, the state might be different
        // This test just ensures the channel doesn't crash
        assert!(matches!(received_state, QuantumState::Zero | QuantumState::One | QuantumState::Plus | QuantumState::Minus));
    }
} 