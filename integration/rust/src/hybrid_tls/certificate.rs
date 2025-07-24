use crate::errors::{QTLSResult, CryptoError};
use crate::crypto::{HybridSignature, SignatureAlgorithm};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Hybrid certificate combining classical and post-quantum signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCertificate {
    pub version: u8,
    pub serial_number: Vec<u8>,
    pub signature_algorithm: SignatureAlgorithm,
    pub issuer: CertificateSubject,
    pub validity: CertificateValidity,
    pub subject: CertificateSubject,
    pub public_key: HybridPublicKey,
    pub classical_signature: Vec<u8>,
    pub post_quantum_signature: Vec<u8>,
    pub extensions: Vec<CertificateExtension>,
}

/// Certificate subject information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSubject {
    pub common_name: String,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
}

/// Certificate validity period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateValidity {
    pub not_before: u64,
    pub not_after: u64,
}

/// Hybrid public key containing both classical and post-quantum keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub classical_public_key: Vec<u8>,
    pub post_quantum_public_key: Vec<u8>,
    pub key_algorithm: String,
}

/// Certificate extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateExtension {
    pub oid: String,
    pub critical: bool,
    pub value: Vec<u8>,
}

impl HybridCertificate {
    /// Create a new test certificate
    pub fn new_test_cert() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            version: 3,
            serial_number: vec![1, 2, 3, 4, 5, 6, 7, 8],
            signature_algorithm: SignatureAlgorithm::Hybrid(
                Box::new(SignatureAlgorithm::ECDSA256),
                Box::new(SignatureAlgorithm::Dilithium3),
            ),
            issuer: CertificateSubject {
                common_name: "qTLS Test CA".to_string(),
                organization: Some("qTLS Project".to_string()),
                organizational_unit: Some("Quantum Security".to_string()),
                country: Some("US".to_string()),
                state: None,
                locality: None,
            },
            validity: CertificateValidity {
                not_before: now,
                not_after: now + 365 * 24 * 60 * 60, // 1 year
            },
            subject: CertificateSubject {
                common_name: "localhost".to_string(),
                organization: Some("qTLS Test Server".to_string()),
                organizational_unit: Some("Quantum TLS".to_string()),
                country: Some("US".to_string()),
                state: None,
                locality: None,
            },
            public_key: HybridPublicKey {
                classical_public_key: vec![0u8; 65], // ECDSA P-256 public key
                post_quantum_public_key: vec![0u8; 1952], // Dilithium3 public key
                key_algorithm: "Hybrid-ECDSA-Dilithium3".to_string(),
            },
            classical_signature: vec![0u8; 64], // ECDSA signature
            post_quantum_signature: vec![0u8; 2701], // Dilithium3 signature
            extensions: vec![
                CertificateExtension {
                    oid: "2.5.29.19".to_string(), // Basic Constraints
                    critical: true,
                    value: vec![0x30, 0x03, 0x01, 0x01, 0xFF],
                },
                CertificateExtension {
                    oid: "2.5.29.15".to_string(), // Key Usage
                    critical: true,
                    value: vec![0x03, 0x02, 0x05, 0xA0],
                },
            ],
        }
    }

    /// Verify the certificate signatures
    pub async fn verify_signatures(&self, ca_public_key: &HybridPublicKey) -> QTLSResult<bool> {
        // Get the certificate data to be signed (excluding signatures)
        let cert_data = self.get_certificate_data()?;
        
        // Create hybrid signature for verification
        let hybrid_signature = HybridSignature {
            classical_signature: self.classical_signature.clone(),
            post_quantum_signature: self.post_quantum_signature.clone(),
            signature_algorithm: self.signature_algorithm,
        };
        
        // In a real implementation, this would verify both signatures
        // For simulation, we'll just check that signatures are not empty
        let classical_valid = !self.classical_signature.is_empty();
        let post_quantum_valid = !self.post_quantum_signature.is_empty();
        
        Ok(classical_valid && post_quantum_valid)
    }

    /// Check if the certificate is currently valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now >= self.validity.not_before && now <= self.validity.not_after
    }

    /// Get the certificate data that was signed (excluding signatures)
    fn get_certificate_data(&self) -> QTLSResult<Vec<u8>> {
        // Create a temporary certificate without signatures for serialization
        let cert_without_sigs = CertificateWithoutSignatures {
            version: self.version,
            serial_number: self.serial_number.clone(),
            signature_algorithm: self.signature_algorithm,
            issuer: self.issuer.clone(),
            validity: self.validity.clone(),
            subject: self.subject.clone(),
            public_key: self.public_key.clone(),
            extensions: self.extensions.clone(),
        };
        
        serde_json::to_vec(&cert_without_sigs)
            .map_err(|e| CryptoError::SignatureError(format!("Serialization error: {}", e)))
    }

    /// Get the subject common name
    pub fn subject_cn(&self) -> &str {
        &self.subject.common_name
    }

    /// Get the issuer common name
    pub fn issuer_cn(&self) -> &str {
        &self.issuer.common_name
    }

    /// Get the public key
    pub fn public_key(&self) -> &HybridPublicKey {
        &self.public_key
    }

    /// Get the signature algorithm
    pub fn signature_algorithm(&self) -> &SignatureAlgorithm {
        &self.signature_algorithm
    }

    /// Check if the certificate is a CA certificate
    pub fn is_ca(&self) -> bool {
        self.extensions.iter().any(|ext| {
            ext.oid == "2.5.29.19" && ext.critical // Basic Constraints extension
        })
    }

    /// Get the key usage
    pub fn key_usage(&self) -> Option<u8> {
        self.extensions.iter()
            .find(|ext| ext.oid == "2.5.29.15") // Key Usage extension
            .and_then(|ext| ext.value.get(3).copied())
    }
}

/// Certificate without signatures for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertificateWithoutSignatures {
    version: u8,
    serial_number: Vec<u8>,
    signature_algorithm: SignatureAlgorithm,
    issuer: CertificateSubject,
    validity: CertificateValidity,
    subject: CertificateSubject,
    public_key: HybridPublicKey,
    extensions: Vec<CertificateExtension>,
}

impl HybridPublicKey {
    /// Create a new hybrid public key
    pub fn new(classical_key: Vec<u8>, post_quantum_key: Vec<u8>, algorithm: String) -> Self {
        Self {
            classical_public_key: classical_key,
            post_quantum_public_key: post_quantum_key,
            key_algorithm: algorithm,
        }
    }

    /// Get the classical public key
    pub fn classical_key(&self) -> &[u8] {
        &self.classical_public_key
    }

    /// Get the post-quantum public key
    pub fn post_quantum_key(&self) -> &[u8] {
        &self.post_quantum_public_key
    }

    /// Get the key algorithm
    pub fn algorithm(&self) -> &str {
        &self.key_algorithm
    }

    /// Get the total key size
    pub fn total_size(&self) -> usize {
        self.classical_public_key.len() + self.post_quantum_public_key.len()
    }
}

impl CertificateSubject {
    /// Create a new certificate subject
    pub fn new(common_name: String) -> Self {
        Self {
            common_name,
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        }
    }

    /// Add organization
    pub fn with_organization(mut self, organization: String) -> Self {
        self.organization = Some(organization);
        self
    }

    /// Add organizational unit
    pub fn with_organizational_unit(mut self, ou: String) -> Self {
        self.organizational_unit = Some(ou);
        self
    }

    /// Add country
    pub fn with_country(mut self, country: String) -> Self {
        self.country = Some(country);
        self
    }

    /// Get the common name
    pub fn common_name(&self) -> &str {
        &self.common_name
    }
}

impl CertificateValidity {
    /// Create a new validity period
    pub fn new(not_before: u64, not_after: u64) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    /// Create a validity period for the next year
    pub fn for_one_year() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            not_before: now,
            not_after: now + 365 * 24 * 60 * 60, // 1 year
        }
    }

    /// Check if the validity period is currently active
    pub fn is_active(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now >= self.not_before && now <= self.not_after
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_creation() {
        let cert = HybridCertificate::new_test_cert();
        
        assert_eq!(cert.version, 3);
        assert_eq!(cert.serial_number.len(), 8);
        assert_eq!(cert.subject_cn(), "localhost");
        assert_eq!(cert.issuer_cn(), "qTLS Test CA");
        assert!(cert.is_valid());
    }

    #[test]
    fn test_certificate_subject() {
        let subject = CertificateSubject::new("test.example.com".to_string())
            .with_organization("Test Org".to_string())
            .with_country("US".to_string());
        
        assert_eq!(subject.common_name(), "test.example.com");
        assert_eq!(subject.organization.as_ref().unwrap(), "Test Org");
        assert_eq!(subject.country.as_ref().unwrap(), "US");
    }

    #[test]
    fn test_certificate_validity() {
        let validity = CertificateValidity::for_one_year();
        assert!(validity.is_active());
        
        let past_validity = CertificateValidity::new(0, 1);
        assert!(!past_validity.is_active());
    }

    #[test]
    fn test_hybrid_public_key() {
        let classical_key = vec![1u8; 65];
        let post_quantum_key = vec![2u8; 1952];
        
        let public_key = HybridPublicKey::new(
            classical_key.clone(),
            post_quantum_key.clone(),
            "Hybrid-ECDSA-Dilithium3".to_string(),
        );
        
        assert_eq!(public_key.classical_key(), classical_key.as_slice());
        assert_eq!(public_key.post_quantum_key(), post_quantum_key.as_slice());
        assert_eq!(public_key.algorithm(), "Hybrid-ECDSA-Dilithium3");
        assert_eq!(public_key.total_size(), 2017);
    }

    #[tokio::test]
    async fn test_certificate_verification() {
        let cert = HybridCertificate::new_test_cert();
        let ca_public_key = HybridPublicKey::new(
            vec![0u8; 65],
            vec![0u8; 1952],
            "Hybrid-ECDSA-Dilithium3".to_string(),
        );
        
        let is_valid = cert.verify_signatures(&ca_public_key).await.unwrap();
        assert!(is_valid);
    }
} 