//! SSL certificate pinning for enhanced security.
//!
//! This module provides certificate pinning functionality to prevent
//! man-in-the-middle attacks by verifying server certificates against
//! known fingerprints.

use std::collections::HashMap;
use std::sync::Arc;

use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    Certificate, ServerName,
};
use sha2::{Digest, Sha256};

use crate::error::{ElectrumError, Result};

/// Certificate fingerprint (SHA-256 hash of DER-encoded certificate).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertFingerprint([u8; 32]);

impl CertFingerprint {
    /// Create a fingerprint from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a fingerprint from hex string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)
            .map_err(|e| ElectrumError::TlsError(format!("Invalid hex fingerprint: {}", e)))?;
        
        if bytes.len() != 32 {
            return Err(ElectrumError::TlsError(format!(
                "Fingerprint must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Calculate fingerprint from a DER-encoded certificate.
    pub fn from_certificate(cert_der: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        Self(arr)
    }

    /// Get the fingerprint as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get the fingerprint as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for CertFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Certificate pin store for multiple servers.
#[derive(Debug, Clone, Default)]
pub struct CertPinStore {
    pins: HashMap<String, Vec<CertFingerprint>>,
}

impl CertPinStore {
    /// Create a new empty pin store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a certificate pin for a server.
    ///
    /// Multiple pins can be added for the same server (for certificate rotation).
    pub fn add_pin(&mut self, server: impl Into<String>, fingerprint: CertFingerprint) {
        self.pins
            .entry(server.into())
            .or_default()
            .push(fingerprint);
    }

    /// Add a certificate pin from hex string.
    pub fn add_pin_hex(&mut self, server: impl Into<String>, hex: &str) -> Result<()> {
        let fingerprint = CertFingerprint::from_hex(hex)?;
        self.add_pin(server, fingerprint);
        Ok(())
    }

    /// Check if a certificate is pinned for a server.
    pub fn verify(&self, server: &str, cert_der: &[u8]) -> bool {
        let fingerprint = CertFingerprint::from_certificate(cert_der);
        
        if let Some(pins) = self.pins.get(server) {
            pins.contains(&fingerprint)
        } else {
            // No pins for this server - allow any certificate
            true
        }
    }

    /// Get all pins for a server.
    pub fn get_pins(&self, server: &str) -> Option<&[CertFingerprint]> {
        self.pins.get(server).map(|v| v.as_slice())
    }

    /// Check if any pins are configured for a server.
    pub fn has_pins(&self, server: &str) -> bool {
        self.pins.contains_key(server)
    }

    /// Remove all pins for a server.
    pub fn remove_pins(&mut self, server: &str) {
        self.pins.remove(server);
    }

    /// Get the number of servers with pins.
    pub fn server_count(&self) -> usize {
        self.pins.len()
    }
}

/// Certificate verifier with pinning support.
pub struct PinningVerifier {
    pin_store: CertPinStore,
    allow_unpinned: bool,
}

impl PinningVerifier {
    /// Create a new pinning verifier.
    ///
    /// # Arguments
    /// * `pin_store` - Store containing certificate pins
    /// * `allow_unpinned` - If true, allow connections to servers without pins
    pub fn new(pin_store: CertPinStore, allow_unpinned: bool) -> Self {
        Self {
            pin_store,
            allow_unpinned,
        }
    }

    /// Create a verifier that requires all servers to have pins.
    pub fn strict(pin_store: CertPinStore) -> Self {
        Self::new(pin_store, false)
    }

    /// Create a verifier that allows unpinned servers.
    pub fn permissive(pin_store: CertPinStore) -> Self {
        Self::new(pin_store, true)
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let server = match server_name {
            ServerName::DnsName(name) => name.as_ref().to_string(),
            _ => return Err(rustls::Error::General("Invalid server name".into())),
        };

        // Check if server has pins
        if !self.pin_store.has_pins(&server) {
            if self.allow_unpinned {
                return Ok(ServerCertVerified::assertion());
            } else {
                return Err(rustls::Error::General(format!(
                    "No certificate pins for server: {}",
                    server
                )));
            }
        }

        // Verify against pins
        if self.pin_store.verify(&server, &end_entity.0) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "Certificate fingerprint mismatch for server: {}",
                server
            )))
        }
    }
}

/// Builder for creating TLS config with certificate pinning.
pub struct PinningConfigBuilder {
    pin_store: CertPinStore,
    allow_unpinned: bool,
}

impl PinningConfigBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            pin_store: CertPinStore::new(),
            allow_unpinned: true,
        }
    }

    /// Add a certificate pin.
    pub fn pin(mut self, server: impl Into<String>, fingerprint: CertFingerprint) -> Self {
        self.pin_store.add_pin(server, fingerprint);
        self
    }

    /// Add a certificate pin from hex.
    pub fn pin_hex(mut self, server: impl Into<String>, hex: &str) -> Result<Self> {
        self.pin_store.add_pin_hex(server, hex)?;
        Ok(self)
    }

    /// Set whether to allow connections to unpinned servers.
    pub fn allow_unpinned(mut self, allow: bool) -> Self {
        self.allow_unpinned = allow;
        self
    }

    /// Build the TLS configuration.
    pub fn build(self) -> rustls::ClientConfig {
        let verifier = PinningVerifier::new(self.pin_store, self.allow_unpinned);
        
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    }

    /// Get the pin store.
    pub fn pin_store(&self) -> &CertPinStore {
        &self.pin_store
    }
}

impl Default for PinningConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Known certificate fingerprints for popular Electrum servers.
pub mod known_pins {
    use super::CertFingerprint;

    /// Get fingerprint for electrum.blockstream.info (if known).
    /// Note: These fingerprints may change when certificates are rotated.
    pub fn blockstream() -> Option<CertFingerprint> {
        // Certificate fingerprints change over time
        // Users should verify and update these periodically
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_from_hex() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let fp = CertFingerprint::from_hex(hex).unwrap();
        assert_eq!(fp.to_hex(), hex);
    }

    #[test]
    fn test_fingerprint_from_certificate() {
        let cert_der = b"test certificate data";
        let fp = CertFingerprint::from_certificate(cert_der);
        assert_eq!(fp.as_bytes().len(), 32);
    }

    #[test]
    fn test_pin_store() {
        let mut store = CertPinStore::new();
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        
        store.add_pin("server.example.com", fp.clone());
        
        assert!(store.has_pins("server.example.com"));
        assert!(!store.has_pins("other.example.com"));
        
        let pins = store.get_pins("server.example.com").unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0], fp);
    }

    #[test]
    fn test_pin_store_verify() {
        let mut store = CertPinStore::new();
        let cert_der = b"test certificate";
        let fp = CertFingerprint::from_certificate(cert_der);
        
        store.add_pin("server.example.com", fp);
        
        assert!(store.verify("server.example.com", cert_der));
        assert!(!store.verify("server.example.com", b"wrong cert"));
        // Unpinned server allows any cert
        assert!(store.verify("unpinned.example.com", b"any cert"));
    }
}
