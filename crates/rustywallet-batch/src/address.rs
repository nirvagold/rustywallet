//! Batch address generation.
//!
//! This module provides [`BatchAddressGenerator`] for generating large batches
//! of addresses efficiently with parallel processing and streaming output.
//!
//! ## Supported Address Types
//!
//! - **P2PKH** - Legacy Bitcoin addresses (1...)
//! - **P2WPKH** - SegWit Bitcoin addresses (bc1q...)
//! - **P2TR** - Taproot Bitcoin addresses (bc1p...)
//!
//! ## Example
//!
//! ```rust
//! use rustywallet_batch::address::{BatchAddressGenerator, BatchAddressType};
//! use rustywallet_address::Network;
//!
//! // Generate 1000 P2WPKH addresses
//! let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinMainnet);
//! let addresses: Vec<_> = generator.generate_stream(1000).take(10).collect();
//!
//! for (key, addr) in addresses {
//!     println!("{}: {}", key.to_hex(), addr);
//! }
//! ```

use crate::error::BatchError;
use rayon::prelude::*;
use rustywallet_address::{Network, P2PKHAddress, P2TRAddress, P2WPKHAddress};
use rustywallet_keys::private_key::PrivateKey;

/// Supported address types for batch generation.
///
/// This enum defines the Bitcoin address types that can be generated
/// in batch operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BatchAddressType {
    /// Pay-to-Public-Key-Hash (Legacy) - addresses starting with `1` (mainnet)
    P2PKH,
    /// Pay-to-Witness-Public-Key-Hash (SegWit) - addresses starting with `bc1q` (mainnet)
    P2WPKH,
    /// Pay-to-Taproot - addresses starting with `bc1p` (mainnet)
    P2TR,
}

impl BatchAddressType {
    /// Returns the address prefix for this type on mainnet.
    pub fn mainnet_prefix(&self) -> &'static str {
        match self {
            BatchAddressType::P2PKH => "1",
            BatchAddressType::P2WPKH => "bc1q",
            BatchAddressType::P2TR => "bc1p",
        }
    }

    /// Returns the address prefix for this type on testnet.
    pub fn testnet_prefix(&self) -> &'static str {
        match self {
            BatchAddressType::P2PKH => "m/n",
            BatchAddressType::P2WPKH => "tb1q",
            BatchAddressType::P2TR => "tb1p",
        }
    }
}

impl std::fmt::Display for BatchAddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchAddressType::P2PKH => write!(f, "P2PKH"),
            BatchAddressType::P2WPKH => write!(f, "P2WPKH"),
            BatchAddressType::P2TR => write!(f, "P2TR"),
        }
    }
}


/// Batch address generator for efficient address generation.
///
/// `BatchAddressGenerator` provides a high-performance API for generating
/// large batches of addresses with parallel processing and streaming output.
///
/// # Example
///
/// ```rust
/// use rustywallet_batch::address::{BatchAddressGenerator, BatchAddressType};
/// use rustywallet_address::Network;
///
/// // Create generator for P2WPKH addresses on mainnet
/// let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinMainnet);
///
/// // Generate 100 addresses as a vector
/// let addresses = generator.generate_vec(100).unwrap();
/// assert_eq!(addresses.len(), 100);
///
/// // Or stream addresses for memory efficiency
/// for (key, addr) in generator.generate_stream(1000).take(10) {
///     println!("{}: {}", key.to_hex(), addr);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct BatchAddressGenerator {
    address_type: BatchAddressType,
    network: Network,
    parallel: bool,
    chunk_size: usize,
}

impl BatchAddressGenerator {
    /// Create a new batch address generator.
    ///
    /// # Arguments
    ///
    /// * `address_type` - The type of addresses to generate (P2PKH, P2WPKH, P2TR)
    /// * `network` - The Bitcoin network (mainnet or testnet)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rustywallet_batch::address::{BatchAddressGenerator, BatchAddressType};
    /// use rustywallet_address::Network;
    ///
    /// let generator = BatchAddressGenerator::new(BatchAddressType::P2TR, Network::BitcoinMainnet);
    /// ```
    pub fn new(address_type: BatchAddressType, network: Network) -> Self {
        Self {
            address_type,
            network,
            parallel: true, // Default to parallel for performance
            chunk_size: 1000,
        }
    }

    /// Enable or disable parallel processing.
    ///
    /// Parallel processing is enabled by default for better performance.
    pub fn parallel(mut self, enabled: bool) -> Self {
        self.parallel = enabled;
        self
    }

    /// Set the chunk size for streaming operations.
    ///
    /// Larger chunks improve throughput but use more memory.
    /// Default is 1000.
    pub fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Get the address type.
    #[inline]
    pub fn address_type(&self) -> BatchAddressType {
        self.address_type
    }

    /// Get the network.
    #[inline]
    pub fn network(&self) -> Network {
        self.network
    }

    /// Generate addresses as a streaming iterator.
    ///
    /// This method returns an iterator that generates key-address pairs on-demand,
    /// allowing processing of millions of addresses without memory exhaustion.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of addresses to generate
    ///
    /// # Example
    ///
    /// ```rust
    /// use rustywallet_batch::address::{BatchAddressGenerator, BatchAddressType};
    /// use rustywallet_address::Network;
    ///
    /// let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinMainnet);
    ///
    /// // Stream 1 million addresses without storing all in memory
    /// for (key, addr) in generator.generate_stream(1_000_000).take(100) {
    ///     println!("{}", addr);
    /// }
    /// ```
    pub fn generate_stream(&self, count: usize) -> AddressStream {
        AddressStream::new(
            self.address_type,
            self.network,
            count,
            self.parallel,
            self.chunk_size,
        )
    }

    /// Generate addresses and collect them into a vector.
    ///
    /// This method generates all addresses and stores them in memory.
    /// For large batches, consider using `generate_stream()` for streaming.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of addresses to generate
    ///
    /// # Example
    ///
    /// ```rust
    /// use rustywallet_batch::address::{BatchAddressGenerator, BatchAddressType};
    /// use rustywallet_address::Network;
    ///
    /// let generator = BatchAddressGenerator::new(BatchAddressType::P2PKH, Network::BitcoinMainnet);
    /// let addresses = generator.generate_vec(1000).unwrap();
    ///
    /// for (key, addr) in &addresses {
    ///     assert!(addr.starts_with('1'));
    /// }
    /// ```
    pub fn generate_vec(&self, count: usize) -> Result<Vec<(PrivateKey, String)>, BatchError> {
        if !self.network.is_bitcoin() {
            return Err(BatchError::invalid_config(format!(
                "Network {} is not supported for Bitcoin address generation",
                self.network
            )));
        }

        if self.parallel {
            self.generate_parallel_vec(count)
        } else {
            self.generate_sequential_vec(count)
        }
    }

    /// Generate a single key-address pair.
    fn generate_single(&self) -> Result<(PrivateKey, String), BatchError> {
        let key = PrivateKey::random();
        let pubkey = key.public_key();

        let address = match self.address_type {
            BatchAddressType::P2PKH => {
                P2PKHAddress::from_public_key(&pubkey, self.network)
                    .map_err(|e| BatchError::generation_error(e.to_string()))?
                    .to_string()
            }
            BatchAddressType::P2WPKH => {
                P2WPKHAddress::from_public_key(&pubkey, self.network)
                    .map_err(|e| BatchError::generation_error(e.to_string()))?
                    .to_string()
            }
            BatchAddressType::P2TR => {
                P2TRAddress::from_public_key(&pubkey, self.network)
                    .map_err(|e| BatchError::generation_error(e.to_string()))?
                    .to_string()
            }
        };

        Ok((key, address))
    }

    /// Generate addresses sequentially.
    fn generate_sequential_vec(&self, count: usize) -> Result<Vec<(PrivateKey, String)>, BatchError> {
        (0..count)
            .map(|_| self.generate_single())
            .collect()
    }

    /// Generate addresses in parallel.
    fn generate_parallel_vec(&self, count: usize) -> Result<Vec<(PrivateKey, String)>, BatchError> {
        let address_type = self.address_type;
        let network = self.network;

        let results: Vec<_> = (0..count)
            .into_par_iter()
            .map(|_| generate_address_pair(address_type, network))
            .collect();

        // Check for errors
        results.into_iter().collect()
    }
}

/// Generate a single address pair (used in parallel context).
fn generate_address_pair(
    address_type: BatchAddressType,
    network: Network,
) -> Result<(PrivateKey, String), BatchError> {
    let key = PrivateKey::random();
    let pubkey = key.public_key();

    let address = match address_type {
        BatchAddressType::P2PKH => {
            P2PKHAddress::from_public_key(&pubkey, network)
                .map_err(|e| BatchError::generation_error(e.to_string()))?
                .to_string()
        }
        BatchAddressType::P2WPKH => {
            P2WPKHAddress::from_public_key(&pubkey, network)
                .map_err(|e| BatchError::generation_error(e.to_string()))?
                .to_string()
        }
        BatchAddressType::P2TR => {
            P2TRAddress::from_public_key(&pubkey, network)
                .map_err(|e| BatchError::generation_error(e.to_string()))?
                .to_string()
        }
    };

    Ok((key, address))
}


/// Streaming iterator for batch address generation.
///
/// `AddressStream` generates key-address pairs on-demand, allowing
/// processing of large batches without memory exhaustion.
pub struct AddressStream {
    address_type: BatchAddressType,
    network: Network,
    remaining: usize,
    parallel: bool,
    chunk_size: usize,
    current_chunk: std::vec::IntoIter<(PrivateKey, String)>,
}

impl AddressStream {
    /// Create a new address stream.
    fn new(
        address_type: BatchAddressType,
        network: Network,
        count: usize,
        parallel: bool,
        chunk_size: usize,
    ) -> Self {
        Self {
            address_type,
            network,
            remaining: count,
            parallel,
            chunk_size,
            current_chunk: Vec::new().into_iter(),
        }
    }

    /// Generate a chunk of addresses.
    fn generate_chunk(&mut self) -> Vec<(PrivateKey, String)> {
        let chunk_count = self.remaining.min(self.chunk_size);
        self.remaining -= chunk_count;

        let address_type = self.address_type;
        let network = self.network;

        if self.parallel {
            (0..chunk_count)
                .into_par_iter()
                .filter_map(|_| generate_address_pair(address_type, network).ok())
                .collect()
        } else {
            (0..chunk_count)
                .filter_map(|_| generate_address_pair(address_type, network).ok())
                .collect()
        }
    }

    /// Get the number of remaining addresses to generate.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.remaining + self.current_chunk.len()
    }
}

impl Iterator for AddressStream {
    type Item = (PrivateKey, String);

    fn next(&mut self) -> Option<Self::Item> {
        // Try to get from current chunk
        if let Some(pair) = self.current_chunk.next() {
            return Some(pair);
        }

        // Generate new chunk if there are remaining addresses
        if self.remaining > 0 {
            let chunk = self.generate_chunk();
            self.current_chunk = chunk.into_iter();
            self.current_chunk.next()
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for AddressStream {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_address_type_display() {
        assert_eq!(BatchAddressType::P2PKH.to_string(), "P2PKH");
        assert_eq!(BatchAddressType::P2WPKH.to_string(), "P2WPKH");
        assert_eq!(BatchAddressType::P2TR.to_string(), "P2TR");
    }

    #[test]
    fn test_batch_address_type_prefixes() {
        assert_eq!(BatchAddressType::P2PKH.mainnet_prefix(), "1");
        assert_eq!(BatchAddressType::P2WPKH.mainnet_prefix(), "bc1q");
        assert_eq!(BatchAddressType::P2TR.mainnet_prefix(), "bc1p");
    }

    #[test]
    fn test_generate_p2pkh_addresses() {
        let generator = BatchAddressGenerator::new(BatchAddressType::P2PKH, Network::BitcoinMainnet);
        let addresses = generator.generate_vec(10).unwrap();

        assert_eq!(addresses.len(), 10);
        for (_, addr) in &addresses {
            assert!(addr.starts_with('1'), "P2PKH address should start with '1': {}", addr);
        }
    }

    #[test]
    fn test_generate_p2wpkh_addresses() {
        let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinMainnet);
        let addresses = generator.generate_vec(10).unwrap();

        assert_eq!(addresses.len(), 10);
        for (_, addr) in &addresses {
            assert!(addr.starts_with("bc1q"), "P2WPKH address should start with 'bc1q': {}", addr);
        }
    }

    #[test]
    fn test_generate_p2tr_addresses() {
        let generator = BatchAddressGenerator::new(BatchAddressType::P2TR, Network::BitcoinMainnet);
        let addresses = generator.generate_vec(10).unwrap();

        assert_eq!(addresses.len(), 10);
        for (_, addr) in &addresses {
            assert!(addr.starts_with("bc1p"), "P2TR address should start with 'bc1p': {}", addr);
        }
    }

    #[test]
    fn test_generate_testnet_addresses() {
        let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinTestnet);
        let addresses = generator.generate_vec(10).unwrap();

        assert_eq!(addresses.len(), 10);
        for (_, addr) in &addresses {
            assert!(addr.starts_with("tb1q"), "Testnet P2WPKH should start with 'tb1q': {}", addr);
        }
    }

    #[test]
    fn test_generate_stream() {
        let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinMainnet);
        let stream = generator.generate_stream(100);

        let addresses: Vec<_> = stream.collect();
        assert_eq!(addresses.len(), 100);
    }

    #[test]
    fn test_generate_stream_parallel() {
        let generator = BatchAddressGenerator::new(BatchAddressType::P2TR, Network::BitcoinMainnet)
            .parallel(true)
            .chunk_size(50);

        let stream = generator.generate_stream(200);
        let addresses: Vec<_> = stream.collect();

        assert_eq!(addresses.len(), 200);
        for (_, addr) in &addresses {
            assert!(addr.starts_with("bc1p"));
        }
    }

    #[test]
    fn test_generate_sequential() {
        let generator = BatchAddressGenerator::new(BatchAddressType::P2PKH, Network::BitcoinMainnet)
            .parallel(false);

        let addresses = generator.generate_vec(50).unwrap();
        assert_eq!(addresses.len(), 50);
    }

    #[test]
    fn test_addresses_are_unique() {
        let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinMainnet);
        let addresses = generator.generate_vec(100).unwrap();

        let unique_addrs: std::collections::HashSet<_> = addresses.iter().map(|(_, a)| a.clone()).collect();
        assert_eq!(unique_addrs.len(), addresses.len(), "All addresses should be unique");
    }

    #[test]
    fn test_key_derives_to_address() {
        let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinMainnet);
        let addresses = generator.generate_vec(10).unwrap();

        for (key, addr) in addresses {
            // Manually derive address from key and verify it matches
            let pubkey = key.public_key();
            let derived_addr = P2WPKHAddress::from_public_key(&pubkey, Network::BitcoinMainnet)
                .unwrap()
                .to_string();
            assert_eq!(addr, derived_addr, "Address should match derived address");
        }
    }
}
