# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-01-04

### Added
- **Descriptor-Based Address Derivation** (BIP380-386)
  - `Address::from_descriptor()` method to derive addresses from descriptor strings
  - `Address::from_descriptor_range()` for deriving multiple addresses
  - `AddressFromDescriptor` trait for descriptor-based derivation
  - `derive_address_from_descriptor()` function for direct derivation
  - `derive_addresses_from_descriptor()` for batch derivation
  - `get_descriptor_type()` to detect descriptor type
  - `descriptor_has_wildcard()` to check for ranged descriptors
  - `DescriptorType` enum for all supported descriptor types
- Support for all descriptor types:
  - `pkh()` - Pay to pubkey hash (P2PKH)
  - `wpkh()` - Pay to witness pubkey hash (P2WPKH)
  - `sh(wpkh())` - Nested SegWit (P2SH-P2WPKH)
  - `tr()` - Pay to Taproot (P2TR)
  - `wsh()` - Pay to witness script hash (P2WSH)
  - `multi()` and `sortedmulti()` - Multisig descriptors
- Wildcard descriptor support for ranged derivation
- Property-based tests for descriptor derivation consistency (Property 19)

### Changed
- Updated to version 0.3.0
- Added `rustywallet-descriptor` as dependency
- Updated prelude with descriptor exports
- Enhanced documentation with descriptor examples

## [0.2.0] - 2026-01-03

### Added
- **Silent Payments (BIP352)** support for enhanced privacy
  - `SilentPaymentAddress` struct with scan and spend public keys
  - Bech32m encoding with `sp1` (mainnet) and `tsp1` (testnet) prefixes
  - `SilentPaymentDeriver` for tweak computation and outpoint hashing
  - `SilentPaymentLabel` for labeled addresses (multiple addresses per wallet)
  - Parse and validate Silent Payment addresses from string
  - Single-key mode for simplified usage

### Changed
- Updated to version 0.2.0

## [0.1.0] - 2024-01-15

### Added
- Initial release of rustywallet-address
- Bitcoin Legacy (P2PKH) address support with Base58Check encoding
- Bitcoin SegWit (P2WPKH) address support with Bech32 encoding
- Bitcoin Taproot (P2TR) address support with Bech32m encoding
- Ethereum address support with EIP-55 checksum validation
- Multi-network support for Bitcoin (mainnet, testnet, regtest, signet)
- Comprehensive address validation with detailed error reporting
- Type-safe API preventing address format errors
- Zero-copy parsing for efficient address operations
- Serde support for serialization and deserialization
- Generic `Address` enum supporting all address types
- Network-specific validation methods
- Address type detection and classification
- Conversion utilities between address formats
- Complete documentation with examples
- Unit tests covering all address types and networks

### Security
- Secure address validation preventing malformed inputs
- Checksum verification for all supported address formats
- Network validation to prevent cross-network address usage

[Unreleased]: https://github.com/rustywallet/rustywallet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rustywallet/rustywallet/releases/tag/v0.1.0