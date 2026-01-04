# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-04

### Added
- **Fluent Derivation Path Builder**
  - `DerivationPathBuilder` struct for fluent path construction
  - `hardened()` and `normal()` methods for adding components
  - `build()` method with validation
  - BIP presets: `bip44()`, `bip49()`, `bip84()`, `bip86()`
  - `DerivationPath::builder()` convenience method
  - Path component validation (index must be < 2^31)

- **SLIP39 Shamir Secret Sharing**
  - `Slip39` struct for basic threshold secret sharing
  - `split()` method to split secrets into shares
  - `combine()` method to recover secrets from shares
  - `Slip39Share` struct with checksum validation
  - GF(256) arithmetic for Shamir's Secret Sharing

- **Multi-Group SLIP39**
  - `Slip39MultiGroup` struct for advanced multi-group schemes
  - `GroupConfig` struct for per-group threshold configuration
  - Support for up to 16 groups with different thresholds
  - Hierarchical secret sharing (group threshold + member threshold)

- **Property-Based Tests**
  - Derivation path round-trip property test
  - SLIP39 split/combine round-trip property test
  - Multi-group SLIP39 round-trip property test

### Changed
- Updated version to 0.3.0
- Updated keywords to include "slip39"
- Enhanced documentation with SLIP39 examples

## [0.2.0] - 2026-01-03

### Added
- **BIP85 - Deterministic Entropy From BIP32 Keychains**
  - `Bip85` struct for entropy derivation
  - `derive_mnemonic_entropy()` - Derive child mnemonic entropy (12/15/18/21/24 words)
  - `derive_wif_entropy()` - Derive WIF private key entropy
  - `derive_xprv_entropy()` - Derive XPRV seed entropy (64 bytes)
  - `derive_hex_entropy()` - Derive arbitrary hex entropy (16-64 bytes)
  - `derive_pwd_base64()` - Derive password entropy
  - `derive_child_master()` - Derive independent child master key
  - Convenience functions: `derive_bip85_mnemonic()`, `derive_bip85_master()`
  - Application constants: `bip85_app` module
  - Language constants: `bip85_language` module
- New error types: `InvalidBip85WordCount`, `InvalidBip85ByteCount`

### Changed
- Updated description to include BIP85
- Updated keywords to include "bip85"

## [0.1.2] - 2026-01-02

### Fixed
- Minor documentation improvements

## [0.1.0] - 2024-01-15

### Added
- Initial release of rustywallet-hd
- BIP32 hierarchical deterministic key derivation implementation
- BIP44 standard derivation path support
- Master key generation from 64-byte seeds
- Child key derivation with normal and hardened derivation modes
- Extended private key (xprv/tprv) support with Base58Check encoding
- Extended public key (xpub/tpub) support with Base58Check encoding
- Public key derivation from extended public keys (non-hardened paths only)
- Network support for both mainnet and testnet
- Derivation path parsing from string format (e.g., "m/44'/0'/0'/0/0")
- Helper methods for common BIP44 paths
- Secure memory handling with automatic zeroization on drop
- Debug protection for sensitive data

[0.3.0]: https://github.com/nirvagold/rustywallet/compare/rustywallet-hd-v0.2.0...rustywallet-hd-v0.3.0
[0.2.0]: https://github.com/nirvagold/rustywallet/compare/rustywallet-hd-v0.1.2...rustywallet-hd-v0.2.0
[0.1.2]: https://github.com/nirvagold/rustywallet/compare/rustywallet-hd-v0.1.0...rustywallet-hd-v0.1.2
[0.1.0]: https://github.com/nirvagold/rustywallet/releases/tag/rustywallet-hd-v0.1.0
