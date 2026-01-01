# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-01-15

### Added
- Initial release of rustywallet umbrella crate
- Unified API for all wallet functionality through `prelude` module
- Re-exports of all sub-crates:
  - `rustywallet-keys` - Private and public key management (secp256k1)
  - `rustywallet-address` - Bitcoin and Ethereum address generation
  - `rustywallet-mnemonic` - BIP39 mnemonic phrase support
  - `rustywallet-hd` - BIP32/BIP44 hierarchical deterministic wallets
  - `rustywallet-signer` - ECDSA message signing and verification
  - `rustywallet-checker` - Address validation and format checking
  - `rustywallet-bloom` - Bloom filter implementation for efficient lookups
- Feature flags for selective compilation:
  - `keys` - Key management functionality
  - `address` - Address generation and validation
  - `mnemonic` - BIP39 mnemonic support
  - `hd` - HD wallet derivation
  - `signer` - Message signing capabilities
  - `checker` - Address validation utilities
  - `bloom` - Bloom filter implementation
  - `full` - All features (default)
- Comprehensive documentation with examples
- MIT license

[Unreleased]: https://github.com/username/rustywallet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/username/rustywallet/releases/tag/v0.1.0