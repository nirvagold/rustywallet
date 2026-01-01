# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Helper methods for common BIP44 paths:
  - `DerivationPath::bip44_bitcoin()` for Bitcoin paths
  - `DerivationPath::bip44_ethereum()` for Ethereum paths
- Secure memory handling with automatic zeroization on drop
- Debug protection for sensitive data (private keys, chain codes)
- Integration support with rustywallet-mnemonic crate
- Comprehensive error handling with custom error types
- No-std compatibility (with default features disabled)
- Full documentation with examples and API reference

### Security
- Private keys and chain codes are zeroized when dropped from memory
- Debug implementations mask sensitive data to prevent accidental exposure
- Hardened derivation prevents public key derivation attacks

[Unreleased]: https://github.com/rustywallet/rustywallet-hd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rustywallet/rustywallet-hd/releases/tag/v0.1.0