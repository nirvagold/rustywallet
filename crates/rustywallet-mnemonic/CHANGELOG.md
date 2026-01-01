# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-01-15

### Added
- Initial release of rustywallet-mnemonic
- BIP39 mnemonic phrase generation with support for 12, 15, 18, 21, and 24-word mnemonics
- Cryptographically secure random mnemonic generation using `OsRng`
- Complete mnemonic validation including checksum verification and wordlist compliance
- PBKDF2-HMAC-SHA512 seed derivation with 2048 iterations as per BIP39 specification
- Optional passphrase support for enhanced security (BIP39 "25th word")
- Secure memory handling with automatic zeroization of sensitive data on drop
- Debug output masking to prevent accidental exposure of sensitive information
- English wordlist support (BIP39 standard 2048-word list)
- Integration with rustywallet-keys for seamless private key derivation
- Comprehensive error handling with detailed error types
- Full BIP39 specification compliance
- Memory-safe operations with constant-time checksum validation
- `Mnemonic` type with secure generation and parsing capabilities
- `Seed` type with hex encoding and secure memory management
- `WordCount` enum for specifying mnemonic lengths
- `MnemonicError` enum for detailed error reporting

### Security
- All entropy and seed bytes are automatically zeroized on drop
- Uses cryptographically secure random number generation
- Implements constant-time operations for security-critical comparisons
- Debug trait implementation masks sensitive data to prevent accidental logging

[Unreleased]: https://github.com/rustywallet/rustywallet-mnemonic/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rustywallet/rustywallet-mnemonic/releases/tag/v0.1.0