# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-01-15

### Added
- Initial release of rustywallet-signer
- Core ECDSA signing and verification functionality using secp256k1
- Bitcoin message signing compatible with BIP-137 standard
- Ethereum personal_sign implementation following EIP-191
- Recoverable signatures for public key recovery
- Deterministic signing using RFC 6979 nonce generation
- Signature verification against public keys and addresses
- Bitcoin message signing and verification functions
- Ethereum message signing and verification functions
- Public key recovery from signatures
- Ethereum address derivation from public keys
- EIP-55 checksum formatting for Ethereum addresses
- Comprehensive error handling with `SignerError` enum
- Zero-copy operations for efficient memory usage
- Constant-time cryptographic operations
- Cross-platform compatibility
- Complete API documentation
- Usage examples for all major features

### Security
- Implemented constant-time operations to prevent timing attacks
- No secret key material exposed in error messages
- Uses audited secp256k1 cryptographic library
- RFC 6979 deterministic nonce generation prevents nonce reuse vulnerabilities

[Unreleased]: https://github.com/rustywallet/rustywallet-signer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rustywallet/rustywallet-signer/releases/tag/v0.1.0