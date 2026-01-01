# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2024-01-15

### Added
- Batch key generation iterator via `PrivateKey::batch_generate(count: usize)`
- Memory-efficient iterator-based key generation for high-volume operations
- Enhanced documentation with comprehensive examples and API reference
- Security notes and threat model documentation
- Additional badges for build status and code coverage

### Changed
- Updated README.md with comprehensive documentation sections
- Improved code examples with batch generation use cases

### Fixed
- Minor documentation formatting improvements

## [0.1.0] - 2024-01-01

### Added
- Initial release of rustywallet-keys
- Secure secp256k1 private key generation using CSPRNG
- Multiple import formats: hex, WIF, raw bytes
- Multiple export formats: hex, WIF, decimal, raw bytes
- Public key derivation with compressed and uncompressed formats
- Automatic memory zeroization for security
- Comprehensive key validation
- Support for Bitcoin mainnet and testnet networks
- MIT license

### Security
- Private keys automatically zeroized on drop
- Uses OS-level CSPRNG for random number generation
- Battle-tested secp256k1 cryptographic operations

[Unreleased]: https://github.com/nirvagold/rustywallet/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/nirvagold/rustywallet/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nirvagold/rustywallet/releases/tag/v0.1.0