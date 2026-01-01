# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-01-15

### Added
- Initial release of rustywallet-checker
- Bitcoin balance checking support for all address types:
  - Legacy (P2PKH) addresses starting with `1`
  - SegWit (P2WPKH) addresses starting with `bc1q`
  - Taproot (P2TR) addresses starting with `bc1p`
- Ethereum balance checking for standard addresses
- Async/await support with Tokio runtime
- Multiple API provider support with automatic fallback:
  - Bitcoin: blockstream.info (primary), blockchain.info (fallback)
  - Ethereum: Multiple public RPC endpoints
- Comprehensive error handling with `CheckerError` enum
- Rate limit detection and handling
- `BtcBalance` struct with confirmed/unconfirmed balances and transaction count
- `EthBalance` struct with wei and ETH denominations
- Zero-copy JSON parsing for optimal performance
- Full documentation and examples
- MIT license

### Security
- Input validation for cryptocurrency addresses
- Safe handling of large numbers in balance calculations
- Protection against malformed API responses

[Unreleased]: https://github.com/username/rustywallet-checker/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/username/rustywallet-checker/releases/tag/v0.1.0