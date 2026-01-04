# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-04

### Added
- **Electrum Protocol Backend** - Direct blockchain queries without rate limits
  - `ElectrumChecker` struct for Electrum-based balance checking
  - `ElectrumConfig` for configuring server, port, SSL, timeout
  - `check_btc_balance_electrum()` convenience function
  - `check_btc_balances_batch()` for efficient batch queries
- **Connection Caching** - Reuse Electrum connections for better performance
  - `with_cache()` configuration option
  - `clear_cache()` and `has_cached_connection()` methods
- **Automatic Fallback** - Falls back to API providers if Electrum fails
  - `with_fallback()` configuration option
- Support for all Bitcoin address types via Electrum:
  - P2PKH, P2SH, P2WPKH, P2WSH, P2TR
- Address to scripthash conversion for Electrum protocol
- Bech32 address decoding

### Changed
- Updated to version 0.2.0
- Updated thiserror to v2.0
- Added sha2, hex, bs58 dependencies for address handling
- Enhanced prelude with Electrum exports

## [0.1.2] - 2026-01-02

### Fixed
- Minor bug fixes and improvements

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