# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-01-03

### Added
- **Silent Payment Scanning** (`silent_payment` module)
  - `SilentPaymentScanner` for BIP352 Silent Payment detection via Electrum
  - `SilentPaymentScanKey` for managing scan and spend private keys
  - `SilentPaymentLabel` for labeled address scanning
  - `DetectedPayment` struct with txid, output index, amount, spending key, label, and block height
  - `scan_blocks()` for scanning block ranges
  - `scan_block()` for scanning individual blocks
  - `scan_transaction()` for scanning individual transactions
  - `scan_transactions()` for batch transaction scanning
  - `scan_address_history()` for scanning P2TR address history
  - Label management: `add_label()`, `add_labels()`, `has_label()`, `remove_label()`, `clear_labels()`
  - Helper methods on `DetectedPayment`: `outpoint()`, `is_labeled()`, `is_confirmed()`, `spending_key_hex()`
- Integration with `rustywallet-silent` for core Silent Payment cryptography
- Property-based tests for Silent Payment detection

### Changed
- Bumped version to 0.3.0

### Dependencies
- Added `rustywallet-silent` dependency
- Added `rustywallet-keys` dependency
- Added `secp256k1` dependency

## [0.2.0] - 2026-01-03

### Added
- **SSL Certificate Pinning** (`pinning` module)
  - `CertFingerprint` for SHA-256 certificate fingerprints
  - `CertPinStore` for managing pins per server
  - `PinningVerifier` for TLS verification with pinning
  - `PinningConfigBuilder` for easy configuration
- **Server Discovery** (`discovery` module)
  - `ServerDiscovery` for DNS-based server discovery
  - `DiscoveredServer` with latency testing
  - `DNS_SEEDS` for mainnet and testnet
  - `best_server()`, `reachable_servers()`, `random_server()` methods
- **Connection Pooling** (`pool` module)
  - `ConnectionPool` for managing multiple connections
  - `PoolConfig` for pool configuration
  - `PooledClient` for borrowed connections
  - `PoolStats` for monitoring pool health
  - Automatic connection validation and cleanup
- **Real-time Subscriptions** (`subscription` module)
  - `SubscriptionManager` for managing subscriptions
  - `SubscriptionClient` for easy subscription handling
  - `AddressWatcher` for monitoring specific addresses
  - Address status change notifications
  - Block header notifications
  - `SubscriptionEvent` enum for event handling
- **Batch Request Optimization** (`batch` module)
  - `BatchRequest` builder for multi-query batching
  - `BatchResponse` with aggregated results
  - `ParallelBatchExecutor` for large address sets
  - `GapLimitScanner` for HD wallet scanning
  - `total_confirmed()`, `total_utxo_value()`, `funded_addresses()` helpers
- New error types: `CertificatePinningFailed`, `NoServersAvailable`, `PoolExhausted`, `SubscriptionError`

## [0.1.0] - 2026-01-02

### Added
- Initial release
- `ElectrumClient` for Electrum protocol communication
- TCP and TLS/SSL connection support
- Balance checking (`get_balance`, `get_balances`)
- UTXO listing (`list_unspent`)
- Transaction operations (`get_transaction`, `broadcast`, `get_history`)
- Server methods (`server_version`, `ping`, `get_block_height`, `estimate_fee`)
- Address to scripthash conversion for all address types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- JSON-RPC batch requests for efficient multi-address queries
- Configurable timeout and retry settings
- Built-in list of public Electrum servers
