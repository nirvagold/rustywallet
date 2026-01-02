# Changelog

All notable changes to this project will be documented in this file.

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
