# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-01-03

### Added
- **Parallel Scanning**: New `ParallelRecoveryScanner` for high-performance recovery
  - Multiple backend support for parallel queries
  - Connection pooling via `PooledBackend`
  - Configurable thread count
- **Descriptor Support**: Scan using output descriptors
  - Support for all descriptor types: pkh, wpkh, sh, wsh, tr
  - Taproot (tr()) descriptor support for P2TR addresses
  - Wildcard descriptor support for ranged scanning
- **Connection Pooling**: `PooledBackend` wrapper for efficient Electrum connections
  - Automatic connection management
  - Configurable pool size
- **Progress Reporting**: Enhanced progress callback for parallel scans
  - `ParallelScanProgress` with descriptor index, current index, found count
  - Real-time progress updates during scanning
- **Result Aggregation**: `RecoveryResult::merge()` for combining results
  - Aggregate results from multiple parallel scans
  - Preserves all UTXOs and addresses
- **New Configuration**: `ParallelScanConfig` for parallel scanning options
  - Thread count configuration
  - Gap limit and batch size settings

### Changed
- Bumped version to 0.2.0
- Added `rustywallet-descriptor` dependency for descriptor parsing
- Added `tokio` and `futures` dependencies for async parallel execution

## [0.1.0] - 2026-01-03

### Added
- Initial release
- Mnemonic-based wallet recovery
- Extended key (xpub/xprv) recovery
- Multi-path scanning: BIP44, BIP49, BIP84, BIP86
- Configurable gap limit and account gap limit
- Batch address queries via Electrum backend
- UTXO discovery with confirmation filtering
- Progress callback support
- JSON export for recovery results
- Summary report generation
