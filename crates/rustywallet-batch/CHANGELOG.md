# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-03

### Added
- **Batch Address Generation** - Generate addresses in batch with parallel processing
  - `BatchAddressType` enum supporting P2PKH, P2WPKH, and P2TR address types
  - `BatchAddressGenerator` struct for efficient address generation
  - `generate_stream()` for memory-efficient streaming of key-address pairs
  - `generate_vec()` for collecting addresses into a vector
  - Support for both mainnet and testnet networks
  - Parallel processing enabled by default for maximum performance
  - Configurable chunk size for streaming operations
  - `AddressStream` iterator for on-demand address generation
- Property-based tests for batch address consistency (100+ iterations)

### Changed
- Updated to version 0.3.0
- Added `rustywallet-address` dependency for address generation
- Updated crate description to include address generation
- Updated prelude to export address generation types

## [0.2.0] - 2026-01-03

### Added
- **SIMD Optimization** - Platform-aware SIMD batch processing
  - `SimdBatchProcessor` for SIMD-optimized key generation
  - Auto-detection of AVX-512, AVX2, SSE2, and ARM NEON
  - Optimal batch sizing based on SIMD register width
  - `simd_hex_encode()` for fast hex conversion
  - `simd_validate_keys()` for batch validation
- **Memory-Mapped File Output** - Direct file writes without buffering
  - `MmapWriter` for memory-mapped file output
  - `MmapBatchGenerator` for combined generation and file output
  - `OutputFormat` enum: Raw (32 bytes), Hex (65 bytes), WIF
  - Automatic file truncation to actual size
- **Resume Capability** - Checkpoint and resume for long operations
  - `Checkpoint` struct for saving/loading progress
  - `ResumableBatchGenerator` with automatic checkpoint handling
  - `GenerationMode` for random and incremental modes
  - Configurable checkpoint intervals
  - Progress callbacks for monitoring

### Changed
- Updated to version 0.2.0
- Added `serde` and `serde_json` dependencies for checkpoint serialization
- Added `memmap2` dependency for memory-mapped files

## [0.1.3] - 2026-01-02

### Added
- Initial release
- `BatchGenerator` - fluent API for high-performance batch key generation
- `KeyStream` - memory-efficient streaming iterator for large batches
- `KeyScanner` - incremental key scanning using EC point addition
- `FastKeyGenerator` - ChaCha20 RNG-based fast generation (7M+ keys/sec)
- `IncrementalKeyGenerator` - sequential key generation for scanning
- `BatchConfig` with preset configurations:
  - `fast()` - optimized for speed (100K batch, 10K chunks)
  - `balanced()` - balanced performance (50K batch, 5K chunks)
  - `memory_efficient()` - low memory usage (10K batch, 100 chunks)
- Parallel processing support with rayon
- Bidirectional scanning (forward/backward)
- Comprehensive error handling with `BatchError`
- 18 property-based tests with 100+ iterations each
- Full compatibility with `rustywallet-keys` formats (hex, WIF, bytes)
