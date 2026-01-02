# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
