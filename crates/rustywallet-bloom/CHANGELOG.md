# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-04

### Added
- **Counting Bloom Filter** - Supports removal of items
  - `CountingBloomFilter` struct with 4-bit counters (0-15)
  - `insert()` method to increment counters
  - `try_insert()` method with overflow checking
  - `remove()` method to decrement counters with underflow protection
  - `contains()` method for membership testing
  - `count_estimate()` method to get approximate item count
  - `CountingBloomError` enum for error handling
- Property-based tests for counting bloom filter (Property 17)
- `proptest` dev-dependency for property testing

### Changed
- Updated to version 0.2.0
- Enhanced prelude with CountingBloomFilter exports
- Updated documentation with counting bloom filter examples

## [0.1.0] - 2024-01-15

### Added
- Initial release of rustywallet-bloom
- Core `BloomFilter` struct with optimized memory usage
- FNV-1a hash function with double hashing technique
- Automatic calculation of optimal parameters (bits and hash functions)
- `new()` constructor for creating filters with expected items and false positive rate
- `with_params()` constructor for custom parameter specification
- `insert()` method for adding items to the filter
- `contains()` method for membership testing
- `memory_usage()` method for checking memory consumption
- `clear()` method for resetting the filter
- Zero external dependencies - pure Rust implementation
- Memory efficiency: ~1.2 bytes per item at 1% FPR