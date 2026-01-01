# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- `false_positive_rate()` method for getting actual FPR
- `hash_functions()` method for getting number of hash functions
- `bit_count()` method for getting total number of bits
- `clear()` method for resetting the filter
- `is_empty()` method for checking if filter is empty
- Utility functions for parameter calculation
- Zero external dependencies - pure Rust implementation
- Thread-safe read operations
- Optimized for cryptocurrency address filtering
- Comprehensive documentation and examples
- Memory efficiency: ~1.2 bytes per item at 1% FPR
- High performance: ~20M operations/second on modern hardware

### Performance
- Insert operations: O(k) complexity where k is number of hash functions
- Lookup operations: O(k) complexity
- Memory usage: O(m) where m is number of bits
- Only 2 hash computations per operation regardless of k value

### Documentation
- Complete API reference
- Usage examples for cryptocurrency wallets
- Performance benchmarks
- Memory usage tables
- False positive rate explanations
- Integration examples

[Unreleased]: https://github.com/rustywallet/rustywallet-bloom/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rustywallet/rustywallet-bloom/releases/tag/v0.1.0