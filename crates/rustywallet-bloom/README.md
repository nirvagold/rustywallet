# rustywallet-bloom

[![Crates.io](https://img.shields.io/crates/v/rustywallet-bloom.svg)](https://crates.io/crates/rustywallet-bloom)
[![Documentation](https://docs.rs/rustywallet-bloom/badge.svg)](https://docs.rs/rustywallet-bloom)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Fast and memory-efficient Bloom Filter implementations optimized for cryptocurrency address matching.

## Features

- **Standard Bloom Filter**: Memory efficient (~1.2 bytes per item at 1% FPR)
- **Counting Bloom Filter**: Supports removal of items (4x memory of standard)
- **Fast**: Uses FNV-1a hash with double hashing technique
- **No dependencies**: Pure Rust implementation
- **Optimized parameters**: Automatically calculates optimal bits and hash functions

## Installation

```toml
[dependencies]
rustywallet-bloom = "0.2"
```

## Standard Bloom Filter

For when you only need to add items (no removal):

```rust
use rustywallet_bloom::BloomFilter;

// Create filter for 1 million addresses with 1% false positive rate
let mut bloom = BloomFilter::new(1_000_000, 0.01);

// Insert Bitcoin addresses
bloom.insert("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
bloom.insert("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");

// Test membership
if bloom.contains("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") {
    println!("Address might be in the wallet!");
}

// Check memory usage
println!("Memory: {} bytes", bloom.memory_usage());
```

## Counting Bloom Filter

For when you need to add AND remove items:

```rust
use rustywallet_bloom::CountingBloomFilter;

let mut filter = CountingBloomFilter::new(100_000, 0.01);

// Insert items
filter.insert("address1");
filter.insert("address2");
assert!(filter.contains("address1"));

// Remove an item
filter.remove("address1").unwrap();
assert!(!filter.contains("address1"));
assert!(filter.contains("address2"));

// Insert same item multiple times
filter.insert("address3");
filter.insert("address3");
filter.insert("address3");

// Must remove same number of times
filter.remove("address3").unwrap();  // Still present
filter.remove("address3").unwrap();  // Still present
filter.remove("address3").unwrap();  // Now gone
assert!(!filter.contains("address3"));
```

## Memory Usage

| Items | FPR | Standard | Counting |
|-------|-----|----------|----------|
| 100K | 1% | ~120 KB | ~480 KB |
| 1M | 1% | ~1.2 MB | ~4.8 MB |
| 10M | 1% | ~12 MB | ~48 MB |

## False Positive Rates

| FPR | Use Case |
|-----|----------|
| 0.1% | High precision needed |
| 1% | **Recommended** for most cases |
| 5% | Memory constrained |

## API Reference

### BloomFilter

```rust
// Create new filter
let bloom = BloomFilter::new(expected_items, false_positive_rate);

// Insert and check
bloom.insert("item");
bloom.contains("item"); // true or false

// Utilities
bloom.memory_usage();   // bytes
bloom.num_bits();       // bit count
bloom.num_hashes();     // hash function count
bloom.clear();          // reset filter
```

### CountingBloomFilter

```rust
// Create new filter
let filter = CountingBloomFilter::new(expected_items, false_positive_rate);

// Insert (always succeeds)
filter.insert("item");

// Remove (returns Result)
filter.remove("item")?;  // Ok(()) or Err(CounterUnderflow)

// Check membership
filter.contains("item"); // true or false

// Get approximate count
filter.count_estimate("item"); // 0-15

// Utilities
filter.memory_usage();
filter.clear();
```

## License

MIT