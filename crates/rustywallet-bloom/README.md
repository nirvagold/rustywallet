# rustywallet-bloom

[![Crates.io](https://img.shields.io/crates/v/rustywallet-bloom.svg)](https://crates.io/crates/rustywallet-bloom)
[![Documentation](https://docs.rs/rustywallet-bloom/badge.svg)](https://docs.rs/rustywallet-bloom)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/workflow/status/rustywallet/rustywallet-bloom/CI)](https://github.com/rustywallet/rustywallet-bloom/actions)

Fast and memory-efficient Bloom Filter implementation optimized for cryptocurrency address matching in rustywallet.

## Features

- **Memory efficient**: ~1.2 bytes per item at 1% false positive rate
- **Fast**: Uses FNV-1a hash with double hashing technique (only 2 hash computations regardless of k)
- **No dependencies**: Pure Rust implementation with zero external dependencies
- **Optimized parameters**: Automatically calculates optimal bits and hash functions
- **Thread-safe**: Safe for concurrent read operations
- **Cryptocurrency optimized**: Designed for Bitcoin and other cryptocurrency address filtering
- **Configurable**: Adjustable false positive rates from 0.001% to 10%

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rustywallet-bloom = "0.1.0"
```

## Quick Start

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
```

## Bloom Filter Creation

### Basic Creation

```rust
use rustywallet_bloom::BloomFilter;

// Create with expected items and false positive rate
let bloom = BloomFilter::new(1_000_000, 0.01); // 1M items, 1% FPR

// Create with custom parameters
let bloom = BloomFilter::with_params(1_000_000, 7, 9_585_059); // items, k, m
```

### Recommended Configurations

```rust
// High precision (0.1% FPR) - for critical applications
let precise = BloomFilter::new(1_000_000, 0.001);

// Balanced (1% FPR) - recommended for most use cases
let balanced = BloomFilter::new(1_000_000, 0.01);

// Memory optimized (5% FPR) - for memory-constrained environments
let compact = BloomFilter::new(1_000_000, 0.05);
```

## Membership Testing

```rust
let mut bloom = BloomFilter::new(100_000, 0.01);

// Insert addresses
bloom.insert("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
bloom.insert("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");

// Test membership
match bloom.contains("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") {
    true => println!("Address MIGHT be in wallet (needs verification)"),
    false => println!("Address is DEFINITELY NOT in wallet"),
}

// Batch testing
let addresses = vec![
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
];

for addr in addresses {
    if bloom.contains(addr) {
        println!("Potential match: {}", addr);
    }
}
```

## False Positive Rates

Understanding false positives is crucial for proper Bloom filter usage:

| False Positive Rate | Use Case | Memory Overhead |
|-------------------|----------|-----------------|
| 0.001% (0.00001) | Critical applications | ~2.4x |
| 0.01% (0.0001) | High precision needed | ~2.0x |
| 0.1% (0.001) | Balanced precision | ~1.7x |
| 1% (0.01) | **Recommended** | ~1.2x |
| 5% (0.05) | Memory constrained | ~0.8x |
| 10% (0.1) | Very memory constrained | ~0.6x |

```rust
// Calculate actual false positive rate
let bloom = BloomFilter::new(1_000_000, 0.01);
println!("Actual FPR: {:.4}%", bloom.false_positive_rate() * 100.0);
```

## Use Cases

### Address Matching in Cryptocurrency Wallets

```rust
use rustywallet_bloom::BloomFilter;

struct WalletFilter {
    bloom: BloomFilter,
    addresses: Vec<String>, // Backup for verification
}

impl WalletFilter {
    fn new(expected_addresses: usize) -> Self {
        Self {
            bloom: BloomFilter::new(expected_addresses, 0.01),
            addresses: Vec::new(),
        }
    }
    
    fn add_address(&mut self, address: &str) {
        self.bloom.insert(address);
        self.addresses.push(address.to_string());
    }
    
    fn might_own(&self, address: &str) -> bool {
        self.bloom.contains(address)
    }
    
    fn definitely_owns(&self, address: &str) -> bool {
        self.might_own(address) && self.addresses.contains(&address.to_string())
    }
}

// Usage
let mut wallet = WalletFilter::new(10_000);
wallet.add_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");

// Fast pre-filtering
if wallet.might_own("some_address") {
    // Only do expensive verification if bloom filter says "maybe"
    if wallet.definitely_owns("some_address") {
        println!("Address belongs to wallet!");
    }
}
```

### Transaction Filtering

```rust
// Filter relevant transactions from blockchain data
let mut relevant_addresses = BloomFilter::new(50_000, 0.01);

// Add all wallet addresses
for address in wallet_addresses {
    relevant_addresses.insert(&address);
}

// Process blockchain transactions
for transaction in blockchain_transactions {
    let mut is_relevant = false;
    
    // Check outputs
    for output in &transaction.outputs {
        if relevant_addresses.contains(&output.address) {
            is_relevant = true;
            break;
        }
    }
    
    if is_relevant {
        // Process this transaction (with verification)
        process_transaction(transaction);
    }
}
```

## Memory Usage

| Items | FPR | Memory | Bits per Item |
|-------|-----|--------|---------------|
| 100K | 1% | ~120 KB | ~9.6 |
| 1M | 1% | ~1.2 MB | ~9.6 |
| 10M | 1% | ~12 MB | ~9.6 |
| 37M | 1% | ~44 MB | ~9.6 |
| 100M | 1% | ~120 MB | ~9.6 |

```rust
// Check memory usage
let bloom = BloomFilter::new(1_000_000, 0.01);
println!("Memory usage: {} bytes", bloom.memory_usage());
println!("Memory usage: {:.2} MB", bloom.memory_usage() as f64 / 1_000_000.0);
```

## Performance

- **Insert**: O(k) where k = number of hash functions (typically 7 for 1% FPR)
- **Lookup**: O(k)
- **Space**: O(m) where m = number of bits
- **Hash computations**: Only 2 per operation (uses double hashing)

### Benchmarks

On a modern CPU (Intel i7-10700K):
- Insert: ~50ns per operation
- Lookup: ~45ns per operation
- Throughput: ~20M operations/second

## API Reference

### BloomFilter

```rust
impl BloomFilter {
    // Create new bloom filter
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self
    
    // Create with custom parameters
    pub fn with_params(expected_items: usize, k: usize, m: usize) -> Self
    
    // Insert item
    pub fn insert(&mut self, item: &str)
    
    // Check membership
    pub fn contains(&self, item: &str) -> bool
    
    // Get memory usage in bytes
    pub fn memory_usage(&self) -> usize
    
    // Get actual false positive rate
    pub fn false_positive_rate(&self) -> f64
    
    // Get number of hash functions
    pub fn hash_functions(&self) -> usize
    
    // Get number of bits
    pub fn bit_count(&self) -> usize
    
    // Clear all items
    pub fn clear(&mut self)
    
    // Check if empty
    pub fn is_empty(&self) -> bool
}
```

### Utility Functions

```rust
// Calculate optimal parameters
pub fn optimal_params(expected_items: usize, false_positive_rate: f64) -> (usize, usize)

// Calculate memory requirement
pub fn memory_required(expected_items: usize, false_positive_rate: f64) -> usize
```

## Examples

See the `examples/` directory for complete examples:
- `basic_usage.rs` - Simple address filtering
- `wallet_integration.rs` - Integration with wallet software
- `performance_test.rs` - Performance benchmarking

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.