# High-Performance Batch Generation

This guide covers high-speed key and address generation using `rustywallet-batch`.

## Overview

`rustywallet-batch` achieves 7M+ keys/second through:
- Parallel processing with Rayon
- Optimized secp256k1 operations
- Efficient memory management
- Streaming output for large datasets

## Basic Usage

### Generate Keys

```rust
use rustywallet_batch::{BatchGenerator, BatchConfig};

let config = BatchConfig::default();
let generator = BatchGenerator::new(config);

// Generate 1 million keys
let keys = generator.generate(1_000_000)?;

for key in keys {
    println!("Private: {}", key.private_key_hex());
    println!("Address: {}", key.address_p2wpkh());
}
```

### With Custom Configuration

```rust
use rustywallet_batch::{BatchConfig, AddressType, Network};

let config = BatchConfig {
    address_type: AddressType::P2WPKH,
    network: Network::Mainnet,
    threads: 8,                    // Number of threads
    chunk_size: 10_000,            // Keys per chunk
    include_uncompressed: false,   // Skip uncompressed addresses
};

let generator = BatchGenerator::new(config);
let keys = generator.generate(100_000)?;
```

## Streaming Generation

For very large datasets, use streaming to avoid memory issues:

```rust
use rustywallet_batch::{BatchGenerator, BatchConfig};
use std::fs::File;
use std::io::{BufWriter, Write};

let generator = BatchGenerator::new(BatchConfig::default());
let file = File::create("keys.txt")?;
let mut writer = BufWriter::new(file);

// Stream 10 million keys directly to file
generator.generate_stream(10_000_000, |key| {
    writeln!(writer, "{},{}", key.private_key_wif(), key.address_p2wpkh())?;
    Ok(())
})?;
```

## Address Types

Generate different address types:

```rust
use rustywallet_batch::AddressType;

// Legacy (P2PKH) - starts with 1
let config = BatchConfig {
    address_type: AddressType::P2PKH,
    ..Default::default()
};

// SegWit (P2WPKH) - starts with bc1q
let config = BatchConfig {
    address_type: AddressType::P2WPKH,
    ..Default::default()
};

// Taproot (P2TR) - starts with bc1p
let config = BatchConfig {
    address_type: AddressType::P2TR,
    ..Default::default()
};

// All types at once
let config = BatchConfig {
    address_type: AddressType::All,
    ..Default::default()
};
```

## Scanning with Bloom Filter

Combine with bloom filter for address matching:

```rust
use rustywallet_batch::{BatchGenerator, BatchConfig, Scanner};
use rustywallet_bloom::BloomFilter;

// Load target addresses into bloom filter
let mut bloom = BloomFilter::new(1_000_000, 0.0001);
bloom.insert("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
bloom.insert("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
// ... add more addresses

// Create scanner
let scanner = Scanner::new(bloom);
let generator = BatchGenerator::new(BatchConfig::default());

// Scan for matches
let matches = generator.scan(1_000_000, &scanner)?;

for m in matches {
    println!("FOUND: {} -> {}", m.address, m.private_key_wif());
}
```

## Progress Tracking

Track generation progress:

```rust
use rustywallet_batch::{BatchGenerator, BatchConfig};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

let counter = Arc::new(AtomicU64::new(0));
let counter_clone = counter.clone();

let generator = BatchGenerator::new(BatchConfig::default());

// Progress callback
generator.generate_with_progress(10_000_000, move |batch_count| {
    let total = counter_clone.fetch_add(batch_count as u64, Ordering::Relaxed);
    println!("Generated: {} keys", total + batch_count as u64);
})?;
```

## Performance Tuning

### Thread Count

```rust
// Auto-detect (recommended)
let config = BatchConfig {
    threads: 0,  // Uses all available cores
    ..Default::default()
};

// Manual setting
let config = BatchConfig {
    threads: num_cpus::get(),
    ..Default::default()
};
```

### Chunk Size

Larger chunks = better throughput, more memory:

```rust
// Small memory footprint
let config = BatchConfig {
    chunk_size: 1_000,
    ..Default::default()
};

// Maximum throughput
let config = BatchConfig {
    chunk_size: 100_000,
    ..Default::default()
};
```

### Benchmarking

```rust
use std::time::Instant;

let generator = BatchGenerator::new(BatchConfig::default());

let start = Instant::now();
let keys = generator.generate(1_000_000)?;
let elapsed = start.elapsed();

let rate = 1_000_000.0 / elapsed.as_secs_f64();
println!("Generated {} keys in {:?}", keys.len(), elapsed);
println!("Rate: {:.2} keys/second", rate);
```

## Output Formats

### CSV Output

```rust
use rustywallet_batch::{BatchGenerator, BatchConfig};
use std::fs::File;
use std::io::{BufWriter, Write};

let generator = BatchGenerator::new(BatchConfig::default());
let file = File::create("keys.csv")?;
let mut writer = BufWriter::new(file);

writeln!(writer, "private_key,address_p2pkh,address_p2wpkh,address_p2tr")?;

generator.generate_stream(100_000, |key| {
    writeln!(
        writer,
        "{},{},{},{}",
        key.private_key_wif(),
        key.address_p2pkh(),
        key.address_p2wpkh(),
        key.address_p2tr()
    )?;
    Ok(())
})?;
```

### JSON Lines Output

```rust
generator.generate_stream(100_000, |key| {
    let json = serde_json::json!({
        "wif": key.private_key_wif(),
        "hex": key.private_key_hex(),
        "addresses": {
            "p2pkh": key.address_p2pkh(),
            "p2wpkh": key.address_p2wpkh(),
            "p2tr": key.address_p2tr(),
        }
    });
    writeln!(writer, "{}", json)?;
    Ok(())
})?;
```

## Memory Management

### Estimate Memory Usage

```rust
// Each key uses approximately:
// - Private key: 32 bytes
// - Public key: 33 bytes (compressed)
// - Addresses: ~100 bytes (all types)
// Total: ~165 bytes per key

let count = 10_000_000;
let estimated_mb = (count * 165) / (1024 * 1024);
println!("Estimated memory: {} MB", estimated_mb);
```

### Low Memory Mode

```rust
// Use streaming for large datasets
generator.generate_stream(count, |key| {
    // Process immediately, don't store
    process_key(&key)?;
    Ok(())
})?;
```

## Error Handling

```rust
use rustywallet_batch::{BatchGenerator, BatchConfig, BatchError};

let generator = BatchGenerator::new(BatchConfig::default());

match generator.generate(1_000_000) {
    Ok(keys) => {
        println!("Generated {} keys", keys.len());
    }
    Err(BatchError::InvalidConfig(msg)) => {
        eprintln!("Configuration error: {}", msg);
    }
    Err(BatchError::IoError(e)) => {
        eprintln!("I/O error: {}", e);
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}
```

## Best Practices

1. **Use streaming for large datasets** - Avoid memory exhaustion
2. **Match thread count to CPU cores** - Optimal parallelization
3. **Use bloom filters for scanning** - O(1) lookup vs O(n)
4. **Buffer file writes** - Use `BufWriter` for performance
5. **Monitor memory usage** - Especially for 10M+ keys

## Performance Reference

Typical performance on modern hardware:

| CPU Cores | Keys/Second | 1M Keys Time |
|-----------|-------------|--------------|
| 4 | ~2M | 0.5s |
| 8 | ~4M | 0.25s |
| 16 | ~7M | 0.14s |
| 32 | ~12M | 0.08s |

## Next Steps

- [Vanity Addresses](./vanity-addresses.md)
- [Security Best Practices](./security.md)
- [Balance Checking](../guides/balance-checking.md)
