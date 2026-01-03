# rustywallet-batch

High-performance batch key and address generation for cryptocurrency wallets.

## Features

- **Batch Generation**: Generate millions of keys and addresses efficiently
- **Address Generation**: Support for P2PKH, P2WPKH, and P2TR address types
- **Parallel Processing**: Utilize all CPU cores with rayon
- **Memory Streaming**: Process unlimited keys/addresses without memory exhaustion
- **Incremental Scanning**: Scan key ranges using EC point addition
- **SIMD Optimization**: Platform-aware SIMD for faster processing
- **Memory-Mapped Output**: Direct file writes without buffering overhead
- **Resume Capability**: Checkpoint and resume long-running operations
- **Configurable**: Flexible configuration for different use cases

## Batch Address Generation

```rust
use rustywallet_batch::address::{BatchAddressGenerator, BatchAddressType};
use rustywallet_address::Network;

// Generate 1000 P2WPKH addresses in parallel
let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinMainnet);
let addresses = generator.generate_vec(1000).unwrap();

for (key, addr) in &addresses {
    println!("{}: {}", key.to_hex(), addr);
}
```

### Supported Address Types

- **P2PKH** - Legacy addresses (1...)
- **P2WPKH** - SegWit addresses (bc1q...)
- **P2TR** - Taproot addresses (bc1p...)

### Streaming Address Generation

```rust
use rustywallet_batch::address::{BatchAddressGenerator, BatchAddressType};
use rustywallet_address::Network;

// Stream 1 million addresses without storing all in memory
let generator = BatchAddressGenerator::new(BatchAddressType::P2TR, Network::BitcoinMainnet);

for (key, addr) in generator.generate_stream(1_000_000).take(100) {
    println!("{}", addr);
}
```

## Quick Start

```rust
use rustywallet_batch::prelude::*;

// Generate 1000 keys in parallel
let keys = BatchGenerator::new()
    .count(1000)
    .parallel()
    .generate_vec()
    .unwrap();

println!("Generated {} keys", keys.len());
```

## Memory-Mapped File Output

```rust,no_run
use rustywallet_batch::mmap::{MmapBatchGenerator, OutputFormat};

// Generate keys directly to file
let count = MmapBatchGenerator::new("keys.txt", 1_000_000)
    .format(OutputFormat::Hex)
    .parallel(true)
    .generate()
    .unwrap();

println!("Generated {} keys to file", count);
```

## Resumable Generation

```rust,no_run
use rustywallet_batch::checkpoint::ResumableBatchGenerator;

// Start or resume generation with checkpoints
let mut generator = ResumableBatchGenerator::new(
    "my-job",
    10_000_000,
    "keys.txt",
    "checkpoint.json",
);

generator.generate_with_progress(|progress| {
    println!("Progress: {:.1}%", progress);
}).unwrap();
```

## SIMD Optimization

```rust
use rustywallet_batch::simd::SimdBatchProcessor;

// Check SIMD availability
println!("SIMD: {} ({})", 
    SimdBatchProcessor::is_available(),
    SimdBatchProcessor::feature_name()
);

// Generate with SIMD optimization
let processor = SimdBatchProcessor::new();
let keys = processor.parallel_generate(10_000);
```

## Streaming Large Batches

```rust
use rustywallet_batch::prelude::*;

// Stream keys without storing all in memory
let stream = BatchGenerator::new()
    .count(1_000_000)
    .generate()
    .unwrap();

for key in stream.take(100) {
    println!("{}", key.unwrap().to_hex());
}
```

## Incremental Key Scanning

```rust
use rustywallet_batch::prelude::*;
use rustywallet_keys::prelude::PrivateKey;

// Scan from a base key
let base = PrivateKey::from_hex(
    "0000000000000000000000000000000000000000000000000000000000000001"
).unwrap();

let scanner = KeyScanner::new(base)
    .direction(ScanDirection::Forward);

for key in scanner.scan_range(10) {
    println!("{}", key.unwrap().to_hex());
}
```

## Configuration Presets

```rust
use rustywallet_batch::prelude::*;

// Fast mode - maximum speed
let config = BatchConfig::fast();

// Balanced mode - good speed with reasonable memory
let config = BatchConfig::balanced();

// Memory efficient - minimal memory usage
let config = BatchConfig::memory_efficient();
```

## Performance

Target performance: **1M+ keys per second** with parallel processing enabled.

## License

MIT
