# rustywallet-vanity

High-performance vanity address generator for Bitcoin and Ethereum.

## Features

- **Prefix/Suffix/Contains Matching**: Find addresses with custom patterns
- **Multi-Pattern Search**: Search for multiple patterns simultaneously
- **Case-Insensitive Matching**: Find more matches faster
- **Difficulty Estimation**: Know how long a search will take
- **Progress Callbacks**: Track search progress in real-time
- **Parallel Processing**: Utilize all CPU cores
- **Multiple Address Types**: P2PKH, P2WPKH, P2TR (Taproot), Ethereum
- **Regex Patterns**: Full regex support for flexible matching
- **Distributed Search**: Multi-worker coordination for large searches

## Quick Start

```rust
use rustywallet_vanity::prelude::*;
use rustywallet_keys::prelude::Network;

// Search for an address starting with "1Love"
let result = VanityGenerator::new()
    .pattern("1Love")
    .search_parallel()
    .unwrap();

println!("Address: {}", result.address);
println!("Private Key: {}", result.private_key.to_wif(Network::Mainnet));
```

## Taproot (P2TR) Addresses

Generate vanity Taproot addresses starting with `bc1p`:

```rust
use rustywallet_vanity::prelude::*;

// Search for a Taproot address
let result = VanityGenerator::new()
    .pattern("bc1ptest")
    .address_type(AddressType::P2TR)
    .search_parallel()
    .unwrap();

println!("Taproot Address: {}", result.address);  // bc1ptest...

// Testnet Taproot (tb1p...)
let result = VanityGenerator::new()
    .pattern("tb1p")
    .address_type(AddressType::P2TR)
    .testnet()
    .search();
```

## Difficulty Estimation

```rust
use rustywallet_vanity::prelude::*;

let gen = VanityGenerator::new()
    .pattern("bc1ptest")
    .address_type(AddressType::P2TR);

for est in gen.estimate_difficulty() {
    println!("{}", est);
}
```

## Address Types

```rust
use rustywallet_vanity::prelude::*;

// Legacy P2PKH (1...)
let result = VanityGenerator::new()
    .pattern("1BTC")
    .address_type(AddressType::P2PKH)
    .search();

// Native SegWit P2WPKH (bc1q...)
let result = VanityGenerator::new()
    .pattern("bc1qtest")
    .address_type(AddressType::P2WPKH)
    .search();

// Taproot P2TR (bc1p...)
let result = VanityGenerator::new()
    .pattern("bc1ptest")
    .address_type(AddressType::P2TR)
    .search();

// Ethereum (0x...)
let result = VanityGenerator::new()
    .pattern("0xdead")
    .address_type(AddressType::Ethereum)
    .case_insensitive()
    .search();
```

## Regex Patterns

```rust
use rustywallet_vanity::prelude::*;

// Use regex for flexible matching
let result = VanityGenerator::new()
    .regex_pattern(r"^1[A-Z]{3}")  // 1 followed by 3 uppercase letters
    .search();

// Common pattern helpers
let pattern = CommonPatterns::repeated_char('A', 3);  // AAA
let pattern = CommonPatterns::numeric_sequence(4);    // 4 digits
```

## Distributed Search

```rust
use rustywallet_vanity::prelude::*;

// Run distributed search across multiple threads
let result = run_distributed_search(
    DistributedConfig::new()
        .pattern("1Love")
        .workers(4),
    |progress| println!("Progress: {:?}", progress),
)?;
```

## Performance

Leverages `rustywallet-batch` for high-speed key generation (1M+ keys/sec).

## License

MIT
