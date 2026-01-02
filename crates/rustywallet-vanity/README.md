# rustywallet-vanity

High-performance vanity address generator for Bitcoin and Ethereum.

## Features

- **Prefix/Suffix/Contains Matching**: Find addresses with custom patterns
- **Multi-Pattern Search**: Search for multiple patterns simultaneously
- **Case-Insensitive Matching**: Find more matches faster
- **Difficulty Estimation**: Know how long a search will take
- **Progress Callbacks**: Track search progress in real-time
- **Parallel Processing**: Utilize all CPU cores
- **Multiple Address Types**: P2PKH, P2WPKH, P2TR, Ethereum

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

## Difficulty Estimation

```rust
use rustywallet_vanity::prelude::*;

let gen = VanityGenerator::new().pattern("1Love");
for est in gen.estimate_difficulty() {
    println!("{}", est);
}
```

## Address Types

```rust
use rustywallet_vanity::prelude::*;

// Legacy (1...)
let result = VanityGenerator::new()
    .pattern("1BTC")
    .address_type(AddressType::P2PKH)
    .search();

// SegWit (bc1q...)
let result = VanityGenerator::new()
    .pattern("bc1qtest")
    .address_type(AddressType::P2WPKH)
    .search();

// Ethereum (0x...)
let result = VanityGenerator::new()
    .pattern("0xdead")
    .address_type(AddressType::Ethereum)
    .case_insensitive()
    .search();
```

## Performance

Leverages `rustywallet-batch` for high-speed key generation (1M+ keys/sec).

## License

MIT
