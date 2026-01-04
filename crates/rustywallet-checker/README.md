# rustywallet-checker

[![Crates.io](https://img.shields.io/crates/v/rustywallet-checker.svg)](https://crates.io/crates/rustywallet-checker)
[![Documentation](https://docs.rs/rustywallet-checker/badge.svg)](https://docs.rs/rustywallet-checker)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A fast, reliable Rust library for checking cryptocurrency wallet balances. Supports Bitcoin and Ethereum with Electrum protocol backend and automatic fallback between multiple API providers.

## Features

- **Bitcoin Balance Checking**: Support for all address types (Legacy, SegWit, Taproot)
- **Ethereum Balance Checking**: Native ETH balance queries
- **Electrum Protocol Backend**: Direct blockchain queries without rate limits
- **Batch Balance Checking**: Check multiple addresses efficiently
- **Connection Caching**: Reuse connections for better performance
- **Automatic Fallback**: Falls back to API providers if Electrum fails
- **Async/Await Support**: Built with Tokio for high-performance async operations
- **Multiple API Providers**: Automatic fallback between providers for reliability
- **Rate Limit Handling**: Built-in retry logic and rate limit detection

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rustywallet-checker = "0.2"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Quick Start

```rust
use rustywallet_checker::{check_btc_balance, check_eth_balance};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check Bitcoin balance (uses API providers)
    let btc_balance = check_btc_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
    println!("BTC Balance: {} satoshis", btc_balance.balance);
    
    // Check Ethereum balance
    let eth_balance = check_eth_balance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").await?;
    println!("ETH Balance: {} ETH", eth_balance.balance_eth);
    
    Ok(())
}
```

## Electrum Backend

Use the Electrum protocol for direct blockchain queries without rate limits:

```rust
use rustywallet_checker::electrum::{ElectrumChecker, ElectrumConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create checker with custom config
    let config = ElectrumConfig::new("electrum.blockstream.info")
        .with_port(50002)
        .with_ssl(true)
        .with_cache(true)
        .with_fallback(true);  // Fall back to API if Electrum fails
    
    let checker = ElectrumChecker::with_config(config);
    
    // Check single address
    let balance = checker.check_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
    println!("Balance: {} satoshis", balance.balance);
    
    Ok(())
}
```

## Batch Balance Checking

Check multiple addresses efficiently in a single request:

```rust
use rustywallet_checker::electrum::check_btc_balances_batch;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addresses = vec![
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    ];
    
    let balances = check_btc_balances_batch(&addresses).await?;
    
    for balance in balances {
        println!("{}: {} satoshis", balance.address, balance.balance);
    }
    
    Ok(())
}
```

## Configuration Options

```rust
use rustywallet_checker::electrum::ElectrumConfig;
use std::time::Duration;

let config = ElectrumConfig::new("electrum.blockstream.info")
    .with_port(50002)           // Server port (default: 50002)
    .with_ssl(true)             // Use SSL/TLS (default: true)
    .with_timeout(Duration::from_secs(30))  // Connection timeout
    .with_cache(true)           // Enable connection caching
    .with_fallback(true);       // Fall back to API on failure
```

## API Providers

### Bitcoin
- **Electrum**: Direct protocol connection (no rate limits)
- **Primary API**: blockstream.info (supports all address types)
- **Fallback API**: blockchain.info (legacy addresses only)

### Ethereum
- Multiple public RPC endpoints with automatic failover

## Error Handling

```rust
use rustywallet_checker::{check_btc_balance, CheckerError};

match check_btc_balance("invalid-address").await {
    Ok(balance) => println!("Balance: {} satoshis", balance.balance),
    Err(CheckerError::InvalidAddress(addr)) => eprintln!("Invalid address: {}", addr),
    Err(CheckerError::RateLimited) => eprintln!("Rate limited, try again later"),
    Err(CheckerError::Network(e)) => eprintln!("Network error: {}", e),
    Err(CheckerError::ApiError(msg)) => eprintln!("API error: {}", msg),
    Err(CheckerError::ParseError(e)) => eprintln!("Parse error: {}", e),
}
```

## License

MIT