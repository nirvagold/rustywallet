# rustywallet-checker

[![Crates.io](https://img.shields.io/crates/v/rustywallet-checker.svg)](https://crates.io/crates/rustywallet-checker)
[![Documentation](https://docs.rs/rustywallet-checker/badge.svg)](https://docs.rs/rustywallet-checker)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/username/rustywallet-checker/workflows/CI/badge.svg)](https://github.com/username/rustywallet-checker/actions)

A fast, reliable Rust library for checking cryptocurrency wallet balances. Supports Bitcoin and Ethereum with automatic fallback between multiple API providers.

## Features

- **Bitcoin Balance Checking**: Support for all address types (Legacy, SegWit, Taproot)
- **Ethereum Balance Checking**: Native ETH balance queries
- **Async/Await Support**: Built with Tokio for high-performance async operations
- **Multiple API Providers**: Automatic fallback between providers for reliability
- **Rate Limit Handling**: Built-in retry logic and rate limit detection
- **Comprehensive Error Handling**: Detailed error types for different failure scenarios
- **Zero-Copy Parsing**: Efficient JSON parsing with minimal allocations
- **Type Safety**: Strong typing for addresses and balance amounts

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rustywallet-checker = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Quick Start

```rust
use rustywallet_checker::{check_btc_balance, check_eth_balance};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check Bitcoin balance
    let btc_balance = check_btc_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
    println!("BTC Balance: {} satoshis", btc_balance.balance);
    
    // Check Ethereum balance
    let eth_balance = check_eth_balance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").await?;
    println!("ETH Balance: {} ETH", eth_balance.balance_eth);
    
    Ok(())
}
```

## Bitcoin Balance Checking

### Supported Address Types

- **Legacy (P2PKH)**: Addresses starting with `1`
- **SegWit (P2WPKH)**: Addresses starting with `bc1q`
- **Taproot (P2TR)**: Addresses starting with `bc1p`

### Example

```rust
use rustywallet_checker::{check_btc_balance, BtcBalance};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let balance: BtcBalance = check_btc_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
    
    println!("Confirmed balance: {} satoshis", balance.balance);
    println!("Unconfirmed balance: {} satoshis", balance.unconfirmed);
    println!("Total received: {} satoshis", balance.total_received);
    println!("Transaction count: {}", balance.tx_count);
    
    Ok(())
}
```

### API Providers

- **Primary**: blockstream.info API
- **Fallback**: blockchain.info API

## Ethereum Balance Checking

### Example

```rust
use rustywallet_checker::{check_eth_balance, EthBalance};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let balance: EthBalance = check_eth_balance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").await?;
    
    println!("Balance in wei: {}", balance.balance_wei);
    println!("Balance in ETH: {}", balance.balance_eth);
    
    Ok(())
}
```

### API Providers

Multiple public Ethereum RPC endpoints with automatic failover:
- Cloudflare ETH Gateway
- Ankr Public RPC
- Public Node RPC

## Async Usage

All functions are async and return `Future`s. Use with any async runtime:

```rust
use rustywallet_checker::check_btc_balance;
use tokio;

// With Tokio
#[tokio::main]
async fn main() {
    let balance = check_btc_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await.unwrap();
    println!("Balance: {}", balance.balance);
}

// With async-std
use async_std::task;

fn main() {
    task::block_on(async {
        let balance = check_btc_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await.unwrap();
        println!("Balance: {}", balance.balance);
    });
}
```

## Error Handling

The library provides comprehensive error handling with the `CheckerError` enum:

```rust
use rustywallet_checker::{check_btc_balance, CheckerError};

match check_btc_balance("invalid-address").await {
    Ok(balance) => {
        println!("Balance: {} satoshis", balance.balance);
    }
    Err(CheckerError::InvalidAddress(addr)) => {
        eprintln!("Invalid address format: {}", addr);
    }
    Err(CheckerError::RateLimited) => {
        eprintln!("Rate limited by API provider, try again later");
    }
    Err(CheckerError::NetworkError(e)) => {
        eprintln!("Network error: {}", e);
    }
    Err(CheckerError::ApiError(msg)) => {
        eprintln!("API error: {}", msg);
    }
    Err(CheckerError::ParseError(e)) => {
        eprintln!("Failed to parse response: {}", e);
    }
}
```

### Error Types

- `InvalidAddress`: The provided address format is invalid
- `RateLimited`: API rate limit exceeded
- `NetworkError`: Network connectivity issues
- `ApiError`: API provider returned an error
- `ParseError`: Failed to parse API response

## API Reference

### Functions

#### `check_btc_balance(address: &str) -> Result<BtcBalance, CheckerError>`

Checks the balance of a Bitcoin address.

**Parameters:**
- `address`: Bitcoin address string (Legacy, SegWit, or Taproot)

**Returns:**
- `Ok(BtcBalance)`: Balance information
- `Err(CheckerError)`: Error details

#### `check_eth_balance(address: &str) -> Result<EthBalance, CheckerError>`

Checks the balance of an Ethereum address.

**Parameters:**
- `address`: Ethereum address string (0x prefixed)

**Returns:**
- `Ok(EthBalance)`: Balance information
- `Err(CheckerError)`: Error details

### Types

#### `BtcBalance`

```rust
pub struct BtcBalance {
    pub balance: u64,        // Confirmed balance in satoshis
    pub unconfirmed: u64,    // Unconfirmed balance in satoshis
    pub total_received: u64, // Total received in satoshis
    pub tx_count: u32,       // Number of transactions
}
```

#### `EthBalance`

```rust
pub struct EthBalance {
    pub balance_wei: String, // Balance in wei (as string to handle large numbers)
    pub balance_eth: f64,    // Balance in ETH (converted from wei)
}
```

#### `CheckerError`

```rust
pub enum CheckerError {
    InvalidAddress(String),
    RateLimited,
    NetworkError(String),
    ApiError(String),
    ParseError(String),
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.