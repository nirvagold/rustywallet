# rustywallet-checker

Cryptocurrency balance checker for Bitcoin and Ethereum addresses.

## Installation

```toml
[dependencies]
rustywallet-checker = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Usage

### Check Bitcoin Balance

```rust
use rustywallet_checker::check_btc_balance;

#[tokio::main]
async fn main() {
    let balance = check_btc_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await.unwrap();
    
    println!("Balance: {} satoshis", balance.balance);
    println!("Unconfirmed: {} satoshis", balance.unconfirmed);
    println!("Total received: {} satoshis", balance.total_received);
    println!("Transactions: {}", balance.tx_count);
}
```

Supports all Bitcoin address types:
- Legacy (P2PKH) - starts with `1`
- SegWit (P2WPKH) - starts with `bc1q`
- Taproot (P2TR) - starts with `bc1p`

### Check Ethereum Balance

```rust
use rustywallet_checker::check_eth_balance;

#[tokio::main]
async fn main() {
    let balance = check_eth_balance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").await.unwrap();
    
    println!("Balance: {} wei", balance.balance_wei);
    println!("Balance: {} ETH", balance.balance_eth);
}
```

## API Providers

### Bitcoin
- Primary: blockstream.info
- Fallback: blockchain.info

### Ethereum
- Multiple public RPC endpoints with automatic fallback

## Error Handling

```rust
use rustywallet_checker::{check_btc_balance, CheckerError};

match check_btc_balance("invalid").await {
    Ok(balance) => println!("Balance: {}", balance.balance),
    Err(CheckerError::InvalidAddress(addr)) => println!("Invalid address: {}", addr),
    Err(CheckerError::RateLimited) => println!("Rate limited, try again later"),
    Err(e) => println!("Error: {}", e),
}
```

## License

MIT
