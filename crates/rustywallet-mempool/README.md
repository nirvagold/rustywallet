# rustywallet-mempool

Mempool.space API client for fee estimation, address info, and transaction tracking.

## Features

- **Fee estimation** - Get recommended fee rates for different confirmation targets
- **Address info** - Get balance, transaction count, and UTXOs
- **Transaction tracking** - Get transaction details and confirmation status
- **Broadcasting** - Broadcast signed transactions to the network
- **Block info** - Get current block height and block details
- **Multi-network** - Support for mainnet, testnet, and signet

## Quick Start

```rust
use rustywallet_mempool::MempoolClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = MempoolClient::new();
    
    // Get fee estimates
    let fees = client.get_fees().await?;
    println!("Next block: {} sat/vB", fees.fastest_fee);
    println!("1 hour: {} sat/vB", fees.hour_fee);
    
    // Get address balance
    let info = client.get_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
    println!("Balance: {} sats", info.confirmed_balance());
    
    // Get UTXOs
    let utxos = client.get_utxos("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
    println!("UTXOs: {}", utxos.len());
    
    Ok(())
}
```

## Networks

```rust
use rustywallet_mempool::MempoolClient;

// Mainnet (default)
let mainnet = MempoolClient::new();

// Testnet
let testnet = MempoolClient::testnet();

// Signet
let signet = MempoolClient::signet();

// Custom endpoint
let custom = MempoolClient::with_base_url("https://my-mempool.example.com/api");
```

## API Reference

### Fee Estimation
- `get_fees()` - Get recommended fee rates (fastest, half_hour, hour, economy, minimum)

### Address Methods
- `get_address(address)` - Get address info (balance, tx count)
- `get_utxos(address)` - Get UTXOs for address
- `get_address_txs(address)` - Get transaction history

### Transaction Methods
- `get_tx(txid)` - Get transaction details
- `get_tx_hex(txid)` - Get raw transaction hex
- `broadcast(hex)` - Broadcast signed transaction

### Block Methods
- `get_block_height()` - Get current block height
- `get_block_hash(height)` - Get block hash by height
- `get_block(hash)` - Get block details

## License

MIT
