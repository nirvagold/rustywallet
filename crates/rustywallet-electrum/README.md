# rustywallet-electrum

Electrum protocol client for Bitcoin balance checking and UTXO fetching.

## Features

- **Balance checking** - Get confirmed and unconfirmed balance for any address
- **Batch queries** - Check multiple addresses efficiently in a single request
- **UTXO listing** - Get unspent outputs for transaction building
- **Transaction operations** - Get raw transactions and broadcast signed ones
- **TLS support** - Secure connections to Electrum servers
- **No rate limits** - Unlike public APIs, Electrum has no rate limiting

## Quick Start

```rust
use rustywallet_electrum::{ElectrumClient, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to a public Electrum server
    let client = ElectrumClient::new("electrum.blockstream.info").await?;
    
    // Check balance for an address
    let balance = client.get_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
    println!("Confirmed: {} sats", balance.confirmed);
    println!("Unconfirmed: {} sats", balance.unconfirmed);
    
    // Batch check multiple addresses
    let addresses = vec![
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    ];
    let balances = client.get_balances(&addresses).await?;
    
    Ok(())
}
```

## Address Support

All Bitcoin address types are supported:
- P2PKH (1...)
- P2SH (3...)
- P2WPKH (bc1q...)
- P2WSH (bc1q... longer)
- P2TR (bc1p...)

## Custom Configuration

```rust
use rustywallet_electrum::ClientConfig;
use std::time::Duration;

let config = ClientConfig::ssl("electrum.blockstream.info")
    .with_port(50002)
    .with_timeout(Duration::from_secs(60))
    .with_retry(5, Duration::from_secs(2));

let client = ElectrumClient::with_config(config).await?;
```

## Public Servers

Built-in list of public Electrum servers:
- `electrum.blockstream.info:50002` (SSL)
- `electrum1.bluewallet.io:443` (SSL)
- `bitcoin.aranguren.org:50002` (SSL)

## API Reference

### Balance Methods
- `get_balance(address)` - Get balance for single address
- `get_balances(addresses)` - Batch balance check

### UTXO Methods
- `list_unspent(address)` - List UTXOs for address

### Transaction Methods
- `get_transaction(txid)` - Get raw transaction
- `broadcast(raw_tx)` - Broadcast signed transaction
- `get_history(address)` - Get transaction history

### Server Methods
- `server_version()` - Get server version
- `ping()` - Check connection
- `get_block_height()` - Get current block height
- `estimate_fee(blocks)` - Estimate fee rate

## License

MIT
