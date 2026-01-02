# Balance Checking Guide

This guide covers different methods to check Bitcoin balances and fetch UTXOs.

## Methods Comparison

| Method | Rate Limits | Speed | Best For |
|--------|-------------|-------|----------|
| Electrum | None! | Fast | High-volume checking |
| Mempool.space | Yes | Medium | Fee estimates, explorer |
| Public APIs | Yes | Slow | Simple queries |

## Electrum Protocol (Recommended)

The Electrum protocol connects directly to Electrum servers with **no rate limits**.

### Setup

```rust
use rustywallet_electrum::{ElectrumClient, Network};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to server (SSL on port 50002)
    let client = ElectrumClient::connect(
        "electrum.blockstream.info:50002",
        Network::Mainnet
    ).await?;
    
    println!("Connected!");
    Ok(())
}
```

### Public Servers

**Mainnet:**
- `electrum.blockstream.info:50002`
- `electrum.emzy.de:50002`
- `electrum.bitaroo.net:50002`

**Testnet:**
- `electrum.blockstream.info:60002`
- `testnet.aranguren.org:51002`

### Check Single Balance

```rust
let balance = client.get_balance("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").await?;

println!("Confirmed: {} sats", balance.confirmed);
println!("Unconfirmed: {} sats", balance.unconfirmed);
println!("Total: {} sats", balance.confirmed + balance.unconfirmed);
```

### Batch Balance Check

Check thousands of addresses efficiently:

```rust
let addresses = vec![
    "bc1q...",
    "bc1q...",
    "bc1q...",
    // ... thousands more
];

let balances = client.get_balances(&addresses).await?;

for (addr, balance) in addresses.iter().zip(balances.iter()) {
    if balance.confirmed > 0 {
        println!("{}: {} sats", addr, balance.confirmed);
    }
}
```

### Get UTXOs

```rust
let utxos = client.get_utxos("bc1q...").await?;

println!("Found {} UTXOs", utxos.len());
for utxo in &utxos {
    println!("  TXID: {}", hex::encode(&utxo.txid));
    println!("  Vout: {}", utxo.vout);
    println!("  Value: {} sats", utxo.value);
    println!("  ---");
}
```

### Get Transaction History

```rust
let history = client.get_history("bc1q...").await?;

println!("Transaction history:");
for tx in &history {
    println!("  TXID: {}", tx.txid);
    println!("  Height: {}", tx.height);  // 0 = unconfirmed
}
```

### Broadcast Transaction

```rust
let tx_hex = "0200000001...";  // Your signed transaction
let txid = client.broadcast(tx_hex).await?;
println!("Broadcast! TXID: {}", txid);
```

## Mempool.space API

Good for fee estimates and block explorer data.

### Setup

```rust
use rustywallet_mempool::MempoolClient;

let client = MempoolClient::new();  // Mainnet
// or
let client = MempoolClient::testnet();
```

### Fee Estimates

```rust
let fees = client.get_fee_estimates().await?;

println!("Fee estimates (sat/vB):");
println!("  Fastest (next block): {}", fees.fastest_fee);
println!("  Half hour (~3 blocks): {}", fees.half_hour_fee);
println!("  Hour (~6 blocks): {}", fees.hour_fee);
println!("  Economy: {}", fees.economy_fee);
println!("  Minimum: {}", fees.minimum_fee);
```

### Address Info

```rust
let info = client.get_address("bc1q...").await?;

println!("Address stats:");
println!("  Funded: {} sats", info.chain_stats.funded_txo_sum);
println!("  Spent: {} sats", info.chain_stats.spent_txo_sum);
println!("  Balance: {} sats", 
    info.chain_stats.funded_txo_sum - info.chain_stats.spent_txo_sum);
println!("  TX count: {}", info.chain_stats.tx_count);
```

### Transaction Details

```rust
let tx = client.get_transaction("txid...").await?;

println!("Transaction:");
println!("  Confirmed: {}", tx.status.confirmed);
println!("  Block height: {:?}", tx.status.block_height);
println!("  Fee: {} sats", tx.fee);
```

### Broadcast

```rust
let txid = client.broadcast("0200000001...").await?;
println!("Broadcast! TXID: {}", txid);
```

## High-Volume Scanning

For scanning millions of addresses:

```rust
use rustywallet_batch::FastKeyGenerator;
use rustywallet_address::prelude::*;
use rustywallet_electrum::{ElectrumClient, Network};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ElectrumClient::connect(
        "electrum.blockstream.info:50002",
        Network::Mainnet
    ).await?;
    
    let generator = FastKeyGenerator::new();
    let batch_size = 100;
    
    let mut addresses: Vec<String> = Vec::new();
    
    for key in generator.take(1000) {
        let addr = Address::p2wpkh(&key.public_key(), Network::Mainnet)?
            .to_string();
        addresses.push(addr);
        
        // Check in batches
        if addresses.len() >= batch_size {
            let balances = client.get_balances(&addresses).await?;
            
            for (addr, bal) in addresses.iter().zip(balances.iter()) {
                if bal.confirmed > 0 {
                    println!("FOUND: {} has {} sats!", addr, bal.confirmed);
                }
            }
            
            addresses.clear();
        }
    }
    
    Ok(())
}
```

## Error Handling

```rust
use rustywallet_electrum::ElectrumError;

match client.get_balance("bc1q...").await {
    Ok(balance) => {
        println!("Balance: {}", balance.confirmed);
    }
    Err(ElectrumError::ConnectionFailed(e)) => {
        eprintln!("Connection failed: {}", e);
        // Try another server
    }
    Err(ElectrumError::InvalidAddress(addr)) => {
        eprintln!("Invalid address: {}", addr);
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}
```

## Caching Strategies

### Simple Cache

```rust
use std::collections::HashMap;

struct BalanceCache {
    cache: HashMap<String, u64>,
}

impl BalanceCache {
    fn new() -> Self {
        Self { cache: HashMap::new() }
    }
    
    async fn get_balance(
        &mut self,
        client: &ElectrumClient,
        address: &str,
    ) -> Result<u64, Error> {
        if let Some(&balance) = self.cache.get(address) {
            return Ok(balance);
        }
        
        let balance = client.get_balance(address).await?;
        self.cache.insert(address.to_string(), balance.confirmed);
        Ok(balance.confirmed)
    }
}
```

### TTL Cache

```rust
use std::time::{Duration, Instant};

struct CachedBalance {
    balance: u64,
    fetched_at: Instant,
}

struct BalanceCache {
    cache: HashMap<String, CachedBalance>,
    ttl: Duration,
}

impl BalanceCache {
    fn new(ttl_seconds: u64) -> Self {
        Self {
            cache: HashMap::new(),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }
    
    fn is_valid(&self, entry: &CachedBalance) -> bool {
        entry.fetched_at.elapsed() < self.ttl
    }
}
```

## Best Practices

1. **Use Electrum for high volume** - No rate limits
2. **Batch requests** - More efficient than individual calls
3. **Handle connection errors** - Servers can go down
4. **Cache results** - Reduce unnecessary requests
5. **Use multiple servers** - Fallback if one fails
6. **Verify with multiple sources** - For large amounts

## Next Steps

- [Transaction Building](./transactions.md)
- [HD Wallets](./hd-wallets.md)
- [High-Performance Generation](../advanced/batch-generation.md)
