# rustywallet-electrum

Electrum protocol client for Bitcoin balance checking and UTXO fetching.

## Features

- **Balance checking** - Get confirmed and unconfirmed balance for any address
- **Batch queries** - Check multiple addresses efficiently in a single request
- **UTXO listing** - Get unspent outputs for transaction building
- **Transaction operations** - Get raw transactions and broadcast signed ones
- **TLS support** - Secure connections to Electrum servers
- **Certificate pinning** - Enhanced security with SSL certificate pinning
- **Server discovery** - DNS-based server discovery with latency testing
- **Connection pooling** - Efficient connection management for high throughput
- **Real-time subscriptions** - Address and header change notifications
- **Silent Payment scanning** - BIP352 Silent Payment detection via Electrum (v0.3)
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

## Server Discovery

Find the best server automatically:

```rust
use rustywallet_electrum::discovery::ServerDiscovery;

let discovery = ServerDiscovery::new();
let best = discovery.best_server().await?;
println!("Best server: {} ({}ms)", best.hostname, best.latency_ms.unwrap_or(0));

let client = ElectrumClient::with_config(best.to_ssl_config()).await?;
```

## Connection Pooling

Manage multiple connections efficiently:

```rust
use rustywallet_electrum::{ClientConfig, pool::{ConnectionPool, PoolConfig}};

let config = ClientConfig::ssl("electrum.blockstream.info");
let pool = ConnectionPool::new(config, PoolConfig::default());
pool.initialize().await?;

// Acquire connection from pool
let client = pool.acquire().await?;
let balance = client.get_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
// Connection automatically returned when dropped
```

## Batch Requests

Efficiently query multiple addresses:

```rust
use rustywallet_electrum::BatchRequest;

let response = BatchRequest::new(&client)
    .balances(["addr1", "addr2", "addr3"])
    .utxos(["addr1", "addr2"])
    .execute()
    .await?;

println!("Total confirmed: {} sats", response.total_confirmed());
println!("Funded addresses: {:?}", response.funded_addresses());
```

## Real-time Subscriptions

Monitor addresses for changes:

```rust
use rustywallet_electrum::{SubscriptionClient, ClientConfig};

let client = SubscriptionClient::new(ClientConfig::default()).await?;

// Subscribe to address
let status = client.subscribe_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;

// Subscribe to new blocks
let header = client.subscribe_headers().await?;
println!("Current height: {}", header.height);

// Listen for events
let mut rx = client.subscribe();
while let Ok(event) = rx.recv().await {
    match event {
        SubscriptionEvent::AddressStatus(e) => println!("Address {} changed", e.address),
        SubscriptionEvent::BlockHeader(e) => println!("New block: {}", e.height),
        _ => {}
    }
}
```

## Certificate Pinning

Enhanced security with certificate pinning:

```rust
use rustywallet_electrum::pinning::{CertFingerprint, PinningConfigBuilder};

let tls_config = PinningConfigBuilder::new()
    .pin_hex("electrum.blockstream.info", "abc123...")?
    .allow_unpinned(false)
    .build();
```

## Silent Payment Scanning (v0.3)

Scan for BIP352 Silent Payments using Electrum backend:

```rust
use rustywallet_electrum::{ElectrumClient, SilentPaymentScanner, SilentPaymentScanKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ElectrumClient::new("electrum.blockstream.info").await?;
    
    // Create scan key from your private keys
    let scan_key = SilentPaymentScanKey::new(
        scan_privkey,   // 32-byte scan private key
        spend_privkey,  // 32-byte spend private key
    )?;
    
    // Create scanner
    let mut scanner = SilentPaymentScanner::new(client, scan_key);
    
    // Add labels for multiple addresses (optional)
    scanner.add_labels(5); // Scan labels 0-4
    
    // Scan a transaction for payments
    let payments = scanner.scan_transaction("txid...", 800000).await?;
    
    for payment in payments {
        println!("Found payment: {} sats", payment.amount);
        println!("  Output: {}:{}", payment.txid, payment.output_index);
        println!("  Label: {:?}", payment.label);
        // Use payment.spending_key to spend the output
    }
    
    Ok(())
}
```

### Silent Payment Features

- **Transaction scanning** - Scan individual transactions for Silent Payments
- **Block scanning** - Scan entire blocks for payments
- **Address history scanning** - Scan all transactions for a P2TR address
- **Label support** - Detect payments to labeled addresses
- **Spending key derivation** - Get the private key to spend detected outputs

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

### Discovery (v0.2)
- `ServerDiscovery::new()` - Create discovery service
- `best_server()` - Find lowest latency server
- `reachable_servers()` - Get all reachable servers

### Pooling (v0.2)
- `ConnectionPool::new()` - Create connection pool
- `acquire()` - Get connection from pool
- `stats()` - Get pool statistics

### Subscriptions (v0.2)
- `subscribe_address(address)` - Subscribe to address changes
- `subscribe_headers()` - Subscribe to new blocks
- `subscribe()` - Get event receiver

### Batch (v0.2)
- `BatchRequest::new()` - Create batch builder
- `GapLimitScanner` - Scan with gap limit

### Silent Payments (v0.3)
- `SilentPaymentScanner::new()` - Create Silent Payment scanner
- `SilentPaymentScanKey::new()` - Create scan key from private keys
- `SilentPaymentLabel::new()` - Create label for scanning
- `scan_blocks()` - Scan block range for payments
- `scan_block()` - Scan single block
- `scan_transaction()` - Scan single transaction
- `scan_transactions()` - Scan multiple transactions
- `scan_address_history()` - Scan address transaction history
- `add_label()` / `add_labels()` - Add labels for scanning
- `DetectedPayment` - Detected payment with spending key

## License

MIT
