# rustywallet-recovery

Wallet recovery tools for Bitcoin - scan blockchain for funds from mnemonic or xpub with parallel scanning support.

## Features

- **Mnemonic Recovery**: Scan all standard derivation paths from a seed phrase
- **Extended Key Recovery**: Scan from xpub or xprv
- **Multi-Path Support**: BIP44, BIP49, BIP84, BIP86
- **Gap Limit**: Configurable gap limit for address scanning
- **UTXO Discovery**: Find all unspent outputs for spending
- **Progress Reporting**: Callback for scan progress updates
- **Parallel Scanning**: High-performance parallel scanning with multiple backends
- **Descriptor Support**: Scan using output descriptors including tr() (Taproot)
- **Connection Pooling**: Efficient Electrum connection management

## Installation

```toml
[dependencies]
rustywallet-recovery = "0.2"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Usage

### Basic Recovery from Mnemonic

```rust
use rustywallet_recovery::{RecoveryScanner, RecoveryConfig, ElectrumBackend};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to Electrum server
    let backend = ElectrumBackend::mainnet().await?;

    // Configure scan
    let config = RecoveryConfig::new()
        .with_gap_limit(20);

    // Create scanner from mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let scanner = RecoveryScanner::from_mnemonic(mnemonic, None, backend, config)?;

    // Run scan
    let result = scanner.scan().await?;

    println!("Total balance: {} sats", result.total_balance);
    println!("Addresses found: {}", result.addresses.len());
    println!("UTXOs found: {}", result.utxos.len());
    
    // Print summary
    println!("{}", result.summary());
    
    Ok(())
}
```

### Parallel Scanning with Multiple Backends

For high-performance recovery with multiple Electrum servers:

```rust
use rustywallet_recovery::{
    ParallelRecoveryScanner, ParallelScanConfig, PooledBackend
};
use rustywallet_descriptor::Descriptor;
use rustywallet_electrum::PoolConfig;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create multiple pooled backends for parallel queries
    let backend1 = Arc::new(PooledBackend::mainnet().await?);
    let backend2 = Arc::new(PooledBackend::from_server(
        "electrum2.example.com",
        PoolConfig::default()
    ).await?);
    let backends = vec![backend1, backend2];

    // Configure parallel scan
    let config = ParallelScanConfig::new()
        .with_thread_count(4)
        .with_gap_limit(20);

    // Create scanner
    let scanner = ParallelRecoveryScanner::from_mnemonic(
        "abandon abandon abandon...",
        None,
        backends,
        config
    )?;

    // Parse descriptors to scan
    let descriptors = vec![
        Descriptor::parse("wpkh(xpub.../0/*)")?,
        Descriptor::parse("tr(xpub.../0/*)")?,
    ];

    // Run parallel scan with progress callback
    let result = scanner.scan_parallel(&descriptors, |progress| {
        println!(
            "Descriptor {}: scanned {}, found {}",
            progress.descriptor_index,
            progress.total_scanned,
            progress.found_count
        );
    }).await?;

    println!("Total balance: {} sats", result.total_balance);
    Ok(())
}
```

### Parallel Scanning with Connection Pooling

```rust
use rustywallet_recovery::{ParallelRecoveryScanner, ParallelScanConfig};
use rustywallet_electrum::PoolConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create scanner with connection pooling
    let servers = &["electrum.blockstream.info", "electrum1.bluewallet.io"];
    let pool_config = PoolConfig::default()
        .min_connections(2)
        .max_connections(10);
    let scan_config = ParallelScanConfig::new()
        .with_thread_count(4);

    let scanner = ParallelRecoveryScanner::from_mnemonic_with_pool(
        "your mnemonic...",
        None,
        servers,
        pool_config,
        scan_config
    ).await?;

    // Scan standard BIP paths in parallel
    let result = scanner.scan_standard_paths(|progress| {
        println!("Progress: {} addresses scanned", progress.total_scanned);
    }).await?;

    println!("{}", result.summary());
    Ok(())
}
```

### Quick Scan (Smaller Gap Limit)

```rust
use rustywallet_recovery::{RecoveryScanner, RecoveryConfig, ElectrumBackend, ScanPath};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = RecoveryConfig::quick()
        .with_scan_paths(vec![ScanPath::Bip84]); // Only native segwit

    let backend = ElectrumBackend::mainnet().await?;
    let scanner = RecoveryScanner::from_mnemonic("your mnemonic...", None, backend, config)?;

    let result = scanner.scan().await?;
    println!("{}", result.summary());
    Ok(())
}
```

### Export Results to JSON

```rust
let result = scanner.scan().await?;
let json = result.to_json()?;
std::fs::write("recovery_result.json", json)?;
```

## Configuration Options

### RecoveryConfig (Sequential Scanning)

| Option | Default | Description |
|--------|---------|-------------|
| `gap_limit` | 20 | Consecutive empty addresses before stopping |
| `account_gap_limit` | 3 | Consecutive empty accounts before stopping |
| `batch_size` | 10 | Addresses to query in each batch |
| `scan_paths` | All | BIP44, BIP49, BIP84, BIP86 |
| `min_confirmations` | 1 | Minimum confirmations for UTXOs |
| `scan_change` | true | Scan internal (change) addresses |
| `testnet` | false | Use testnet derivation paths |

### ParallelScanConfig (Parallel Scanning)

| Option | Default | Description |
|--------|---------|-------------|
| `thread_count` | 4 | Number of parallel tasks |
| `gap_limit` | 20 | Consecutive empty addresses before stopping |
| `batch_size` | 10 | Addresses to query in each batch |
| `min_confirmations` | 1 | Minimum confirmations for UTXOs |
| `testnet` | false | Use testnet derivation paths |

## Scan Paths

| Path | Standard | Address Type |
|------|----------|--------------|
| BIP44 | m/44'/0'/account'/change/index | P2PKH (1...) |
| BIP49 | m/49'/0'/account'/change/index | P2SH-P2WPKH (3...) |
| BIP84 | m/84'/0'/account'/change/index | P2WPKH (bc1q...) |
| BIP86 | m/86'/0'/account'/change/index | P2TR (bc1p...) |

## Descriptor Support

The parallel scanner supports all descriptor types:

| Descriptor | Description |
|------------|-------------|
| `pkh(KEY)` | Pay to pubkey hash (P2PKH) |
| `wpkh(KEY)` | Pay to witness pubkey hash (P2WPKH) |
| `sh(wpkh(KEY))` | Nested SegWit (P2SH-P2WPKH) |
| `tr(KEY)` | Pay to Taproot (P2TR) |
| `multi(k,KEY,...)` | k-of-n multisig |

## License

MIT
