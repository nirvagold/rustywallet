# rustywallet-recovery

Wallet recovery tools for Bitcoin - scan blockchain for funds from mnemonic or xpub.

## Features

- **Mnemonic Recovery**: Scan all standard derivation paths from a seed phrase
- **Extended Key Recovery**: Scan from xpub or xprv
- **Multi-Path Support**: BIP44, BIP49, BIP84, BIP86
- **Gap Limit**: Configurable gap limit for address scanning
- **UTXO Discovery**: Find all unspent outputs for spending
- **Progress Reporting**: Callback for scan progress updates

## Installation

```toml
[dependencies]
rustywallet-recovery = "0.1"
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

### Recovery from Extended Public Key

```rust
use rustywallet_recovery::{RecoveryScanner, RecoveryConfig, ElectrumBackend};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = ElectrumBackend::mainnet().await?;
    let config = RecoveryConfig::new();

    let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    let scanner = RecoveryScanner::from_xpub(xpub, backend, config)?;

    let result = scanner.scan().await?;
    println!("Found {} addresses with balance", result.addresses.len());
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

| Option | Default | Description |
|--------|---------|-------------|
| `gap_limit` | 20 | Consecutive empty addresses before stopping |
| `account_gap_limit` | 3 | Consecutive empty accounts before stopping |
| `batch_size` | 10 | Addresses to query in each batch |
| `scan_paths` | All | BIP44, BIP49, BIP84, BIP86 |
| `min_confirmations` | 1 | Minimum confirmations for UTXOs |
| `scan_change` | true | Scan internal (change) addresses |
| `testnet` | false | Use testnet derivation paths |

## Scan Paths

| Path | Standard | Address Type |
|------|----------|--------------|
| BIP44 | m/44'/0'/account'/change/index | P2PKH (1...) |
| BIP49 | m/49'/0'/account'/change/index | P2SH-P2WPKH (3...) |
| BIP84 | m/84'/0'/account'/change/index | P2WPKH (bc1q...) |
| BIP86 | m/86'/0'/account'/change/index | P2TR (bc1p...) |

## License

MIT
