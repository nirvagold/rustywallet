# Quick Start Guide

This guide will walk you through the most common wallet operations.

## 1. Generate a New Wallet

```rust
use rustywallet::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate 12-word mnemonic
    let mnemonic = Mnemonic::generate(12)?;
    println!("🔐 Save these words securely!");
    println!("Mnemonic: {}", mnemonic.phrase());
    
    // Convert to seed (with optional passphrase)
    let seed = mnemonic.to_seed("optional-passphrase");
    
    // Create HD wallet
    let master = ExtendedPrivateKey::from_seed(&seed)?;
    
    // Derive first receiving address (BIP84 - Native SegWit)
    let account = master.derive_path("m/84'/0'/0'/0/0")?;
    let address = Address::p2wpkh(&account.public_key(), Network::Mainnet)?;
    
    println!("Address: {}", address);
    
    Ok(())
}
```

## 2. Import Existing Wallet

### From Mnemonic
```rust
let mnemonic = Mnemonic::from_phrase("abandon abandon abandon ... about")?;
let seed = mnemonic.to_seed("");
let master = ExtendedPrivateKey::from_seed(&seed)?;
```

### From WIF (Wallet Import Format)
```rust
use rustywallet_import::import_wif;

let key = import_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")?;
println!("Imported key: {}", key.to_hex());
```

### Auto-detect Format
```rust
use rustywallet_import::import_any;

// Works with WIF, hex, or mnemonic
let key = import_any("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")?;
```

## 3. Generate Addresses

```rust
use rustywallet_keys::prelude::PrivateKey;
use rustywallet_address::prelude::*;

let private_key = PrivateKey::random();
let public_key = private_key.public_key();

// Legacy (starts with 1)
let p2pkh = Address::p2pkh(&public_key, Network::Mainnet)?;
println!("P2PKH: {}", p2pkh);  // 1...

// SegWit (starts with bc1q)
let p2wpkh = Address::p2wpkh(&public_key, Network::Mainnet)?;
println!("P2WPKH: {}", p2wpkh);  // bc1q...

// Taproot (starts with bc1p)
let p2tr = Address::p2tr(&public_key, Network::Mainnet)?;
println!("P2TR: {}", p2tr);  // bc1p...
```

## 4. Check Balance

### Using Electrum (No Rate Limits!)
```rust
use rustywallet_electrum::{ElectrumClient, Network};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to Electrum server
    let client = ElectrumClient::connect(
        "electrum.blockstream.info:50002",
        Network::Mainnet
    ).await?;
    
    // Check single address
    let balance = client.get_balance("bc1q...").await?;
    println!("Confirmed: {} sats", balance.confirmed);
    println!("Unconfirmed: {} sats", balance.unconfirmed);
    
    // Batch check (efficient!)
    let addresses = vec!["bc1q...", "bc1q...", "bc1q..."];
    let balances = client.get_balances(&addresses).await?;
    
    for (addr, bal) in addresses.iter().zip(balances.iter()) {
        println!("{}: {} sats", addr, bal.confirmed);
    }
    
    Ok(())
}
```

### Using Mempool.space API
```rust
use rustywallet_mempool::MempoolClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = MempoolClient::new();
    
    // Get address info
    let info = client.get_address("bc1q...").await?;
    println!("Total received: {} sats", info.chain_stats.funded_txo_sum);
    
    // Get fee estimates
    let fees = client.get_fee_estimates().await?;
    println!("Fast (1 block): {} sat/vB", fees.fastest_fee);
    println!("Medium (3 blocks): {} sat/vB", fees.half_hour_fee);
    println!("Slow (6 blocks): {} sat/vB", fees.hour_fee);
    
    Ok(())
}
```

## 5. Build a Transaction

```rust
use rustywallet_tx::prelude::*;
use rustywallet_keys::prelude::PrivateKey;

// Your UTXO (unspent output)
let utxo = Utxo {
    txid: [/* 32 bytes */],
    vout: 0,
    value: 100_000,  // satoshis
    script_pubkey: vec![/* ... */],
    address: "bc1q...".to_string(),
};

// Build transaction
let unsigned = TxBuilder::new()
    .add_input(utxo.clone())
    .add_output(50_000, recipient_script)  // Send 50k sats
    .set_fee_rate(10)  // 10 sat/vB
    .set_change_address("bc1q...")  // Your change address
    .build()?;

println!("Fee: {} sats", unsigned.fee());

// Sign the transaction
let private_key = PrivateKey::from_wif("...")?;
let mut tx = unsigned.tx;
sign_p2wpkh(&mut tx, 0, utxo.value, &private_key)?;

// Get hex for broadcasting
let hex = tx.to_hex();
println!("Broadcast this: {}", hex);
```

## 6. Export Wallet

```rust
use rustywallet_export::*;

let private_key = PrivateKey::random();

// Export as WIF
let wif = export_wif(&private_key, Network::Mainnet, true)?;
println!("WIF: {}", wif);

// Export as JSON
let json = export_json(&private_key, Network::Mainnet)?;
println!("JSON: {}", json);

// Export as encrypted BIP38
let encrypted = export_bip38(&private_key, "my-password", Network::Mainnet)?;
println!("BIP38: {}", encrypted);
```

## Next Steps

- [Key Management Guide](../guides/key-management.md)
- [HD Wallets Guide](../guides/hd-wallets.md)
- [Transaction Building Guide](../guides/transactions.md)
