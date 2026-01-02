# Transaction Building Guide

This guide covers building, signing, and broadcasting Bitcoin transactions.

## Transaction Basics

A Bitcoin transaction consists of:
- **Inputs** - UTXOs (unspent outputs) you're spending
- **Outputs** - Where the funds go
- **Fee** - Paid to miners

```
Inputs (100,000 sats) = Outputs (90,000 sats) + Fee (10,000 sats)
```

## Building a Transaction

### Step 1: Get UTXOs

First, find your unspent outputs:

```rust
use rustywallet_electrum::{ElectrumClient, Network};

let client = ElectrumClient::connect("electrum.blockstream.info:50002", Network::Mainnet).await?;

// Get UTXOs for your address
let utxos = client.get_utxos("bc1q...your-address...").await?;

for utxo in &utxos {
    println!("TXID: {}", hex::encode(&utxo.txid));
    println!("Vout: {}", utxo.vout);
    println!("Value: {} sats", utxo.value);
}
```

### Step 2: Build Transaction

```rust
use rustywallet_tx::prelude::*;

// Create UTXO struct
let utxo = Utxo {
    txid: [/* 32 bytes from previous tx */],
    vout: 0,
    value: 100_000,  // satoshis
    script_pubkey: vec![/* scriptPubKey */],
    address: "bc1q...".to_string(),
};

// Build transaction
let unsigned = TxBuilder::new()
    .add_input(utxo.clone())
    .add_output(50_000, recipient_script)  // Send 50k sats
    .set_fee_rate(10)                       // 10 sat/vB
    .set_change_address("bc1q...change...")
    .build()?;

println!("Transaction built!");
println!("Fee: {} sats", unsigned.fee());
println!("Inputs: {}", unsigned.tx.inputs.len());
println!("Outputs: {}", unsigned.tx.outputs.len());
```

### Step 3: Sign Transaction

```rust
use rustywallet_keys::prelude::PrivateKey;

let private_key = PrivateKey::from_wif("...")?;
let mut tx = unsigned.tx;

// Sign P2WPKH input
sign_p2wpkh(&mut tx, 0, utxo.value, &private_key)?;

// Get hex for broadcasting
let hex = tx.to_hex();
println!("Signed transaction: {}", hex);
```

### Step 4: Broadcast

```rust
// Using Electrum
let txid = client.broadcast(&hex).await?;
println!("Broadcast! TXID: {}", txid);

// Or using Mempool.space
use rustywallet_mempool::MempoolClient;
let mempool = MempoolClient::new();
let txid = mempool.broadcast(&hex).await?;
```

## Fee Calculation

### Fee Rate

Fee is calculated as: `fee = vsize × fee_rate`

```rust
use rustywallet_tx::{estimate_fee, estimate_vsize};

// Estimate vsize for 2 inputs, 2 outputs
let vsize = estimate_vsize(0, 2, 2);  // P2WPKH inputs
println!("Estimated vsize: {} vB", vsize);

// Calculate fee at different rates
let fee_1 = estimate_fee(2, 2, 1);   // 1 sat/vB (slow)
let fee_10 = estimate_fee(2, 2, 10); // 10 sat/vB (medium)
let fee_50 = estimate_fee(2, 2, 50); // 50 sat/vB (fast)

println!("Slow: {} sats", fee_1);
println!("Medium: {} sats", fee_10);
println!("Fast: {} sats", fee_50);
```

### Get Current Fee Rates

```rust
use rustywallet_mempool::MempoolClient;

let client = MempoolClient::new();
let fees = client.get_fee_estimates().await?;

println!("Next block: {} sat/vB", fees.fastest_fee);
println!("~30 min: {} sat/vB", fees.half_hour_fee);
println!("~1 hour: {} sat/vB", fees.hour_fee);
println!("Economy: {} sat/vB", fees.economy_fee);
println!("Minimum: {} sat/vB", fees.minimum_fee);
```

## Coin Selection

### Automatic Selection

```rust
let utxos = vec![
    make_utxo(10_000),
    make_utxo(50_000),
    make_utxo(25_000),
    make_utxo(100_000),
];

// TxBuilder with automatic coin selection
let unsigned = TxBuilder::new()
    .add_output(60_000, recipient_script)
    .set_fee_rate(10)
    .set_change_address("bc1q...")
    .build_with_coin_selection(&utxos)?;
```

### Manual Selection

```rust
use rustywallet_tx::select_coins;

let target = 60_000;  // Amount to send
let fee_rate = 10;    // sat/vB

let (selected, total) = select_coins(&utxos, target, fee_rate)?;

println!("Selected {} UTXOs", selected.len());
println!("Total value: {} sats", total);
println!("Change: {} sats", total - target - fee);
```

## Dust Threshold

Outputs below the dust threshold are rejected by nodes:

```rust
use rustywallet_tx::is_dust;

// Check if output is dust
let is_too_small = is_dust(500, true);  // true = SegWit
println!("500 sats is dust: {}", is_too_small);  // true

let is_ok = is_dust(1000, true);
println!("1000 sats is dust: {}", is_ok);  // false
```

**Dust thresholds:**
- P2PKH: 546 sats
- P2WPKH: 294 sats

## Script Building

### Output Scripts

```rust
use rustywallet_tx::{build_p2pkh_script, build_p2wpkh_script, build_p2tr_script};

// P2PKH script
let pubkey_hash = [/* 20 bytes */];
let p2pkh = build_p2pkh_script(&pubkey_hash);

// P2WPKH script
let p2wpkh = build_p2wpkh_script(&pubkey_hash);

// P2TR script
let x_only_pubkey = [/* 32 bytes */];
let p2tr = build_p2tr_script(&x_only_pubkey);
```

### Address to Script

The TxBuilder handles this automatically:

```rust
let unsigned = TxBuilder::new()
    .add_input(utxo)
    .add_output_p2pkh("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 50_000)?
    .build()?;
```

## Signing Different Input Types

### P2PKH (Legacy)

```rust
sign_p2pkh(&mut tx, input_index, &script_pubkey, &private_key)?;
```

### P2WPKH (SegWit)

```rust
sign_p2wpkh(&mut tx, input_index, utxo_value, &private_key)?;
```

### Multiple Inputs

```rust
// Sign all inputs
let utxo_info = vec![
    (script1.clone(), value1, &key1),
    (script2.clone(), value2, &key2),
];

sign_all(&mut tx, &utxo_info)?;
```

## Complete Example

```rust
use rustywallet_keys::prelude::PrivateKey;
use rustywallet_tx::prelude::*;
use rustywallet_electrum::{ElectrumClient, Network};
use rustywallet_mempool::MempoolClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup
    let private_key = PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy")?;
    let my_address = "tb1q...";
    let recipient = "tb1q...recipient...";
    
    // 2. Connect to Electrum
    let electrum = ElectrumClient::connect(
        "electrum.blockstream.info:60002",
        Network::Testnet
    ).await?;
    
    // 3. Get UTXOs
    let utxos = electrum.get_utxos(my_address).await?;
    println!("Found {} UTXOs", utxos.len());
    
    // 4. Get fee rate
    let mempool = MempoolClient::testnet();
    let fees = mempool.get_fee_estimates().await?;
    let fee_rate = fees.half_hour_fee;
    
    // 5. Build transaction
    let unsigned = TxBuilder::new()
        .add_output_p2pkh(recipient, 10_000)?
        .set_fee_rate(fee_rate)
        .set_change_address(my_address)
        .build_with_coin_selection(&utxos)?;
    
    println!("Fee: {} sats ({} sat/vB)", unsigned.fee(), fee_rate);
    
    // 6. Sign
    let mut tx = unsigned.tx;
    for (i, info) in unsigned.input_info.iter().enumerate() {
        sign_p2wpkh(&mut tx, i, info.utxo.value, &private_key)?;
    }
    
    // 7. Broadcast
    let hex = tx.to_hex();
    let txid = electrum.broadcast(&hex).await?;
    
    println!("Success! TXID: {}", txid);
    
    Ok(())
}
```

## Error Handling

```rust
match TxBuilder::new()
    .add_input(utxo)
    .add_output(amount, script)
    .build()
{
    Ok(unsigned) => {
        println!("Built successfully");
    }
    Err(TxError::NoInputs) => {
        println!("No inputs provided");
    }
    Err(TxError::NoOutputs) => {
        println!("No outputs provided");
    }
    Err(TxError::InsufficientFunds { needed, available }) => {
        println!("Need {} sats but only have {}", needed, available);
    }
    Err(TxError::DustOutput(value)) => {
        println!("Output {} sats is below dust threshold", value);
    }
    Err(e) => {
        println!("Error: {}", e);
    }
}
```

## Next Steps

- [Multi-Signature Wallets](./multisig.md)
- [Balance Checking](./balance-checking.md)
- [Security Best Practices](../advanced/security.md)
