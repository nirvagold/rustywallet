# rustywallet-tx

Bitcoin transaction building, signing, and serialization.

## Features

- **Transaction Building** - Create transactions with multiple inputs/outputs
- **Coin Selection** - Automatic UTXO selection (largest-first algorithm)
- **Fee Calculation** - vsize-based fee estimation with dust detection
- **Script Building** - P2PKH, P2WPKH, and P2TR scriptPubKey generation
- **Signing** - Sign P2PKH and P2WPKH inputs
- **Serialization** - Serialize transactions to hex for broadcasting

## Installation

```toml
[dependencies]
rustywallet-tx = "0.1"
```

## Quick Start

```rust
use rustywallet_tx::prelude::*;

// Create UTXOs
let utxo = Utxo {
    txid: [0u8; 32],
    vout: 0,
    value: 100_000,
    script_pubkey: vec![0x00, 0x14, /* 20 bytes pubkey hash */],
    address: "bc1q...".to_string(),
};

// Build unsigned transaction
let unsigned = TxBuilder::new()
    .add_input(utxo)
    .add_output(50_000, vec![/* scriptPubKey */])
    .set_fee_rate(10) // 10 sat/vB
    .set_change_address("bc1q...")
    .build()
    .unwrap();

println!("Fee: {} sats", unsigned.fee());
```

## Signing Transactions

```rust
use rustywallet_tx::{sign_p2pkh, sign_p2wpkh};
use rustywallet_keys::prelude::PrivateKey;

let private_key = PrivateKey::random();
let mut tx = unsigned.tx;

// Sign P2PKH input
sign_p2pkh(&mut tx, 0, &private_key).unwrap();

// Or sign P2WPKH input (SegWit)
sign_p2wpkh(&mut tx, 0, 100_000, &private_key).unwrap();

// Serialize for broadcast
let hex = tx.to_hex();
```

## Coin Selection

```rust
use rustywallet_tx::{select_coins, Utxo};

let utxos = vec![/* available UTXOs */];
let target = 50_000; // sats
let fee_rate = 10; // sat/vB

let (selected, total) = select_coins(&utxos, target, fee_rate).unwrap();
```

## Fee Estimation

```rust
use rustywallet_tx::{estimate_fee, is_dust};

// Estimate fee for 2 inputs, 2 outputs at 10 sat/vB
let fee = estimate_fee(2, 2, 10);

// Check if output is dust
let is_too_small = is_dust(500, true); // true = SegWit
```

## Script Building

```rust
use rustywallet_tx::{build_p2pkh_script, build_p2wpkh_script, build_p2tr_script};

let pubkey_hash = [0u8; 20];
let p2pkh = build_p2pkh_script(&pubkey_hash);
let p2wpkh = build_p2wpkh_script(&pubkey_hash);

let x_only_pubkey = [0u8; 32];
let p2tr = build_p2tr_script(&x_only_pubkey);
```

## License

MIT
