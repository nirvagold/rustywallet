# rustywallet-psbt

PSBT (Partially Signed Bitcoin Transaction) implementation for Bitcoin wallet development.

[![Crates.io](https://img.shields.io/crates/v/rustywallet-psbt.svg)](https://crates.io/crates/rustywallet-psbt)
[![Documentation](https://docs.rs/rustywallet-psbt/badge.svg)](https://docs.rs/rustywallet-psbt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **BIP174 (PSBT v0)** - Full support for standard PSBT format
- **BIP370 (PSBT v2)** - Support for improved PSBT format
- **All BIP174 Roles** - Creator, Updater, Signer, Combiner, Finalizer, Extractor
- **Multiple Input Types** - P2PKH, P2WPKH, P2SH, P2WSH, P2TR
- **Hardware Wallet Compatible** - Interoperable with Ledger, Trezor, Coldcard

## Installation

```toml
[dependencies]
rustywallet-psbt = "0.1"
```

## Quick Start

### Parse PSBT

```rust
use rustywallet_psbt::Psbt;

// From base64
let psbt = Psbt::from_base64("cHNidP8BAH...")?;

// From bytes
let psbt = Psbt::from_bytes(&bytes)?;

println!("Inputs: {}", psbt.input_count());
println!("Outputs: {}", psbt.output_count());
```

### Create PSBT

```rust
use rustywallet_psbt::Psbt;

// Create from unsigned transaction
let unsigned_tx = vec![/* transaction bytes */];
let psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

// Or create PSBT v2
let psbt = Psbt::new_v2(2, 2); // 2 inputs, 2 outputs
```

### Update PSBT

```rust
use rustywallet_psbt::{Psbt, TxOut, KeySource};

let mut psbt = Psbt::from_base64("...")?;

// Add witness UTXO
psbt.update_input_with_utxo(0, TxOut {
    value: 100_000,
    script_pubkey: vec![0x00, 0x14, /* pubkey hash */],
})?;

// Add BIP32 derivation
psbt.update_input_with_bip32(
    0,
    pubkey.to_vec(),
    KeySource::new([0x01, 0x02, 0x03, 0x04], vec![84 | 0x80000000, 0, 0, 0, 0]),
)?;
```

### Sign PSBT

```rust
use rustywallet_psbt::Psbt;
use rustywallet_keys::PrivateKey;

let mut psbt = Psbt::from_base64("...")?;
let private_key = PrivateKey::from_wif("...")?;

// Sign all inputs that match this key
let signed_count = psbt.sign(&private_key)?;
println!("Signed {} inputs", signed_count);
```

### Combine PSBTs

```rust
use rustywallet_psbt::Psbt;

let psbt1 = Psbt::from_base64("...")?; // Signed by party 1
let psbt2 = Psbt::from_base64("...")?; // Signed by party 2

// Combine signatures
let combined = Psbt::combine(&[psbt1, psbt2])?;
```

### Finalize and Extract

```rust
use rustywallet_psbt::Psbt;

let mut psbt = Psbt::from_base64("...")?;

// Finalize all inputs
psbt.finalize()?;

// Check if finalized
if psbt.is_finalized() {
    // Extract signed transaction
    let tx = psbt.extract_tx()?;
    println!("Transaction: {}", hex::encode(&tx));
}
```

## BIP174 Roles

| Role | Description | Methods |
|------|-------------|---------|
| Creator | Create PSBT from unsigned tx | `from_unsigned_tx()`, `new_v2()` |
| Updater | Add UTXO info, scripts, paths | `update_input_with_*()` |
| Signer | Add partial signatures | `sign()`, `sign_input()` |
| Combiner | Merge PSBTs | `combine()`, `merge()` |
| Finalizer | Build final scriptSig/witness | `finalize()`, `finalize_input()` |
| Extractor | Extract signed transaction | `extract_tx()` |

## Supported Input Types

| Type | Description | Support |
|------|-------------|---------|
| P2PKH | Legacy pay-to-pubkey-hash | ✅ |
| P2WPKH | Native SegWit | ✅ |
| P2SH-P2WPKH | Wrapped SegWit | ✅ |
| P2SH | Pay-to-script-hash | ✅ |
| P2WSH | Native SegWit script | ✅ |
| P2SH-P2WSH | Wrapped SegWit script | ✅ |
| P2TR | Taproot key path | ✅ |

## Serialization

```rust
// To bytes
let bytes = psbt.to_bytes();

// To base64
let base64 = psbt.to_base64();

// Display (base64)
println!("{}", psbt);

// Parse from string
let psbt: Psbt = "cHNidP8BAH...".parse()?;
```

## Error Handling

```rust
use rustywallet_psbt::{Psbt, PsbtError};

match Psbt::from_base64(input) {
    Ok(psbt) => { /* success */ }
    Err(PsbtError::InvalidMagic) => {
        eprintln!("Not a valid PSBT");
    }
    Err(PsbtError::Base64Error(e)) => {
        eprintln!("Invalid base64: {}", e);
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}
```

## License

MIT License - see [LICENSE](../../LICENSE) for details.

## Related Crates

- [rustywallet-tx](https://crates.io/crates/rustywallet-tx) - Transaction building
- [rustywallet-keys](https://crates.io/crates/rustywallet-keys) - Key management
- [rustywallet-multisig](https://crates.io/crates/rustywallet-multisig) - Multi-signature wallets
