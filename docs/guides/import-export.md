# Import & Export Guide

This guide covers importing keys from various formats and exporting to different formats.

## Import Formats

### Auto-Detect

The easiest way - automatically detects the format:

```rust
use rustywallet_import::import_any;

// WIF
let key = import_any("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")?;

// Hex
let key = import_any("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")?;

// Mini key
let key = import_any("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy")?;
```

### Detect Format First

```rust
use rustywallet_import::{detect_format, KeyFormat};

let input = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";

match detect_format(input) {
    KeyFormat::Wif => println!("WIF format"),
    KeyFormat::WifUncompressed => println!("WIF uncompressed"),
    KeyFormat::Hex => println!("Hex format"),
    KeyFormat::MiniKey => println!("Mini key"),
    KeyFormat::Mnemonic => println!("Mnemonic phrase"),
    KeyFormat::Bip38 => println!("BIP38 encrypted"),
    KeyFormat::Unknown => println!("Unknown format"),
}
```

### WIF Import

```rust
use rustywallet_import::import_wif;

// Compressed (starts with K or L on mainnet)
let key = import_wif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")?;

// Uncompressed (starts with 5 on mainnet)
let key = import_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")?;

// Testnet (starts with c or 9)
let key = import_wif("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA")?;
```

### Hex Import

```rust
use rustywallet_import::import_hex;

// 64-character hex string
let key = import_hex("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")?;

// With or without 0x prefix
let key = import_hex("0x0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")?;
```

### Mini Key Import

Casascius-style mini private keys:

```rust
use rustywallet_import::import_mini_key;

let key = import_mini_key("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy")?;
```

### BIP38 Encrypted Import

```rust
use rustywallet_import::import_bip38;

let encrypted = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
let password = "TestingOneTwoThree";

let key = import_bip38(encrypted, password)?;
```

### Mnemonic Import

```rust
use rustywallet_import::import_mnemonic;

let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let passphrase = "";  // Optional BIP39 passphrase
let path = "m/84'/0'/0'/0/0";  // Derivation path

let key = import_mnemonic(phrase, passphrase, path)?;
```

## Export Formats

### WIF Export

```rust
use rustywallet_export::{export_wif, export_wif_uncompressed};

let key = PrivateKey::random();

// Compressed (recommended)
let wif = export_wif(&key, Network::Mainnet)?;
println!("WIF: {}", wif);  // K... or L...

// Uncompressed (legacy)
let wif = export_wif_uncompressed(&key, Network::Mainnet)?;
println!("WIF: {}", wif);  // 5...
```

### Hex Export

```rust
use rustywallet_export::{export_hex, HexOptions};

// Default (lowercase, no prefix)
let hex = export_hex(&key, HexOptions::default())?;
println!("Hex: {}", hex);

// With options
let hex = export_hex(&key, HexOptions {
    uppercase: true,
    prefix: true,
})?;
println!("Hex: {}", hex);  // 0x0C28FCA3...
```

### JSON Export

```rust
use rustywallet_export::export_json;

let json = export_json(&key, Network::Mainnet)?;
println!("{}", json);
```

Output:
```json
{
  "private_key": {
    "wif": "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
    "hex": "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
  },
  "public_key": {
    "compressed": "02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c",
    "uncompressed": "04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a"
  },
  "addresses": {
    "p2pkh": "1LoVGDgRs9hTfTNJNuXKSpwtcr4XYXnjBf",
    "p2wpkh": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "p2tr": "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
  },
  "network": "mainnet"
}
```

### CSV Export

```rust
use rustywallet_export::export_csv;

let keys = vec![key1, key2, key3];
let columns = &["wif", "address", "pubkey"];

let csv = export_csv(&keys, columns, Network::Mainnet)?;
println!("{}", csv);
```

Output:
```csv
wif,address,pubkey
KwDiBf89...,bc1q...,02d0de0a...
L1aW4aubD...,bc1q...,03a1b2c3...
KxDQjJwv...,bc1q...,02e4f5g6...
```

### BIP38 Encrypted Export

```rust
use rustywallet_export::export_bip38;

let encrypted = export_bip38(&key, "my-strong-password", Network::Mainnet)?;
println!("BIP38: {}", encrypted);  // 6P...
```

### Paper Wallet

```rust
use rustywallet_export::export_paper_wallet;

let paper = export_paper_wallet(&key, Network::Mainnet)?;

println!("=== PAPER WALLET ===");
println!("Address (P2PKH): {}", paper.address_p2pkh);
println!("Address (P2WPKH): {}", paper.address_p2wpkh);
println!("Address (P2TR): {}", paper.address_p2tr);
println!("Private Key (WIF): {}", paper.wif);
println!("====================");
```

### BIP21 URI

```rust
use rustywallet_export::export_bip21;

// Simple
let uri = export_bip21("bc1q...", None, None, None)?;
// bitcoin:bc1q...

// With amount and label
let uri = export_bip21(
    "bc1q...",
    Some(0.001),           // 0.001 BTC
    Some("Coffee"),        // Label
    Some("Thanks!"),       // Message
)?;
// bitcoin:bc1q...?amount=0.001&label=Coffee&message=Thanks!
```

## Batch Operations

### Import Multiple Keys

```rust
use rustywallet_import::import_any;

let inputs = vec![
    "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
    "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
    "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d",
];

let keys: Vec<_> = inputs
    .iter()
    .filter_map(|input| import_any(input).ok())
    .collect();

println!("Imported {} keys", keys.len());
```

### Export to File

```rust
use rustywallet_export::export_csv;
use std::fs::File;
use std::io::Write;

let keys = vec![key1, key2, key3];
let csv = export_csv(&keys, &["wif", "address"], Network::Mainnet)?;

let mut file = File::create("keys.csv")?;
file.write_all(csv.as_bytes())?;
```

## Error Handling

```rust
use rustywallet_import::{import_any, ImportError};

match import_any(user_input) {
    Ok(key) => {
        println!("Imported successfully!");
    }
    Err(ImportError::InvalidWif(e)) => {
        eprintln!("Invalid WIF format: {}", e);
    }
    Err(ImportError::InvalidHex(e)) => {
        eprintln!("Invalid hex: {}", e);
    }
    Err(ImportError::InvalidMiniKey) => {
        eprintln!("Invalid mini key");
    }
    Err(ImportError::Bip38DecryptionFailed) => {
        eprintln!("Wrong password for BIP38");
    }
    Err(ImportError::UnknownFormat) => {
        eprintln!("Could not detect format");
    }
    Err(e) => {
        eprintln!("Import error: {}", e);
    }
}
```

## Security Considerations

### When Importing

1. **Validate source** - Only import from trusted sources
2. **Check network** - Mainnet vs testnet WIF
3. **Verify address** - Generate address and verify it matches expected

### When Exporting

1. **Encrypt sensitive exports** - Use BIP38 for storage
2. **Secure deletion** - Overwrite files after use
3. **Never log private keys** - Even in debug mode

```rust
// GOOD: Export encrypted
let encrypted = export_bip38(&key, "strong-password", Network::Mainnet)?;

// BAD: Plain text to file
let wif = export_wif(&key, Network::Mainnet)?;
std::fs::write("key.txt", wif)?;  // Don't do this!
```

## Format Reference

| Format | Example | Use Case |
|--------|---------|----------|
| WIF Compressed | K... or L... | Standard wallet import |
| WIF Uncompressed | 5... | Legacy compatibility |
| Hex | 64 chars | Developer tools |
| Mini Key | S... (30 chars) | Physical coins |
| BIP38 | 6P... | Encrypted storage |
| Mnemonic | 12-24 words | HD wallet backup |

## Next Steps

- [Key Management](./key-management.md)
- [HD Wallets](./hd-wallets.md)
- [Security Best Practices](../advanced/security.md)
