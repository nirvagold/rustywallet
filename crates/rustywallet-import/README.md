# rustywallet-import

Import private keys from various wallet formats.

## Supported Formats

| Format | Description | Example |
|--------|-------------|---------|
| WIF | Wallet Import Format | `5HueCGU8...` or `KwdMAjG...` |
| Hex | Raw 64-char hex | `0c28fca3...` |
| Mini Key | Casascius format | `S6c56bnX...` |
| Mnemonic | BIP39 phrase | `abandon abandon...` |
| BIP38 | Encrypted key | `6PRVWUbk...` |

## Quick Start

```rust
use rustywallet_import::{import_any, import_wif, import_hex, import_mnemonic, MnemonicImport};

// Auto-detect format
let result = import_any("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")?;
println!("Format: {}, Compressed: {}", result.format, result.compressed);

// Import WIF directly
let (key, network, compressed) = import_wif("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617")?;

// Import hex
let key = import_hex("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")?;

// Import mnemonic with custom path
let config = MnemonicImport::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    .with_path("m/84'/0'/0'/0/0")
    .with_passphrase("optional");
let result = import_mnemonic(config)?;
```

## Format Detection

```rust
use rustywallet_import::{detect_format, ImportFormat};

let format = detect_format("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ");
assert_eq!(format, Some(ImportFormat::Wif));
```

## BIP38 Encrypted Keys

BIP38 keys require a password:

```rust
use rustywallet_import::import_bip38;

let key = import_bip38("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg", "TestingOneTwoThree")?;
```

## Mnemonic Derivation Paths

```rust
use rustywallet_import::mnemonic_import::paths;

// BIP44 - Legacy (P2PKH): m/44'/0'/0'/0/0
// BIP49 - SegWit-compatible (P2SH-P2WPKH): m/49'/0'/0'/0/0  
// BIP84 - Native SegWit (P2WPKH): m/84'/0'/0'/0/0
```

## License

MIT
