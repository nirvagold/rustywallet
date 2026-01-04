# rustywallet-import

Import private keys from various wallet formats, including descriptors and wallet files.

## Supported Formats

| Format | Description | Example |
|--------|-------------|---------|
| WIF | Wallet Import Format | `5HueCGU8...` or `KwdMAjG...` |
| Hex | Raw 64-char hex | `0c28fca3...` |
| Mini Key | Casascius format | `S6c56bnX...` |
| Mnemonic | BIP39 phrase | `abandon abandon...` |
| BIP38 | Encrypted key | `6PRVWUbk...` |
| Descriptor | Output descriptors | `wpkh(...)`, `tr(...)` |

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

## Descriptor Import

Parse output descriptors and extract keys/scripts:

```rust
use rustywallet_import::descriptor::{import_descriptor, import_taproot_descriptor, is_descriptor};

// Import any descriptor
let result = import_descriptor("wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)")?;
println!("Type: {}", result.descriptor_type);  // "wpkh"
println!("Is SegWit: {}", result.is_segwit);   // true
println!("Keys: {:?}", result.keys);

// Import Taproot descriptor specifically
let tr_result = import_taproot_descriptor("tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)")?;
assert!(tr_result.is_taproot);

// Check if string is a descriptor
assert!(is_descriptor("wpkh(...)"));
```

## Wallet Format Import

Import from common wallet file formats:

```rust
use rustywallet_import::wallet_format::{
    import_electrum_wallet, import_sparrow_wallet, import_bitcoin_core_wallet, import_wallet_auto
};

// Auto-detect wallet format
let wallet = import_wallet_auto(json_content)?;
println!("Format: {:?}", wallet.format);
println!("Descriptors: {:?}", wallet.descriptors);

// Import Electrum wallet
let electrum = import_electrum_wallet(electrum_json)?;

// Import Sparrow wallet
let sparrow = import_sparrow_wallet(sparrow_json)?;

// Import Bitcoin Core wallet
let core = import_bitcoin_core_wallet(core_json)?;
```

## Format Detection

```rust
use rustywallet_import::{detect_format, ImportFormat};

let format = detect_format("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ");
assert_eq!(format, Some(ImportFormat::Wif));

// Descriptors are also detected
let desc_format = detect_format("wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)");
assert_eq!(desc_format, Some(ImportFormat::Descriptor));
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
// BIP86 - Taproot (P2TR): m/86'/0'/0'/0/0
```

## License

MIT
