# rustywallet-export

Export private keys to various formats, including descriptors and PSBTs.

## Supported Formats

| Format | Description | Example Output |
|--------|-------------|----------------|
| WIF | Wallet Import Format | `KwdMAjG...` or `5HueCGU...` |
| Hex | Raw hex string | `0c28fca3...` |
| JSON | Structured JSON | `{"address": "1...", "wif": "K..."}` |
| CSV | Comma-separated | `address,wif,hex` |
| Paper Wallet | Address + WIF pair | For cold storage |
| BIP38 | Encrypted key | `6PRVWUbk...` |
| BIP21 | Bitcoin URI | `bitcoin:1...?amount=1.5` |
| Descriptor | Output descriptors | `wpkh(...)#checksum` |
| PSBT | Partially Signed Bitcoin Tx | Base64 encoded |

## Quick Start

```rust
use rustywallet_export::prelude::*;
use rustywallet_keys::prelude::PrivateKey;

let key = PrivateKey::random();

// Export to WIF
let wif = export_wif(&key, Network::Mainnet, true);

// Export to hex
let hex = export_hex(&key, HexOptions::new().with_prefix(true));

// Export to JSON
let json = export_json(&key, Network::Mainnet)?;

// Generate paper wallet
let paper = to_paper_wallet(&key, Network::Mainnet, AddressType::P2WPKH)?;
println!("Address: {}", paper.address);
println!("WIF: {}", paper.wif);
```

## Descriptor Export

Export keys as output descriptors with checksum:

```rust
use rustywallet_export::descriptor::{
    export_descriptor, export_pubkey_descriptor, export_multisig_descriptor,
    export_wrapped_multisig_descriptor, DescriptorType, DescriptorOptions
};
use rustywallet_keys::prelude::PrivateKey;

let key = PrivateKey::random();

// Export as wpkh descriptor
let wpkh = export_descriptor(&key, DescriptorType::Wpkh, DescriptorOptions::new())?;
// Returns: wpkh(02...)#checksum

// Export as Taproot descriptor
let tr = export_descriptor(&key, DescriptorType::Tr, DescriptorOptions::new())?;
// Returns: tr(02...)#checksum

// Export without checksum
let options = DescriptorOptions::new().with_checksum(false);
let desc = export_descriptor(&key, DescriptorType::Pkh, options)?;

// Export multisig descriptor
let pubkeys = vec!["02...", "03..."];
let multi = export_multisig_descriptor(2, &pubkeys, true, DescriptorOptions::new())?;
// Returns: sortedmulti(2,02...,03...)#checksum

// Export wrapped multisig (wsh)
let wsh_multi = export_wrapped_multisig_descriptor(2, &pubkeys, true, true, DescriptorOptions::new())?;
// Returns: wsh(sortedmulti(2,02...,03...))#checksum
```

## PSBT Export

Export PSBTs with descriptor context:

```rust
use rustywallet_export::psbt_export::{
    export_psbt, export_psbt_json, export_psbt_for_file, export_descriptor_with_psbts,
    PsbtExportOptions
};

// Export PSBT to base64
let base64 = export_psbt(&psbt, PsbtExportOptions::default())?;

// Export PSBT as JSON
let json = export_psbt_json(&psbt)?;

// Export PSBT for file storage
let file_export = export_psbt_for_file(&psbt, "my_transaction")?;
println!("Filename: {}", file_export.suggested_filename);
println!("Content: {}", file_export.content);

// Export descriptor with associated PSBTs
let bundle = export_descriptor_with_psbts(&key, DescriptorType::Wpkh, &psbts, options)?;
```

## Batch Export

```rust
use rustywallet_export::prelude::*;
use rustywallet_keys::prelude::PrivateKey;

let keys: Vec<PrivateKey> = (0..100).map(|_| PrivateKey::random()).collect();

// Export to CSV
let csv = export_csv(&keys, CsvOptions::new())?;

// Export to JSON array
let json = export_json_batch(&keys, Network::Mainnet)?;
```

## BIP38 Encryption

```rust
use rustywallet_export::{export_bip38, Network};
use rustywallet_keys::prelude::PrivateKey;

let key = PrivateKey::random();
let encrypted = export_bip38(&key, "mypassword", true)?;
// Returns: 6PRVWUbk...
```

## BIP21 URI (for QR codes)

```rust
use rustywallet_export::{to_bip21_uri, Bip21Options};

let uri = to_bip21_uri(
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    Bip21Options::new()
        .with_amount(0.001)
        .with_label("Donation")
);
// Returns: bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.001&label=Donation
```

## License

MIT
