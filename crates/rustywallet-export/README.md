# rustywallet-export

Export private keys to various formats.

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
