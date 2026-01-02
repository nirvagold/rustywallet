# Choosing the Right Crate

This guide helps you pick the right crates for your use case.

## Use Case Matrix

| I want to... | Crates needed |
|--------------|---------------|
| Generate random keys | `rustywallet-keys` |
| Create Bitcoin addresses | `rustywallet-keys` + `rustywallet-address` |
| Use mnemonic phrases | `rustywallet-mnemonic` |
| Build HD wallet | `rustywallet-mnemonic` + `rustywallet-hd` |
| Check balances | `rustywallet-electrum` or `rustywallet-mempool` |
| Build transactions | `rustywallet-tx` |
| Create multisig wallet | `rustywallet-multisig` |
| Import existing keys | `rustywallet-import` |
| Export/backup keys | `rustywallet-export` |
| Generate millions of keys | `rustywallet-batch` |
| Find vanity addresses | `rustywallet-vanity` |

## Crate Dependency Graph

```
rustywallet-mnemonic
        │
        ▼
rustywallet-hd ──────────────────┐
        │                        │
        ▼                        ▼
rustywallet-keys ◄───── rustywallet-import
        │                        │
        ▼                        ▼
rustywallet-address ◄─── rustywallet-export
        │
        ├──────────────────┬─────────────────┐
        ▼                  ▼                 ▼
rustywallet-tx    rustywallet-multisig   rustywallet-vanity
        │                  │
        ▼                  ▼
rustywallet-electrum ◄─────┘
```

## Detailed Crate Descriptions

### Core Crates

#### rustywallet-keys
The foundation. Handles private and public keys.

```rust
use rustywallet_keys::prelude::*;

let key = PrivateKey::random();
let pubkey = key.public_key();
let wif = key.to_wif(Network::Mainnet);
```

**Use when:** You need basic key operations.

---

#### rustywallet-address
Generates all Bitcoin address types.

```rust
use rustywallet_address::prelude::*;

let addr = Address::p2wpkh(&pubkey, Network::Mainnet)?;
```

**Supported types:**
- P2PKH (1...)
- P2SH (3...)
- P2WPKH (bc1q...)
- P2WSH (bc1q... longer)
- P2TR (bc1p...)
- Ethereum (0x...)

---

#### rustywallet-mnemonic
BIP39 mnemonic phrases.

```rust
use rustywallet_mnemonic::Mnemonic;

let mnemonic = Mnemonic::generate(12)?;  // 12, 15, 18, 21, or 24 words
let seed = mnemonic.to_seed("passphrase");
```

**Use when:** You want human-readable backups.

---

#### rustywallet-hd
Hierarchical Deterministic wallets (BIP32/44/84/86).

```rust
use rustywallet_hd::ExtendedPrivateKey;

let master = ExtendedPrivateKey::from_seed(&seed)?;
let child = master.derive_path("m/84'/0'/0'/0/0")?;
```

**Use when:** You need multiple addresses from one seed.

---

### Network Crates

#### rustywallet-electrum
Electrum protocol client. **No rate limits!**

```rust
let client = ElectrumClient::connect("server:50002", Network::Mainnet).await?;
let balance = client.get_balance("bc1q...").await?;
```

**Best for:** High-volume balance checking, UTXO fetching.

---

#### rustywallet-mempool
Mempool.space REST API.

```rust
let client = MempoolClient::new();
let fees = client.get_fee_estimates().await?;
```

**Best for:** Fee estimation, transaction tracking, block explorer data.

---

### Transaction Crates

#### rustywallet-tx
Build and sign Bitcoin transactions.

```rust
let tx = TxBuilder::new()
    .add_input(utxo)
    .add_output(amount, script)
    .set_fee_rate(10)
    .build()?;
```

**Features:**
- Coin selection
- Fee calculation
- P2PKH/P2WPKH signing
- Dust detection

---

#### rustywallet-multisig
Multi-signature wallets and Shamir Secret Sharing.

```rust
let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet)?;
println!("2-of-3: {}", wallet.address_p2wsh);
```

**Features:**
- M-of-N multisig (up to 15-of-15)
- P2SH, P2WSH, P2SH-P2WSH
- Shamir secret sharing

---

### Utility Crates

#### rustywallet-import
Import keys from various formats.

```rust
let key = import_any("5HueCGU...")?;  // Auto-detect format
```

**Supported formats:**
- WIF (compressed/uncompressed)
- Hex (64 characters)
- Mini key (Casascius)
- Mnemonic
- BIP38 encrypted

---

#### rustywallet-export
Export keys to various formats.

```rust
let json = export_json(&key, Network::Mainnet)?;
let csv = export_csv(&keys, &["wif", "address"])?;
```

**Supported formats:**
- WIF, Hex, JSON, CSV
- Paper wallet
- BIP38 encrypted
- BIP21 URI

---

### Performance Crates

#### rustywallet-batch
High-speed key generation (7M+ keys/sec).

```rust
let gen = FastKeyGenerator::new();
for key in gen.take(1_000_000) {
    // Process key
}
```

**Use when:** You need to generate/scan millions of keys.

---

#### rustywallet-vanity
Find addresses with custom patterns.

```rust
let result = VanityGenerator::new()
    .pattern(Pattern::prefix("1Love"))
    .generate()?;
```

**Use when:** You want a memorable address.

## Minimal Setup Examples

### Just generate addresses
```toml
[dependencies]
rustywallet-keys = "0.1"
rustywallet-address = "0.1"
```

### Full HD wallet
```toml
[dependencies]
rustywallet-mnemonic = "0.1"
rustywallet-hd = "0.1"
rustywallet-address = "0.1"
```

### Check balances
```toml
[dependencies]
rustywallet-electrum = "0.1"
tokio = { version = "1", features = ["full"] }
```

### Build transactions
```toml
[dependencies]
rustywallet-keys = "0.1"
rustywallet-tx = "0.1"
rustywallet-electrum = "0.1"
tokio = { version = "1", features = ["full"] }
```
