# HD Wallets Guide

Hierarchical Deterministic (HD) wallets let you generate unlimited addresses from a single seed.

## Why HD Wallets?

- **Single Backup** - One mnemonic backs up all addresses
- **Privacy** - Use a new address for each transaction
- **Organization** - Separate accounts for different purposes
- **Recovery** - Restore entire wallet from 12-24 words

## Quick Start

```rust
use rustywallet_mnemonic::Mnemonic;
use rustywallet_hd::ExtendedPrivateKey;
use rustywallet_address::prelude::*;

// 1. Generate mnemonic
let mnemonic = Mnemonic::generate(12)?;
println!("Backup these words: {}", mnemonic.phrase());

// 2. Convert to seed
let seed = mnemonic.to_seed("optional-passphrase");

// 3. Create master key
let master = ExtendedPrivateKey::from_seed(&seed)?;

// 4. Derive addresses
let child = master.derive_path("m/84'/0'/0'/0/0")?;
let address = Address::p2wpkh(&child.public_key(), Network::Mainnet)?;

println!("First address: {}", address);
```

## Mnemonic Phrases

### Generation

```rust
use rustywallet_mnemonic::Mnemonic;

// 12 words (128 bits entropy) - recommended
let mnemonic = Mnemonic::generate(12)?;

// 24 words (256 bits entropy) - maximum security
let mnemonic = Mnemonic::generate(24)?;

// Available word counts: 12, 15, 18, 21, 24
```

### Import Existing

```rust
let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::from_phrase(phrase)?;
```

### Passphrase (Optional)

The passphrase adds an extra layer of security:

```rust
// Without passphrase
let seed1 = mnemonic.to_seed("");

// With passphrase - creates completely different wallet!
let seed2 = mnemonic.to_seed("my-secret-passphrase");

// seed1 != seed2
```

**Benefits of passphrase:**
- Plausible deniability (different passphrase = different wallet)
- Extra security layer
- Can create multiple wallets from same mnemonic

**Risks:**
- If forgotten, funds are lost forever
- No way to recover or reset

## Derivation Paths

### Path Format

```
m / purpose' / coin_type' / account' / change / address_index
```

| Component | Description |
|-----------|-------------|
| m | Master key |
| purpose' | BIP number (44, 49, 84, 86) |
| coin_type' | 0 = Bitcoin, 1 = Testnet |
| account' | Account number (0, 1, 2...) |
| change | 0 = receiving, 1 = change |
| address_index | Address number (0, 1, 2...) |

The `'` means hardened derivation (more secure).

### Standard Paths

| BIP | Path | Address Type |
|-----|------|--------------|
| BIP44 | m/44'/0'/0'/0/0 | P2PKH (1...) |
| BIP49 | m/49'/0'/0'/0/0 | P2SH-P2WPKH (3...) |
| BIP84 | m/84'/0'/0'/0/0 | P2WPKH (bc1q...) |
| BIP86 | m/86'/0'/0'/0/0 | P2TR (bc1p...) |

### Examples

```rust
let master = ExtendedPrivateKey::from_seed(&seed)?;

// First receiving address (BIP84)
let addr0 = master.derive_path("m/84'/0'/0'/0/0")?;

// Second receiving address
let addr1 = master.derive_path("m/84'/0'/0'/0/1")?;

// First change address
let change0 = master.derive_path("m/84'/0'/0'/1/0")?;

// Second account, first address
let account1 = master.derive_path("m/84'/0'/1'/0/0")?;
```

## Extended Keys

### Extended Private Key (xprv)

```rust
let master = ExtendedPrivateKey::from_seed(&seed)?;

// Serialize to string
let xprv = master.to_string();
// xprv9s21ZrQH143K3GJpoapnV8SFfuZcESnO...

// Deserialize
let restored = ExtendedPrivateKey::from_str(&xprv)?;
```

### Extended Public Key (xpub)

```rust
let xpub = master.extended_public_key();

// Can derive child public keys without private key!
let child_pub = xpub.derive_path("0/0")?;  // Non-hardened only
```

**Use cases for xpub:**
- Watch-only wallets
- Payment processors (generate addresses without private keys)
- Hardware wallet integration

### Key Versions

| Version | Prefix | Network | Type |
|---------|--------|---------|------|
| xprv | 0488ADE4 | Mainnet | Private |
| xpub | 0488B21E | Mainnet | Public |
| tprv | 04358394 | Testnet | Private |
| tpub | 043587CF | Testnet | Public |

## Generating Multiple Addresses

### Sequential Generation

```rust
fn generate_addresses(master: &ExtendedPrivateKey, count: usize) -> Vec<String> {
    (0..count)
        .map(|i| {
            let path = format!("m/84'/0'/0'/0/{}", i);
            let child = master.derive_path(&path).unwrap();
            Address::p2wpkh(&child.public_key(), Network::Mainnet)
                .unwrap()
                .to_string()
        })
        .collect()
}

let addresses = generate_addresses(&master, 10);
```

### Account Structure

```rust
struct Account {
    index: u32,
    receiving: Vec<String>,
    change: Vec<String>,
}

fn create_account(master: &ExtendedPrivateKey, account_index: u32) -> Account {
    let base = format!("m/84'/0'/{}'/", account_index);
    
    let receiving: Vec<String> = (0..20)
        .map(|i| {
            let path = format!("{}0/{}", base, i);
            let child = master.derive_path(&path).unwrap();
            Address::p2wpkh(&child.public_key(), Network::Mainnet)
                .unwrap()
                .to_string()
        })
        .collect();
    
    let change: Vec<String> = (0..20)
        .map(|i| {
            let path = format!("{}1/{}", base, i);
            let child = master.derive_path(&path).unwrap();
            Address::p2wpkh(&child.public_key(), Network::Mainnet)
                .unwrap()
                .to_string()
        })
        .collect();
    
    Account { index: account_index, receiving, change }
}
```

## Gap Limit

The "gap limit" is the number of consecutive unused addresses to scan before stopping.

```rust
const GAP_LIMIT: usize = 20;

async fn find_used_addresses(
    master: &ExtendedPrivateKey,
    client: &ElectrumClient,
) -> Vec<String> {
    let mut used = Vec::new();
    let mut gap = 0;
    let mut index = 0;
    
    while gap < GAP_LIMIT {
        let path = format!("m/84'/0'/0'/0/{}", index);
        let child = master.derive_path(&path).unwrap();
        let address = Address::p2wpkh(&child.public_key(), Network::Mainnet)
            .unwrap()
            .to_string();
        
        let balance = client.get_balance(&address).await.unwrap();
        
        if balance.confirmed > 0 || balance.unconfirmed > 0 {
            used.push(address);
            gap = 0;
        } else {
            gap += 1;
        }
        
        index += 1;
    }
    
    used
}
```

## Best Practices

1. **Always backup mnemonic** - Write it down, store securely
2. **Use passphrase for large amounts** - Extra security layer
3. **Use standard derivation paths** - For wallet compatibility
4. **Implement gap limit** - For proper wallet recovery
5. **Never reuse addresses** - Generate new one for each transaction
6. **Keep xpub secure** - It reveals all your addresses

## Wallet Recovery

```rust
// User provides mnemonic
let phrase = "abandon abandon abandon ...";
let passphrase = "optional";

// Restore wallet
let mnemonic = Mnemonic::from_phrase(phrase)?;
let seed = mnemonic.to_seed(passphrase);
let master = ExtendedPrivateKey::from_seed(&seed)?;

// Scan for used addresses
let addresses = find_used_addresses(&master, &client).await;

// Calculate total balance
let total: u64 = addresses.iter()
    .map(|addr| client.get_balance(addr).await.unwrap().confirmed)
    .sum();

println!("Recovered {} addresses with {} sats", addresses.len(), total);
```

## Next Steps

- [Transaction Building](./transactions.md)
- [Balance Checking](./balance-checking.md)
- [Import & Export](./import-export.md)
