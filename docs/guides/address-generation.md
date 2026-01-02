# Address Generation Guide

This guide covers all Bitcoin address types and how to generate them.

## Address Types Overview

| Type | Prefix | BIP | Description |
|------|--------|-----|-------------|
| P2PKH | 1... | - | Legacy, pay to public key hash |
| P2SH | 3... | 16 | Pay to script hash |
| P2WPKH | bc1q... | 141 | Native SegWit |
| P2WSH | bc1q... (longer) | 141 | SegWit script hash |
| P2TR | bc1p... | 341 | Taproot |

## Basic Usage

```rust
use rustywallet_keys::prelude::PrivateKey;
use rustywallet_address::prelude::*;

let private_key = PrivateKey::random();
let public_key = private_key.public_key();

// Generate all address types
let p2pkh = Address::p2pkh(&public_key, Network::Mainnet)?;
let p2wpkh = Address::p2wpkh(&public_key, Network::Mainnet)?;
let p2tr = Address::p2tr(&public_key, Network::Mainnet)?;

println!("P2PKH:  {}", p2pkh);   // 1...
println!("P2WPKH: {}", p2wpkh);  // bc1q...
println!("P2TR:   {}", p2tr);    // bc1p...
```

## P2PKH (Legacy)

The original Bitcoin address format.

```rust
let address = Address::p2pkh(&public_key, Network::Mainnet)?;
// Example: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
```

**Characteristics:**
- Starts with `1` (mainnet) or `m`/`n` (testnet)
- 25-34 characters
- Base58Check encoded
- Highest transaction fees

**When to use:**
- Maximum compatibility with old wallets
- Not recommended for new applications

## P2SH (Script Hash)

Used for complex scripts like multisig.

```rust
// For multisig, use rustywallet-multisig
use rustywallet_multisig::MultisigWallet;

let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet)?;
println!("P2SH: {}", wallet.address_p2sh);  // 3...
```

**Characteristics:**
- Starts with `3` (mainnet) or `2` (testnet)
- Used for multisig, time-locks, etc.
- Medium transaction fees

## P2WPKH (Native SegWit)

The recommended address type for most use cases.

```rust
let address = Address::p2wpkh(&public_key, Network::Mainnet)?;
// Example: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
```

**Characteristics:**
- Starts with `bc1q` (mainnet) or `tb1q` (testnet)
- Bech32 encoded (lowercase, no ambiguous characters)
- ~30% lower fees than P2PKH
- Better error detection

**When to use:**
- Default choice for new wallets
- Best balance of compatibility and efficiency

## P2WSH (SegWit Script Hash)

SegWit version of P2SH.

```rust
use rustywallet_multisig::MultisigWallet;

let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet)?;
println!("P2WSH: {}", wallet.address_p2wsh);  // bc1q... (longer)
```

**Characteristics:**
- Starts with `bc1q` (mainnet)
- Longer than P2WPKH (62 characters)
- Used for SegWit multisig

## P2TR (Taproot)

The newest and most advanced address type.

```rust
let address = Address::p2tr(&public_key, Network::Mainnet)?;
// Example: bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297
```

**Characteristics:**
- Starts with `bc1p` (mainnet) or `tb1p` (testnet)
- Bech32m encoded
- Best privacy (single-sig looks like multisig)
- Lowest fees for complex scripts
- Schnorr signatures

**When to use:**
- Privacy-focused applications
- Complex scripts (multisig, time-locks)
- Future-proof wallets

## Network Selection

```rust
// Mainnet
let addr = Address::p2wpkh(&public_key, Network::Mainnet)?;
// bc1q...

// Testnet
let addr = Address::p2wpkh(&public_key, Network::Testnet)?;
// tb1q...
```

## Address Validation

```rust
use rustywallet_address::validate_address;

// Check if address is valid
let is_valid = validate_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
assert!(is_valid);

// Invalid address
let is_valid = validate_address("bc1invalid");
assert!(!is_valid);
```

## Ethereum Addresses

rustywallet also supports Ethereum addresses:

```rust
let eth_address = Address::ethereum(&public_key)?;
// Example: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F
```

**Characteristics:**
- Starts with `0x`
- 40 hex characters (20 bytes)
- Keccak-256 hash of public key
- Optional EIP-55 checksum (mixed case)

## Derivation Paths for HD Wallets

Different address types use different BIP44 derivation paths:

| Type | Path | BIP |
|------|------|-----|
| P2PKH | m/44'/0'/0'/0/0 | BIP44 |
| P2SH-P2WPKH | m/49'/0'/0'/0/0 | BIP49 |
| P2WPKH | m/84'/0'/0'/0/0 | BIP84 |
| P2TR | m/86'/0'/0'/0/0 | BIP86 |

```rust
use rustywallet_hd::ExtendedPrivateKey;

let master = ExtendedPrivateKey::from_seed(&seed)?;

// BIP84 for P2WPKH
let child = master.derive_path("m/84'/0'/0'/0/0")?;
let address = Address::p2wpkh(&child.public_key(), Network::Mainnet)?;

// BIP86 for P2TR
let child = master.derive_path("m/86'/0'/0'/0/0")?;
let address = Address::p2tr(&child.public_key(), Network::Mainnet)?;
```

## Fee Comparison

Approximate transaction sizes and fees:

| Type | Input Size | Relative Fee |
|------|------------|--------------|
| P2PKH | 148 vB | 100% |
| P2SH-P2WPKH | 91 vB | 61% |
| P2WPKH | 68 vB | 46% |
| P2TR | 58 vB | 39% |

## Best Practices

1. **Use P2WPKH for most cases** - Good balance of compatibility and fees
2. **Use P2TR for privacy** - All scripts look the same
3. **Avoid P2PKH for new wallets** - Higher fees, no benefits
4. **Always validate addresses** - Before sending funds
5. **Use correct network** - Don't mix mainnet/testnet

## Common Patterns

### Generate Multiple Addresses

```rust
fn generate_addresses(count: usize, network: Network) -> Vec<String> {
    (0..count)
        .map(|_| {
            let key = PrivateKey::random();
            Address::p2wpkh(&key.public_key(), network)
                .unwrap()
                .to_string()
        })
        .collect()
}
```

### Address with Metadata

```rust
struct AddressInfo {
    address: String,
    address_type: String,
    network: Network,
    public_key: String,
}

fn create_address_info(public_key: &PublicKey, network: Network) -> AddressInfo {
    AddressInfo {
        address: Address::p2wpkh(public_key, network).unwrap().to_string(),
        address_type: "P2WPKH".to_string(),
        network,
        public_key: public_key.to_hex_compressed(),
    }
}
```

## Next Steps

- [HD Wallets Guide](./hd-wallets.md)
- [Transaction Building](./transactions.md)
- [Multi-Signature Wallets](./multisig.md)
