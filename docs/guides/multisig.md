# Multi-Signature Wallets Guide

Multi-signature (multisig) wallets require multiple keys to authorize transactions, providing enhanced security.

## What is Multisig?

In an M-of-N multisig:
- **N** = Total number of keys
- **M** = Required signatures to spend

Examples:
- **2-of-3**: 3 keys, need 2 to sign (common for businesses)
- **3-of-5**: 5 keys, need 3 to sign (board of directors)
- **1-of-2**: 2 keys, either can sign (joint account)

## Creating a Multisig Wallet

```rust
use rustywallet_multisig::prelude::*;
use rustywallet_keys::prelude::PrivateKey;

// Generate 3 keys (in practice, from different parties)
let key1 = PrivateKey::random();
let key2 = PrivateKey::random();
let key3 = PrivateKey::random();

// Get compressed public keys
let pubkeys = vec![
    key1.public_key().to_compressed(),
    key2.public_key().to_compressed(),
    key3.public_key().to_compressed(),
];

// Create 2-of-3 multisig wallet
let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet)?;

println!("Configuration: {}", wallet.config.description());  // "2-of-3"
println!("P2SH:  {}", wallet.address_p2sh);       // 3...
println!("P2WSH: {}", wallet.address_p2wsh);      // bc1q...
println!("Nested: {}", wallet.address_p2sh_p2wsh); // 3...
```

## Address Types

| Type | Prefix | Description | Fees |
|------|--------|-------------|------|
| P2SH | 3... | Legacy multisig | Highest |
| P2WSH | bc1q... | Native SegWit | Lowest |
| P2SH-P2WSH | 3... | Nested SegWit | Medium |

### When to Use Each

- **P2SH**: Maximum compatibility with old wallets
- **P2WSH**: Lowest fees, modern wallets
- **P2SH-P2WSH**: Balance of compatibility and fees

## Signing Transactions

### Step 1: Create Sighash

```rust
// Each party needs the same sighash
let sighash = compute_p2sh_sighash(&tx_bytes, input_index, &wallet.redeem_script);
```

### Step 2: Collect Signatures

Each party signs independently:

```rust
// Party 1 signs
let sig1 = sign_p2sh_multisig(&sighash, &key1, &wallet)?;
println!("Signature 1: {} bytes", sig1.signature.len());

// Party 2 signs
let sig2 = sign_p2sh_multisig(&sighash, &key2, &wallet)?;
println!("Signature 2: {} bytes", sig2.signature.len());

// Party 3 doesn't need to sign (2-of-3)
```

### Step 3: Combine Signatures

```rust
// Combine signatures (need at least M)
let combined = combine_signatures(&[sig1, sig2], &wallet)?;

// Build scriptSig for P2SH
let script_sig = combined.build_script_sig();

// Or build witness for P2WSH
let witness = combined.build_witness();
```

## Complete Signing Example

```rust
use rustywallet_multisig::prelude::*;
use rustywallet_keys::prelude::PrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup: 3 parties each have a key
    let key1 = PrivateKey::random();
    let key2 = PrivateKey::random();
    let key3 = PrivateKey::random();

    let pubkeys = vec![
        key1.public_key().to_compressed(),
        key2.public_key().to_compressed(),
        key3.public_key().to_compressed(),
    ];

    // Create 2-of-3 wallet
    let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet)?;
    println!("Deposit to: {}", wallet.address_p2wsh);

    // Later: spending from the multisig
    // (In practice, sighash comes from transaction building)
    let sighash = [0xab; 32];  // Example sighash

    // Party 1 signs and sends sig1 to coordinator
    let sig1 = sign_p2sh_multisig(&sighash, &key1, &wallet)?;

    // Party 2 signs and sends sig2 to coordinator
    let sig2 = sign_p2sh_multisig(&sighash, &key2, &wallet)?;

    // Coordinator combines signatures
    let combined = combine_signatures(&[sig1, sig2], &wallet)?;

    // For P2WSH transaction
    let witness = combined.build_witness();
    println!("Witness has {} items", witness.len());

    Ok(())
}
```

## BIP67: Key Ordering

rustywallet automatically sorts public keys lexicographically (BIP67):

```rust
// Keys are sorted regardless of input order
let wallet1 = MultisigWallet::from_pubkeys(2, vec![key_a, key_b, key_c], Network::Mainnet)?;
let wallet2 = MultisigWallet::from_pubkeys(2, vec![key_c, key_a, key_b], Network::Mainnet)?;

// Same addresses!
assert_eq!(wallet1.address_p2wsh, wallet2.address_p2wsh);
```

## Redeem Script

The redeem script defines the multisig rules:

```rust
// Access the redeem script
let script = &wallet.redeem_script;
println!("Redeem script: {} bytes", script.len());

// For backup/recovery, save the redeem script
let hex = hex::encode(script);
println!("Save this: {}", hex);
```

**Important**: Always backup the redeem script! Without it, you cannot spend from the multisig address.

## Error Handling

```rust
// Invalid threshold
let result = MultisigConfig::new(0, pubkeys.clone());
// Error: InvalidThreshold { m: 0, n: 3 }

let result = MultisigConfig::new(5, pubkeys.clone());
// Error: InvalidThreshold { m: 5, n: 3 }

// Duplicate keys
let result = MultisigConfig::new(2, vec![key1, key1, key2]);
// Error: DuplicateKey { index: 1 }

// Not enough signatures
let result = combine_signatures(&[sig1], &wallet);  // Need 2
// Error: NotEnoughSignatures { need: 2, got: 1 }

// Wrong key
let wrong_key = PrivateKey::random();
let result = sign_p2sh_multisig(&sighash, &wrong_key, &wallet);
// Error: InvalidPublicKey("Key not in multisig")
```

## Shamir Secret Sharing

Split a private key into shares for secure backup:

```rust
use rustywallet_multisig::{split_secret, combine_shares, ShamirShare};

// Split into 5 shares, need 3 to recover
let secret = private_key.to_bytes();
let shares = split_secret(&secret, 3, 5)?;

println!("Created {} shares", shares.len());
for (i, share) in shares.iter().enumerate() {
    println!("Share {}: {}", i + 1, share.to_hex());
}

// Distribute shares to different locations...

// Later: recover with any 3 shares
let recovered = combine_shares(&[
    shares[0].clone(),
    shares[2].clone(),
    shares[4].clone(),
])?;

assert_eq!(recovered, secret);
println!("Secret recovered successfully!");
```

### Share Format

```rust
let share = &shares[0];
println!("Index: {}", share.index);       // 1-255
println!("Threshold: {}", share.threshold); // M required
println!("Total: {}", share.total);        // N total

// Serialize for storage
let hex = share.to_hex();

// Deserialize
let restored = ShamirShare::from_hex(&hex)?;
```

### Security Properties

- Any M shares can recover the secret
- M-1 shares reveal **nothing** about the secret
- Shares are deterministic (same input = same shares)

## Best Practices

### 1. Key Generation
- Each party generates their own key
- Never share private keys
- Use hardware wallets for high-value multisig

### 2. Backup
- Backup redeem script separately from keys
- Store shares in different locations
- Test recovery before depositing funds

### 3. Signing Workflow
```
1. Coordinator creates unsigned transaction
2. Coordinator sends sighash to all parties
3. Each party signs and returns signature
4. Coordinator combines signatures
5. Coordinator broadcasts transaction
```

### 4. Threshold Selection

| Use Case | Recommended |
|----------|-------------|
| Personal backup | 2-of-3 |
| Small business | 2-of-3 or 3-of-5 |
| Large organization | 3-of-5 or 4-of-7 |
| Cold storage | 3-of-5 with geographic distribution |

## Common Configurations

### Personal Wallet (2-of-3)
- Key 1: Your phone
- Key 2: Your computer
- Key 3: Hardware wallet (backup)

### Business (3-of-5)
- Key 1-3: Active signers
- Key 4-5: Backup keys in secure storage

### Inheritance Planning
- 2-of-3 with keys held by:
  - You
  - Spouse
  - Lawyer/executor

## Next Steps

- [Transaction Building](./transactions.md)
- [Shamir Secret Sharing](../advanced/shamir.md)
- [Security Best Practices](../advanced/security.md)
