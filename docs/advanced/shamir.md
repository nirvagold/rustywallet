# Shamir Secret Sharing

This guide covers splitting and recovering secrets using Shamir's Secret Sharing Scheme (SSSS) in `rustywallet-multisig`.

## What is Shamir Secret Sharing?

Shamir's Secret Sharing splits a secret into N shares where any K shares can reconstruct the original secret, but K-1 shares reveal nothing.

Use cases:
- **Backup distribution** - Split seed across family members
- **Corporate custody** - Require multiple executives to sign
- **Dead man's switch** - Heirs can recover with threshold
- **Geographic distribution** - Shares in different locations

## Basic Usage

### Split a Secret

```rust
use rustywallet_multisig::shamir::{split_secret, ShamirConfig};

// Your secret (e.g., private key bytes)
let secret = b"my-secret-private-key-32-bytes!!";

// Split into 5 shares, requiring 3 to recover
let config = ShamirConfig {
    threshold: 3,  // K - minimum shares needed
    shares: 5,     // N - total shares created
};

let shares = split_secret(secret, config)?;

// Distribute shares to different parties
for (i, share) in shares.iter().enumerate() {
    println!("Share {}: {}", i + 1, hex::encode(share));
}
```

### Recover a Secret

```rust
use rustywallet_multisig::shamir::recover_secret;

// Collect any 3 of the 5 shares
let collected_shares = vec![
    shares[0].clone(),  // Share 1
    shares[2].clone(),  // Share 3
    shares[4].clone(),  // Share 5
];

// Recover the original secret
let recovered = recover_secret(&collected_shares)?;

assert_eq!(recovered, secret);
println!("Secret recovered successfully!");
```

## Splitting Private Keys

### Split a WIF Private Key

```rust
use rustywallet_keys::PrivateKey;
use rustywallet_multisig::shamir::{split_secret, recover_secret, ShamirConfig};

// Generate or import a private key
let private_key = PrivateKey::random();
let secret_bytes = private_key.to_bytes();

// Split 2-of-3
let config = ShamirConfig {
    threshold: 2,
    shares: 3,
};

let shares = split_secret(&secret_bytes, config)?;

// Later: recover with any 2 shares
let recovered_bytes = recover_secret(&shares[0..2].to_vec())?;
let recovered_key = PrivateKey::from_bytes(&recovered_bytes)?;

assert_eq!(private_key, recovered_key);
```

### Split a Mnemonic Seed

```rust
use rustywallet_mnemonic::Mnemonic;
use rustywallet_multisig::shamir::{split_secret, ShamirConfig};

let mnemonic = Mnemonic::generate(24)?;
let seed = mnemonic.to_seed("");

// Split seed into 5 shares, need 3 to recover
let config = ShamirConfig {
    threshold: 3,
    shares: 5,
};

let shares = split_secret(&seed, config)?;

// Encode shares for storage
for (i, share) in shares.iter().enumerate() {
    let encoded = hex::encode(share);
    println!("Share {}: {}", i + 1, encoded);
    // Store each share in a different secure location
}
```

## Share Format

Each share contains:
- **Index** (1 byte) - Share number (1-255)
- **Threshold** (1 byte) - Required shares (K)
- **Data** - Encrypted share data

```rust
// Share structure
struct Share {
    index: u8,      // 1-255
    threshold: u8,  // K value
    data: Vec<u8>,  // Share data
}

// Encode to hex for storage
let hex_share = hex::encode(&share);

// Decode from hex
let share_bytes = hex::decode(&hex_share)?;
```

## Configuration Options

### Common Configurations

```rust
// 2-of-3: Simple backup
let config = ShamirConfig { threshold: 2, shares: 3 };

// 3-of-5: Corporate custody
let config = ShamirConfig { threshold: 3, shares: 5 };

// 4-of-7: High security
let config = ShamirConfig { threshold: 4, shares: 7 };

// 2-of-2: Dual control (both required)
let config = ShamirConfig { threshold: 2, shares: 2 };
```

### Validation

```rust
use rustywallet_multisig::shamir::ShamirConfig;

// Valid configurations
assert!(ShamirConfig { threshold: 2, shares: 3 }.is_valid());
assert!(ShamirConfig { threshold: 3, shares: 5 }.is_valid());

// Invalid: threshold > shares
assert!(!ShamirConfig { threshold: 4, shares: 3 }.is_valid());

// Invalid: threshold = 0
assert!(!ShamirConfig { threshold: 0, shares: 3 }.is_valid());

// Invalid: shares > 255
assert!(!ShamirConfig { threshold: 2, shares: 256 }.is_valid());
```

## Error Handling

```rust
use rustywallet_multisig::shamir::{split_secret, recover_secret, ShamirError};

// Splitting errors
match split_secret(secret, config) {
    Ok(shares) => println!("Split into {} shares", shares.len()),
    Err(ShamirError::InvalidThreshold) => {
        eprintln!("Threshold must be <= shares");
    }
    Err(ShamirError::TooManyShares) => {
        eprintln!("Maximum 255 shares");
    }
    Err(e) => eprintln!("Error: {}", e),
}

// Recovery errors
match recover_secret(&shares) {
    Ok(secret) => println!("Recovered!"),
    Err(ShamirError::InsufficientShares { have, need }) => {
        eprintln!("Need {} shares, only have {}", need, have);
    }
    Err(ShamirError::InvalidShare) => {
        eprintln!("One or more shares are corrupted");
    }
    Err(ShamirError::InconsistentShares) => {
        eprintln!("Shares are from different secrets");
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## Security Best Practices

### Share Distribution

```rust
// GOOD: Distribute to independent parties
// Share 1 -> Safety deposit box
// Share 2 -> Trusted family member
// Share 3 -> Lawyer
// Share 4 -> Home safe
// Share 5 -> Cloud backup (encrypted)

// BAD: All shares in one location
// let all_shares = shares;  // Don't store together!
```

### Threshold Selection

```rust
// Consider failure scenarios:

// 2-of-3: Lose 1 share, still recoverable
// Risk: 2 colluding parties can steal

// 3-of-5: Lose 2 shares, still recoverable
// Risk: 3 colluding parties can steal

// 4-of-7: Lose 3 shares, still recoverable
// Risk: 4 colluding parties can steal

// Rule of thumb: threshold = (shares / 2) + 1
```

### Share Verification

```rust
// After splitting, verify recovery works
let shares = split_secret(secret, config)?;

// Test recovery with threshold shares
let test_shares: Vec<_> = shares.iter().take(config.threshold as usize).cloned().collect();
let recovered = recover_secret(&test_shares)?;

assert_eq!(recovered, secret, "Recovery verification failed!");
```

## Complete Example

```rust
use rustywallet_keys::PrivateKey;
use rustywallet_multisig::shamir::{split_secret, recover_secret, ShamirConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate a private key
    let private_key = PrivateKey::random();
    println!("Original WIF: {}", private_key.to_wif(Network::Mainnet));
    
    // 2. Split into shares
    let config = ShamirConfig {
        threshold: 3,
        shares: 5,
    };
    
    let shares = split_secret(&private_key.to_bytes(), config)?;
    
    println!("\n=== SHARES (store separately!) ===");
    for (i, share) in shares.iter().enumerate() {
        println!("Share {}: {}", i + 1, hex::encode(share));
    }
    
    // 3. Simulate recovery with 3 random shares
    println!("\n=== RECOVERY ===");
    let recovery_shares = vec![
        shares[1].clone(),  // Share 2
        shares[3].clone(),  // Share 4
        shares[4].clone(),  // Share 5
    ];
    
    let recovered_bytes = recover_secret(&recovery_shares)?;
    let recovered_key = PrivateKey::from_bytes(&recovered_bytes)?;
    
    println!("Recovered WIF: {}", recovered_key.to_wif(Network::Mainnet));
    
    // 4. Verify
    assert_eq!(private_key, recovered_key);
    println!("\n✓ Recovery successful!");
    
    Ok(())
}
```

## GF(256) Implementation Details

Shamir's scheme uses polynomial interpolation over a finite field:

```rust
// Internally uses GF(2^8) arithmetic:
// - Addition: XOR
// - Multiplication: Log/antilog tables
// - Division: Multiply by inverse

// The secret is the constant term of a random polynomial
// f(x) = secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)

// Each share is (i, f(i)) for i = 1, 2, ..., n
// Any k points can reconstruct f(0) = secret via Lagrange interpolation
```

## Comparison with Multisig

| Feature | Shamir | Multisig |
|---------|--------|----------|
| On-chain footprint | Single sig | Multiple sigs |
| Recovery | Offline | Requires signing |
| Key exposure | Full key recovered | Keys never combined |
| Flexibility | Any secret | Only signing |
| Verification | Trust shares | On-chain verification |

### When to Use Shamir

- Backup seed phrases
- Cold storage recovery
- Estate planning
- Offline key storage

### When to Use Multisig

- Active wallet security
- Corporate treasury
- Escrow services
- Verifiable threshold signing

## Next Steps

- [Multi-Signature Wallets](../guides/multisig.md)
- [Security Best Practices](./security.md)
- [Key Management](../guides/key-management.md)
