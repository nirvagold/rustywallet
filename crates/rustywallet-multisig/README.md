# rustywallet-multisig

Bitcoin multi-signature wallet utilities with Shamir Secret Sharing.

## Features

- **M-of-N Multisig** - Create 1-of-2 up to 15-of-15 configurations
- **Multiple Address Types** - P2SH (legacy), P2WSH (native SegWit), P2SH-P2WSH (nested)
- **BIP67 Compliance** - Automatic lexicographic key sorting
- **Partial Signing** - Sign with individual keys
- **Signature Combination** - Combine signatures for broadcast
- **Shamir Secret Sharing** - Split keys into recoverable shares

## Installation

```toml
[dependencies]
rustywallet-multisig = "0.1"
```

## Quick Start

```rust
use rustywallet_multisig::prelude::*;
use rustywallet_keys::prelude::PrivateKey;

// Generate 3 keys
let key1 = PrivateKey::random();
let key2 = PrivateKey::random();
let key3 = PrivateKey::random();

let pubkeys = vec![
    key1.public_key().to_compressed(),
    key2.public_key().to_compressed(),
    key3.public_key().to_compressed(),
];

// Create 2-of-3 multisig wallet
let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet).unwrap();

println!("P2SH: {}", wallet.address_p2sh);       // 3...
println!("P2WSH: {}", wallet.address_p2wsh);     // bc1q...
println!("Nested: {}", wallet.address_p2sh_p2wsh); // 3...
```

## Signing Transactions

```rust
use rustywallet_multisig::{sign_p2sh_multisig, combine_signatures};

// Each party signs with their key
let sig1 = sign_p2sh_multisig(&sighash, &key1, &wallet).unwrap();
let sig2 = sign_p2sh_multisig(&sighash, &key2, &wallet).unwrap();

// Combine signatures (need M signatures)
let combined = combine_signatures(&[sig1, sig2], &wallet).unwrap();

// Build scriptSig for P2SH
let script_sig = combined.build_script_sig();

// Or build witness for P2WSH
let witness = combined.build_witness();
```

## Shamir Secret Sharing

Split a private key into shares for secure backup:

```rust
use rustywallet_multisig::{split_secret, combine_shares};

// Split into 5 shares, requiring 3 to recover
let secret = [0x42u8; 32]; // Your private key bytes
let shares = split_secret(&secret, 3, 5).unwrap();

// Distribute shares to different locations...

// Later, recover with any 3 shares
let recovered = combine_shares(&shares[0..3]).unwrap();
assert_eq!(recovered, secret);
```

## Address Types

| Type | Prefix | Description |
|------|--------|-------------|
| P2SH | `3...` (mainnet) | Legacy multisig |
| P2WSH | `bc1q...` | Native SegWit (lower fees) |
| P2SH-P2WSH | `3...` | Nested SegWit (compatibility) |

## License

MIT
