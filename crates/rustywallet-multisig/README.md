# rustywallet-multisig

Bitcoin multi-signature wallet utilities with Shamir Secret Sharing, MuSig2, and FROST support.

## Features

- **M-of-N Multisig** - Create 1-of-2 up to 15-of-15 configurations
- **Multiple Address Types** - P2SH (legacy), P2WSH (native SegWit), P2SH-P2WSH (nested)
- **BIP67 Compliance** - Automatic lexicographic key sorting
- **Partial Signing** - Sign with individual keys
- **Signature Combination** - Combine signatures for broadcast
- **Shamir Secret Sharing** - Split keys into recoverable shares
- **MuSig2 Support** - n-of-n Schnorr multisig with key aggregation
- **FROST Threshold Signatures** - t-of-n threshold Schnorr signatures

## Installation

```toml
[dependencies]
rustywallet-multisig = "0.3"
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

## FROST Threshold Signatures

FROST enables t-of-n threshold Schnorr signatures without reconstructing the private key:

```rust
use rustywallet_multisig::frost::{FrostMultisig, FrostParticipant};
use rustywallet_frost::prelude::*;

// After DKG (Distributed Key Generation), create FrostMultisig
let frost_multisig = FrostMultisig::from_dkg(public_key_package);

// Get P2TR address for the threshold wallet
let address = frost_multisig.p2tr_address(Network::Mainnet).unwrap();
println!("FROST P2TR address: {}", address); // bc1p...

// Start a signing round
let message = [0xab; 32]; // Transaction sighash
let mut round = frost_multisig.start_signing(message);

// Each participant generates nonces and commitments
let mut participant = FrostParticipant::new(key_package);
let commitments = participant.generate_nonces().unwrap();

// Add commitments from all participating signers
round.add_commitment(participant.identifier(), commitments).unwrap();
// ... add more commitments from other participants

// Finalize commitment phase
round.finalize_commitments().unwrap();

// Each participant creates a partial signature
let partial_sig = participant.sign(round.commitments(), &message).unwrap();
round.add_partial_sig(partial_sig).unwrap();
// ... add more partial signatures

// Aggregate into final Schnorr signature
let signature = round.finalize().unwrap();
```

## FROST PSBT Integration

For hardware wallet compatibility, use the PSBT builder:

```rust
use rustywallet_multisig::frost::FrostPsbtBuilder;

// Create PSBT builder for FROST signing
let mut builder = FrostPsbtBuilder::new(frost_multisig, input_count);

// Set message hash for each input
builder.set_message(0, sighash).unwrap();

// Add commitments and signatures as they arrive
builder.add_commitment(0, identifier, commitments).unwrap();
builder.add_partial_sig(0, signature_share).unwrap();

// Finalize when threshold is reached
if builder.is_complete() {
    let signature = builder.finalize_input(0).unwrap();
}
```

## MuSig2 Key Aggregation

For n-of-n Schnorr multisig:

```rust
use rustywallet_multisig::{MuSigKeyAgg, musig_to_p2tr_address, Network};

let pubkeys = vec![
    key1.public_key().to_compressed(),
    key2.public_key().to_compressed(),
];

// Aggregate keys
let key_agg = MuSigKeyAgg::new(pubkeys).unwrap();

// Get P2TR address
let address = musig_to_p2tr_address(&key_agg, Network::Mainnet).unwrap();
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
| P2TR (FROST/MuSig2) | `bc1p...` | Taproot (lowest fees, best privacy) |

## Comparison: FROST vs MuSig2

| Feature | FROST | MuSig2 |
|---------|-------|--------|
| Threshold | t-of-n | n-of-n only |
| Setup | DKG required | Key aggregation |
| Rounds | 2 rounds | 2-3 rounds |
| Use Case | Flexible threshold | All parties must sign |

## License

MIT
