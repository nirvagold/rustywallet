# rustywallet-frost

FROST (Flexible Round-Optimized Schnorr Threshold) signatures for rustywallet.

## Features

- **Distributed Key Generation (DKG)**: Generate threshold keys across multiple participants
- **Threshold Signing**: t-of-n threshold signatures
- **Signature Aggregation**: Combine partial signatures into valid Schnorr signature
- **Robustness**: Detection of malicious signers

## Installation

```toml
[dependencies]
rustywallet-frost = "0.1"
```

## Quick Start

```rust
use rustywallet_frost::prelude::*;

// Setup: 2-of-3 threshold
let threshold = 2;
let num_participants = 3;

// Run DKG
let (key_packages, group_public) = run_dkg(threshold, num_participants)?;

// Create signing session
let message = b"Hello, FROST!";
let signers = vec![1, 2]; // Participants 1 and 2 will sign

// Generate commitments
let commitments: Vec<_> = signers.iter()
    .map(|&id| generate_nonces(&key_packages[&id]))
    .collect();

// Create partial signatures
let partial_sigs: Vec<_> = signers.iter()
    .zip(commitments.iter())
    .map(|(&id, nonce)| sign(&key_packages[&id], nonce, message, &commitments))
    .collect();

// Aggregate into final signature
let signature = aggregate(&partial_sigs, &group_public)?;

// Verify
assert!(verify(&signature, &group_public, message)?);
```

## Security Notes

- Minimum threshold of 2 is enforced
- Secret shares are zeroized on drop
- Malicious participant detection during DKG
- Nonces must never be reused

## License

MIT
