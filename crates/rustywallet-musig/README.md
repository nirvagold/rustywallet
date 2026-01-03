# rustywallet-musig

MuSig2 Schnorr multisig implementation (BIP327).

## Features

- **Key Aggregation**: Combine multiple public keys into one aggregate key
- **Nonce Generation**: Secure nonce generation with reuse prevention
- **Partial Signatures**: Create and aggregate partial signatures
- **Adaptor Signatures**: Support for atomic swaps and other protocols
- **Session Management**: High-level API for signing sessions

## Installation

```toml
[dependencies]
rustywallet-musig = "0.1"
```

## Quick Start

### Basic 2-of-2 MuSig

```rust
use rustywallet_musig::prelude::*;
use rustywallet_keys::PrivateKey;

// Generate keys for 2 signers
let sk1 = PrivateKey::random();
let sk2 = PrivateKey::random();
let pk1 = sk1.public_key().to_compressed();
let pk2 = sk2.public_key().to_compressed();

// Aggregate keys
let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
let agg_pubkey = key_agg.xonly_pubkey();

// Message to sign
let msg = [0u8; 32];

// Generate nonces (NEVER reuse!)
let mut nonce1 = SecretNonce::generate(
    sk1.as_bytes(), &pk1, agg_pubkey, Some(&msg), None
).unwrap();
let mut nonce2 = SecretNonce::generate(
    sk2.as_bytes(), &pk2, agg_pubkey, Some(&msg), None
).unwrap();

let pub_nonces = vec![
    nonce1.public_nonce().unwrap(),
    nonce2.public_nonce().unwrap(),
];

// Aggregate nonces
let agg_nonce = AggregatedNonce::aggregate(&pub_nonces, agg_pubkey, &msg).unwrap();

// Create partial signatures
let idx1 = key_agg.index_of(&pk1).unwrap();
let idx2 = key_agg.index_of(&pk2).unwrap();

let partial1 = create_partial_signature(
    &mut nonce1, sk1.as_bytes(), &key_agg, &agg_nonce, &pub_nonces, &msg, idx1
).unwrap();
let partial2 = create_partial_signature(
    &mut nonce2, sk2.as_bytes(), &key_agg, &agg_nonce, &pub_nonces, &msg, idx2
).unwrap();

// Aggregate signatures
let signature = aggregate_partial_signatures(
    &[partial1, partial2], &agg_nonce, &key_agg
).unwrap();

// Verify
assert!(verify_signature(&signature, agg_pubkey, &msg).unwrap());
```

### Using SigningSession

```rust
use rustywallet_musig::prelude::*;
use rustywallet_keys::PrivateKey;

let sk1 = PrivateKey::random();
let sk2 = PrivateKey::random();
let pk1 = sk1.public_key().to_compressed();
let pk2 = sk2.public_key().to_compressed();

let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
let msg = [0u8; 32];

// Create session
let mut session = SigningSession::new(key_agg.clone(), msg);

// Generate nonces
let mut nonce1 = SecretNonce::generate(
    sk1.as_bytes(), &pk1, key_agg.xonly_pubkey(), Some(&msg), None
).unwrap();
let mut nonce2 = SecretNonce::generate(
    sk2.as_bytes(), &pk2, key_agg.xonly_pubkey(), Some(&msg), None
).unwrap();

let idx1 = key_agg.index_of(&pk1).unwrap();
let idx2 = key_agg.index_of(&pk2).unwrap();

// Add nonces
session.add_nonce(idx1, nonce1.public_nonce().unwrap()).unwrap();
session.add_nonce(idx2, nonce2.public_nonce().unwrap()).unwrap();

// Sign
let partial1 = session.sign(&mut nonce1, sk1.as_bytes(), idx1).unwrap();
let partial2 = session.sign(&mut nonce2, sk2.as_bytes(), idx2).unwrap();
session.add_partial_signature(partial1).unwrap();
session.add_partial_signature(partial2).unwrap();

// Aggregate and verify
let sig = session.aggregate().unwrap();
assert!(session.verify().unwrap());
```

### Adaptor Signatures

```rust
use rustywallet_musig::prelude::*;
use rustywallet_keys::PrivateKey;

// Setup (same as basic MuSig)
let sk1 = PrivateKey::random();
let sk2 = PrivateKey::random();
let pk1 = sk1.public_key().to_compressed();
let pk2 = sk2.public_key().to_compressed();

// Adaptor secret (known only to one party initially)
let adaptor_sk = PrivateKey::random();
let adaptor_point = adaptor_sk.public_key().to_compressed();

let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
let msg = [0u8; 32];

// ... generate nonces and aggregate ...

// Create adaptor partial signatures
let partial1 = create_adaptor_partial_signature(
    &mut nonce1, sk1.as_bytes(), &key_agg, &agg_nonce,
    &pub_nonces, &adaptor_point, &msg, idx1
).unwrap();

// ... aggregate adaptor signatures ...

// Complete with adaptor secret
let final_sig = adaptor_sig.complete(adaptor_sk.as_bytes()).unwrap();

// Extract secret from completed signature
let extracted = adaptor_sig.extract_secret(&final_sig).unwrap();
assert_eq!(extracted, *adaptor_sk.as_bytes());
```

## API Reference

### Types

| Type | Description |
|------|-------------|
| `KeyAggContext` | Key aggregation context |
| `SecretNonce` | Secret nonce pair (k1, k2) |
| `PublicNonce` | Public nonce pair (R1, R2) |
| `AggregatedNonce` | Aggregated nonce from all signers |
| `PartialSignature` | Partial signature from one signer |
| `SchnorrSignature` | Complete 64-byte Schnorr signature |
| `AdaptorSignature` | Adaptor signature for atomic swaps |
| `SigningSession` | High-level signing session manager |

### Session States

| State | Description |
|-------|-------------|
| `AwaitingNonces` | Waiting for nonces from signers |
| `ReadyToSign` | All nonces received, ready to sign |
| `Signing` | Signing in progress |
| `ReadyToAggregate` | All signatures received |
| `Complete` | Session complete |

## Security Notes

⚠️ **CRITICAL: NEVER reuse nonces!** Nonce reuse will leak your private key.

- Secret nonces are automatically marked as used after signing
- Attempting to reuse a nonce will return an error
- Secret nonces are zeroized on drop
- Debug output for secret values is redacted

## License

MIT
