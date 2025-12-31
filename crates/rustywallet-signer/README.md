# rustywallet-signer

ECDSA message signing and verification for Bitcoin and Ethereum.

## Features

- Sign arbitrary messages with ECDSA secp256k1
- Verify signatures against public keys
- Bitcoin message signing (BIP-137 compatible)
- Ethereum personal_sign (EIP-191)
- Recoverable signatures for public key recovery
- Deterministic signing (RFC 6979)

## Installation

```toml
[dependencies]
rustywallet-signer = "0.1"
rustywallet-keys = "0.1"
```

## Quick Start

```rust
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_signer::prelude::*;
use sha2::{Sha256, Digest};

// Generate a key
let key = PrivateKey::random();
let pubkey = key.public_key();

// Sign a message hash
let hash: [u8; 32] = Sha256::digest(b"hello world").into();
let signature = sign(&key, &hash).unwrap();

// Verify the signature
assert!(verify(&pubkey, &hash, &signature));
```

## Bitcoin Message Signing

Sign messages compatible with Bitcoin Core's `signmessage`:

```rust
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_signer::bitcoin::sign_bitcoin_message;

let key = PrivateKey::random();
let signature = sign_bitcoin_message(&key, "Hello Bitcoin!").unwrap();
println!("Base64 signature: {}", signature);
```

## Ethereum Personal Sign

Sign messages compatible with MetaMask and web3.js:

```rust
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_signer::ethereum::{sign_ethereum_message, public_key_to_address, format_address};

let key = PrivateKey::random();
let address = public_key_to_address(&key.public_key());
let signature = sign_ethereum_message(&key, b"Hello Ethereum!").unwrap();

println!("Address: {}", format_address(&address));
println!("Signature: {}", signature.to_ethereum_hex());
```

## Recoverable Signatures

Recover the public key from a signature:

```rust
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_signer::{sign_recoverable, recover_public_key};
use sha2::{Sha256, Digest};

let key = PrivateKey::random();
let hash: [u8; 32] = Sha256::digest(b"hello").into();

let sig = sign_recoverable(&key, &hash).unwrap();
let recovered = recover_public_key(&sig, &hash).unwrap();

assert_eq!(key.public_key().to_compressed(), recovered.to_compressed());
```

## API Overview

### Core Functions

- `sign(private_key, message_hash)` - Sign a 32-byte hash
- `sign_recoverable(private_key, message_hash)` - Sign with recovery id
- `verify(public_key, message_hash, signature)` - Verify a signature
- `recover_public_key(signature, message_hash)` - Recover public key

### Bitcoin Functions

- `sign_bitcoin_message(private_key, message)` - Sign in Bitcoin format
- `verify_bitcoin_message(address, message, signature)` - Verify Bitcoin signature

### Ethereum Functions

- `sign_ethereum_message(private_key, message)` - Sign in EIP-191 format
- `verify_ethereum_message(address, message, signature)` - Verify Ethereum signature
- `recover_ethereum_address(signature, message)` - Recover address from signature
- `public_key_to_address(public_key)` - Derive Ethereum address
- `format_address(address)` - Format with EIP-55 checksum

## Security

- Uses RFC 6979 for deterministic nonce generation
- Constant-time operations via secp256k1 library
- No secret data in error messages

## License

MIT
